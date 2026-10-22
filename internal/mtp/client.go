package mtp

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"
	"unicode/utf16"
)

// ErrNameConflict is returned when the daemon rejects a duplicate object name
// (0x2002).
var ErrNameConflict = errors.New("mtp: object name already exists")

// Transport is the packet-level USB transport the client needs.
type Transport interface {
	// Send writes one raw container (with retries and halt recovery).
	Send(pkt []byte) error
	// ReadPkt returns whatever arrived within the timeout (nil on timeout).
	ReadPkt(timeout time.Duration) []byte
}

// LogFunc receives verbose trace lines; nil is a no-op.
type LogFunc func(format string, args ...any)

// Client speaks MTP over a Transport.
type Client struct {
	t   Transport
	log LogFunc
	buf []byte
}

func New(t Transport, log LogFunc) *Client {
	return &Client{t: t, log: log}
}

func (c *Client) trace(format string, args ...any) {
	if c.log != nil {
		c.log(format, args...)
	}
}

func (c *Client) Send(pkt []byte) error {
	if c.log != nil {
		head := pkt
		if len(head) > 64 {
			head = head[:64]
		}
		c.trace(">> %s", hex.EncodeToString(head))
	}
	return c.t.Send(pkt)
}

// recv assembles containers until the timeout expires with nothing left.
func (c *Client) recv(timeout time.Duration) ([][]byte, error) {
	var out [][]byte
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		left := time.Until(deadline)
		if left > 50*time.Millisecond {
			left = 50 * time.Millisecond
		}
		pkt := c.t.ReadPkt(left)
		if len(pkt) > 0 {
			c.buf = append(c.buf, pkt...)
		}
		for len(c.buf) >= 12 {
			ln := binary.LittleEndian.Uint32(c.buf)
			if ln < 12 || ln > maxContainer {
				return nil, fmt.Errorf("bad MTP container length %d", ln)
			}
			if uint32(len(c.buf)) < ln {
				break
			}
			out = append(out, c.buf[:ln])
			c.buf = c.buf[ln:]
		}
		if len(out) > 0 && len(pkt) == 0 {
			break
		}
		if len(pkt) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	return out, nil
}

// Command sends a command container and collects the response containers.
func (c *Client) Command(code uint16, params []uint32, tid uint32, timeout time.Duration) ([][]byte, error) {
	if err := c.Send(Command(code, tid, params)); err != nil {
		return nil, err
	}
	return c.recv(timeout)
}

// response returns the last response packet in pkts, if any.
func response(pkts [][]byte) (Packet, bool) {
	var resp Packet
	found := false
	for _, raw := range pkts {
		p, err := Parse(raw)
		if err != nil {
			continue
		}
		if p.Type == TypeResponse {
			resp = p
			found = true
		}
	}
	return resp, found
}

// OpenSession runs the OpenSession handshake, tolerating an already-open
// session and recovering from a stale one.
func (c *Client) OpenSession(session uint32) error {
	pkts, err := c.Command(OpOpenSession, []uint32{session}, 0, time.Second)
	if err != nil {
		return err
	}
	if resp, ok := response(pkts); ok {
		if resp.Code == RespOK || resp.Code == RespSessionOpen {
			return nil
		}
		return fmt.Errorf("OpenSession response 0x%04x", resp.Code)
	}
	// Stale session: close it and retry once.
	if _, err := c.Command(OpCloseSession, nil, 0, time.Second); err != nil {
		return err
	}
	pkts, err = c.Command(OpOpenSession, []uint32{session}, 0, time.Second)
	if err != nil {
		return err
	}
	if resp, ok := response(pkts); ok {
		if resp.Code == RespOK || resp.Code == RespSessionOpen {
			return nil
		}
		return fmt.Errorf("OpenSession retry response 0x%04x", resp.Code)
	}
	return fmt.Errorf("OpenSession: no response")
}

// GetDeviceInfo issues 0x1001 and returns the raw response packets.
func (c *Client) GetDeviceInfo(timeout time.Duration) ([][]byte, error) {
	return c.Command(OpGetDeviceInfo, nil, 1, timeout)
}

// SendObjectInfo creates an object and returns its handle. A stale data phase
// can swallow the first attempts, so it retries.
func (c *Client) SendObjectInfo(name string, parent, storeID uint32, format uint16, size uint32, tries int) (uint32, error) {
	var lastCode uint16
	for i := 0; i < tries; i++ {
		if err := c.Send(Command(OpSendObjectInfo, 1, []uint32{storeID, parent, 0})); err != nil {
			return 0, err
		}
		time.Sleep(150 * time.Millisecond)
		if err := c.Send(Data(OpSendObjectInfo, 1, ObjectInfo(storeID, format, parent, name, size, assocType(format)))); err != nil {
			return 0, err
		}
		pkts, err := c.recv(1500 * time.Millisecond)
		if err != nil {
			return 0, err
		}
		resp, ok := response(pkts)
		if !ok {
			time.Sleep(600 * time.Millisecond)
			continue
		}
		lastCode = resp.Code
		if resp.Code == RespNameConflict {
			return 0, ErrNameConflict
		}
		if resp.Code != RespOK {
			time.Sleep(600 * time.Millisecond)
			continue
		}
		params := resp.Params()
		if len(params) < 3 {
			return 0, fmt.Errorf("SendObjectInfo: short response payload (%d bytes)", len(resp.Payload))
		}
		return params[2], nil
	}
	if lastCode != 0 {
		return 0, fmt.Errorf("SendObjectInfo 0x%04x", lastCode)
	}
	return 0, fmt.Errorf("SendObjectInfo: no response")
}

func assocType(format uint16) uint16 {
	if format == FormatAssoc {
		return 1
	}
	return 0
}

// Warmup creates throwaway folders until the daemon accepts one.
func (c *Client) Warmup(tries int) error {
	var last error
	for i := 0; i < tries; i++ {
		_, err := c.MakeFolder("w"+RandName(12), ObjectHandleRoot)
		if err == nil {
			c.trace("warmup ok after %d tries", i)
			return nil
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("warmup: %w", last)
}

func (c *Client) MakeFolder(name string, parent uint32) (uint32, error) {
	return c.SendObjectInfo(name, parent, 0, FormatAssoc, 0, 5)
}

func (c *Client) MakeFile(name string, parent uint32, size uint32) (uint32, error) {
	return c.SendObjectInfo(name, parent, 0, FormatFile, size, 5)
}

// MoveObject moves handle under parent in the internal store.
func (c *Client) MoveObject(handle, storeID, parent uint32) error {
	_, err := c.Command(OpMoveObject, []uint32{handle, storeID, parent}, 1, time.Second)
	return err
}

func (c *Client) GetObjectPropValue(handle, prop uint32, timeout time.Duration) ([][]byte, error) {
	return c.Command(OpGetObjectPropValue, []uint32{handle, prop}, 1, timeout)
}

// DataPayload extracts the MTP-string bytes from the last data container in
// pkts (payload[0] is the character count; the rest is UTF-16LE).
func DataPayload(pkts [][]byte) []byte {
	var pay []byte
	for _, raw := range pkts {
		p, err := Parse(raw)
		if err != nil {
			continue
		}
		if p.Type == TypeData {
			pay = p.Payload
		}
	}
	if len(pay) == 0 || pay[0] == 0 {
		return nil
	}
	n := 1 + 2*int(pay[0])
	if n > len(pay) {
		n = len(pay)
	}
	return pay[1:n]
}

func DataMTPString(pkts [][]byte) (string, bool) {
	raw := DataPayload(pkts)
	if len(raw) < 2 {
		return "", false
	}
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+2 <= len(raw); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(raw[i:]))
	}
	return strings.TrimSuffix(string(utf16.Decode(units)), "\x00"), true
}

// Data-phase chunk sizes: the first transfer carries the container header plus
// firstChunk payload bytes, continuations use nextChunk.
const (
	firstChunk = 4084
	nextChunk  = 4096
)

// SendObject runs the 0x100D data phase: a command container, then a data
// container whose header announces the full length, then raw continuations.
func (c *Client) SendObject(payload []byte, tid uint32, wait time.Duration) (uint16, error) {
	if err := c.Send(Command(OpSendObject, tid, nil)); err != nil {
		return 0, err
	}
	time.Sleep(150 * time.Millisecond)
	total := len(payload)
	hdr := make([]byte, 12)
	binary.LittleEndian.PutUint32(hdr[0:], uint32(12+total))
	binary.LittleEndian.PutUint16(hdr[4:], TypeData)
	binary.LittleEndian.PutUint16(hdr[6:], OpSendObject)
	binary.LittleEndian.PutUint32(hdr[8:], tid)
	first := firstChunk
	if total < first {
		first = total
	}
	if err := c.Send(append(hdr, payload[:first]...)); err != nil {
		return 0, err
	}
	for i := first; i < total; i += nextChunk {
		end := i + nextChunk
		if end > total {
			end = total
		}
		if err := c.Send(payload[i:end]); err != nil {
			return 0, err
		}
	}
	pkts, err := c.recv(wait)
	if err != nil {
		return 0, err
	}
	resp, ok := response(pkts)
	if !ok {
		return 0, fmt.Errorf("SendObject: no response")
	}
	return resp.Code, nil
}

func (c *Client) DeleteObject(handle uint32) error {
	pkts, err := c.Command(OpDeleteObject, []uint32{handle}, 1, time.Second)
	if err != nil {
		return err
	}
	resp, ok := response(pkts)
	if !ok {
		return fmt.Errorf("DeleteObject: no response")
	}
	if resp.Code != RespOK {
		return fmt.Errorf("DeleteObject 0x%04x", resp.Code)
	}
	return nil
}

// FindObjectByName looks for a root-level object with the given name.
func (c *Client) FindObjectByName(name string) (uint32, bool, error) {
	pkts, err := c.Command(OpGetObjectHandles, []uint32{StoreInternal, 0, ObjectHandleRoot}, 1, 2*time.Second)
	if err != nil {
		return 0, false, err
	}
	var handles []uint32
	for _, raw := range pkts {
		p, err := Parse(raw)
		if err != nil || p.Type != TypeResponse || p.Code != RespOK {
			continue
		}
		handles = p.Params()
	}
	for _, h := range handles {
		props, err := c.GetObjectPropValue(h, PropObjectName, time.Second)
		if err != nil {
			return 0, false, err
		}
		if got, ok := DataMTPString(props); ok && got == name {
			return h, true, nil
		}
	}
	return 0, false, nil
}

// PutFile creates a root-level file, replacing an existing one; the daemon
// answers 0x2002 for duplicate names.
func (c *Client) PutFile(name string, data []byte) (bool, error) {
	if len(data) == 0 {
		return false, fmt.Errorf("PutFile: empty payload")
	}
	_, err := c.SendObjectInfo(name, ObjectHandleRoot, 0, FormatFile, uint32(len(data)), 5)
	replaced := false
	if errors.Is(err, ErrNameConflict) {
		old, found, ferr := c.FindObjectByName(name)
		if ferr != nil {
			return false, ferr
		}
		if !found {
			return false, fmt.Errorf("mtp: %q reported as duplicate but not found", name)
		}
		if derr := c.DeleteObject(old); derr != nil {
			return false, derr
		}
		if _, err = c.SendObjectInfo(name, ObjectHandleRoot, 0, FormatFile, uint32(len(data)), 5); err != nil {
			return false, err
		}
		replaced = true
	} else if err != nil {
		return false, err
	}
	// The daemon writes the object to disk before answering; jb.sh is several
	// megabytes, so allow time for the write.
	code, err := c.SendObject(data, 1, 15*time.Second)
	if err != nil {
		return replaced, err
	}
	if code != RespOK {
		return replaced, fmt.Errorf("SendObject %q: response 0x%04x", name, code)
	}
	return replaced, nil
}

const nameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// RandName builds a random MTP object name of n characters.
func RandName(n int) string {
	if n < 1 {
		n = 1
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(nameChars[rand.Intn(len(nameChars))])
	}
	return b.String()
}
