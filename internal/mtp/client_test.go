package mtp

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// fakeLib answers commands the way the daemon does, so the client's
// request/response sequencing can be checked offline.
type fakeLib struct {
	mu      sync.Mutex
	sent    [][]byte
	queue   [][]byte
	dupInfo int
}

func (f *fakeLib) Send(pkt []byte) error {
	f.mu.Lock()
	f.sent = append(f.sent, append([]byte(nil), pkt...))
	f.mu.Unlock()
	if p, err := Parse(pkt); err == nil && p.Type == TypeCommand {
		f.onCommand(p)
	}
	return nil
}

func (f *fakeLib) onCommand(p Packet) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch p.Code {
	case OpSendObjectInfo:
		if f.dupInfo > 0 {
			f.dupInfo--
			f.queue = append(f.queue, Container(TypeResponse, RespNameConflict, p.TID, nil))
			return
		}
		f.queue = append(f.queue, respOK(p.TID, 0, ObjectHandleRoot, 0x42))
	case OpSendObject:
		f.queue = append(f.queue, respOK(p.TID))
	case OpGetObjectHandles:
		f.queue = append(f.queue, respOK(p.TID, 0x42))
	case OpGetObjectPropValue:
		f.queue = append(f.queue, Data(OpGetObjectPropValue, p.TID, MTPString("jb.sh")))
	case OpDeleteObject:
		f.queue = append(f.queue, respOK(p.TID))
	}
}

func (f *fakeLib) ReadPkt(timeout time.Duration) []byte {
	f.mu.Lock()
	if len(f.queue) > 0 {
		b := f.queue[0]
		f.queue = f.queue[1:]
		f.mu.Unlock()
		return b
	}
	f.mu.Unlock()
	time.Sleep(timeout)
	return nil
}

func (f *fakeLib) packets() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.sent))
	copy(out, f.sent)
	return out
}

func respOK(tid uint32, params ...uint32) []byte {
	payload := make([]byte, 4*len(params))
	for i, p := range params {
		binary.LittleEndian.PutUint32(payload[4*i:], p)
	}
	return Container(TypeResponse, RespOK, tid, payload)
}

func pattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

func TestPutFileClean(t *testing.T) {
	data := pattern(10000) // larger than firstChunk, exercises continuations
	f := &fakeLib{}
	c := New(f, nil)

	replaced, err := c.PutFile("jb.sh", data)
	if err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	if replaced {
		t.Fatal("PutFile reported a replacement on a clean run")
	}

	pkts := f.packets()
	if len(pkts) != 6 {
		t.Fatalf("sent %d packets, want 6", len(pkts))
	}
	if want := Command(OpSendObjectInfo, 1, []uint32{0, ObjectHandleRoot, 0}); !bytes.Equal(pkts[0], want) {
		t.Errorf("SendObjectInfo command mismatch: %x", pkts[0])
	}
	info := ObjectInfo(0, FormatFile, ObjectHandleRoot, "jb.sh", uint32(len(data)), 0)
	if want := Data(OpSendObjectInfo, 1, info); !bytes.Equal(pkts[1], want) {
		t.Errorf("SendObjectInfo data mismatch")
	}
	if want := Command(OpSendObject, 1, nil); !bytes.Equal(pkts[2], want) {
		t.Errorf("SendObject command mismatch: %x", pkts[2])
	}

	stream := bytes.Join(pkts[3:], nil)
	if len(stream) != 12+len(data) {
		t.Fatalf("data stream = %d bytes, want %d", len(stream), 12+len(data))
	}
	if ln := binary.LittleEndian.Uint32(stream[0:]); int(ln) != 12+len(data) {
		t.Errorf("stream length header = %d", ln)
	}
	if typ := binary.LittleEndian.Uint16(stream[4:]); typ != TypeData {
		t.Errorf("stream type = %d", typ)
	}
	if code := binary.LittleEndian.Uint16(stream[6:]); code != OpSendObject {
		t.Errorf("stream code = %#x", code)
	}
	if !bytes.Equal(stream[12:], data) {
		t.Error("payload corrupted across chunks")
	}
}

func TestPutFileReplacesDuplicate(t *testing.T) {
	data := pattern(64)
	f := &fakeLib{dupInfo: 1}
	c := New(f, nil)

	replaced, err := c.PutFile("jb.sh", data)
	if err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	if !replaced {
		t.Fatal("PutFile did not report the replacement")
	}

	pkts := f.packets()
	var codes []uint16
	for _, p := range pkts {
		if pk, err := Parse(p); err == nil && pk.Type == TypeCommand {
			codes = append(codes, pk.Code)
		}
	}
	want := []uint16{
		OpSendObjectInfo,
		OpGetObjectHandles,
		OpGetObjectPropValue,
		OpDeleteObject,
		OpSendObjectInfo,
		OpSendObject,
	}
	if len(codes) != len(want) {
		t.Fatalf("command sequence %#x, want %#x", codes, want)
	}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("command sequence %#x, want %#x", codes, want)
		}
	}
	del := Command(OpDeleteObject, 1, []uint32{0x42})
	if !contains(pkts, del) {
		t.Error("DeleteObject for the stale handle not sent")
	}
	probe := Command(OpGetObjectPropValue, 1, []uint32{0x42, PropObjectName})
	if !contains(pkts, probe) {
		t.Error("DC08 name probe for the stale handle not sent")
	}
}

func TestPutFileRejectsEmpty(t *testing.T) {
	c := New(&fakeLib{}, nil)
	if _, err := c.PutFile("jb.sh", nil); err == nil {
		t.Fatal("empty payload accepted")
	}
}

func contains(pkts [][]byte, want []byte) bool {
	for _, p := range pkts {
		if bytes.Equal(p, want) {
			return true
		}
	}
	return false
}
