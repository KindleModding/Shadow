package mtp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestCommandBytes(t *testing.T) {
	got := Command(OpGetDeviceInfo, 1, []uint32{0x10001, 0, 0xFFFFFFFF})
	want := mustHex(t, "1800000001000110010000000100010000000000ffffffff")
	if !bytes.Equal(got, want) {
		t.Fatalf("Command mismatch\n got %x\nwant %x", got, want)
	}
}

func TestParseRoundTrip(t *testing.T) {
	pkt := Data(OpSendObjectInfo, 7, []byte{1, 2, 3, 4})
	p, err := Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Type != TypeData || p.Code != OpSendObjectInfo || p.TID != 7 {
		t.Fatalf("header mismatch: %+v", p)
	}
	if !bytes.Equal(p.Payload, []byte{1, 2, 3, 4}) {
		t.Fatalf("payload mismatch: %x", p.Payload)
	}
	if _, err := Parse([]byte{1, 2, 3}); err == nil {
		t.Fatal("short container did not error")
	}
	if _, err := Parse([]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Fatal("absurd length did not error")
	}
}

func TestMTPString(t *testing.T) {
	got := MTPString("d0AbcDeF")
	want := mustHex(t, "09640030004100620063004400650046000000")
	if !bytes.Equal(got, want) {
		t.Fatalf("MTPString mismatch\n got %x\nwant %x", got, want)
	}
	if !bytes.Equal(MTPString(""), []byte{0}) {
		t.Fatalf("empty MTPString = %x", MTPString(""))
	}
}

func TestObjectInfoBytes(t *testing.T) {
	got := ObjectInfo(0, FormatAssoc, ObjectHandleRoot, "Txxxx", 0, 1)
	want := mustHex(t, "0000000001300000000000000000000000000000000000000000000000000000000000000000ffffffff0100000000000000000006540078007800780078000000000000")
	if !bytes.Equal(got, want) {
		t.Fatalf("ObjectInfo mismatch\n got %x\nwant %x", got, want)
	}
	if len(got) != 68 {
		t.Fatalf("ObjectInfo length = %d, want 68", len(got))
	}
}

func TestDataPayload(t *testing.T) {
	pkts := [][]byte{
		Command(OpGetObjectPropValue, 1, []uint32{1, PropObjectName}),
		Data(OpGetObjectPropValue, 1, MTPString("ABCD")),
	}
	got := DataPayload(pkts)
	want := mustHex(t, "41004200430044000000")
	if !bytes.Equal(got, want) {
		t.Fatalf("DataPayload = %x, want %x", got, want)
	}
	if DataPayload([][]byte{Data(1, 1, []byte{0, 1, 2})}) != nil {
		t.Fatal("zero-count MTP string should return nil")
	}
	if DataPayload(nil) != nil {
		t.Fatal("empty packet list should return nil")
	}
}
