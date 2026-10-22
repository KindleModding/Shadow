#!/usr/bin/env python3
"""fwderive: derive build-specific responder offsets by code-shape matching.

Anchors (for the Kindle 5.x tizen-mtp lineage):
  rx_copy      - entry of the small copy helper that moves the received
                 container into the caller's frame (breakpoint target for the
                 stackdelta measurement; the caller's sp at the call is `S`)
  inject_event - entry of the daemon's event writer called to post
                 MTP_ENABLE(14,0,0,0) so the transport threads start offline

Extract a reference from a known binary (writes/updates the reference file):

  tools/fwderive/derive.py extract --elf <tizen-mtp> --refs <dir> \
      --key 4832540042 --addr rx_copy=0x1fcf0 --addr inject_event=0x189d4

Match a new firmware image against all references:

  tools/fwderive/derive.py match --elf <tizen-mtp> --refs <dir> --out derived.json

Matching normalizes instruction tokens (PC-relative operands wildcarded) and
requires exactly one hit per anchor. Zero or multiple hits -> exit 3
(unsupported build), never a guessed offset.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

WINDOW = 24
BIG_IMM = re.compile(r"#0x[0-9a-f]{3,}")
PC_LIT = re.compile(r"\[pc, #0x[0-9a-f]+\]")
BRANCH = re.compile(r"^(b|bl|blx|b\.(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al))\b")

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)


def normalize(ins):
    op = ins.op_str
    if BRANCH.match(ins.mnemonic) and "#" in op:
        op = re.sub(r"#0x[0-9a-f]+", "?", op)
    op = PC_LIT.sub("[pc, #?]", op)
    op = BIG_IMM.sub("#?", op)
    return (ins.mnemonic + " " + op).strip() if op else ins.mnemonic


def tokens_at(code, addr, window=WINDOW):
    out = []
    for ins in md.disasm(code[addr:addr + window * 4], addr):
        out.append(normalize(ins))
        if len(out) >= window:
            break
    return out


def elf_sections(path):
    f = open(path, "rb").read()
    if f[:4] != b"\x7fELF" or f[4] != 1 or f[5] != 1:
        sys.exit("fwderive: not ELF32 LE")
    e_shoff, = struct.unpack_from("<I", f, 0x20)
    e_shentsize, = struct.unpack_from("<H", f, 0x2E)
    e_shnum, = struct.unpack_from("<H", f, 0x30)
    e_shstrndx, = struct.unpack_from("<H", f, 0x32)
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        vals = struct.unpack_from("<IIIIIIIIII", f, o)
        secs.append({"name_off": vals[0], "type": vals[1], "addr": vals[3],
                     "off": vals[4], "size": vals[5]})
    shstr = secs[e_shstrndx]
    for s in secs:
        end = f.index(b"\0", shstr["off"] + s["name_off"])
        s["name"] = f[shstr["off"] + s["name_off"]:end].decode()
    return f, secs


def text_section(path):
    raw, secs = elf_sections(path)
    for s in secs:
        if s["name"] == ".text":
            return raw, raw[s["off"]:s["off"] + s["size"]], s["addr"], s["size"]
    sys.exit("fwderive: no .text section")


def cmd_extract(args):
    raw, text, taddr, tsize = text_section(args.elf)
    refs_path = os.path.join(args.refs, "%s.json" % args.key)
    refs = {"key": args.key,
            "tizen_mtp_sha256": hashlib.sha256(raw).hexdigest(),
            "anchors": {}}
    if os.path.exists(refs_path):
        refs = json.load(open(refs_path))
    for spec in args.addr:
        name, addr_s = spec.split("=", 1)
        addr = int(addr_s, 0)
        if addr < taddr or addr + 4 * WINDOW > taddr + tsize:
            sys.exit("fwderive: %s: %#x outside .text" % (name, addr))
        toks = tokens_at(text, addr - taddr)
        if len(toks) < WINDOW:
            sys.exit("fwderive: %s: only %d instructions decoded" % (name, len(toks)))
        refs["anchors"][name] = {
            "addr": hex(addr),
            "window": WINDOW,
            "tokens": toks,
            "bytes": text[addr - taddr:addr - taddr + 4 * WINDOW].hex(),
        }
        print("extracted %-12s @ %#x: %s" % (name, addr, toks[0]))
    os.makedirs(args.refs, exist_ok=True)
    json.dump(refs, open(refs_path, "w"), indent=2)
    open(refs_path, "a").write("\n")
    print("wrote", refs_path)


def cmd_match(args):
    raw, text, taddr, tsize = text_section(args.elf)
    sha = hashlib.sha256(raw).hexdigest()
    ref_files = sorted(
        os.path.join(args.refs, n) for n in os.listdir(args.refs) if n.endswith(".json"))
    if not ref_files:
        sys.exit("fwderive: no reference files in %s" % args.refs)

    refs = [(p, json.load(open(p))) for p in ref_files]

    # First-claims pass: the first reference that carries an anchor owns it. With
    # a single reference per responder lineage this is the whole story; anchors
    # it cannot resolve are retried below.
    results = {}
    problems = {}
    for _, ref in refs:
        for name, anchor in ref["anchors"].items():
            if name in results:
                continue
            hits = find_hits(text, anchor["tokens"], taddr)
            results[name] = {
                "addr": hex(taddr + hits[0]) if len(hits) == 1 else None,
                "hits": [hex(taddr + h) for h in hits],
                "reference": {"key": ref["key"], "addr": anchor["addr"],
                              "sha256": ref["tizen_mtp_sha256"]},
            }
            if len(hits) != 1:
                problems[name] = len(hits)
            else:
                print("matched  %-12s @ %#x (%d hit, ref key %s)"
                      % (name, taddr + hits[0], len(hits), ref["key"]))

    # Recovery pass: an anchor a reference merely *claims* (rather than resolves
    # uniquely) must not shadow a reference from another lineage that does
    # resolve it. Only anchors the first pass left unresolved are retried, and
    # the reference recorded for this exact binary is tried first, so builds that
    # already resolve keep byte-identical results.
    if problems:
        exact = [r for r in refs if r[1]["tizen_mtp_sha256"] == sha]
        others = [r for r in refs if r[1]["tizen_mtp_sha256"] != sha]
        for name in list(problems):
            for _, ref in exact + others:
                anchor = ref["anchors"].get(name)
                if anchor is None:
                    continue
                hits = find_hits(text, anchor["tokens"], taddr)
                if len(hits) != 1:
                    continue
                results[name] = {
                    "addr": hex(taddr + hits[0]),
                    "hits": [hex(taddr + h) for h in hits],
                    "reference": {"key": ref["key"], "addr": anchor["addr"],
                                  "sha256": ref["tizen_mtp_sha256"]},
                }
                del problems[name]
                print("recovered %-12s @ %#x (1 hit, ref key %s)"
                      % (name, taddr + hits[0], ref["key"]))
                break

    out = {"tizen_mtp_sha256": sha, "anchors": results}
    if args.out:
        json.dump(out, open(args.out, "w"), indent=2)
        open(args.out, "a").write("\n")
    if problems or not results:
        print("fwderive: unsupported build: %s"
              % ("; ".join("%s: %d matches" % (n, c) for n, c in problems.items())
                 or "no anchors"), file=sys.stderr)
        return 3
    return 0


def find_hits(text, tokens, taddr):
    # Disassemble candidates at their real load address: the reference tokens were
    # extracted that way, and branch operands render as absolute addresses, so a
    # base-0 decode normalises them differently (#0x28 vs #?) and never matches.
    first = tokens[0]
    candidates = []
    for off in range(0, len(text) - 4, 2):
        dis = list(md.disasm(text[off:off + 4], taddr + off))
        if not dis or normalize(dis[0]) != first:
            continue
        got = []
        for ins in md.disasm(text[off:], taddr + off):
            got.append(normalize(ins))
            if len(got) == len(tokens):
                break
        if got == tokens:
            candidates.append(off)
            if len(candidates) > 8:
                break
    return candidates


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("extract")
    ex.add_argument("--elf", required=True)
    ex.add_argument("--refs", required=True)
    ex.add_argument("--key", required=True)
    ex.add_argument("--addr", action="append", required=True,
                    help="name=0xADDR (repeatable)")
    ex.set_defaults(func=cmd_extract)
    mt = sub.add_parser("match")
    mt.add_argument("--elf", required=True)
    mt.add_argument("--refs", required=True)
    mt.add_argument("--out")
    mt.set_defaults(func=cmd_match)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
