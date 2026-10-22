#!/usr/bin/env python3
"""Verify a firmware record against the hardware-pinned 5.19.6 offsets."""
import json
import sys

PINS = {
    "system": 0x1FA01,
    "pop_gadget": 0x4BB1,
    "ldr_blx_gadget": 0x1AD03,
    "got_base": 0x2B000,
    "stack_delta": 0xCD8,
}


def main():
    if len(sys.argv) != 2:
        print("usage: check_pins.py firmware/<build_key>.json", file=sys.stderr)
        return 2
    rec = json.load(open(sys.argv[1]))
    ok = True
    for name, want in PINS.items():
        got = rec["offsets"].get(name)
        mark = "OK " if got == want else "BAD"
        if got != want:
            ok = False
        print("%s %-16s %8s (pin %8s)" % (mark, name, got, want))
    checks = {
        "stack_delta_supported": rec["offsets"].get("stack_delta_supported"),
        "stack_delta_verified": rec["offsets"].get("stack_delta_verified"),
        "chain_verified": (rec.get("chain_verification") or {}).get("verified"),
    }
    for name, val in checks.items():
        print("%s %-20s %s" % ("OK " if val else "BAD", name, val))
        if not val:
            ok = False
    print("build key:", rec["build_key"], "| tizen-mtp:", rec["tizen_mtp_sha256"][:16])
    if not ok:
        print("PIN MISMATCH")
        return 1
    print("ALL PINS MATCH")
    return 0


if __name__ == "__main__":
    sys.exit(main())
