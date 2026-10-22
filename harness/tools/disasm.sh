#!/bin/sh
# Regenerate the linear force-thumb disassembly used for gadget hunting.
#
# Usage: harness/tools/disasm.sh [elf] [out]
#   defaults: notes/artifacts/tizen-mtp -> /tmp/opencode/mtp.asm
#
# The toolchain disassembles the (stripped, Thumb-only) binary linearly; data
# sections decode as junk, which is fine for byte-pattern gadget searches.
set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ELF="${1:-$ROOT/notes/artifacts/tizen-mtp}"
OUT="${2:-/tmp/opencode/mtp.asm}"

arm-linux-gnueabihf-objdump -d -M force-thumb "$ELF" > "$OUT"
echo "$OUT: $(wc -l < "$OUT") lines"
