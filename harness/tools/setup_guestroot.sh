#!/bin/sh
# Recreate the qemu fake-rootfs overlay used by the offline harness
# (driver/real_bin.py, arm_* drivers). Safe to re-run.
#
# Usage: harness/tools/setup_guestroot.sh [guestroot] [rootfs]
set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RF="${2:-$ROOT/5196/rootfs_mount}"
GR="${1:-/tmp/opencode/guestroot}"

test -d "$RF" || { echo "missing $RF" >&2; exit 1; }
RF="$(cd "$RF" && pwd)"
mkdir -p "$GR"
GR="$(cd "$GR" && pwd)"

mkdir -p "$GR/bin" "$GR/dev/usb-ffs/mtp" "$GR/mnt/base-us/droid/media"

# host-absolute symlinks so qemu-arm -L can resolve guest paths
for d in etc lib usr var; do ln -sfn "$RF/$d" "$GR/$d"; done
for b in busybox busybox.nosuid sh touch; do
    ln -sfn "$RF/bin/busybox.nosuid" "$GR/bin/$b"
done

# functionfs endpoint stubs; ep1/ep2 are (re)created by the harness per run
for e in ep0 ep3 ep4 ep5; do : >> "$GR/dev/usb-ffs/mtp/$e"; done
for e in ep1 ep2; do
    rm -f "$GR/dev/usb-ffs/mtp/$e"
    mkfifo "$GR/dev/usb-ffs/mtp/$e"
done

# the *qemu-patched* binary uses /tmp/ghostba as its store root
mkdir -p /tmp/ghostba

echo "guestroot ready at $GR"
