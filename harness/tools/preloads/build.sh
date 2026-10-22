#!/bin/sh
# Build the offline-harness preloads and helper environments.
#
# Produces (default output dir is what driver/real_bin.py + driver/scripts expect):
#   /tmp/opencode/mtpstub/*.so        LD_PRELOAD shims (bridge, inject, spies)
#   /tmp/opencode/mtpstub/libmtp-helper.so.1.0   stub helper (REAL_LDPATH=mtpstub)
#   /tmp/opencode/helperpatch/libmtp-helper.so.1.0
#       real helper with execute_cmd stubbed (no startup fork; gdb runs)
#
# Usage: harness/tools/preloads/build.sh [outdir] [rootfs]
# Needs: arm-linux-gnueabihf-gcc, an extracted rootfs (default 5196/rootfs_mount).
set -e

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
RF="${2:-$ROOT/5196/rootfs_mount}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-/tmp/opencode/mtpstub}"
CC="${CC:-arm-linux-gnueabihf-gcc}"

test -d "$RF/usr/lib" || { echo "missing $RF/usr/lib" >&2; exit 1; }
RF="$(cd "$RF" && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
PATCHDIR="${PATCHDIR:-$(dirname "$OUT")/helperpatch}"
mkdir -p "$PATCHDIR"
PATCHDIR="$(cd "$PATCHDIR" && pwd)"

echo "== preloads -> $OUT"
for s in bridge inject syslog_spy storefix statdump statx_spy slice_spy pw_spy malloc_spy; do
    "$CC" -shared -fPIC -O2 -o "$OUT/$s.so" "$HERE/$s.c" -ldl
    echo "   $s.so"
done

echo "== stub libmtp-helper -> $OUT/libmtp-helper.so.1.0"
DEPS="libglib-2.0.so.0 libdevice-cap.so.1 libmetrics.so.1.0 libcjson.so.1
libstackdump.so.1.0 liblab126utils_advanced.so.1.0 libdpm.so.1.0 libbroadcast.so.1
libz.so.1 libperf_util.so.1.0 libicuuc.so.65 libicudata.so.65 libprocessutils.so.1.0
liblab126utils.so.1.0 liblipc.so.1.0 libota_utils.so.1.0 libdynconf.so.1.0
libssl.so.3 libcrypto.so.3 libappreg.so.1.0 libsqlite3.so.0 libsoup-2.4.so.1
libgio-2.0.so.0 libgobject-2.0.so.0 libipcf4.so libsecurity_manager_client.so.1
libllog.so.1.0 libdbus-1.so.3 libpthread.so.0 librt.so.1 libgthread-2.0.so.0
libstdc++.so.6 libm.so.6 libgcc_s.so.1 libc.so.6"
LIBS=""
SKIPPED=""
for lib in $DEPS; do
    if [ -e "$RF/usr/lib/$lib" ] || [ -e "$RF/lib/$lib" ]; then
        LIBS="$LIBS -l:$lib"
    else
        SKIPPED="$SKIPPED $lib"
    fi
done
[ -n "$SKIPPED" ] && echo "   (absent in rootfs, not linked:$SKIPPED)"
"$CC" -shared -fPIC -nostdlib -Wl,--no-as-needed \
    -o "$OUT/libmtp-helper.so.1.0" "$HERE/helper_stub.c" \
    -L"$RF/usr/lib" -L"$RF/lib" $LIBS

echo "== patched real helper -> $PATCHDIR/libmtp-helper.so.1.0"
cp "$RF/usr/lib/libmtp-helper.so.1.0" "$PATCHDIR/libmtp-helper.so.1.0"
# execute_cmd at file offset 0x9b44: replace the prologue with
# `movs r0, #0; bx lr` (00 20 70 47) so startup does not fork a shell.
if [ "$(dd if="$PATCHDIR/libmtp-helper.so.1.0" bs=1 skip=39748 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')" != "00207047" ]; then
    printf '\000\040\160\107' | dd of="$PATCHDIR/libmtp-helper.so.1.0" \
        bs=1 seek=39748 conv=notrunc status=none
    echo "   patched execute_cmd @0x9b44"
else
    echo "   already patched"
fi

echo "done"
