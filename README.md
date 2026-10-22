# shadow

`shadow` is a kindle MTP jailbreak. It exploits two bugs in the
Kindle's MTP responder (`tizen-mtp`, running as root) over USB and ends in an
in-binary `system()` call that runs jb.sh.

## Cross-compiling from Linux

Needs Go ≥ 1.24.5, `gcc`, `make`, `pkg-config`, `curl` and `tar`.

Linux (native):

```
make shadow-linux        # bin/shadow-linux, static ELF
```

Windows:

```
sudo apt install zig
make shadow-windows      # bin/shadow-windows.exe, PE32+
```

`zig cc -target x86_64-windows-gnu` provides the C toolchain.

macOS:

```
sudo apt install clang lld llvm
make shadow-darwin       # bin/shadow-darwin, universal Mach-O
```

This builds arm64 and x86_64 slices with clang, links a matching libusb into
each, and merges them with `lipo`. It uses `ld64.lld` and a pinned macOS SDK
(26.1) fetched into `build/deps`. Set `DARWIN_SDK` to an existing
`MacOSX*.sdk` to skip the download; `LLVM_BIN`, `CLANG`, `LD64_LLD`, `LLVM_AR`,
`LLVM_RANLIB`, `LLVM_STRIP` and `LIPO` override tool discovery.

Both cross targets link libusb statically and write to `bin/`.

## Adding a firmware

The pipeline runs on Linux. It extracts the update image, measures the
responder under qemu-arm, verifies the resulting chain offline, and writes
`firmware/<build_key>.json` plus the merged `firmware/db.json`.

Prerequisites: `kindletool`, `qemu-arm`, `gdb-multiarch`,
`arm-linux-gnueabihf-gcc`, `unshare` (util-linux, user namespaces enabled) and
Python 3.

```
make build                            # bin/{ext4get,elfscan,fwharvest}
bin/fwharvest --bin <update.bin>      # -> firmware/<build_key>.json
```

The update image is operator-supplied; `firmwares/` is gitignored. Use
`--force` to replace an existing record and `--all` to harvest every
`firmwares/*/*.bin`.

A record ships only when the stack-delta measurement and the chain
verification both succeed; otherwise it stays `partial` and `shadow` refuses
that build. A previously unseen code lineage also needs an anchor reference
under `tools/fwderive/references/`.

Rebuild the client after the harvest so the new `db.json` is embedded:

```
make shadow-linux        # or shadow-windows / shadow-darwin
```
