GO ?= go

# sha256sum (coreutils, Linux) and shasum (perl, macOS) both read the
# "<hash>  <file>" lines `-c` verifies; only the algorithm flag differs.
SHA256       ?= $(shell command -v sha256sum 2>/dev/null || command -v shasum 2>/dev/null)
SHA256_FLAGS := $(if $(findstring shasum,$(notdir $(SHA256))),-a 256,)

# Every binary links libusb statically, so none needs a libusb library at run
# time. The same libusb tarball feeds the native build and the Darwin cross.
LIBUSB_VER     := 1.0.29
LIBUSB_SHA256  := 5977fc950f8d1395ccea9bd48c06b3f808fd3c2c961b44b0c2e6e29fc3a70a85
LIBUSB_URL     := https://github.com/libusb/libusb/releases/download/v$(LIBUSB_VER)/libusb-$(LIBUSB_VER).tar.bz2
DEPS_DIR       := $(CURDIR)/build/deps
LIBUSB_TARBALL := $(DEPS_DIR)/libusb-$(LIBUSB_VER).tar.bz2
LIBUSB_PREFIX  := $(DEPS_DIR)/libusb
LIBUSB_PC      := $(LIBUSB_PREFIX)/lib/pkgconfig/libusb-1.0.pc

UNAME_S := $(shell uname -s)

# --disable-udev is a Linux-only option; libusb picks its own backend (IOKit on
# darwin) elsewhere.
LIBUSB_CONF_FLAGS := --enable-static --disable-shared $(if $(filter Linux,$(UNAME_S)),--disable-udev,)

# cgo needs the private libraries a statically linked libusb declares in its
# pkg-config file (on darwin: IOKit, CoreFoundation, Security), because gousb's
# `#cgo pkg-config` line carries only -lusb-1.0.
ifeq ($(UNAME_S),Darwin)
LIBUSB_CGO_ENV := PKG_CONFIG_PATH=$(LIBUSB_PREFIX)/lib/pkgconfig CGO_ENABLED=1 CGO_LDFLAGS="$$(PKG_CONFIG_PATH=$(LIBUSB_PREFIX)/lib/pkgconfig pkg-config --static --libs-only-other libusb-1.0)"
else
# -L is explicit: pkg-config output is not part of Go's build cache key, so a
# cached cgo package built against the system libusb would otherwise make the
# static link pick /usr/lib's udev-enabled archive.
LIBUSB_CGO_ENV := PKG_CONFIG_PATH=$(LIBUSB_PREFIX)/lib/pkgconfig CGO_ENABLED=1 CGO_LDFLAGS="-L$(LIBUSB_PREFIX)/lib"
endif

# Darwin cross-build: clang's arm64 and x86_64 targets, LLVM's Mach-O linker
# and a macOS SDK. DARWIN_SDK may point at an SDK already on disk; the pinned
# archive is fetched only when the default path is in use.
DARWIN_SDK_VER       := 26.1
DARWIN_SDK_SHA256    := beee7212d265a6d2867d0236cc069314b38d5fb3486a6515734e76fa210c784c
DARWIN_SDK_URL       := https://github.com/joseluisq/macosx-sdks/releases/download/$(DARWIN_SDK_VER)/MacOSX$(DARWIN_SDK_VER).sdk.tar.xz
DARWIN_SDK           ?= $(DEPS_DIR)/MacOSX$(DARWIN_SDK_VER).sdk
DARWIN_SDK_TARBALL   := $(DEPS_DIR)/MacOSX$(DARWIN_SDK_VER).sdk.tar.xz
DARWIN_LIBUSB_ARM64    := $(DEPS_DIR)/libusb-darwin-arm64
DARWIN_LIBUSB_AMD64    := $(DEPS_DIR)/libusb-darwin-amd64
DARWIN_LIBUSB_ARM64_PC := $(DARWIN_LIBUSB_ARM64)/lib/pkgconfig/libusb-1.0.pc
DARWIN_LIBUSB_AMD64_PC := $(DARWIN_LIBUSB_AMD64)/lib/pkgconfig/libusb-1.0.pc
DARWIN_BIN_DIR         := $(DEPS_DIR)/darwin-bin
DARWIN_TOOLS           := $(DEPS_DIR)/darwin-tools
# Recorded in LC_BUILD_VERSION; read from the SDK so an overridden DARWIN_SDK
# reports its real version.
DARWIN_SDK_VERSION   = $(or $(shell sed -n 's/.*"Version":"\([^"]*\)".*/\1/p' $(DARWIN_SDK)/SDKSettings.json 2>/dev/null | head -1),11.0)

# clang and the LLVM binutils are looked up under LLVM_BIN. Install the distro
# `clang` and `lld` packages if the discovered paths are empty.
LLVM_BIN    ?= $(shell command -v clang >/dev/null 2>&1 && dirname $$(command -v clang) || ls -d /usr/lib/llvm-*/bin 2>/dev/null | sort -V | tail -1)
CLANG       ?= $(LLVM_BIN)/clang
LD64_LLD    ?= $(shell command -v ld64.lld 2>/dev/null || echo $(LLVM_BIN)/ld64.lld)
LLVM_AR     ?= $(shell command -v llvm-ar 2>/dev/null || echo $(LLVM_BIN)/llvm-ar)
LLVM_RANLIB ?= $(shell command -v llvm-ranlib 2>/dev/null || echo $(LLVM_BIN)/llvm-ranlib)
LLVM_STRIP  ?= $(shell command -v llvm-strip 2>/dev/null || echo $(LLVM_BIN)/llvm-strip)
LIPO        ?= $(shell command -v llvm-lipo 2>/dev/null || command -v lipo 2>/dev/null || echo $(LLVM_BIN)/llvm-lipo)
DARWIN_PATH := $(DARWIN_TOOLS)$(if $(LLVM_BIN),:$(LLVM_BIN))

# Windows cross-build from a non-Windows host: zig's bundled mingw-w64
# toolchain plus the MSYS2 libusb archive, linked statically.
MSYS2_MINGW        := https://repo.msys2.org/mingw/mingw64
WIN_LIBUSB_PKG     := mingw-w64-x86_64-libusb-1.0.30-1-any.pkg.tar.zst
WIN_LIBUSB_SHA256  := 124edc26b009678a4c5e759481a364abf63ed7f2f49a53092e8bd0a47c0c0740
WIN_LIBUSB_TARBALL := $(DEPS_DIR)/libusb-win.pkg.tar.zst
WIN_LIBUSB_DIR     := $(DEPS_DIR)/msys/mingw64
WIN_LIBUSB_PC      := $(WIN_LIBUSB_DIR)/lib/pkgconfig/libusb-1.0.pc
ZIG                ?= zig

# Windows host: w64devkit provides the mingw-w64 compiler and MSYS2 provides
# libusb + pkgconf. Both are portable (no installer, no admin).
W64DEVKIT_VER := 2.10.0
W64DEVKIT_URL := https://github.com/skeeto/w64devkit/releases/download/v$(W64DEVKIT_VER)/w64devkit-x64-$(W64DEVKIT_VER).7z.exe
PKGCONF_PKG   := mingw-w64-x86_64-pkgconf-1~2.5.1-2-any.pkg.tar.zst

MINGW_DIR  ?= $(DEPS_DIR)/w64devkit
MSYS_DIR   ?= $(DEPS_DIR)/msys/mingw64
WIN_CC     ?= $(MINGW_DIR)/bin/x86_64-w64-mingw32-gcc
WIN_PKGCFG ?= $(MSYS_DIR)/bin/pkg-config.exe

.PHONY: build vet test clean shadow-deps shadow-linux shadow-deps-win shadow-windows shadow-deps-darwin shadow-darwin accept

build:
	$(GO) build -o bin/ext4get ./cmd/ext4get
	$(GO) build -o bin/elfscan ./cmd/elfscan
ifeq ($(UNAME_S),Linux)
	$(GO) build -o bin/fwharvest ./cmd/fwharvest
endif

vet:
	$(LIBUSB_CGO_ENV) $(GO) vet ./internal/... ./cmd/...

test:
	$(LIBUSB_CGO_ENV) $(GO) test ./internal/... ./cmd/shadow

accept: build
	rm -rf firmware
	bin/fwharvest --bin firmwares/kindle-11th-2024/update_kindle_11th_2024_5.19.6.bin --workdir build/fw/accept
	python3 tools/check_pins.py firmware/4832540042.json

# One-time: fetch and build the static libusb the Unix targets link against.
shadow-deps: $(LIBUSB_PC)

$(LIBUSB_TARBALL):
	mkdir -p $(DEPS_DIR)
	curl -fsSL -o $@ $(LIBUSB_URL)
	echo "$(LIBUSB_SHA256)  $@" | $(SHA256) $(SHA256_FLAGS) -c -

$(LIBUSB_PC): $(LIBUSB_TARBALL)
	tar -C $(DEPS_DIR) -xf $<
	cd $(DEPS_DIR)/libusb-$(LIBUSB_VER) && ./configure --prefix=$(LIBUSB_PREFIX) $(LIBUSB_CONF_FLAGS) && $(MAKE) && $(MAKE) install

shadow-linux: $(LIBUSB_PC)
	$(LIBUSB_CGO_ENV) \
		$(GO) build -tags netgo -ldflags '-linkmode external -extldflags "-static"' -o bin/shadow-linux ./cmd/shadow

ifeq ($(UNAME_S),Darwin)
# Native macOS build. macOS cannot link libc statically, so shadow-darwin
# statically links the source-built libusb instead (LIBUSB_CGO_ENV carries the
# frameworks it needs); the result depends on system libraries alone.
shadow-deps-darwin:
	@echo "native macOS build: make shadow-deps && make shadow-darwin"

shadow-darwin: $(LIBUSB_PC)
	$(LIBUSB_CGO_ENV) $(GO) build -o bin/shadow-darwin ./cmd/shadow
else
shadow-deps-darwin: $(DARWIN_LIBUSB_ARM64_PC) $(DARWIN_LIBUSB_AMD64_PC) $(DARWIN_TOOLS)/strip

shadow-darwin: shadow-deps-darwin
	@test -x "$(CLANG)" || { echo "clang not found: install clang + lld (or set CLANG/LLVM_BIN)" >&2; exit 1; }
	@test -x "$(LD64_LLD)" || { echo "ld64.lld not found: install lld (or set LD64_LLD)" >&2; exit 1; }
	@mkdir -p $(DARWIN_BIN_DIR)/arm64 $(DARWIN_BIN_DIR)/amd64
	PATH="$(DARWIN_PATH):$$PATH" \
	PKG_CONFIG_PATH=$(DARWIN_LIBUSB_ARM64)/lib/pkgconfig CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
	CC="$(CLANG) -Qunused-arguments --target=arm64-apple-macos11 -isysroot $(DARWIN_SDK) -F$(DARWIN_SDK)/System/Library/Frameworks -fuse-ld=$(LD64_LLD)" \
	CGO_LDFLAGS="-L$(DARWIN_LIBUSB_ARM64)/lib -Wl,-adhoc_codesign -Wl,-platform_version,macos,11.0,$(DARWIN_SDK_VERSION) -Wl,-arch,arm64 -lobjc -framework IOKit -framework CoreFoundation -framework Security" \
	$(GO) build -o $(DARWIN_BIN_DIR)/arm64/shadow ./cmd/shadow
	PATH="$(DARWIN_PATH):$$PATH" \
	PKG_CONFIG_PATH=$(DARWIN_LIBUSB_AMD64)/lib/pkgconfig CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
	CC="$(CLANG) -Qunused-arguments --target=x86_64-apple-macos11 -isysroot $(DARWIN_SDK) -F$(DARWIN_SDK)/System/Library/Frameworks -fuse-ld=$(LD64_LLD)" \
	CGO_LDFLAGS="-L$(DARWIN_LIBUSB_AMD64)/lib -Wl,-adhoc_codesign -Wl,-platform_version,macos,11.0,$(DARWIN_SDK_VERSION) -Wl,-arch,x86_64 -lobjc -framework IOKit -framework CoreFoundation -framework Security" \
	$(GO) build -o $(DARWIN_BIN_DIR)/amd64/shadow ./cmd/shadow
	@test -x "$(LIPO)" || { echo "lipo not found: install llvm (or set LIPO)" >&2; exit 1; }
	$(LIPO) -create -output bin/shadow-darwin \
		$(DARWIN_BIN_DIR)/arm64/shadow $(DARWIN_BIN_DIR)/amd64/shadow

$(DARWIN_TOOLS)/strip:
	@test -x "$(LLVM_STRIP)" || { echo "llvm-strip not found: install llvm (or set LLVM_STRIP)" >&2; exit 1; }
	mkdir -p $(DARWIN_TOOLS)
	ln -sf "$(LLVM_STRIP)" $@

ifeq ($(DARWIN_SDK),$(DEPS_DIR)/MacOSX$(DARWIN_SDK_VER).sdk)
$(DARWIN_SDK_TARBALL):
	mkdir -p $(DEPS_DIR)
	curl -fsSL -o $@ $(DARWIN_SDK_URL)
	echo "$(DARWIN_SDK_SHA256)  $@" | $(SHA256) $(SHA256_FLAGS) -c -

$(DARWIN_SDK): $(DARWIN_SDK_TARBALL)
	tar -C $(DEPS_DIR) -xf $<
endif

$(DARWIN_LIBUSB_ARM64_PC): $(LIBUSB_TARBALL) $(DARWIN_SDK)
	@test -x "$(CLANG)" || { echo "clang not found: install clang + lld (or set CLANG/LLVM_BIN)" >&2; exit 1; }
	@test -x "$(LD64_LLD)" || { echo "ld64.lld not found: install lld (or set LD64_LLD)" >&2; exit 1; }
	rm -rf $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-arm64 $(DARWIN_LIBUSB_ARM64)
	mkdir -p $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-arm64
	tar -C $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-arm64 --strip-components=1 -xf $(LIBUSB_TARBALL)
	cd $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-arm64 && \
		CC="$(CLANG) --target=arm64-apple-macos11 -isysroot $(DARWIN_SDK) -F$(DARWIN_SDK)/System/Library/Frameworks -fuse-ld=$(LD64_LLD)" \
		AR="$(LLVM_AR)" RANLIB="$(LLVM_RANLIB)" \
		LDFLAGS="-Wl,-platform_version,macos,11.0,$(DARWIN_SDK_VERSION) -Wl,-arch,arm64" \
		./configure --host=aarch64-apple-darwin --prefix=$(DARWIN_LIBUSB_ARM64) --enable-static --disable-shared
	$(MAKE) -C $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-arm64
	$(MAKE) -C $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-arm64 install

$(DARWIN_LIBUSB_AMD64_PC): $(LIBUSB_TARBALL) $(DARWIN_SDK)
	@test -x "$(CLANG)" || { echo "clang not found: install clang + lld (or set CLANG/LLVM_BIN)" >&2; exit 1; }
	@test -x "$(LD64_LLD)" || { echo "ld64.lld not found: install lld (or set LD64_LLD)" >&2; exit 1; }
	rm -rf $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-amd64 $(DARWIN_LIBUSB_AMD64)
	mkdir -p $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-amd64
	tar -C $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-amd64 --strip-components=1 -xf $(LIBUSB_TARBALL)
	cd $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-amd64 && \
		CC="$(CLANG) --target=x86_64-apple-macos11 -isysroot $(DARWIN_SDK) -F$(DARWIN_SDK)/System/Library/Frameworks -fuse-ld=$(LD64_LLD)" \
		AR="$(LLVM_AR)" RANLIB="$(LLVM_RANLIB)" \
		LDFLAGS="-Wl,-platform_version,macos,11.0,$(DARWIN_SDK_VERSION) -Wl,-arch,x86_64" \
		./configure --host=x86_64-apple-darwin --prefix=$(DARWIN_LIBUSB_AMD64) --enable-static --disable-shared
	$(MAKE) -C $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-amd64
	$(MAKE) -C $(DEPS_DIR)/libusb-$(LIBUSB_VER)-darwin-amd64 install
endif

ifeq ($(OS),Windows_NT)
# shadow-windows.exe links a mingw-w64 libusb statically, so it needs no DLL
# next to it. `shadow-deps-win` fetches the two portable pieces (no installer,
# no admin, nothing outside build/). Point MINGW_DIR/MSYS_DIR at your own
# mingw-w64 + libusb to skip that.
shadow-windows: shadow-deps-win
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
		CC=$(WIN_CC) PKG_CONFIG=$(WIN_PKGCFG) \
		PKG_CONFIG_PATH=$(MSYS_DIR)/lib/pkgconfig \
		$(GO) build -ldflags '-linkmode external -extldflags "-static"' -o bin/shadow-windows.exe ./cmd/shadow

# Idempotent: probes for the extracted pieces (with and without the .exe
# suffix, so an overridden MINGW_DIR on a Unix host works too) rather than for a
# sentinel file, so repeating it is free. The SFX cannot delete a tree it
# already extracted, so the target dir is always cleared first.
shadow-deps-win:
	@if [ ! -x "$(WIN_CC)" ] && [ ! -x "$(WIN_CC).exe" ]; then \
		echo "fetching w64devkit $(W64DEVKIT_VER) -> $(MINGW_DIR)"; \
		mkdir -p $(DEPS_DIR); \
		curl -fsSL -o $(DEPS_DIR)/w64devkit-$(W64DEVKIT_VER).7z.exe $(W64DEVKIT_URL); \
		rm -rf $(MINGW_DIR); \
		cd $(DEPS_DIR) && ./w64devkit-$(W64DEVKIT_VER).7z.exe -y; \
	fi
	@if [ ! -x "$(WIN_PKGCFG)" ]; then \
		echo "fetching libusb + pkgconf -> $(MSYS_DIR)"; \
		mkdir -p $(DEPS_DIR)/msys; \
		curl -fsSL -o $(DEPS_DIR)/libusb-win.pkg.tar.zst $(MSYS2_MINGW)/$(WIN_LIBUSB_PKG); \
		curl -fsSL -o $(DEPS_DIR)/pkgconf-win.pkg.tar.zst '$(MSYS2_MINGW)/$(PKGCONF_PKG)'; \
		tar -xf $(DEPS_DIR)/libusb-win.pkg.tar.zst -C $(DEPS_DIR)/msys; \
		tar -xf $(DEPS_DIR)/pkgconf-win.pkg.tar.zst -C $(DEPS_DIR)/msys; \
		sed -i.bak 's|^prefix=.*|prefix=$${pcfiledir}/../..|' $(MSYS_DIR)/lib/pkgconfig/libusb-1.0.pc; \
		rm -f $(MSYS_DIR)/lib/pkgconfig/libusb-1.0.pc.bak; \
	fi
else
shadow-deps-win: $(WIN_LIBUSB_PC)

shadow-windows: $(WIN_LIBUSB_PC)
	@command -v $(ZIG) >/dev/null 2>&1 || { echo "zig not found: install zig (or set ZIG)" >&2; exit 1; }
	PKG_CONFIG_PATH=$(WIN_LIBUSB_DIR)/lib/pkgconfig CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
		CC="$(ZIG) cc -target x86_64-windows-gnu" \
		CGO_LDFLAGS="-L$(WIN_LIBUSB_DIR)/lib -lsetupapi -lole32" \
		$(GO) build -ldflags '-linkmode external -extldflags "-static"' -o bin/shadow-windows.exe ./cmd/shadow

$(WIN_LIBUSB_TARBALL):
	mkdir -p $(DEPS_DIR)
	curl -fsSL -o $@ $(MSYS2_MINGW)/$(WIN_LIBUSB_PKG)
	echo "$(WIN_LIBUSB_SHA256)  $@" | $(SHA256) $(SHA256_FLAGS) -c -

$(WIN_LIBUSB_PC): $(WIN_LIBUSB_TARBALL)
	mkdir -p $(DEPS_DIR)/msys
	tar -xf $< -C $(DEPS_DIR)/msys
	sed -i.bak 's|^prefix=.*|prefix=$${pcfiledir}/../..|' $(WIN_LIBUSB_PC)
	rm -f $(WIN_LIBUSB_PC).bak
endif

clean:
	rm -rf bin
