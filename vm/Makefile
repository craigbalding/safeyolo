.PHONY: build install clean guest-tools

BUILD_DIR = .build/release
BINARY = $(BUILD_DIR)/safeyolo-vm
INSTALL_DIR ?= $(HOME)/.safeyolo/bin
GUEST_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../guest

build:
	swift build -c release
	codesign --entitlements safeyolo-vm.entitlements --options runtime --force -s - $(BINARY)

debug:
	swift build
	codesign --entitlements safeyolo-vm.entitlements --options runtime --force -s - .build/debug/safeyolo-vm

LIMA_VM = safeyolo-builder
UNAME := $(shell uname)

# Cross-compile vsock-term for ARM64 Linux (runs inside guest VM as the
# interactive PTY daemon for non-detached agent sessions).
#
# On Linux: native cross-compile via gcc-aarch64-linux-gnu.
# On macOS: run the cross-compile inside the same Lima VM used for guest
# image builds (see guest/lima.yaml). Requires Lima (brew install lima).
guest-tools: $(BUILD_DIR)/vsock-term

$(BUILD_DIR)/vsock-term: $(GUEST_DIR)/vsock-term.c
	@mkdir -p $(BUILD_DIR)
ifeq ($(UNAME),Linux)
	@command -v aarch64-linux-gnu-gcc >/dev/null || { \
		echo "Error: aarch64-linux-gnu-gcc not found."; \
		echo "  Debian/Ubuntu: sudo apt-get install gcc-aarch64-linux-gnu"; \
		exit 1; }
	aarch64-linux-gnu-gcc -static -O2 -o $@ $< -lutil
else ifeq ($(UNAME),Darwin)
	@command -v limactl >/dev/null || { \
		echo "Error: Lima not found. Install with: brew install lima"; \
		echo "See guest/README.md for details."; \
		exit 1; }
	@limactl list --format '{{.Name}}' 2>/dev/null | grep -qx $(LIMA_VM) || \
		limactl start --name=$(LIMA_VM) --tty=false $(GUEST_DIR)/lima.yaml
	@limactl shell $(LIMA_VM) -- \
		aarch64-linux-gnu-gcc -static -O2 \
		-o /build/vm/.build/release/vsock-term \
		/build/guest/vsock-term.c -lutil; ret=$$?; \
	limactl stop $(LIMA_VM) >/dev/null 2>&1 || true; \
	exit $$ret
else
	$(error Unsupported platform for guest-tools: $(UNAME))
endif

install: build guest-tools
	mkdir -p $(INSTALL_DIR)
	install -m 0755 $(BINARY) $(INSTALL_DIR)/safeyolo-vm
	install -m 0755 $(BUILD_DIR)/vsock-term $(INSTALL_DIR)/vsock-term

clean:
	swift package clean
	rm -f $(BUILD_DIR)/vsock-term
