.PHONY: build install clean guest-tools

BUILD_DIR = .build/release
BINARY = $(BUILD_DIR)/safeyolo-vm
FETH_BRIDGE = $(BUILD_DIR)/feth-bridge
INSTALL_DIR ?= $(HOME)/.safeyolo/bin
GUEST_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../guest

build:
	swift build -c release
	codesign --entitlements safeyolo-vm.entitlements --force -s - $(BINARY)
	cc -O2 -o $(FETH_BRIDGE) feth-bridge.c

debug:
	swift build
	codesign --entitlements safeyolo-vm.entitlements --force -s - .build/debug/safeyolo-vm
	cc -o .build/debug/feth-bridge feth-bridge.c

LIMA_VM = safeyolo-builder
UNAME := $(shell uname)

# Cross-compile vsock-term for ARM64 Linux (runs inside guest VM).
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
	limactl shell $(LIMA_VM) -- \
		aarch64-linux-gnu-gcc -static -O2 \
		-o /build/vm/.build/release/vsock-term \
		/build/guest/vsock-term.c -lutil
else
	$(error Unsupported platform for guest-tools: $(UNAME))
endif

install: build guest-tools
	mkdir -p $(INSTALL_DIR)
	cp $(BINARY) $(INSTALL_DIR)/safeyolo-vm
	cp $(FETH_BRIDGE) $(INSTALL_DIR)/feth-bridge
	cp $(BUILD_DIR)/vsock-term $(INSTALL_DIR)/vsock-term

clean:
	swift package clean
	rm -f $(FETH_BRIDGE) $(BUILD_DIR)/vsock-term .build/debug/feth-bridge
