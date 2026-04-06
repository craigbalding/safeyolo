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

# Cross-compile vsock-term for ARM64 Linux (runs inside guest VM)
guest-tools:
	docker run --rm --platform linux/arm64/v8 \
		-v "$(GUEST_DIR)/vsock-term.c:/src/vsock-term.c:ro" \
		-v "$(BUILD_DIR):/out" \
		debian:trixie-slim bash -c '\
			apt-get update -qq && \
			apt-get install -y -qq --no-install-recommends build-essential >/dev/null && \
			cc -static -O2 -o /out/vsock-term /src/vsock-term.c -lutil'

install: build guest-tools
	mkdir -p $(INSTALL_DIR)
	cp $(BINARY) $(INSTALL_DIR)/safeyolo-vm
	cp $(FETH_BRIDGE) $(INSTALL_DIR)/feth-bridge
	cp $(BUILD_DIR)/vsock-term $(INSTALL_DIR)/vsock-term

clean:
	swift package clean
	rm -f $(FETH_BRIDGE) $(BUILD_DIR)/vsock-term .build/debug/feth-bridge
