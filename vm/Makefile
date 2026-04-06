.PHONY: build install clean

BUILD_DIR = .build/release
BINARY = $(BUILD_DIR)/safeyolo-vm
FETH_BRIDGE = $(BUILD_DIR)/feth-bridge
INSTALL_DIR ?= $(HOME)/.safeyolo/bin

build:
	swift build -c release
	codesign --entitlements safeyolo-vm.entitlements --force -s - $(BINARY)
	cc -O2 -o $(FETH_BRIDGE) feth-bridge.c

debug:
	swift build
	codesign --entitlements safeyolo-vm.entitlements --force -s - .build/debug/safeyolo-vm
	cc -o .build/debug/feth-bridge feth-bridge.c

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BINARY) $(INSTALL_DIR)/safeyolo-vm
	cp $(FETH_BRIDGE) $(INSTALL_DIR)/feth-bridge

clean:
	swift package clean
	rm -f $(FETH_BRIDGE) .build/debug/feth-bridge
