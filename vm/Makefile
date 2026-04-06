.PHONY: build install clean

BUILD_DIR = .build/release
BINARY = $(BUILD_DIR)/safeyolo-vm
BRIDGE_FILTER = $(BUILD_DIR)/bridge-filter
INSTALL_DIR ?= $(HOME)/.safeyolo/bin

build:
	swift build -c release
	codesign --entitlements safeyolo-vm.entitlements --force -s - $(BINARY)
	cc -O2 -o $(BRIDGE_FILTER) bridge-filter.c

debug:
	swift build
	codesign --entitlements safeyolo-vm.entitlements --force -s - .build/debug/safeyolo-vm
	cc -o .build/debug/bridge-filter bridge-filter.c

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BINARY) $(INSTALL_DIR)/safeyolo-vm
	cp $(BRIDGE_FILTER) $(INSTALL_DIR)/bridge-filter

clean:
	swift package clean
	rm -f $(BRIDGE_FILTER) .build/debug/bridge-filter
