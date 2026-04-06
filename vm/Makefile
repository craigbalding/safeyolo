.PHONY: build install clean

BUILD_DIR = .build/release
BINARY = $(BUILD_DIR)/safeyolo-vm
INSTALL_DIR ?= $(HOME)/.safeyolo/bin

build:
	swift build -c release
	codesign --entitlements safeyolo-vm.entitlements --force -s - $(BINARY)

debug:
	swift build
	codesign --entitlements safeyolo-vm.entitlements --force -s - .build/debug/safeyolo-vm

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BINARY) $(INSTALL_DIR)/safeyolo-vm

clean:
	swift package clean
