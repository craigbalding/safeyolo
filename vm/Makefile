.PHONY: build debug install install-helper debug-install verify clean guest-tools test-relays test-control test-admission

PROFILE ?= production
BUILD_ROOT = $(if $(filter production,$(PROFILE)),.build,.build/$(PROFILE))
BUILD_DIR = $(BUILD_ROOT)/release
BINARY = $(BUILD_DIR)/safeyolo-vm
BUILD_INFO = $(abspath $(BUILD_ROOT)/build-info.json)
ENTITLEMENTS = $(if $(filter production,$(PROFILE)),safeyolo-vm.entitlements,safeyolo-vm.$(PROFILE).entitlements)
PYTHON ?= python3
SWIFT_BUILD_FLAGS ?=
INSTALL_DIR ?= $(HOME)/.safeyolo/bin
GUEST_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../guest

build:
	$(PYTHON) build-info.py generate --profile $(PROFILE) "$(BUILD_INFO)"
	swift build --build-system native $(SWIFT_BUILD_FLAGS) --scratch-path "$(BUILD_ROOT)" -c release -Xswiftc -g \
		-Xlinker -sectcreate -Xlinker __TEXT -Xlinker __sy_build -Xlinker "$(BUILD_INFO)"
	dsymutil "$(BINARY)" -o "$(BINARY).dSYM"
	codesign --entitlements "$(ENTITLEMENTS)" --options runtime --force -s - "$(BINARY)"
	$(PYTHON) build-info.py verify --profile $(PROFILE) "$(BINARY)"

debug:
	$(MAKE) PROFILE=development build

debug-install:
	$(MAKE) PROFILE=development install-helper

verify:
	$(PYTHON) build-info.py verify --profile $(PROFILE) "$(BINARY)"

test-relays:
	mkdir -p .build
	swiftc -O -g Sources/SafeYoloVM/SocketRelay.swift Sources/SafeYoloVM/Log.swift \
		test/SocketRelayTests.swift -o .build/relay-tests
	$(PYTHON) -c 'import subprocess; subprocess.run([".build/relay-tests"], check=True, timeout=60)'

test-control:
	mkdir -p .build
	swiftc -O -g Sources/SafeYoloVM/SocketRelay.swift Sources/SafeYoloVM/Log.swift \
		Sources/SafeYoloVM/BuildIdentity.swift Sources/SafeYoloVM/VMRuntimeStatus.swift \
		Sources/SafeYoloVM/VMControl.swift test/VMControlTests.swift -o .build/control-tests
	$(PYTHON) -c 'import subprocess; subprocess.run([".build/control-tests"], check=True, timeout=30)'

test-admission:
	mkdir -p .build
	swiftc -O -g Sources/SafeYoloVM/SocketRelay.swift Sources/SafeYoloVM/Log.swift \
		Sources/SafeYoloVM/VSockConnectionLimit.swift test/VSockConnectionLimitTests.swift -o .build/admission-tests
	$(PYTHON) -c 'import subprocess; subprocess.run([".build/admission-tests"], check=True, timeout=15)'

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
	@set -e; \
	if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -qx "$(LIMA_VM)"; then \
		limactl start --name=$(LIMA_VM) --tty=false $(GUEST_DIR)/lima.yaml; \
	else \
		status=$$(limactl list "$(LIMA_VM)" --format '{{.Status}}' 2>/dev/null); \
		[ "$$status" = "Running" ] || limactl start --tty=false $(LIMA_VM); \
	fi
	@limactl shell $(LIMA_VM) -- \
		aarch64-linux-gnu-gcc -static -O2 \
		-o /build/vm/.build/release/vsock-term \
		/build/guest/vsock-term.c -lutil; ret=$$?; \
	limactl stop $(LIMA_VM); \
	exit $$ret
else
	$(error Unsupported platform for guest-tools: $(UNAME))
endif

install-helper: build
	mkdir -p "$(INSTALL_DIR)"
	install -m 0755 "$(BINARY)" "$(INSTALL_DIR)/safeyolo-vm"
	ditto "$(BINARY).dSYM" "$(INSTALL_DIR)/safeyolo-vm.dSYM"
	install -m 0644 "$(BUILD_INFO)" "$(INSTALL_DIR)/safeyolo-vm.build-info.json"
	$(PYTHON) build-info.py verify --profile $(PROFILE) "$(INSTALL_DIR)/safeyolo-vm"

install: install-helper guest-tools
	install -m 0755 "$(BUILD_DIR)/vsock-term" "$(INSTALL_DIR)/vsock-term"

clean:
	swift package clean
	rm -f $(BUILD_DIR)/vsock-term
