#!/bin/bash
# Prepare a host through the supported install path, then run one BB lane.
#
# Usage:
#   ./tests/blackbox/run-lane.sh systrap [run-tests.sh options]
#   ./tests/blackbox/run-lane.sh kvm     [run-tests.sh options]
#   ./tests/blackbox/run-lane.sh vz      [run-tests.sh options]
#   ./tests/blackbox/run-lane.sh proxy   [run-tests.sh options]
#
# Backend selection is forwarded to run-tests.sh. A native VM lane uses the
# Rust executable packaged by install.sh for the same installed CLI:
#   ./tests/blackbox/run-lane.sh systrap --proxy-impl rust

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LANE="${1:-}"

if [ -z "$LANE" ]; then
    echo "Usage: $0 {systrap|kvm|vz|proxy} [run-tests.sh options]" >&2
    exit 2
fi
shift

# The selected source checkout may differ from the current blackbox harness. The packaged CLI and native binary still come
# from the same install.sh invocation.
INSTALL_ROOT="$REPO_ROOT"
if [ "${1:-}" = "--install-checkout" ]; then
    if [ "$#" -lt 2 ] || [ ! -f "$2/install.sh" ]; then
        echo "ERROR: --install-checkout requires a SafeYolo source checkout" >&2
        exit 2
    fi
    INSTALL_ROOT="$(cd "$2" && pwd -P)"
    shift 2
fi
export SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT="$INSTALL_ROOT"

# The installed scenario runner prepares one product, then gives each section
# a fresh live instance. This option does not select or run assertions.
PREPARE_ONLY=false
if [ "${1:-}" = "--prepare-only" ]; then
    PREPARE_ONLY=true
    shift
fi

case "$LANE" in
    systrap|kvm)
        if [ "$(uname -s)" != "Linux" ]; then
            echo "ERROR: $LANE lane requires a Linux host" >&2
            exit 2
        fi
        ;;
    vz)
        if [ "$(uname -s)" != "Darwin" ]; then
            echo "ERROR: vz lane requires a physical Apple Silicon macOS host" >&2
            exit 2
        fi
        ;;
    proxy)
        ;;
    *)
        echo "ERROR: unknown lane '$LANE' (use systrap|kvm|vz|proxy)" >&2
        exit 2
        ;;
esac

if ! command -v uv >/dev/null 2>&1; then
    echo "ERROR: uv is required before running a blackbox lane" >&2
    exit 2
fi

echo "=== Prepare SafeYolo blackbox lane: $LANE ==="

# Make the software-isolation lane deterministic even if a runner happens to
# expose /dev/kvm.  KVM is deliberately left to auto-detection: that lane must
# prove the device is genuinely usable rather than forcing a label.
if [ "$LANE" = "systrap" ]; then
    export SAFEYOLO_RUNSC_PLATFORM=systrap
else
    unset SAFEYOLO_RUNSC_PLATFORM
fi

# Exercise the supported user installation path on every acceptance run.
# `reinstall` is safe on persistent hosts and equivalent to a first install on
# an ephemeral host after uv reports that no prior tool environment exists.
if uv tool list | grep -q '^safeyolo '; then
    "$INSTALL_ROOT/install.sh" reinstall
else
    "$INSTALL_ROOT/install.sh" install
fi

# Host-side blackbox pytest uses the development dependency group.  The
# product CLI still comes from install.sh's isolated uv tool environment.
uv sync --frozen --group dev
export PATH="$(uv tool dir --bin):$REPO_ROOT/.venv/bin:$PATH"

if [ "$PREPARE_ONLY" = true ]; then
    # The installed Python workflow calls the native lifecycle owner in each
    # instance. Reuse the native installer for its complete host/guest layout.
    NATIVE_ARTIFACTS="$(python3 - "$SCRIPT_DIR" "$(command -v safeyolo)" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from installed_host_smoke import _installed_rust_binary
binary, _ = _installed_rust_binary(sys.argv[2])
print(binary.parent)
PY
)"
    GUEST_HELPER="${SAFEYOLO_GUEST_HELPER:-${SAFEYOLO_GUEST_TARGET_DIR:-$INSTALL_ROOT/guest/command/target}/${SAFEYOLO_GUEST_TARGET:+$SAFEYOLO_GUEST_TARGET/}release/safeyolo-guest}"
    if [ -n "${SAFEYOLO_NATIVE_BUNDLE:-}" ]; then
        "$INSTALL_ROOT/scripts/install_native.sh" --root "$SAFEYOLO_CONFIG_DIR" --bundle "$SAFEYOLO_NATIVE_BUNDLE"
    else
        # Legacy test transport still uses its wheel CLI. Native preparation
        # needs the ordinary installer's complete checked runtime inputs.
        NATIVE_INPUTS=(--artifacts "$NATIVE_ARTIFACTS" --guest-artifacts "$(dirname "$GUEST_HELPER")"
            --runtime-artifacts "${SAFEYOLO_NATIVE_RUNTIME_ARTIFACTS:?set the prepared tmux input directory}")
        if [ "$(uname -s)" = Darwin ]; then
            NATIVE_INPUTS+=(--vm-artifacts "${SAFEYOLO_NATIVE_VM_ARTIFACTS:?set the prepared signed VM/guest-terminal input directory}")
        fi
        "$INSTALL_ROOT/scripts/install_native.sh" --root "$SAFEYOLO_CONFIG_DIR" "${NATIVE_INPUTS[@]}"
    fi
fi

if [ "$LANE" != "proxy" ]; then
    if [ "$(uname -s)" = "Linux" ]; then
        # Bootstrap owns the package list.  Read its structured preflight and
        # install only the missing apt packages rather than copying another
        # package list into this harness or the GitHub workflow.
        PLAN_FILE="$(mktemp)"
        cleanup_plan() { rm -f "$PLAN_FILE"; }
        trap cleanup_plan EXIT
        safeyolo bootstrap --check --json >"$PLAN_FILE" || true

        PACKAGE_MANAGER="$(python3 - "$PLAN_FILE" <<'PY'
import json, sys
print(json.load(open(sys.argv[1])).get("package_manager") or "")
PY
)"
        MISSING_DEPS=()
        while IFS= read -r dep; do
            [ -n "$dep" ] && MISSING_DEPS+=("$dep")
        done < <(python3 - "$PLAN_FILE" <<'PY'
import json, sys
for dep in json.load(open(sys.argv[1])).get("missing_deps", []):
    print(dep)
PY
)

        if [ "${#MISSING_DEPS[@]}" -gt 0 ]; then
            if [ "$PACKAGE_MANAGER" != "apt" ]; then
                echo "ERROR: automatic BB preparation currently supports apt hosts;" >&2
                echo "       install these $PACKAGE_MANAGER dependencies first: ${MISSING_DEPS[*]}" >&2
                exit 2
            fi
            sudo -n apt-get update
            sudo -n apt-get install -y --no-install-recommends "${MISSING_DEPS[@]}"
        fi

        if [ "$LANE" = "kvm" ]; then
            # Automated acceptance has no interactive logout/login boundary in
            # which a newly-added `kvm` group becomes effective. Perform the
            # operator-side prerequisite directly for this process. The normal
            # product bootstrap below remains responsible for installing the
            # persistent udev rule and uid 100000 ACL used by rootless runsc.
            if [ ! -e /dev/kvm ]; then
                echo "ERROR: KVM lane requires /dev/kvm" >&2
                exit 2
            fi
            if ! command -v setfacl >/dev/null 2>&1; then
                echo "ERROR: KVM lane requires setfacl after dependency preparation" >&2
                exit 2
            fi
            OPERATOR_UID="$(id -u)"
            echo "Granting blackbox operator uid $OPERATOR_UID access to /dev/kvm..."
            sudo -n setfacl -m "u:${OPERATOR_UID}:rw" /dev/kvm
            if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
                echo "ERROR: blackbox operator still lacks rw access to /dev/kvm" >&2
                exit 2
            fi
        fi
        rm -f "$PLAN_FILE"
        trap - EXIT
    fi

    if [ "$LANE" = "vz" ]; then
        # bootstrap builds the guest artifacts; the source install deliberately
        # leaves this host-native Swift helper as an explicit macOS step.
        make -C "$INSTALL_ROOT/vm" install
    fi

    safeyolo bootstrap --source-checkout "$INSTALL_ROOT"
fi

if [ "$PREPARE_ONLY" = true ]; then
    # Resolve through the selected wheel. Only this verified executable is
    # copied to section instances; NATS credentials and streams are not shared.
    python3 - "$(command -v safeyolo)" <<'PY'
import subprocess
import sys
from pathlib import Path
python = Path(sys.argv[1]).read_text().splitlines()[0][2:]
subprocess.run([python, '-I', '-c',
               'from safeyolo.coord.nats_runtime import ensure_binary; print(ensure_binary())'], check=True)
PY
    echo "Installed product and $LANE boot inputs prepared; no test instance started"
    exit 0
fi

if [ "$LANE" = "proxy" ]; then
    # The installed lane must test the binary packaged with this CLI. The
    # direct run-tests.sh selector retains its explicit debug-binary default.
    ARGS=("$@")
    EXPLICIT_RUST_BIN=false
    for ((i = 0; i < ${#ARGS[@]}; i++)); do
        if [ "${ARGS[i]}" = "--rust-bin" ]; then
            EXPLICIT_RUST_BIN=true
        fi
    done
    if [ "$EXPLICIT_RUST_BIN" = false ]; then
        INSTALLED_RUST_BIN="$(python3 - "$SCRIPT_DIR" "$(command -v safeyolo)" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from installed_host_smoke import _installed_rust_binary

binary, _ = _installed_rust_binary(sys.argv[2])
print(binary)
PY
)"
        set -- "$@" --rust-bin "$INSTALLED_RUST_BIN"
    fi
    exec "$SCRIPT_DIR/run-tests.sh" --proxy "$@"
else
    exec "$SCRIPT_DIR/run-tests.sh" --expect-platform "$LANE" "$@"
fi
