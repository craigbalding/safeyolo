#!/bin/bash
# Prepare a host through the supported install path, then run one BB lane.
#
# Usage:
#   ./tests/blackbox/run-lane.sh systrap [run-tests.sh options]
#   ./tests/blackbox/run-lane.sh kvm     [run-tests.sh options]
#   ./tests/blackbox/run-lane.sh vz      [run-tests.sh options]
#   ./tests/blackbox/run-lane.sh proxy   [run-tests.sh options]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LANE="${1:-}"

if [ -z "$LANE" ]; then
    echo "Usage: $0 {systrap|kvm|vz|proxy} [run-tests.sh options]" >&2
    exit 2
fi
shift

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
    "$REPO_ROOT/install.sh" reinstall
else
    "$REPO_ROOT/install.sh" install
fi

# Host-side blackbox pytest uses the development dependency group.  The
# product CLI still comes from install.sh's isolated uv tool environment.
uv sync --frozen --group dev
export PATH="$HOME/.local/bin:$REPO_ROOT/.venv/bin:$PATH"

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
        make -C "$REPO_ROOT/vm" install
    fi

    safeyolo bootstrap
fi

if [ "$LANE" = "proxy" ]; then
    exec "$SCRIPT_DIR/run-tests.sh" --proxy "$@"
else
    exec "$SCRIPT_DIR/run-tests.sh" --expect-platform "$LANE" "$@"
fi
