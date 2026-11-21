#!/bin/bash
# Installed probe, run inside an owned disposable standard Debian guest.
# The platform owner selects two bases and a fresh writable root externally.
# Home/workspace and the candidate helper must persist across that boundary.
# prepare installs only sy-retention-fixture and writes named fixture config.
# restore reports the actual missing requirement/conflict, restores/reconciles,
# and verifies retained work. verify repeats recovery to prove prerequisite reuse.
set -euo pipefail
phase=${1:?prepare, restore or verify}
probe=/home/agent/.local/state/safeyolo-retention-probe
config=/usr/local/etc/safeyolo-retention-probe.conf
outside=/opt/safeyolo-retention-probe/config
helper=/run/safeyolo/safeyolo-guest
[ -x "$helper" ] || helper=/safeyolo/safeyolo-guest
: "${SAFEYOLO_RETAINED_EXPECTED_REVISION:?set the full candidate helper source revision}"
"$helper" --version | grep -F "commit=$SAFEYOLO_RETAINED_EXPECTED_REVISION "
command -v safeyolo-guest-state >/dev/null

case "$phase" in
prepare)
    [ ! -e "$probe/work.txt" ] || { echo 'Preparation already exists; inspect it before selecting another operation.' >&2; exit 1; }
    [ ! -e "$config" ] && [ ! -e "$outside" ] || { echo 'Fixture configuration already exists.' >&2; exit 1; }
    install -d -m 0700 "$probe"
    (
        umask 022
        install -d -m 0755 "$probe/package/DEBIAN" "$probe/package/usr/local/bin"
        cat > "$probe/package/DEBIAN/control" <<'CONTROL'
Package: sy-retention-fixture
Version: 2.0
Architecture: all
Maintainer: SafeYolo probe <probe@localhost>
Description: owned guest-restoration acceptance fixture
CONTROL
        printf '#!/bin/sh\nprintf "retained prerequisite 2.0\\n"\n' > "$probe/package/usr/local/bin/sy-retention-fixture"
        chmod 0755 "$probe/package/usr/local/bin/sy-retention-fixture"
        dpkg-deb --root-owner-group --build "$probe/package" "$probe/prerequisite.deb"
    )
    safeyolo-guest-state restore --apply
    sudo -n dpkg --install "$probe/prerequisite.deb"
    # The fixture's constraint is explicit recovery input, not vulnerability assurance.
    . /etc/os-release
    safeyolo-guest-state require sy-retention-fixture ge 2.0 "$ID:$VERSION_CODENAME" advisory:controlled-retention-fixture
    printf 'task_option=retained\n' > "$probe/local.conf"
    sudo -n install -m 0600 "$probe/local.conf" "$config"
    sudo -n install -d -m 0755 "$(dirname "$outside")"
    sudo -n install -m 0640 "$probe/local.conf" "$outside"
    safeyolo-guest-state paths add "$(dirname "$outside")"
    safeyolo-guest-state capture
    printf 'unfinished task survives recreation\n' > "$probe/work.txt"
    safeyolo-guest-state status
    echo 'Prepared. Platform owner now force-stops and boots the selected new base with a fresh writable root and the same home/workspace.'
    ;;
restore)
    test -s "$probe/work.txt"
    # The selected new base must contain this unrelated default and a changed
    # default at $config. Their baseline belongs to that actual built image.
    grep -qx 'security_default=strict' /etc/safeyolo-retention-new-default
    grep -qx 'new_base_option=preserve' "$config"
    safeyolo-guest-state status
    if safeyolo-guest-state restore > "$probe/first-preview.json" 2> "$probe/first-preview.error"; then
        echo 'Expected the unavailable requirement or real configuration conflict.' >&2; exit 1
    fi
    # Inspect actual installed state before a selected installation; never blindly replay.
    current=$(dpkg-query -W '-f=${Version}' sy-retention-fixture 2>/dev/null || true)
    if [ -z "$current" ] || ! dpkg --compare-versions "$current" ge 2.0; then
        sudo -n dpkg --install "$probe/prerequisite.deb"
    fi
    if safeyolo-guest-state restore > "$probe/conflict-preview.json" 2> "$probe/conflict-preview.error"; then
        echo 'Expected the changed-base configuration conflict.' >&2; exit 1
    fi
    # Agent-assisted reconciliation keeps the new default and required local setting.
    printf 'new_base_option=preserve\ntask_option=retained\n' > "$probe/reconciled.conf"
    sudo -n install -m 0600 "$probe/reconciled.conf" "$config"
    safeyolo-guest-state resolve "$config"
    safeyolo-guest-state restore --apply
    "$0" verify
    ;;
verify)
    test -s "$probe/work.txt"
    grep -qx 'security_default=strict' /etc/safeyolo-retention-new-default
    sudo -n grep -qx 'new_base_option=preserve' "$config"
    sudo -n grep -qx 'task_option=retained' "$config"
    sudo -n grep -qx 'task_option=retained' "$outside"
    test "$(sudo -n stat -c %a "$config")" = 600
    test "$(sudo -n stat -c %a "$outside")" = 640
    current=$(dpkg-query -W '-f=${Version}' sy-retention-fixture)
    dpkg --compare-versions "$current" ge 2.0
    sy-retention-fixture
    before=$(sudo -n stat -c %Y /var/lib/dpkg/status)
    safeyolo-guest-state restore --apply
    test "$(sudo -n stat -c %Y /var/lib/dpkg/status)" = "$before"
    safeyolo-guest-state status
    ;;
*) echo 'Use prepare, restore or verify.' >&2; exit 2 ;;
esac
