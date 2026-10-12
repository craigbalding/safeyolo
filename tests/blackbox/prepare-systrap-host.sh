#!/bin/bash
# Prepare a disposable Ubuntu host for the maintained native systrap lane.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"

# Sandbox uid 0 maps to host uid 100000. Hosted runner ranges may differ.
has_range() {
    awk -F: -v user="$USER" '
      $1 == user && $2 <= 100000 && ($2 + $3) >= 165536 { found = 1 }
      END { exit !found }
    ' "$1"
}
if ! has_range /etc/subuid; then
    sudo -n usermod --add-subuids 100000-165535 "$USER"
fi
if ! has_range /etc/subgid; then
    sudo -n usermod --add-subgids 100000-165535 "$USER"
fi
grep -F "$USER:" /etc/subuid
grep -F "$USER:" /etc/subgid

sudo -n apt-get update -qq
sudo -n apt-get install -y -qq --no-install-recommends \
    openssh-server uidmap acl util-linux iproute2 tmux curl gnupg ca-certificates
# Use the same signed gVisor repository as the nightly source lane.
curl -fsSL https://gvisor.dev/archive.key | \
    sudo -n gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
printf 'deb [arch=%s signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main\n' \
    "$(dpkg --print-architecture)" | sudo -n tee /etc/apt/sources.list.d/gvisor.list
sudo -n apt-get update -qq
sudo -n apt-get install -y -qq --no-install-recommends runsc
for command in runsc newuidmap newgidmap setfacl unshare tmux; do
    command -v "$command"
done
runsc --version
tmux -V
ls -l "$(command -v newuidmap)" "$(command -v newgidmap)"
# Native start_userns selects this existing profile on restricted hosts.
if [[ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns && \
      $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns) == 1 ]]; then
    sudo -n apt-get install -y -qq --no-install-recommends apparmor-utils
    runsc_path=$(command -v runsc)
    sed "s|/usr/local/bin/runsc|$runsc_path|" \
        "$REPO_ROOT/cli/src/safeyolo/templates/apparmor-safeyolo-runsc" > "$RUNNER_TEMP/safeyolo-runsc"
    sudo -n install -m 0644 "$RUNNER_TEMP/safeyolo-runsc" /etc/apparmor.d/safeyolo-runsc
    sudo -n apparmor_parser -r /etc/apparmor.d/safeyolo-runsc
    aa-exec -p safeyolo-runsc -- unshare -Urn true
else
    unshare -Urn true
fi
