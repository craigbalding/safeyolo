#!/bin/bash
# Builder fixture: run as the existing rootfs builder, after candidate static
# customization and before its normal tree/ext4 packaging. ROOT must be the
# selected disposable unpacked Debian root, never the builder's own root.
# This changes two named defaults and refreshes that image's actual baseline.
set -euo pipefail
root=${1:?selected disposable unpacked Debian root}
root=$(realpath "$root")
[ "$root" != / ] && [ -d "$root/etc" ] || { echo 'Select the disposable guest root.' >&2; exit 1; }
[ -x "$root/usr/local/lib/safeyolo/guest-state-base" ] || { echo 'Candidate guest integration is absent.' >&2; exit 1; }
install -d -m 0755 "$root/usr/local/etc"
printf 'security_default=strict\n' > "$root/etc/safeyolo-retention-new-default"
printf 'new_base_option=preserve\n' > "$root/usr/local/etc/safeyolo-retention-probe.conf"
chmod 0644 "$root/etc/safeyolo-retention-new-default" "$root/usr/local/etc/safeyolo-retention-probe.conf"
chroot "$root" /usr/local/lib/safeyolo/guest-state-base
