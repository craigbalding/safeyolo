#!/usr/bin/env bash
# Prepare one independent Linux maintenance input from an existing normalized tree.
# Run on the Linux machine that owns SOURCE_ASSETS, with permission to preserve
# its numeric ownership. Confirm space under the existing storage policy first.
# The output remains after failure for inspection; select a new path after repair.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo 'Usage: prepare_guest_maintenance_inputs.sh SOURCE_ASSETS OUTPUT_ASSETS' >&2
  echo 'Copies rootfs-tree and cache-paths.txt, then installs the current package hook. Does not install or start an instance.' >&2
  exit 2
fi
source_assets=$1
output_assets=$2
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
hook=$repository/guest/rootfs/safeyolo-guest-state-hook
[[ $(uname -s) == Linux ]] || { echo 'Linux normalized tree input required.' >&2; exit 1; }
for tool in usr/bin/etckeeper usr/bin/git usr/bin/dpkg usr/bin/dpkg-deb \
    usr/local/bin/safeyolo-guest-state usr/local/lib/safeyolo/guest-state-hook; do
  [[ -x $source_assets/rootfs-tree/$tool ]] || { echo "Missing executable: $source_assets/rootfs-tree/$tool" >&2; exit 1; }
done
[[ -f $source_assets/rootfs-tree/usr/share/safeyolo/guest-base/packages.tsv ]] || {
  echo 'Source has no retained-state base inventory.' >&2; exit 1;
}
[[ -f $source_assets/cache-paths.txt && ! -L $source_assets/cache-paths.txt ]] || {
  echo 'Source requires a regular cache-paths.txt (an explicitly supplied empty file is valid).' >&2; exit 1;
}
source_tree=$(cd -- "$source_assets/rootfs-tree" && pwd -P)
mkdir -- "$output_assets"
cp -a --reflink=auto -- "$source_tree" "$output_assets/rootfs-tree"
cp -a -- "$source_assets/cache-paths.txt" "$output_assets/cache-paths.txt"
copied_hook=$output_assets/rootfs-tree/usr/local/lib/safeyolo/guest-state-hook
copied_tree=$(cd -- "$output_assets/rootfs-tree" && pwd -P)
[[ $(realpath -e -- "$copied_hook") == "$copied_tree/"* ]] || {
  echo 'Copied hook resolves outside the independent tree; input was preserved.' >&2; exit 1;
}
# The prepared tree already has host namespace ownership. Preserve those IDs;
# another archive-profile-tree conversion would shift them a second time.
install -o "$(stat -c %u "$copied_hook")" -g "$(stat -c %g "$copied_hook")" \
  -m 0755 -- "$hook" "$copied_hook"
cmp -- "$hook" "$copied_hook"
cmp -- "$source_assets/rootfs-tree/usr/share/safeyolo/guest-base/packages.tsv" \
  "$output_assets/rootfs-tree/usr/share/safeyolo/guest-base/packages.tsv"
sha256sum -- "$copied_hook"
printf 'Prepared image input: %s\n' "$output_assets"
