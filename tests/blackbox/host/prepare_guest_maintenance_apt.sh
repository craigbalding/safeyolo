#!/usr/bin/env bash
# Run in the existing ownership namespace on an independent, stopped Linux
# rootfs copy. This prepares test inputs; it never installs or starts SafeYolo.
# Preserve a failed output and inspect it before selecting any further effect.
set -euo pipefail
if [[ $# != 2 && $# != 3 ]] || [[ $# == 3 && $3 != --fixed-base ]]; then
  echo 'Usage: prepare_guest_maintenance_apt.sh ROOTFS FIXTURE_2_DEB [--fixed-base]' >&2
  echo 'Adds an offline APT candidate before restoration. --fixed-base also installs it and refreshes the base inventory.' >&2
  exit 2
fi
tree=$(realpath -e -- "$1")
archive=$(realpath -e -- "$2")
[[ $(dpkg-deb -f "$archive" Package) == sy-maintenance-fixture &&
   $(dpkg-deb -f "$archive" Version) == 2.0 &&
   $(dpkg-deb -f "$archive" Architecture) == all ]] || {
  echo 'Expected the retained sy-maintenance-fixture 2.0/all archive.' >&2; exit 1;
}
repo=usr/local/share/q1611-maintenance
source_list=etc/apt/sources.list.d/q1611-maintenance.list
package_list=var/lib/apt/lists/_usr_local_share_q1611-maintenance_._Packages
for path in "$repo" "$source_list" "$package_list" var/lib/dpkg usr/share/safeyolo/guest-base; do
  [[ $(realpath -m -- "$tree/$path") == "$tree/"* ]] || {
    echo "Input path escapes the independent rootfs: $path" >&2; exit 1;
  }
done
[[ ! -e $tree/$repo && ! -e $tree/$source_list && ! -e $tree/$package_list ]] || {
  echo 'APT fixture input already exists; inspect the original preparation instead of replaying it.' >&2; exit 1;
}
uid=$(stat -c %u "$tree/usr/bin/dpkg")
gid=$(stat -c %g "$tree/usr/bin/dpkg")
install -d -o "$uid" -g "$gid" -m 0755 "$tree/$repo"
install -o "$uid" -g "$gid" -m 0644 "$archive" "$tree/$repo/2.0.deb"
{
  dpkg-deb -f "$archive"
  printf 'Filename: ./2.0.deb\nSize: %s\nSHA256: %s\n\n' \
    "$(stat -c %s "$archive")" "$(sha256sum "$archive" | cut -d ' ' -f 1)"
} > "$tree/$repo/Packages"
printf 'deb [trusted=yes] file:/usr/local/share/q1611-maintenance ./\n' > "$tree/$source_list"
cp -- "$tree/$repo/Packages" "$tree/$package_list"
chown "$uid:$gid" "$tree/$repo/Packages" "$tree/$source_list" "$tree/$package_list"
chmod 0644 "$tree/$repo/Packages" "$tree/$source_list" "$tree/$package_list"
candidate=$(apt-cache -o "Dir=$tree" -o "Dir::State::status=$tree/var/lib/dpkg/status" \
  policy sy-maintenance-fixture)
printf '%s\n' "$candidate"
candidate_version=$(printf '%s\n' "$candidate" | awk '$1 == "Candidate:" {print $2}')
dpkg --compare-versions "$candidate_version" ge 2.0 || { echo 'Prepared APT candidate does not satisfy >=2.0.' >&2; exit 1; }
if [[ ${3:-} == --fixed-base ]]; then
  # The caller uses the namespace that owns this normalized tree. No package
  # command runs in the live guest and no old overlay is used as a new base.
  if installed=$(dpkg-query --admindir="$tree/var/lib/dpkg" -W \
      '-f=${db:Status-Status}\t${Version}' sy-maintenance-fixture 2>/dev/null) &&
      [[ $installed == installed$'\t'* ]] &&
      dpkg --compare-versions "${installed#*$'\t'}" ge 2.0; then
    printf 'Base already supplies a satisfactory package: %s\n' "${installed#*$'\t'}"
  else
    SAFEYOLO_RESTORE_ACTIVE=1 dpkg --root="$tree" --force-not-root --install "$archive"
  fi
  dpkg-query --admindir="$tree/var/lib/dpkg" -W \
    '-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
    > "$tree/usr/share/safeyolo/guest-base/packages.tsv"
  chown "$uid:$gid" "$tree/usr/share/safeyolo/guest-base/packages.tsv"
fi
printf 'Prepared APT input: %s (no runtime operation)\n' "$tree"
