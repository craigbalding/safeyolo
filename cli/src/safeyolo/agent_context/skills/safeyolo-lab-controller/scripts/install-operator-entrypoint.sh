#!/usr/bin/env bash
set -euo pipefail

resolved_script=$(readlink -f "${BASH_SOURCE[0]}")
script_dir=$(cd "$(dirname "$resolved_script")" && pwd)
launcher="$script_dir/safeyolo-lab"
install_home=${HOME:?HOME is not set}
install_dir="$install_home/.local/bin"
target="$install_dir/safeyolo-lab"
bashrc="$install_home/.bashrc"

[ -x "$launcher" ] || {
  printf 'The lab launcher is not executable: %s\n' "$launcher" >&2
  exit 126
}

# shellcheck source=lab-bashrc.sh
. "$script_dir/lab-bashrc.sh"
_prepare_safeyolo_lab_bashrc "$bashrc" || exit 2

install -d -m 0755 "$install_dir"

if [ -L "$target" ]; then
  installed_target=$(readlink -f "$target" 2>/dev/null || true)
  if [ "$installed_target" != "$launcher" ]; then
    printf 'Refusing to replace an unrelated symlink: %s\n' "$target" >&2
    exit 2
  fi
elif [ -e "$target" ]; then
  printf 'Refusing to replace an existing file: %s\n' "$target" >&2
  exit 2
else
  ln -s "$launcher" "$target"
fi

# Write in place to retain the existing file's ownership and permissions.
printf '%s' "$_safeyolo_lab_bashrc" > "$bashrc"

printf 'Installed command: %s -> %s\n' "$target" "$launcher"
printf 'New SafeYolo guest shells can run: safeyolo-lab\n'
if [[ :$PATH: != *":$install_dir:"* ]]; then
  printf 'For this shell only, run: export PATH=%q:\$PATH\n' "$install_dir"
fi
