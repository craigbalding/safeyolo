#!/usr/bin/env bash
set -euo pipefail

resolved_script=$(readlink -f "${BASH_SOURCE[0]}")
script_dir=$(cd "$(dirname "$resolved_script")" && pwd)
launcher="$script_dir/safeyolo-lab"
install_home=${HOME:?HOME is not set}
install_dir="$install_home/.local/bin"
target="$install_dir/safeyolo-lab"
bashrc="$install_home/.bashrc"
marker_start='# >>> safeyolo-lab PATH >>>'
marker_end='# <<< safeyolo-lab PATH <<<'

[ -x "$launcher" ] || {
  printf 'The lab launcher is not executable: %s\n' "$launcher" >&2
  exit 126
}

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

if [ -e "$bashrc" ] && [ ! -f "$bashrc" ]; then
  printf 'The Bash startup path is not a regular file: %s\n' "$bashrc" >&2
  exit 2
fi

if [ ! -e "$bashrc" ]; then
  : > "$bashrc"
fi

if ! grep -Fqx "$marker_start" "$bashrc"; then
  cat >> "$bashrc" <<'EOF'

# >>> safeyolo-lab PATH >>>
# Make persistent user commands visible in SafeYolo interactive shells.
if [ -d "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) PATH="$HOME/.local/bin:$PATH" ;;
    esac
    export PATH
fi
if [ -z "${TMUX:-}" ] && [ "${PWD:-}" = "$HOME" ] && [ -x "$HOME/.local/bin/safeyolo-lab" ]; then
    printf 'SafeYolo lab: run safeyolo-lab\n'
fi
# <<< safeyolo-lab PATH <<<
EOF
elif ! grep -Fqx "$marker_end" "$bashrc"; then
  printf 'The safeyolo-lab PATH block is incomplete in %s\n' "$bashrc" >&2
  exit 2
fi

printf 'Installed command: %s -> %s\n' "$target" "$launcher"
printf 'New SafeYolo guest shells can run: safeyolo-lab\n'
if [[ :$PATH: != *":$install_dir:"* ]]; then
  printf 'For this shell only, run: export PATH=%q:\$PATH\n' "$install_dir"
fi
