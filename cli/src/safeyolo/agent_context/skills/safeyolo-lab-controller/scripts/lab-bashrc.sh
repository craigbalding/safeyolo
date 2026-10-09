#!/usr/bin/env bash
# Source this helper before installing or refreshing the safeyolo-lab command.

_prepare_safeyolo_lab_bashrc() {
    local bashrc="$1"
    local marker_start='# >>> safeyolo-lab PATH >>>'
    local marker_end='# <<< safeyolo-lab PATH <<<'
    local contents='' block padded prefix end_prefix end_offset

    if [ -e "$bashrc" ] && [ ! -f "$bashrc" ]; then
        printf 'The Bash startup path is not a regular file: %s\n' "$bashrc" >&2
        return 1
    fi
    if [ -e "$bashrc" ]; then
        # The sentinel retains trailing newlines in operator-owned content.
        contents=$(cat -- "$bashrc" && printf '.') || return 1
        contents=${contents%.}
    fi
    if ! printf '%s\n' "$contents" | awk -v start="$marker_start" -v end="$marker_end" '
        $0 == start { if (opened || closed) invalid = 1; opened++ }
        $0 == end { if (opened != 1 || closed) invalid = 1; closed++ }
        END { exit (invalid || opened != closed) }
    '; then
        printf 'The safeyolo-lab PATH block is incomplete or malformed in %s\n' "$bashrc" >&2
        return 1
    fi

    block=$(cat <<'EOF'
# >>> safeyolo-lab PATH >>>
# Make persistent user commands visible in SafeYolo shells.
if [ -d "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) PATH="$HOME/.local/bin:$PATH" ;;
    esac
    export PATH
fi
case $- in
    *i*)
        if [ -z "${TMUX:-}" ] && [ "${PWD:-}" = "$HOME" ] && [ -x "$HOME/.local/bin/safeyolo-lab" ]; then
            printf 'SafeYolo lab: run safeyolo-lab\n'
        fi
        ;;
esac
# <<< safeyolo-lab PATH <<<
EOF
    )
    # Match whole marker lines, including a marker at either end of the file.
    padded=$'\n'"$contents"$'\n'
    if [[ "$padded" == *$'\n'"$marker_start"$'\n'* ]]; then
        prefix=${padded%%$'\n'"$marker_start"$'\n'*}
        end_prefix=${padded%%$'\n'"$marker_end"$'\n'*}
        end_offset=$((${#end_prefix} + ${#marker_end}))
        _safeyolo_lab_bashrc="${contents:0:${#prefix}}$block${contents:end_offset}"
    else
        _safeyolo_lab_bashrc="$contents"$'\n'"$block"$'\n'
    fi
}
