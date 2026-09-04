#!/usr/bin/env bash
# Shared staging for first-party host setup scripts. Source this file, then
# call: stage_safeyolo_context "$SAFEYOLO_AGENT_HOME" codex|claude|none

_stage_safeyolo_codex_lab_entrypoint() {
    local agent_home="$1"
    local command_dir="$agent_home/.local/bin"
    local command_path="$command_dir/safeyolo-lab"
    local command_target="/safeyolo/skills/safeyolo-lab-controller/scripts/safeyolo-lab"
    local bashrc="$agent_home/.bashrc"
    local marker_start='# >>> safeyolo-lab PATH >>>'
    local marker_end='# <<< safeyolo-lab PATH <<<'
    local current_target

    if [ -e "$bashrc" ] && [ ! -f "$bashrc" ]; then
        echo "Refusing to replace non-regular Bash startup path $bashrc" >&2
        return 1
    fi
    if grep -Fqx "$marker_start" "$bashrc" 2>/dev/null; then
        if ! grep -Fqx "$marker_end" "$bashrc"; then
            echo "The safeyolo-lab PATH block is incomplete in $bashrc" >&2
            return 1
        fi
    elif grep -Fqx "$marker_end" "$bashrc" 2>/dev/null; then
        echo "The safeyolo-lab PATH block is incomplete in $bashrc" >&2
        return 1
    fi

    if [ -L "$command_path" ]; then
        current_target="$(readlink "$command_path")"
        if [ "$current_target" != "$command_target" ]; then
            echo "Refusing to replace existing $command_path -> $current_target" >&2
            return 1
        fi
    elif [ -e "$command_path" ]; then
        echo "Refusing to replace existing command at $command_path" >&2
        return 1
    fi

    mkdir -p "$command_dir"
    if [ ! -L "$command_path" ]; then
        ln -s "$command_target" "$command_path"
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
    fi
}

stage_safeyolo_context() {
    local agent_home="$1"
    local consumer="${2:-none}"
    local helper_dir repo_root guide_src managed_root
    local link_dir skill_names skill_name link_path link_target
    local legacy_link_target current_target

    helper_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    repo_root="$(cd "$helper_dir/../.." && pwd)"
    guide_src="$repo_root/docs/AGENTS.md"
    managed_root="$agent_home/.safeyolo"
    if [ ! -f "$guide_src" ]; then
        echo "SafeYolo agent context sources are missing from $repo_root" >&2
        return 1
    fi

    case "$consumer" in
        codex)
            link_dir="$agent_home/.agents/skills"
            skill_names="safeyolo safeyolo-lab-controller safeyolo-factory"
            ;;
        claude)
            link_dir="$agent_home/.claude/skills"
            skill_names="safeyolo"
            ;;
        none)
            link_dir=""
            skill_names=""
            ;;
        *)
            echo "Unknown SafeYolo context consumer: $consumer" >&2
            return 1
            ;;
    esac

    # Preflight every managed name before changing any skill link.
    if [ -n "$link_dir" ]; then
        for skill_name in $skill_names; do
            link_path="$link_dir/$skill_name"
            link_target="/safeyolo/skills/$skill_name"
            legacy_link_target="../../.safeyolo/skills/$skill_name"
            if [ -L "$link_path" ]; then
                current_target="$(readlink "$link_path")"
                if [ "$current_target" != "$link_target" ] && \
                   [ "$current_target" != "$legacy_link_target" ]; then
                    echo "Refusing to replace existing $link_path -> $current_target" >&2
                    return 1
                fi
            elif [ -e "$link_path" ]; then
                echo "Refusing to replace existing user skill at $link_path" >&2
                return 1
            fi
        done
    fi

    mkdir -p "$managed_root"
    cp "$guide_src" "$managed_root/AGENTS.md"

    if [ -n "$link_dir" ]; then
        mkdir -p "$link_dir"
        for skill_name in $skill_names; do
            link_path="$link_dir/$skill_name"
            link_target="/safeyolo/skills/$skill_name"
            legacy_link_target="../../.safeyolo/skills/$skill_name"
            if [ -L "$link_path" ] && \
               [ "$(readlink "$link_path")" = "$legacy_link_target" ]; then
                rm -- "$link_path"
            fi
            if [ ! -e "$link_path" ] && [ ! -L "$link_path" ]; then
                ln -s "$link_target" "$link_path"
            fi
        done
    fi

    if [ "$consumer" = "codex" ]; then
        _stage_safeyolo_codex_lab_entrypoint "$agent_home"
    fi

    # Install slash commands shipped by the safeyolo skill. Skills live under
    # $link_dir/safeyolo but Claude Code auto-discovers slash commands at
    # $agent_home/.claude/commands/. Skip cleanly on codex/none.
    if [ "$consumer" = "claude" ]; then
        local commands_src="/safeyolo/skills/safeyolo/commands"
        local commands_dst="$agent_home/.claude/commands"
        if [ -d "$commands_src" ]; then
            mkdir -p "$commands_dst"
            local cmd_file cmd_name
            for cmd_file in "$commands_src"/*.md; do
                [ -f "$cmd_file" ] || continue
                cmd_name="$(basename "$cmd_file")"
                # Do not clobber a user-authored command with the same name;
                # safeyolo-shipped commands are prefixed `safeyolo-` to keep
                # the namespace collision surface small.
                if [ ! -e "$commands_dst/$cmd_name" ]; then
                    cp "$cmd_file" "$commands_dst/$cmd_name"
                fi
            done
        fi
    fi
}
