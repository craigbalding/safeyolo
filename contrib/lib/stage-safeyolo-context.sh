#!/usr/bin/env bash
# Shared staging for first-party host setup scripts. Source this file, then
# call: stage_safeyolo_context "$SAFEYOLO_AGENT_HOME" codex|claude|none

stage_safeyolo_context() {
    local agent_home="$1"
    local consumer="${2:-none}"
    local helper_dir repo_root guide_src managed_root
    local link_dir link_path link_target legacy_link_target current_target

    helper_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    repo_root="$(cd "$helper_dir/../.." && pwd)"
    guide_src="$repo_root/docs/AGENTS.md"
    managed_root="$agent_home/.safeyolo"
    link_target="/safeyolo/skills/safeyolo"
    legacy_link_target="../../.safeyolo/skills/safeyolo"

    if [ ! -f "$guide_src" ]; then
        echo "SafeYolo agent context sources are missing from $repo_root" >&2
        return 1
    fi

    case "$consumer" in
        codex) link_dir="$agent_home/.agents/skills" ;;
        claude) link_dir="$agent_home/.claude/skills" ;;
        none) link_dir="" ;;
        *)
            echo "Unknown SafeYolo context consumer: $consumer" >&2
            return 1
            ;;
    esac

    # Never replace user-authored skill content or a symlink to another source.
    if [ -n "$link_dir" ]; then
        link_path="$link_dir/safeyolo"
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
    fi

    mkdir -p "$managed_root"
    cp "$guide_src" "$managed_root/AGENTS.md"

    if [ -n "$link_dir" ]; then
        mkdir -p "$link_dir"
        if [ -L "$link_path" ] && [ "$(readlink "$link_path")" = "$legacy_link_target" ]; then
            rm -- "$link_path"
        fi
        if [ ! -e "$link_path" ] && [ ! -L "$link_path" ]; then
            ln -s "$link_target" "$link_path"
        fi
    fi
}
