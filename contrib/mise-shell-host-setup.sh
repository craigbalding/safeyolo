#!/usr/bin/env bash
# SafeYolo host setup script -- mise-powered shell for bring-your-own-agent.
#
# Runs on the host (macOS or Linux), as you, when `safeyolo agent add
# <name> <folder> --host-script contrib/mise-shell-host-setup.sh` is
# invoked. Sets the agent up as an interactive shell where you can
# install whatever tools you want via mise.
#
# mise itself is already in the base rootfs. MISE_DATA_DIR is
# $HOME/.mise, which is on the persistent home bind-mount -- so
# anything you `mise use -g` sticks across agent restarts.
#
# Example session inside the agent:
#   mise use -g go@latest
#   mise use -g python@3.12
#   mise use -g npm:aider-chat@latest
#   go version   # works
#
# See contrib/HOST_SCRIPT_GUIDE.md for the contract.

set -euo pipefail

: "${SAFEYOLO_AGENT_NAME:?must be run via 'safeyolo agent add --host-script'}"
: "${SAFEYOLO_AGENT_HOME:?must be run via 'safeyolo agent add --host-script'}"

AGENT_HOME="$SAFEYOLO_AGENT_HOME"
mkdir -p "$AGENT_HOME"

# Stage the SafeYolo agent guide at a conventional path for users and
# any BYO agent to reference. The MOTD below points at it.
GUIDE_SRC="$(cd "$(dirname "$0")/.." && pwd)/docs/AGENTS.md"
mkdir -p "$AGENT_HOME/.safeyolo"
if [ -f "$GUIDE_SRC" ]; then
    cp "$GUIDE_SRC" "$AGENT_HOME/.safeyolo/AGENTS.md"
fi

# Welcome MOTD -- shown once when the shell starts. Lists the tools
# mise exposes and points the user at the cheatsheet.
cat > "$AGENT_HOME/.safeyolo-motd" <<'EOF'
=========================================================
SafeYolo sandbox -- mise shell.

Network egress goes through the SafeYolo proxy. Filesystem
writes under /home/agent and /workspace persist across runs.

Install tools:
  mise use -g go@latest
  mise use -g python@3.12
  mise use -g rust@latest
  mise use -g npm:<package>       # node-backed npm package

List available:
  mise ls-remote go

Docs: https://mise.jdx.dev
SafeYolo agent guide: ~/.safeyolo/AGENTS.md
=========================================================
EOF

# Foreground command -- shows the MOTD once on first login of a session, then
# drops to an interactive login shell. mise's profile.d is sourced
# automatically by bash -l, so `mise`, installed runtimes, and shims
# are all on PATH from the first prompt.
cat > "$AGENT_HOME/.safeyolo-command" <<'EOF'
#!/usr/bin/env bash
if [ -f /home/agent/.safeyolo-motd ]; then
    cat /home/agent/.safeyolo-motd
fi
exec bash -l "$@"
EOF
chmod +x "$AGENT_HOME/.safeyolo-command"

echo "mise-shell-host-setup: $SAFEYOLO_AGENT_NAME ready at $AGENT_HOME"
