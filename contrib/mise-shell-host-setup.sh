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

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=lib/stage-safeyolo-context.sh
. "$SCRIPT_DIR/lib/stage-safeyolo-context.sh"

# Stage the vendor-neutral baseline. A BYO agent can link the per-run skill at
# /safeyolo/skills/safeyolo into its own discovery directory.
stage_safeyolo_context "$AGENT_HOME" none

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

Native guest packages:
  sudo -n apt-get install -y PACKAGE   # Debian/Kali
  sudo -n apk add PACKAGE              # Alpine

List available:
  mise ls-remote go

Project mise config (explicit opt-in):
  mise-project install
  mise-project exec -- COMMAND

Docs: https://mise.jdx.dev
SafeYolo agent guide: ~/.safeyolo/AGENTS.md
SafeYolo skill:       /safeyolo/skills/safeyolo/
=========================================================
EOF

# Foreground command -- shows the MOTD once on first login of a session, then
# drops to an interactive login shell. mise's profile.d is sourced
# automatically by bash -l, so global tools are on PATH from the first prompt
# without loading project config. `mise-project` is the deliberate opt-in.
cat > "$AGENT_HOME/.safeyolo-command" <<'EOF'
#!/usr/bin/env bash
if [ -f /home/agent/.safeyolo-motd ]; then
    cat /home/agent/.safeyolo-motd
fi
exec bash -l "$@"
EOF
chmod +x "$AGENT_HOME/.safeyolo-command"

echo "mise-shell-host-setup: $SAFEYOLO_AGENT_NAME ready at $AGENT_HOME"
