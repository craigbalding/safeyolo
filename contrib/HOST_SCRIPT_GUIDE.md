# Host scripts

Host scripts are plain shell scripts that run **on the host** (the machine
you're running SafeYolo on -- macOS or Linux), as **you**, before a
SafeYolo agent boots. They're how you install an agent (e.g. Claude
Code, OpenAI Codex, aider), stage auth, and define what the sandbox
should execute.

SafeYolo invokes them via:

```sh
safeyolo agent add <name> <folder> --host-script path/to/my-host-setup.sh
```

For an existing agent, reapply or change the host setup before boot:

```sh
safeyolo agent run <name> --host-script path/to/my-host-setup.sh
```

There is no template system, no DSL, no TOML -- just a shell script that
does what any shell script does. Read it, edit it, run it anywhere else
to confirm what it does.

## Why host-side

A host script runs in your own shell session with your own permissions.
It can read `~/.claude/.credentials.json`, copy it into the agent's
persistent home, and you can see exactly what happened. Keeping the
script host-side means no magic between "I wrote the script" and "this
is what ran."

The sandbox's trust boundary is between the **agent** (what runs
inside) and the host. The script itself is your code -- there's nothing
to gain by running it in the sandbox.

## The contract

Your script is called with these env vars set:

| Variable | Meaning |
|---|---|
| `SAFEYOLO_AGENT_NAME` | The instance name the user passed to `agent add`. |
| `SAFEYOLO_AGENT_HOME` | Absolute path to the persistent host dir that's bind-mounted to `/home/agent` inside the VM. Write files here. |
| `SAFEYOLO_AGENT_FOLDER` | Absolute path to the workspace folder (mounted as `/workspace` in the VM). |

Exit `0` to proceed. Any non-zero exit aborts `agent add` -- SafeYolo
prints your stderr and leaves the agent in a half-configured state so
you can re-run with `--force` after fixing the script.

## What to write

Typical tasks:

1. **Stage auth, settings, user extensions** into `$SAFEYOLO_AGENT_HOME`
   so the agent finds them on first boot.
2. **Write `$SAFEYOLO_AGENT_HOME/.safeyolo-command`** -- an executable
   foreground command file that is exec'd by `safeyolo agent run`. Use
   it to install the agent binary on first run (idempotently) and then
   exec it with the flags you want.

First-party integrations also source `contrib/lib/stage-safeyolo-context.sh`
to install SafeYolo's compact baseline and shared operational skill. Pass
`codex`, `claude`, or `none` to select the agent-specific discovery link:

```sh
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/stage-safeyolo-context.sh"
stage_safeyolo_context "$SAFEYOLO_AGENT_HOME" codex
```

The helper stages the baseline under `~/.safeyolo/` and links the read-only,
per-run `/safeyolo/skills/safeyolo` tree under the agent's skill directory. It
refuses to overwrite a user-owned skill with the same name. Custom standalone
scripts may instead stage their own instructions.

Sketch:

```sh
#!/usr/bin/env bash
set -euo pipefail

: "${SAFEYOLO_AGENT_HOME:?run this via safeyolo agent add/run --host-script}"

# Stage from host (best-effort)
mkdir -p "$SAFEYOLO_AGENT_HOME/.myagent"
[ -f "$HOME/.myagent/credentials.json" ] && \
    cp "$HOME/.myagent/credentials.json" "$SAFEYOLO_AGENT_HOME/.myagent/"

# Foreground command -- installs on first run, then execs the agent
cat > "$SAFEYOLO_AGENT_HOME/.safeyolo-command" <<'EOF'
#!/usr/bin/env bash
set -e
if ! command -v myagent >/dev/null 2>&1; then
    mise use -g node@22 >&2
    mise use -g npm:@example/myagent@latest >&2
fi
exec myagent --auto "$@"
EOF
chmod +x "$SAFEYOLO_AGENT_HOME/.safeyolo-command"
```

### Entrypoint contract

`$SAFEYOLO_AGENT_HOME/.safeyolo-command` must be an **interactive foreground
process**: a coding agent (`exec claude ...`), a shell (`exec bash -l`), or a
TUI that owns stdin/stdout for the session. `safeyolo agent run <name>`
(without `--detach`) attaches a terminal and expects the command to interact
with it.

Don't write `sleep infinity`, `wait`, `tail -f /dev/null`, or another
non-interactive daemon as the command. To keep the sandbox alive in the
background for a later `safeyolo agent shell <name>` connection, use
`safeyolo agent run <name> --detach`; the guest's built-in keep-alive handles
that cleanly, with no `.safeyolo-command` required.

If you press Ctrl-C during the attached Linux session, SafeYolo detaches the
terminal and leaves the sandbox running. Reconnect with `safeyolo agent shell
<name>` or stop it explicitly with `safeyolo agent stop <name>`.

The bundled `@codex-coord` setup is one explicit exception to the interactive
harness shape. Its foreground process is a guest-side supervisor for bounded
non-interactive Codex turns. SafeYolo still owns the sandbox lifetime and the
terminal attachment. The supervisor does not become a host daemon. See the
[supervisor contract](../docs/codex-coord-supervisor.md) for its recovery and
authority rules.

For Alpine rootfs images, do not rely on `mise use -g node@...`: mise may
try to build Node from source against musl. Use Alpine's native packages and
a persistent home prefix instead:

```sh
sudo -n apk add nodejs npm
npm install --global --prefix /home/agent/.local @example/myagent@latest
```

This `sudo` is guest-only. On rootless Linux, SafeYolo's compatibility helper
uses `setpriv` to reach namespace uid 0, which maps to a subordinate host uid;
on hardware microVMs it delegates to ordinary distro sudo. Host scripts should
use `sudo -n` for noninteractive guest package setup and must not instruct the
operator to run `safeyolo agent shell --root` for routine installs.

## Idempotency

Host scripts run on `safeyolo agent add` and whenever an existing agent is
started with `safeyolo agent run <name> --host-script PATH`. Re-running
`agent add --force` also reruns the script. Make yours re-runnable: check before
creating, overwrite only what you own, and don't assume a blank slate.

## Using an agent to write host scripts

Writing a host script for a new tool is a good use of Claude Code
running inside an existing safeyolo agent. Share this guide and the
existing examples (`contrib/claude-host-setup.sh`,
`contrib/codex-host-setup.sh`) with it. The agent won't see the host's
filesystem -- that's the sandbox's job -- but it doesn't need to. It
writes a script based on this contract + knowledge of where the tool
you're adding typically stores its config, then you read it and run
it.

Ask the agent things like:

> Write a host script for `aider` that stages host auth from
> `~/.aider.conf.yml` if it exists, installs aider via mise on first
> run, and execs it in `--yes` mode.

Review the resulting script, save it to `contrib/<tool>-host-setup.sh`,
and use it via `safeyolo agent add`.

## Security note

The script runs with your host permissions. That's fine when the
script is yours or from a source you trust. Don't run host scripts
from strangers without reading them -- same rule as any shell script.
