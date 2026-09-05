# Host scripts

Host scripts are shell scripts that run on the macOS or Linux host before a
SafeYolo agent boots. SafeYolo runs them with the operator's user permissions.
A host script can install an agent harness, copy authentication or settings,
and define the command that the sandbox executes.

SafeYolo invokes them via:

```sh
safeyolo agent add <name> <folder> --host-script path/to/my-host-setup.sh
```

For an existing agent, reapply or change the host setup before boot:

```sh
safeyolo agent run <name> --host-script path/to/my-host-setup.sh
```

SafeYolo does not interpret a template, domain-specific language (DSL), or
TOML document. It executes the selected shell script. Read the script before
you run it.

## Why host-side

A host script can read any file that the operator can read. For example, it can
copy `~/.claude/.credentials.json` into the agent's persistent home. The
persistent home is mounted at `/home/agent`; the agent process can read that
copied credential. This is an explicit credential-sharing path and is not
covered by the service gateway's vault-isolation guarantee.

The sandbox boundary separates the agent process from the host. A host script
runs outside that boundary and must be trusted as host code.

## The contract

Your script is called with these env vars set:

| Variable | Meaning |
|---|---|
| `SAFEYOLO_AGENT_NAME` | The instance name the user passed to `agent add`. |
| `SAFEYOLO_AGENT_HOME` | Absolute path to the persistent host directory mounted at `/home/agent` in the sandbox. Write agent-readable files here. |
| `SAFEYOLO_AGENT_FOLDER` | Absolute path to the workspace directory mounted at `/workspace` in the sandbox. |

Exit with status `0` to proceed. Any nonzero status aborts `agent add`.
SafeYolo prints the script's standard error and leaves the partial agent state
in place. After you correct the script, run `agent add --force` to retry.

## What to write

Typical tasks:

1. Copy authentication, settings, or user extensions into
   `$SAFEYOLO_AGENT_HOME` only when the agent must be able to read them.
2. Write an executable `$SAFEYOLO_AGENT_HOME/.safeyolo-command` foreground
   command. `safeyolo agent run` executes this file. The command can install the
   agent binary idempotently on first run and then replace itself with the
   selected agent process.

First-party integrations also source `contrib/lib/stage-safeyolo-context.sh`
to install SafeYolo's compact baseline and managed skills. Pass `codex`,
`claude`, `pi`, or `none` to select the agent-specific discovery links:

```sh
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/stage-safeyolo-context.sh"
stage_safeyolo_context "$SAFEYOLO_AGENT_HOME" codex
```

The helper stages the baseline under `~/.safeyolo/` and links applicable
read-only, per-run skill trees under the agent's skill directory. Both Claude
and Codex get `/safeyolo/skills/safeyolo`. Pi gets the same shared skill under
its native `~/.pi/agent/skills` path. Codex also gets
`/safeyolo/skills/safeyolo-lab-controller`,
`/safeyolo/skills/safeyolo-factory`, and the `safeyolo-lab` guest command. The
Codex and Pi setups both stage `repo-map` under `~/.local/bin`; their launchers
put that directory on the harness `PATH`. The helper refuses to overwrite a
user-owned skill or command with a managed name. Custom standalone scripts may
instead stage their own instructions.

`repo-map --query "<task>"` returns likely local implementation, tests, and
documentation. An exact Python symbol, such as `repo-map --query api.send`,
returns its definition with defaults, annotations, and docstring, plus one
lexical example use when found. Large definitions show a labelled 60-line
preview with the full source range; the example is not a semantic binding claim.
The tool reads the current working tree and caches content-derived symbols.
Run it in the checkout being worked on, after selecting the task's revision.

The helper also stages repository guidance beside the command. A checkout's
`repo-map.toml` takes precedence. If that file is absent, installed guidance
applies only when its `project` matches the checkout's `pyproject.toml` project
name. This is hint selection, not repository authorization. Query output names
the guidance file used; unrelated repositories do not receive SafeYolo hints.

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
terminal user interface (TUI) that owns stdin/stdout for the session. `safeyolo agent run <name>`
(without `--detach`) attaches a terminal and expects the command to interact
with it.

Don't write `sleep infinity`, `wait`, `tail -f /dev/null`, or another
non-interactive daemon as the command. To keep the sandbox alive in the
background for a later `safeyolo agent shell <name>` connection, use
`safeyolo agent run <name> --detach` without a `.safeyolo-command`.

When a detached run has a `.safeyolo-command`, SafeYolo publishes that command
to a runtime supervisor owned by guest PID 1. The owner survives loss of the
CLI transport and re-owns the supervisor if it is killed; it restarts every
unexpected exit, including a clean exit, with bounded backoff. A stable run
resets the crash-loop window. Exit classification, byte-counted/truncated
stderr, and a sanitized tail are retained without allowing unbounded output.
It does not restart the sandbox or consume Coord work. Inspect it with
`safeyolo agent diag <name>` or `safeyolo status`; `safeyolo agent stop <name>`
records stop intent before stopping the sandbox, so an intentional operator
stop fences recovery.

If you press Ctrl-C during the attached Linux session, SafeYolo detaches the
terminal and leaves the sandbox running. Reconnect with `safeyolo agent shell
<name>` or stop it explicitly with `safeyolo agent stop <name>`.

The bundled `@codex-coord` and `@pi-coord` setups are explicit exceptions to
the interactive harness shape. Their foreground process is the same guest-side
supervisor for bounded non-interactive harness turns. SafeYolo still owns the
sandbox lifetime and terminal attachment. The supervisor does not become a
host daemon. See the
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

### Pi authentication and trust

The bundled `@pi` setup keeps Pi authentication, settings, models, sessions,
extensions, and prompts in the agent-local `~/.pi/agent/` directory. It does
not inspect or copy host `~/.pi` state. From an interactive Pi session, use
`/login` and `/logout` for the agent's own provider session; never copy a
credential from another agent or from the host. The launcher starts Pi with
`--approve` and appends the SafeYolo baseline. Arguments supplied later by the
user are forwarded unchanged and can alter Pi's trust behavior.

For a factory role, `@pi-coord` adds the approved role contract and the small
native Coord `send` and `read_room` extension, then hands Pi JSON turns to the common factory
supervisor. The role's Pi session, Coord cursor, and pending work use the same
checkpoint and recovery rules as a Codex role.
On Alpine, support is conditional on the image's native `nodejs` package
meeting Node `>=22.19.0`; the setup does not use `nodejs-current`, mix
repositories, or build Node from source.

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
