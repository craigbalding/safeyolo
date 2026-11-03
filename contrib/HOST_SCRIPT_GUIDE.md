# Host scripts

Host scripts are shell scripts that run on the macOS or Linux host before a
SafeYolo agent boots. SafeYolo runs them with the operator's user permissions.
A host script can install an agent harness, copy authentication or settings,
and define the command that the sandbox executes.

For the host path, first complete the [installation and guest prerequisites](../docs/installation.md#install-and-start)
in the instance you installed. The commands below use `$HOME/.safeyolo`;
replace that root if your installation uses another path. Run as your ordinary
host account from the trusted SafeYolo checkout. In these examples, `~/code` is an existing
workspace that you own. Replace `/absolute/path/to/my-host-setup.sh` with your
executable script outside all agent-writable shares. Agent creation runs setup
without starting the sandbox:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent create work --workspace ~/code --host-script /absolute/path/to/my-host-setup.sh
```

For an existing agent, stop it before reapplying or changing host setup.
Select an executable host script outside every agent-writable share:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent stop work
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent configure work --host-script /absolute/path/to/my-host-setup.sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent start work
```

SafeYolo does not interpret a template, domain-specific language (DSL), or
TOML document. It executes the selected shell script. Read the script before
you run it.

## Bundled setups

Select an executable setup file in the installed instance's `assets/contrib/`
directory with `agent create --host-script` or, for an existing stopped agent,
`agent configure --host-script`. A trusted checkout's `contrib/` directory can
also supply these scripts. The CLI does not use the retired Python
CLI's bundled aliases.

Codex, Pi and Claude setup use the installed Coord host executable and
its matching Linux guest artifact. Agent creation and configuration select
both inputs automatically, including on macOS. Direct script invocation uses
`SAFEYOLO_COORD_EXECUTABLE` and `SAFEYOLO_COORD_GUEST_BINARY`, or finds
`safeyolo-coord` on `PATH` from the instance's `bin/` directory. The default
guest input is the host executable's sibling `../assets/guest/safeyolo-coord`.
Missing or mismatched artifacts abort setup with a diagnostic. Setup requires
no Python interpreter.

| File under `assets/contrib/` | Setup |
| --- | --- |
| `claude-host-setup.sh` | Copies Claude Code authentication and selected user extensions into `/home/agent`, registers the coord MCP adapter, installs SafeYolo context, and launches Claude Code. |
| `codex-host-setup.sh` | Stages SafeYolo-owned Codex settings and the coord MCP adapter, without importing host credentials or arbitrary `~/.codex` state. Launches Codex with its inner sandbox disabled (`-s danger-full-access -a never`); SafeYolo remains the outer boundary. |
| `codex-coord-host-setup.sh` | Uses the Codex setup with an explicitly adopted agent-local login and supervises bounded non-interactive turns. See the [supervisor contract](../docs/codex-coord-supervisor.md). |
| `pi-host-setup.sh` | Keeps Pi authentication and state in the agent's own home and stages SafeYolo context. See the Pi section below. |
| `pi-coord-host-setup.sh` | Adds the approved Factory role and Coord extension to the Pi setup. |
| `mise-shell-host-setup.sh` | Opens an interactive shell with mise ready for `mise use -g ...`. |

Without `--host-script`, the sandbox starts an interactive bash shell in its
persistent home. Any executable host script can be selected by its path.

Codex setup installs guest-owned shell rules in `.codex/rules/safeyolo-guest.rules`
so its command heuristics allow ordinary shell cleanup inside SafeYolo. Host rules
are not imported. Organization-managed restrictions and Codex model modes that
ignore local allow rules can still reject commands.

Claude setup selects the host identity/onboarding fields from `~/.claude.json`
and preserves agent-side MCP servers and unrelated configuration. It merges
host settings over retained agent settings, including permission keys, then
sets workspace onboarding/trust and `permissions.defaultMode=bypassPermissions`.
Reapply preserves unselected settings and projects. Invalid agent configuration
or non-object trust/MCP fields stop setup before those documents change.
Non-object permission fields also stop setup unless valid host preferences
replace them.
Malformed settings JSON recovers to defaults; missing or invalid host identity
metadata leaves the retained agent identity intact. Claude credentials still use
the explicit sharing path described below.

With `SAFEYOLO_CLAUDE_COPY_HOST_STATE=0`, the shipped Claude script prepares guest
defaults and SafeYolo context without reading host Claude state. Existing agent
authentication stays in place. With copying enabled, the host helper replaces
credential files through private temporary files with mode `0600`. Extension
files use atomic replacement too; a destination directory link stops copying.
Host skills named `safeyolo`, `safeyolo-lab-controller`, or `safeyolo-factory`
are skipped because SafeYolo stages those shared skills itself. Other host
skills keep the existing copy behavior.

### First Codex login

Use the installed product and its matching Linux guest Coord assets.
For ordinary first use, `safeyolo agent launch . --harness codex` owns setup,
login selection and client startup. Current source offers a trusted host choice
to authorize the selected subscription login for that agent before startup.
It can copy a host login into an empty agent login, with explicit consent.
The public installer invokes the same operation with `--launch --harness codex`;
no additional import command is required. See the
[installation reference](../docs/installation.md#public-bootstrap-availability) for release
limits and the choices. Enter keeps guest login and normal approvals.
Copying and `codex-state adopt` record client state; neither grants proxy
authority. Existing credential and network rules remain applicable.

For explicit setup or coordinated-agent preparation, a fresh agent can instead
log in inside its persistent home. After its first run installs Codex, leave
it running and open a guest shell from a second host terminal. Replace `work`
with the agent name:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent shell work
```

Inside the guest, log in and record that this login belongs to this agent:

```sh
codex login --device-auth
/home/agent/.safeyolo/safeyolo-coord codex-state adopt
```

Then return to the Codex terminal. Repeat the login and adoption commands after
an explicit authentication reset. The coordinated setup requires the same agent
to complete this normal Codex login before selecting `codex-coord-host-setup.sh`.

Codex routing discovery can require credential approval during startup. SafeYolo
holds the routing `GET /backend-api/wham/accounts/check` for up to 30 seconds
while its credential approval is pending. Use the trusted host controls to inspect
and approve or reject the request. Once approval is active, SafeYolo returns a
temporary redirect to the same URL. If the run or policy changes during the wait,
SafeYolo also redirects the GET so the current checks decide it. Codex follows
the redirect without restarting the client. The redirect does not grant access
or send the original request upstream. Current checks can still refuse the new
GET. Rejection or timeout retains the ordinary approval response. Codex's own
HTTP deadline can expire earlier. Other requests keep their existing approval
behavior.

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
| `SAFEYOLO_AGENT_NAME` | The agent name selected by `agent create` or `agent configure`. |
| `SAFEYOLO_AGENT_HOME` | Absolute path to the persistent host directory mounted at `/home/agent` in the sandbox. Write agent-readable files here. |
| `SAFEYOLO_AGENT_FOLDER` | Absolute path to the workspace directory mounted at `/workspace` in the sandbox. |

Exit with status `0` to proceed. Any nonzero status aborts creation or
configuration before the saved policy changes. The script's output remains
visible, and files it wrote into the agent home can remain. After correcting
the script, repeat `agent create` for a new agent or `agent configure
--host-script` for an existing stopped agent.

## What to write

SafeYolo separates its compact, always-on [sandbox baseline](../docs/AGENTS.md)
from detailed operational workflows in the [safeyolo skill](../cli/src/safeyolo/agent_context/skills/safeyolo/SKILL.md).
The baseline covers environment invariants and security boundaries; the skill
covers Agent API, flow, gateway, collaboration, and troubleshooting operations.
Bundled scripts stage the baseline under `~/.safeyolo/`. Claude receives it through
`--append-system-prompt`; Codex receives it as `developer_instructions`.
Managed skills are refreshed in the read-only `/safeyolo` share on each run and
linked into the skill directories without replacing user instructions.

Typical tasks:

1. Copy authentication, settings, or user extensions into
   `$SAFEYOLO_AGENT_HOME` only when the agent must be able to read them.
2. Write an executable `$SAFEYOLO_AGENT_HOME/.safeyolo-command` foreground
   command. `safeyolo agent start` executes this file. The command can install the
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
its native `~/.pi/agent/skills` path. Claude and Codex also get
`/safeyolo/skills/safeyolo-lab-controller`,
`/safeyolo/skills/safeyolo-factory`, and the `safeyolo-lab` guest command. The
Codex and Pi setups both stage `repo-map` under `~/.local/bin`; their launchers
put that directory on the harness `PATH`. The helper refuses to overwrite a
user-owned skill or command with a managed name. Custom standalone scripts may
instead stage their own instructions.

In an owned Claude guest with valid authentication, start a Lab from its
pre-lab shell with `safeyolo-lab --harness claude --objective "OBJECTIVE"`.
The shared runner supplies the baseline, startup instructions and objective
through a private temporary file. The staged Claude command passes that file
with `--append-system-prompt-file`. The native host `safeyolo lab` entry
continues to provision Codex Labs. See the Lab Controller skill's
[bootstrap guide](../cli/src/safeyolo/agent_context/skills/safeyolo-lab-controller/references/bootstrap.md)
for reconnect, recovery, evidence capture and teardown.

`repo-map --query "<task>"` returns likely local implementation, tests, and
documentation. An exact Python symbol, such as `repo-map --query api.send`,
returns its definition with defaults, annotations, and docstring, plus one
lexical example use when found. Large definitions show a labelled 60-line
preview with the full source range; the example is not a semantic binding claim.
The tool parses Python definitions and maps lexical symbols in other
languages. Directory views show up to four public symbols per file; select a
file for private symbols and class methods. The tool reads the current working
tree and caches content-derived symbols. Internal repository symlinks remain
usable; off-tree, broken and looping links are omitted.
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

: "${SAFEYOLO_AGENT_HOME:?run this via agent create/configure --host-script}"

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

`$SAFEYOLO_AGENT_HOME/.safeyolo-command` is the guest entrypoint: an interactive
coding agent, shell, or terminal application. `agent start NAME --foreground`
uses the caller's terminal. Ordinary `agent start NAME` starts it persistently in a
host tmux window unless another launcher or manager is explicitly selected.
Use `agent attach NAME` to reconnect, or `agent shell NAME` for an independent
guest shell. For boot-only work use `agent start NAME --sandbox-only`; it invokes
no coding agent, host launcher, or launch hooks.

The bundled `codex-coord-host-setup.sh` and `pi-coord-host-setup.sh` setups
explicitly select the SafeYolo runtime supervisor. Guest PID 1 owns that
supervisor, which runs the Coord supervisor and its bounded harness turns. Existing recovery and
intentional-stop handling remain unchanged. The setups retain a separate
`.safeyolo-interactive-command` for Command Centre's **Debug Agent** action;
it does not replace the configured managed mode or its checkpoints.

Host setup scripts install the guest environment. Runtime host launchers are
a separate choice and must live outside guest-writable shares. See
[agent launchers](../docs/agent-launchers.md) for shared defaults, tmux presets,
custom hooks, attach, and remote terminal behavior; see the
[supervisor contract](../docs/codex-coord-supervisor.md) for factory recovery.

### Claude and Codex installation and updates

The bundled Claude and Codex launchers use native upstream releases in the
agent's persistent home. Claude uses mise's Aqua backend. This path does not
acquire Node.js or npm. It retains other installed tools and their mise
configuration. Claude keeps its staged authentication and extensions; Codex
keeps its agent-local `.codex` configuration and authentication ownership.
Ordinary Codex, coordinated Codex, Lab and Demo use the same launcher payload.

Mise selects a release at least `SAFEYOLO_MIN_RELEASE_AGE` old (default `24h`)
when it supports `minimum_release_age`. The launcher warns if it cannot apply
that delay. It resolves the selected version before installation and checks
the executable before launch. The installer verifies the GitHub release asset
digest before extraction.
Claude releases also publish `SHASUMS256.txt`. These checks trust upstream
release metadata over HTTPS; they do not independently authenticate the
publisher. Codex uses the complete `codex-package` archive, including its
search executable, code-mode host and adjacent resources. Fresh Codex defaults
use mise's GitHub backend to select the smaller upstream `.tar.zst` archive.
A healthy existing Aqua selection is reused. Explicit native specs keep their
selected backend and archive. Reentry repairs
missing required executables and reuses a healthy selected version.

During public installation with `--launch --harness codex`, SafeYolo can fetch,
verify and extract the complete Linux client while acquiring the host and guest.
Apple Silicon hosts acquire the Linux ARM64 package. After setup consent, launch
moves this payload into the new agent home. A healthy installed selection keeps
precedence. With the default native spec and `24h` age setting, the guest reuses
the host-selected version after checking its platform, version, required
executables and resources. It runs the complete payload in place and records it
with `mise link`. This avoids another version lookup, `mise use`, client download
and extraction on first launch. Unless `MISE_INSTALLS_DIR` is set, the guest also
skips installed-version queries for absent native installation namespaces.
The guest probes mise's release-age support only when a repair or update notice
needs a remote lookup; the imported default already passed the host's 24-hour
selection policy.
Host mise is not required.
Prefetch applies to the fresh default with the default release-age setting.
It checks the first 30 upstream releases and acquires the newest stable version
at least 24 hours old with a complete package and digest for the guest platform.
This can select an older eligible release when the latest release is too young.
Pins, custom age settings and unavailable or invalid prefetch use the ordinary
guest resolver and installer. After resolving a custom age setting, the guest
can still reuse the payload if its version matches. Reentry reuses a healthy
payload and checks for newer supported versions without automatically upgrading.
The harness and its child commands receive the payload on `PATH`. An explicit
mise installation takes precedence on the next launch.
Existing agent state, login, approval and interactive retry controls still apply.

To pin a native version, set `SAFEYOLO_CLAUDE_NATIVE_SPEC` to
`aqua:anthropics/claude-code@VERSION`, or `SAFEYOLO_CODEX_NATIVE_SPEC` to
`aqua:openai/codex@VERSION`, in the guest launch environment. Replace `VERSION`
with an upstream release version. The defaults select `latest`. Update notices
show the exact `mise use -g` command to run inside the guest; launch does not
upgrade a healthy selection. Claude's background updater is disabled by default
on this path to preserve mise's selection. An explicit `DISABLE_AUTOUPDATER`
value is retained.
Codex native pins need the complete `codex-package` layout. Older Claude pins
that Aqua downloads directly from the vendor bucket can lack the GitHub asset
digest check. Existing npm pins remain available through the legacy routes.

An explicit `SAFEYOLO_CLAUDE_NPM_SPEC` or `SAFEYOLO_CLAUDE_NPM_PACKAGE` selects
Claude's legacy npm route instead. The corresponding `SAFEYOLO_CODEX_NPM_SPEC`
or `SAFEYOLO_CODEX_NPM_PACKAGE` selects Codex's legacy npm route. These selections
take precedence over native specs. Their Node/npm dependency remains separate
from native startup.

For npm tools in Alpine rootfs images, do not rely on `mise use -g node@...`: mise may
try to build Node from source against musl. Use Alpine's native packages and
a persistent home prefix instead:

```sh
sudo -n apk add nodejs npm
npm install --global --prefix /home/agent/.local @example/myagent@latest
```

The legacy Codex npm route uses apk-provided Node.js and installs Codex through
mise on Alpine, even if retained mise configuration selects another Node version.
It applies `SAFEYOLO_MIN_RELEASE_AGE` (default `24h`) when mise
supports `minimum_release_age`. The launcher reports when mise lacks that
setting. `SAFEYOLO_CODEX_NPM_PACKAGE` selects the Alpine package and version;
`SAFEYOLO_CODEX_NPM_SPEC` selects the non-Alpine mise spec. If only one is set,
it also supplies the other platform's selection. A healthy Codex installation
is reused. A missing or broken installation is repaired at the selected version.

This `sudo` is guest-only. On rootless Linux, SafeYolo's compatibility helper
uses `setpriv` to reach namespace uid 0, which maps to a subordinate host uid;
on hardware microVMs it delegates to ordinary distro sudo. Host scripts should
use `sudo -n` for noninteractive guest package setup and must not instruct the
operator to run `safeyolo agent shell --root` for routine installs.

## Idempotency

Host scripts run on `agent create --host-script` and when an existing
stopped agent is configured with `agent configure --host-script`.
Make yours re-runnable: check before
creating, overwrite only what you own, and don't assume a blank slate.

### Pi authentication and trust

The bundled `pi-host-setup.sh` keeps Pi authentication, settings, models,
sessions, extensions, and prompts in the agent-local `~/.pi/agent/` directory.
It does not inspect or copy host `~/.pi` state. From an interactive Pi session, use
`/login` and `/logout` for the agent's own provider session; never copy a
credential from another agent or from the host. The launcher starts Pi with
`--approve` and appends the SafeYolo baseline. Arguments supplied later by the
user are forwarded unchanged and can alter Pi's trust behavior.

For a factory role, `pi-coord-host-setup.sh` adds the approved role contract
and the small Coord `send` and `read_room` extension, then hands Pi JSON
turns to the common factory supervisor. The role's Pi session, Coord cursor, and pending work use the same
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
and select its path with `agent create --host-script` or, for an existing
stopped agent, `agent configure --host-script`.

## Security note

The script runs with your host permissions. That's fine when the
script is yours or from a source you trust. Don't run host scripts
from strangers without reading them -- same rule as any shell script.
