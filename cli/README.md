# SafeYolo CLI

Command-line interface for managing the SafeYolo host proxy and agent
sandboxes.

## Installation

Follow the [main quickstart](../README.md#1-install-on-your-host) to install a
published host package with uv. The package includes the CLI, native proxy,
and macOS helper, without Cargo or a local compiler. Guest and host runtime
setup follows in [bootstrap and individual phases](#bootstrap-and-individual-phases).

For source installation, the commands below run on the host, as your usual user, from the
SafeYolo checkout root.

`./install.sh` builds the Rust proxy with Cargo, then installs the CLI and
that executable through uv, normally at `~/.local/bin/safeyolo`. Install and
select Rust 1.94.0, as recorded in
[`proxy/rust-toolchain.toml`](../proxy/rust-toolchain.toml), before running the
installer. Both `cargo` and uv's tool directory must be on `PATH`. The
installer reads the project's Python requirement, currently `>=3.12,<3.14`,
and asks uv to select or acquire a matching interpreter. A newer host default
does not change that requirement.

For source installs on macOS, you need Command Line Tools, Lima for building
guest images, and tmux for the host proxy session. Lima can be installed with
`brew install lima`, `sudo port install lima`, or `mise use -g lima`; install
tmux through your package manager as well.

### Bootstrap and individual phases

Run setup on the host, as your usual user. Guest builds need a source checkout,
including when the CLI was installed from a host package. If you do not already
have a checkout, run these commands from the directory where you want to keep it:

```sh
git clone https://github.com/craigbalding/safeyolo.git
cd safeyolo
```

Run the following commands from that checkout root. When running the installed
CLI elsewhere, pass the checkout path with `--source-checkout` to
`safeyolo bootstrap` or `safeyolo build`.

`safeyolo bootstrap` initializes configuration under `~/.safeyolo/` and builds
missing guest artifacts under `~/.safeyolo/share/`.
On Linux, it also runs host setup when runtime prerequisites are missing.
The command skips phases whose required state is already present.

When Linux build packages are missing, bootstrap prints the package-manager
command to install them and exits before building. Run that command, then rerun
bootstrap. Runtime setup can install gVisor, user-namespace tools, and ACL tools
using apt, dnf, apk, or pacman as appropriate. It explains its privileged changes
before invoking `sudo`, which may prompt for your password.

```sh
safeyolo bootstrap
```

**Optional:** To inspect or retry an individual phase, use the commands below.
`init` writes configuration under `~/.safeyolo/`, including policy, addon settings,
and tokens. `build` installs guest artifacts under `~/.safeyolo/share/`: an
unpacked rootfs tree on Linux, or a kernel, initramfs, and ext4 image on macOS.
See the [guest build reference](../guest/README.md) for rebuild controls.

```sh
safeyolo init
safeyolo build
```

For **source installs on macOS**, build and install the Swift VM helper after
the guest build. Skip this step when you installed a host package; that package
already includes the helper:

```sh
make -C vm install
```

Then run host setup. On Linux it applies missing runtime prerequisites,
AppArmor configuration, and KVM access where applicable. On macOS it checks the
guest artifacts and Swift helper without privileged changes.

```sh
safeyolo setup
```

### Troubleshooting installation

Run `safeyolo doctor` on the host. It reports runtime prerequisites, guest
artifacts, isolation platform, and agent state, and exits nonzero if a check fails.
On Linux it reports gVisor, KVM or systrap, and user namespaces; on macOS it
checks Apple Silicon and the Swift helper.

| Output | Command |
| --- | --- |
| Normal console report | `safeyolo doctor` |
| Plain text without color or wrapping | `safeyolo doctor --raw` |
| Machine-readable JSON | `safeyolo doctor --json` |

If `safeyolo start` reports that the Rust proxy executable is missing, run the
repository installer again from the same checkout. It builds the native proxy
and reinstalls the CLI package:

```sh
./install.sh reinstall
```

### Return to the prior Python package

The explicit rollback target for this cutover is source commit
`7e934a5470f1aa9b74052fea08c6bae9b5f32e8a`, not a tagged release or a
prebuilt wheel. Keep a separate checkout of that exact commit: its installer
uses an editable uv tool installation, and its Python proxy imports `pdp/`
from the checkout. Its installer resolves dependencies when it runs. The
[Linux B4 result](https://github.com/craigbalding/safeyolo/pull/828) is a
preparatory historical result. The completed cutover acceptance is recorded
in [#640](https://github.com/craigbalding/safeyolo/issues/640).
Use the selected checkpoint on
an instance whose state you intend to reuse; test changes first in a
disposable instance. The current package cannot run the Python backend.

On the host, from the current release checkout, record its path, fetch the
selected commit, and prepare the separate prior checkout. Keep both
checkouts available until you return to Rust:

```sh
export SAFEYOLO_RUST_CHECKOUT="$PWD"
git fetch origin 7e934a5470f1aa9b74052fea08c6bae9b5f32e8a
git worktree add --detach ../safeyolo-python-rollback 7e934a5470f1aa9b74052fea08c6bae9b5f32e8a
```

Stop the Rust proxy with the currently installed CLI. Confirm it has stopped
before replacing the tool:

```sh
safeyolo stop
safeyolo status
```

Now edit `~/.safeyolo/config.yaml` (or the active
`$SAFEYOLO_CONFIG_DIR/config.yaml`) so `proxy.backend` is `python`. Preserve
the policy, vault, certificate authority, HMAC key, and other instance state.
This state-preserving package swap does not call `safeyolo init` or
`bootstrap`; both can change instance or host setup. From the same host
shell, install and start the selected prior checkout:

```sh
cd ../safeyolo-python-rollback
./install.sh reinstall
export SAFEYOLO_PDP_DIR="$PWD/pdp"
safeyolo start
safeyolo status
```

The running process must identify the prior Python package. If startup fails,
inspect its error and leave the Rust proxy stopped; there is no automatic
fallback. The prior package has its own security and compatibility limits,
recorded in [state compatibility](../docs/state-compatibility.md).

To return, stop the prior proxy with its installed CLI and confirm it has
stopped:

```sh
safeyolo stop
safeyolo status
```

Edit the same `config.yaml` so `proxy.backend` is `rust`. From the saved Rust
checkout, reinstall the current package. Its installer rebuilds and packages
the Rust executable. Check readiness and the executable before resuming agents:

```sh
cd "$SAFEYOLO_RUST_CHECKOUT"
./install.sh reinstall
unset SAFEYOLO_PDP_DIR
safeyolo start
safeyolo status
safeyolo doctor
```

## Commands

### Setup & Lifecycle

| Command | Description |
|---------|-------------|
| `safeyolo init` | Initialize configuration with interactive wizard |
| `safeyolo start` | Start the host proxy process |
| `safeyolo stop` | Stop the host proxy process |
| `safeyolo status` | Show native proxy readiness, executable, and agents |
| `safeyolo build` | Build platform-specific guest artifacts from source |
| `safeyolo check` | Verify setup is working correctly |
| `safeyolo doctor` | Run diagnostic cascade (config, proxy, addons, sandbox runtime) |
| `safeyolo demo` | Guided tour of SafeYolo security features |
| `safeyolo lab` | Create, attach, recover, inspect, or tear down a SafeYolo experimentation workbench |

#### Lab

```bash
safeyolo lab                         # Ask for an objective, then propose and confirm a Lab agent
safeyolo lab --status                 # Inspect the selected Lab agent and its guest controller
safeyolo lab --recover                # Relaunch an owned dead controller and attach
safeyolo lab --teardown               # Capture redacted evidence, then remove the Lab session
safeyolo lab --teardown --keep-agent  # Retain the managed agent for later inspection
```

Lab selects only agents explicitly marked as Lab-managed. It does not adopt
or overwrite an unrelated agent or guest tmux session. Teardown retains the
captured evidence and Lab configuration; deleting retained artifacts is a
separate operator choice.

The Lab is an optional experiment workflow, independent of `safeyolo demo`.
The bundled Codex setup also provides `safeyolo-lab` inside an existing running
agent. From a host terminal, replace `AGENT` with its name and open a shell:

```sh
safeyolo agent shell AGENT
```

Inside that guest shell, run:

```sh
safeyolo-lab
```

The guest tmux prefix is `C-a`. Run `safeyolo-lab` again after a disconnect to
attach to the existing Lab. It does not adopt an unrelated guest session or
start a second controller. See the [Lab skill](../cli/src/safeyolo/agent_context/skills/safeyolo-lab-controller/SKILL.md)
for the experiment workflow.

#### Start options

Normal startup uses the Rust proxy and its generated instance configuration.
The old Python backend and source/test start flags are unavailable. The
[contract notes](../tests/proxy_contracts/CONTRACT.md) retain historical migration
receipts; they do not prescribe a production comparator or routine PR gate.

```bash
safeyolo start
safeyolo status
safeyolo start --no-wait
```

`safeyolo status` reports the selected Rust executable and readiness. The
`--no-wait` option returns after launch without waiting for the health check.

Build guest artifacts separately with `safeyolo build`. Linux uses an unpacked
rootfs tree. macOS uses a kernel, initramfs, and ext4 rootfs image. See the
top-level README.

**Doctor:**

```bash
safeyolo doctor             # Report host prerequisites, runtime, agents
```

### Monitoring & Logs

| Command | Description |
|---------|-------------|
| `safeyolo logs` | View formatted logs |
| `safeyolo logs -f` | Follow logs in real-time |
| `safeyolo logs --event security` | Show structured security events |
| `safeyolo logs --raw` | Output raw JSONL |
| `safeyolo logs --tail 50` | Show recent native proxy events and failures |

### Traffic inspection

For an already prepared native instance, use its installed native client. The
[operator instructions](../docs/native-operator.md) cover direct selection,
one `inspect` session, retained exports and scoped Helper preparation. The Python
traffic presentation entry has been retired. Streamed or pruned bodies remain
unavailable. WebMITM and its tailnet sharing commands remain registered in the
retained host CLI but are unavailable with the native proxy. See
[capture and export limits](../docs/DEVELOPERS.md#live-traffic-inspection).

### Approval Workflow

| Command | Description |
|---------|-------------|
| `safeyolo watch` | Monitor logs and handle credential + risky route approval requests interactively |
| `safeyolo watch --log-only` | Display events without prompts |
| `safeyolo watch --tmux` | Optimized for tmux status bar integration |
| `safeyolo policies` | List approval policies |
| `safeyolo policies <project>` | Show policy details |

`safeyolo watch` handles these approval states:

- It presents credential-routing approvals and risky-route grant approvals.
- At startup, it scans for pending approvals.
- It deduplicates prompts for the same route.
- Before final rejection, it presents a second prompt for a denied request.

### Configuration

| Command | Description |
|---------|-------------|
| `safeyolo mode` | Show all addon modes |
| `safeyolo mode <addon>` | Show mode for specific addon |
| `safeyolo mode <addon> <warn\|block>` | Set addon mode |

### Agent Management

Runs AI agents in isolated sandboxes. macOS uses Apple Virtualization framework
(VZ) microVMs. Linux uses rootless gVisor. Both platforms route external
traffic through SafeYolo.

First complete the [native host installation and guest prerequisites](../docs/native-policy.md#install-and-start)
for a fresh `$HOME/.safeyolo-native` instance. The table uses subcommands of
`$HOME/.safeyolo-native/bin/safeyolo --root $HOME/.safeyolo-native`.
The native installer does not change `PATH` or convert a Python instance.

| Command | Description |
|---------|-------------|
| `agent create NAME --workspace PATH [--host-script PATH]` | Create native agent configuration |
| `agent configure NAME [--workspace PATH] [--memory MB] [--host-script PATH]` | Update the next start's configuration; host setup requires a stopped agent |
| `agent start NAME [--foreground\|--sandbox-only] [-- ARGUMENTS...]` | Start an existing agent; arguments affect only this launch |
| `agent stop NAME` | Stop the selected agent |
| `status` | Inspect configured agents and proxy state |
| `agent attach NAME` | Reopen the recorded terminal without launching an absent agent |
| `agent shell NAME` | Open an independent shell in a running agent |
| `agent diagnostics NAME` | Inspect runtime and control failures |

**Quick start:** run from a trusted SafeYolo checkout outside the agent's writable
shares. Host setup scripts run with your host permissions. Stop an existing
agent before applying a host script; configure workspace changes for its next
stop/start.

In the example below, `~/code` and `~/other-project` are existing owned workspaces.
Harness approval behavior comes from the
selected host setup and harness arguments. Arguments after `start NAME --`
apply to one launch and do not change saved defaults.

```bash
# Create a Claude Code agent using the trusted checkout's host script
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" agent create myproject --workspace ~/code --host-script "$PWD/contrib/claude-host-setup.sh"

# Later, start in the background and open its terminal
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" agent start myproject
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" agent attach myproject

# Stop before reapplying or switching host setup
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" agent stop myproject
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" agent configure myproject --host-script "$PWD/contrib/codex-host-setup.sh"

# Opt into a supervised, coord-driven Codex factory worker
SAFEYOLO_CODEX_COORD_ROOMS=backlog SAFEYOLO_CODEX_COORDINATORS=relay \
  "$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" agent configure myproject --host-script "$PWD/contrib/codex-coord-host-setup.sh"
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" agent start myproject

# Persist a new /workspace folder for ordinary future runs
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" agent configure myproject --workspace ~/other-project
```

The remaining examples use the retained Python CLI installed by `uv sync`,
with its separate default `$HOME/.safeyolo` instance. Run them from the checkout.
They prepare custom images and provide the existing desktop controls; they do
not operate on `myproject` in the native instance. Here `~/code-2` is an existing
owned workspace and `legacy-project` is an already-running Python agent with a
custom rootfs and a desktop stack. The copy prepares `second-project` without
starting it. Desktop commands target the existing `legacy-project`.

```bash
# Reuse the Python agent's custom rootfs with fresh home, overlay, and credentials
uv run --frozen safeyolo agent add second-project ~/code-2 --rootfs-from legacy-project --no-run

# If the running rootfs supplies a desktop stack, start and open it directly
uv run --frozen safeyolo agent desktop legacy-project --open

# Override the persistent desktop.size preference for one invocation
uv run --frozen safeyolo agent desktop legacy-project --size 1600x900 --open

# Set this host's default once, then use ordinary desktop commands thereafter
uv run --frozen safeyolo agent desktop legacy-project --size 1280x1246 --remember-size --open

# Optionally launch a guest browser and expire the host preview automatically
uv run --frozen safeyolo agent desktop legacy-project --browser https://example.com --open --ttl 15m

# On a remote Tailscale host, publish the same gated preview to the tailnet
uv run --frozen safeyolo agent desktop legacy-project --share tailnet --ttl 15m

```

**Host scripts** configure what the agent is. Ready-made examples in `contrib/`:
- `contrib/claude-host-setup.sh` — Claude Code; copies host authentication and
  selected extensions into the persistent agent home.
- `contrib/codex-host-setup.sh` — OpenAI Codex CLI; copies `~/.codex/` into the
  persistent agent home.
- `contrib/codex-coord-host-setup.sh` — supervised Codex coord worker (explicit opt-in)
- `contrib/mise-shell-host-setup.sh` — bring-your-own-agent interactive shell with mise
- See `contrib/HOST_SCRIPT_GUIDE.md` to write your own.

Files copied into the persistent agent home are mounted at `/home/agent` and
are readable by the agent process. The service gateway's vault isolation does
not apply to these deliberately staged coding-harness credentials.

**Notes:**
- Agent names must be lowercase alphanumeric with hyphens (hostname rules)
- The retained Python `add` command is idempotent: running it twice with the same folder + script just runs the existing agent
- Use `--no-run` with Python `add` to create config without running
- Without `--host-script`, the sandbox boots to a plain bash shell
- Inside an agent, use ordinary `sudo apt install ...` (or the distro
  equivalent) for ephemeral guest packages. This grants root only inside the
  VM or gVisor sandbox; it does not invoke host sudo. The native shell command
  has no guest-root flag. If the guest sudo helper is missing or broken, report
  that prerequisite for operator repair; `agent recover` diagnoses guest health
  through the separate shared-home/PID-1 path, without SSH.
- `agent desktop` requires an already-running agent and never installs missing
  guest packages; use `--status` or `--stop` for desktop lifecycle checks
- Set `desktop.size` in `~/.safeyolo/config.yaml` to `auto` or a persistent
  `WIDTHxHEIGHT` operator preference. SafeYolo also stages that preference for
  trusted agent-side desktop orchestrators. `--remember-size` persists an
  explicit `--size`; without it, `--size` remains a one-shot override.
- `--share tailnet` keeps the guest and preview gateway loopback-only, then
  publishes the gated gateway with foreground Tailscale Serve. SafeYolo
  reserves a stable per-agent HTTPS port starting at 8443.

### Service Gateway

Authorize agents to access external or sandbox-provided services through the
gateway. A YAML service definition can supply:

- the service host;
- named capabilities and their allowed routes;
- risky routes and their MITRE ATT&CK tactics; and
- an optional authentication method and injection settings.

| Command | Description |
|---------|-------------|
| `safeyolo agent authorize <agent> <service>` | Authorize an agent to use a service (with `--capability`) |
| `safeyolo agent revoke <agent> <service>` | Revoke service access for an agent |
| `safeyolo services list` | List available service definitions |
| `safeyolo services show <name>` | Show service details (host, capabilities, risky routes) |

To supply a credential from a host environment variable, first set `GMAIL_TOKEN`
in your host shell to the token you intend to share. For an existing agent named
`work`, this command binds that credential to Gmail's `read_agent_folder`
capability:

```sh
safeyolo agent authorize work gmail --capability read_agent_folder --token-env GMAIL_TOKEN
```

**Example flow:**

```bash
# List available services
safeyolo services list

# Authorize the agent to use the github service with a specific capability
safeyolo agent authorize myproject github --capability create_pr

# Verify the policy was updated
safeyolo policy show --section hosts

# Revoke access when no longer needed
safeyolo agent revoke myproject github
```

When the selected capability declares `source: operator` contract bindings,
`agent authorize` records the service authorization but reports that setup is
incomplete and lists the binding names. Have the named agent submit the
operator-provided values to its Agent API at `POST /gateway/submit-binding`,
then approve the system-authored contract prompt with `safeyolo watch`. There
is no host-side binding submission command.

A sandbox-provided service uses a configured provider agent with the same name
as the service. Its definition can omit `auth`; the caller still needs an
agent-bound service authorization. See [Service provided by a sandbox](../docs/CONFIGURATION.md#service-provided-by-a-sandbox)
for the service definition, host mapping, and caller workflow.

### Vault Management

Store and manage credentials used by service gateway integrations.

| Command | Description |
|---------|-------------|
| `safeyolo vault add <name>` | Store a credential (value prompted securely) |
| `safeyolo vault list` | List stored credentials (never shows values) |
| `safeyolo vault remove <name>` | Remove a credential |
| `safeyolo vault oauth2 <name> --provider google ...` | Run OAuth2 browser consent flow |

```bash
# Add a credential
safeyolo vault add github-token

# List stored credentials
safeyolo vault list

# Remove a credential
safeyolo vault remove github-token

# OAuth2 flow (opens browser for consent)
safeyolo vault oauth2 google-creds --provider google --client-id <id> --client-secret <secret> --scope gmail.readonly
```

**Note:** The vault is encrypted at rest. An encryption key is auto-generated at `~/.safeyolo/data/vault.key` on first use.

### Policy Inspection

Inspect the merged policy that the proxy enforces at runtime.

| Command | Description |
|---------|-------------|
| `safeyolo policy show` | Show merged policy (policy.toml + addons.yaml) |
| `safeyolo policy show --compiled` | Show compiled Identity and Access Management (IAM) format |
| `safeyolo policy show --section hosts` | Filter output to one section |

```bash
# View full merged policy
safeyolo policy show

# View only the hosts section
safeyolo policy show --section hosts

# View compiled IAM representation
safeyolo policy show --compiled
```

### Policy Management

Manage hosts, egress posture, and named lists in policy.toml.

**Host rules:**

| Command | Description |
|---------|-------------|
| `safeyolo policy host add <host> [--rate N] [options]` | Allow a host, optionally with a stricter per-host requests/minute ceiling |
| `safeyolo policy host remove <host>` | Remove a host rule |
| `safeyolo policy host deny <host>` | Deny all traffic to a host |
| `safeyolo policy host list` | List all host rules |
| `safeyolo policy host bypass <host>` | Bypass proxy for a host (no MITM) |
| `safeyolo policy host add-list <name> [--rate N] [--egress POSTURE]` | Apply a named list as a host entry |

**Addon list settings:**

| Command | Description |
|---------|-------------|
| `safeyolo policy addon-list add <addon> <setting> <value>` | Add a unique string to an `addons.yaml` list |
| `safeyolo policy addon-list remove <addon> <setting> <value>` | Remove a string from an `addons.yaml` list |

**Egress posture:**

| Command | Description |
|---------|-------------|
| `safeyolo policy egress set <posture>` | Set egress posture (allow, prompt, deny) |
| `safeyolo policy egress show` | Show current egress posture |

**Named lists:**

| Command | Description |
|---------|-------------|
| `safeyolo policy list add <name> <host>` | Add a host to a named list |
| `safeyolo policy list remove <name> <host>` | Remove a host from a named list |
| `safeyolo policy list show <name>` | Show hosts in a named list |

### Certificate Management

| Command | Description |
|---------|-------------|
| `safeyolo cert env` | Print env vars for CA trust and proxy config |
| `safeyolo cert show` | Show CA certificate location and status |

```bash
# Configure shell for proxy CA trust (useful for pip, curl, etc.)
eval $(safeyolo cert env)
```

### Tmux Integration

| Command | Description |
|---------|-------------|
| `safeyolo tmux setup` | Configure current tmux session for SafeYolo status line |
| `safeyolo tmux config` | Output tmux config snippet |
| `safeyolo tmux config --write` | Write config to `~/.config/tmux/safeyolo.conf` |
| `safeyolo tmux status` | Show current SafeYolo status (for status bar scripts) |

### Setup & Prerequisites

| Command | Description |
|---------|-------------|
| `safeyolo setup` | Check and apply platform prerequisites idempotently |
| `safeyolo setup apparmor` | Apply only the Linux `runsc` AppArmor profile |
| `safeyolo setup sudoers` | Install the optional legacy rootfs-extraction fallback rules on Linux; current runtime paths do not require these rules |

## Configuration

Configuration is stored in `$SAFEYOLO_CONFIG_DIR` when that variable is set.
Otherwise, SafeYolo uses `~/.safeyolo/`. SafeYolo does not search for a
project-local `./safeyolo/` directory.

```
~/.safeyolo/
├── config.yaml          # Main configuration
├── policy.toml          # Host-centric policy (hosts, credentials, rate limits)
├── addons.yaml          # Addon tuning (credential_guard, circuit_breaker, etc.)
├── services/            # User service definitions (one YAML per service)
├── certs/               # Retained TLS interception CA certificate and key
├── agents/              # Agent metadata, persistent homes, and overlays
├── policies/            # Reserved policy-data directory
├── share/               # Installed guest artifacts
└── data/                # Runtime data, tokens, and encrypted vault files
```

Logs default to `$XDG_STATE_HOME/safeyolo/`, or
`~/.local/state/safeyolo/` when `XDG_STATE_HOME` is unset. Set
`SAFEYOLO_LOGS_DIR` to override that state directory.

### config.yaml

```yaml
version: 1
proxy:
  port: 8080           # Proxy port for agents
  admin_port: 9090     # Admin API port
  image: safeyolo:latest
  container_name: safeyolo
modes:
  credential_guard: block
  network_guard: block
  pattern_scanner: warn
  test_context: block
```

### policy.toml

Host-centric policy defining hosts, credentials, and rate limits:

```toml
version = "2.0"
budget = 12_000  # aggregate requests/minute across all domains
# egress posture is set on the wildcard [hosts] entry, not at top level

required = ["credential_guard", "network_guard", "circuit_breaker"]

[hosts]
"api.openai.com"    = { allow = ["openai:*"],    rate = 3_000 }
"api.anthropic.com" = { allow = ["anthropic:*"],  rate = 3_000 }
"*"                 = { egress = "allow", unknown_creds = "prompt", rate = 600 }

[credential.openai]
match   = ['sk-proj-[a-zA-Z0-9_-]{80,}']
headers = ["authorization", "x-api-key"]
```

### addons.yaml

Addon tuning lives in a separate file, sibling to `policy.toml`:

```yaml
addons:
  credential_guard:
    enabled: true
    detection_level: standard
    entropy: { min_length: 20, min_charset_diversity: 0.5, min_shannon_entropy: 3.5 }
  circuit_breaker:
    enabled: true
    failure_threshold: 5
```

## Workflow

1. **Initialize** - Run `safeyolo init` to create configuration
2. **Start** - Run `safeyolo start` to launch the host proxy process
3. **Configure agent** - Point your AI coding agent at `http://localhost:8080`
4. **Watch** - Run `safeyolo watch` to handle credential approval requests
5. **Monitor** - Use `safeyolo logs -f` to watch activity

When a credential is blocked:
- The proxy returns HTTP 428 with details
- The event appears in `safeyolo watch`
- You approve or deny interactively
- Approved credentials are added to the policy file
- Subsequent requests pass through

## Requirements

- Python 3.12 or 3.13
- macOS: Apple Virtualization.framework (built into macOS 13+)
- Linux: gVisor (`runsc`), `newuidmap`/`newgidmap`, KVM group membership

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SAFEYOLO_ADMIN_TOKEN` | Admin API authentication token |
| `SAFEYOLO_CONFIG_DIR` | Override config directory location |

## License

MIT
