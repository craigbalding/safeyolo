# Configuration

Select the installed instance with `safeyolo --root ROOT COMMAND`, or set
`SAFEYOLO_CONFIG_DIR`. The default root is `$HOME/.safeyolo`. The native product
reads `config.toml` and `policy.toml`. Paths resolve relative to the selected
configuration or policy file. It does not search for project-local configuration,
convert old state, read `config.yaml`/`addons.yaml` or select a Python fallback.

## Directory structure

```text
ROOT/
├── config.toml          # Native runtime settings
├── policy.toml          # Hosts, agents, grants, budgets, lists and controls
├── bin/                 # Native host executables
├── libexec/ and lib/    # Private tmux runtime and non-system libraries
├── assets/              # Helpers, guest scripts, skills, launchers and services
├── share/               # Prepared platform images or Linux rootfs-tree
├── agents/              # Persistent homes, overlays and owned run metadata
├── certs/               # Public CA and private signing key
├── data/                # Private tokens, instance identity and durable state
└── logs/                # Audit, runtime diagnostics and flow storage
```

The [settings reference](native-settings.md#runtime-settings) gives every
retained key, default and consumer. Native paths such as `data_dir`,
`audit_log_path`, `event_log` and `flow_store_db_path` belong to this root by
default; the earlier Python XDG log selection is not a native runtime setting.
Keep private tokens, signing keys and service credentials on the host.

## Runtime settings

Check a saved configuration before starting it:

```sh
safeyolo config check "$SAFEYOLO_CONFIG_DIR/config.toml"
safeyolo start
safeyolo status
```

The Admin API defaults to IPv4 loopback port 9090 and requires the selected
`admin_api_token_file`. Port zero requests an ephemeral Admin port, reported
in readiness. Agent listeners are Unix sockets with host-owned identity;
request headers cannot change that identity. Native lifecycle stages their
listeners and the agent discovery map from the same policy/runtime state.

To use an explicit parent or additional CA trust, set the native keys:

```toml
parent_proxy = "https://parent.example:8443"
upstream_ca_file = "certs/additional-trust.pem"
ignore_hosts = ["pinned-app.example:443"]
```

Parent proxy URLs must be HTTP(S) authorities with no credentials, path, query
or fragment. Upstream trust still checks certificate validity, signature and
hostname; TLS failure cannot choose uninspected fallback. For an exact
operator-selected TLS passthrough, use `ignore_hosts`. See
[TLS trust and passthrough](TLS_CERTIFICATE.md).

To send selected agents through one shared parent, add the following top-level
keys to the host's `config.toml`. The operator-provided parent must be listening
on host port 18080. Restart SafeYolo to apply the saved settings:

```toml
parent_proxy = "http://127.0.0.1:18080"
parent_proxy_agents = ["zx"]
```

Agent `zx` uses the parent. Other agents use SafeYolo's direct upstream
connection. Every agent still sends traffic through SafeYolo. Names match the
host-assigned listener identity; request headers cannot select the route.
An omitted or empty `parent_proxy_agents` list preserves global parent use.
Removing the last name restores global use. Without `parent_proxy`, the list
has no effect. If a selected parent fails or refuses CONNECT, the request fails
without a direct fallback.

Runtime listeners, audit, trace and capture settings take effect on restart.
Policy apply updates policy controls without restarting. Existing capture
limits, queue modes and trace/storage retention are unchanged; use the exact
values and zero/negative handling in [native settings](native-settings.md).

## Workspace and memory

An agent's saved `folder` is exposed as `/workspace`. `memory_mb` defaults to 4096 MiB in the native host. Extra `mounts` retain their specified access;
`HOST:GUEST:ro` is read-only. Choose owned workspaces and review trusted host
scripts before executing them.

```sh
safeyolo agent configure work --workspace "$HOME/new-project" --memory 2048
safeyolo agent configure work --mount "$HOME/reference:/reference:ro"
safeyolo agent stop work
safeyolo agent start work
```

Saved changes apply at the next sandbox start. Existing live runs keep their
bound inputs. The explicit `--dangerously-allow-unowned` option retains the
native host's existing ownership override; it is not required for an owned
project. A launcher can be `tmux-window`, `tmux-pane`, `supervisor` or a trusted
script. [Agent launchers](agent-launchers.md) describe selection and attach.

Native `desktop.size` retains `auto` or an explicit `WIDTHxHEIGHT` preference;
`desktop.present_host_port` selects the permitted loopback presentation port.
Use `safeyolo agent present work` for the running desktop. Web and Commander
listener/share settings stay in the same native config. Their authenticated
Admin owners and Commander make the existing operator changes; the retired
Python desktop/web/command-centre wrappers are not installed.

## Policy

The host policy file contains hosts, agent settings, named lists, scoped
credential/service grants, budgets and named controls. There is no addon model.
[Policy guidance](native-policy.md#policy-and-runtime-settings) explains
precedence, expiration, show and apply with examples.

```toml
version = "2.0"

[hosts."*"]
egress = "allow"

[hosts."blocked.example"]
egress = "deny"

[agents.work]
folder = "/home/operator/code"
memory_mb = 2048

[agents.work.hosts."api.example"]
egress = "allow"

[controls.credentials]
enabled = true
action = "block"

[controls.patterns]
enabled = true
action = "warn"
```

Validate a complete candidate before applying it. List paths belong to the
policy's directory; unreadable or invalid updates do not replace active policy.

```sh
safeyolo policy check "$HOME/reviewed-policy.toml"
safeyolo policy apply "$HOME/reviewed-policy.toml"
safeyolo policy show
```

Network permission and credential permission remain separate. Service bindings
retain route/method, capability, risk and credential scope through the existing
native gateway. The #819 source/prerequisite and installed credential proofs
remain in the [responsibility map](native-settings.md#operator-entry-responsibilities);
removing Python does not accept them or invent a replacement credential store.

## Restart and persistence

The current product retains initialized identity, policy, service/vault state,
Coord data and agent homes under their existing owners. Runtime/process receipts
are observations with birth identity, not permission to signal an arbitrary PID.
Do not remove a private token or key to make a failed start appear successful.
Stop each agent separately, then stop the proxy before changing runtime inputs.

```sh
safeyolo agent stop work
safeyolo stop
safeyolo start
safeyolo agent start work
```

Use `doctor`, `agent diagnostics NAME` and the named logs to diagnose failure.
The [native operator guide](native-operator.md) covers scoped evidence and
approvals. Historical Python/addon descriptions remain in [ADDONS.md](ADDONS.md)
for interpreting retained tests and older records; they are not install guidance.
