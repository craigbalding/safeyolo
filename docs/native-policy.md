# Native agents and policy commands

The native CLI validates, displays and applies host-centred policy through the
existing native proxy. Use a fresh instance directory. These commands also
validate runtime settings and format, write, declare, read and clear test context.
The installed CLI also configures agents, controls their lifecycle and opens
terminals. Final release packages remain separate work.

## Install and start

On supported Ubuntu, run the following command as your ordinary host account
from the repository checkout. The source installation requires Bash and Rust
1.94. The directory `$HOME/.safeyolo-native` must have no existing instance
configuration or tokens. Installation builds the production CLI, proxy and
Linux guest command helper. It installs the host executables in `bin`, stages
the guest helper and boot scripts in `assets/guest`, and creates `config.toml`, `policy.toml`, a private
operator token, a separate private Agent API token, a durable instance identity,
and separate runtime and log directories.

```sh
./scripts/install_native.sh --root "$HOME/.safeyolo-native"
```

The installer prints the full source commit and build profile. If matching
native host binaries are already built, supply their directory with `--artifacts`
and the Linux guest artifact directory with `--guest-artifacts`. The latter must
contain `safeyolo-guest`, `safeyolo-guest.version` and `safeyolo-guest.sha256`
from `scripts/build_guest_command.sh`, with the same source commit and profile.
Installation verifies and copies those binaries without compiling. The installed
commands use neither Python nor source-checkout imports.

The generated policy retains the existing wildcard network allowance, credential
approval prompt, global budget of 12,000 requests per minute and host rate of 600.
Edit `policy.toml` to select the policy for your agent listeners.

Before startup, edit `config.toml` to select the Admin API port and the trusted
agent listeners. Relative paths belong to this configuration directory. An
agent name on a listener supplies host-owned identity; a request header cannot
replace that identity. For two host-owned test listeners, the configuration is:

```toml
admin_port = 9090

[[listeners]]
agent_id = "alice"
socket_path = "data/alice.sock"
source_id = "10.0.0.2"

[[listeners]]
agent_id = "bob"
socket_path = "data/bob.sock"
source_id = "10.0.0.3"
```

The `source_id` values are host-owned declaration slots for these test listeners.
The Admin API binds IPv4 loopback and requires the token in `data/admin_token`.
Keep that token on the host. Check the configuration, then start and inspect
the proxy from a host terminal:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" config check "$HOME/.safeyolo-native/config.toml"
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" start
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" status
```

The proxy runs in the background. An occupied endpoint or unreadable input
produces a startup error and points to `logs/proxy.log`. `status` and `doctor`
report proxy health separately from each agent's runtime, control, command and
terminal state. These observations remain available when the Admin API is down.
The top-level `stop` command stops the proxy; stop each agent separately.

## Configure and use an agent

Run these commands on the host as the account that owns the workspace.
The native installation above supplies guest helpers and launchers. Before
starting a sandbox, also install the platform's guest images: Ubuntu uses
`share/rootfs-tree`; macOS uses `share/Image`, `share/initramfs.cpio.gz` and
`share/rootfs-base.ext4`. Ubuntu needs the maintained runsc and user-namespace
setup. macOS needs the installed `bin/safeyolo-vm` and `bin/vsock-term` helpers.
See the [guest build instructions](../guest/README.md) for these prerequisites.

In this example, `$HOME/work` is an existing directory owned by your account.
The command runs an interactive shell in the guest, using your current terminal:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" agent create work --workspace "$HOME/work" --memory 4096
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" agent start work --foreground
```

To start a persistent background command, set `--command` when creating or
configuring the agent, then use `agent start work` without `--foreground`.
The shipped tmux-window launcher survives viewer loss. `agent attach work`
reopens the recorded session. Attach reports absence when the command is stopped;
it does not launch a replacement. `agent shell work` opens an independent shell.

Use `agent configure work --workspace PATH --memory MB` to change settings.
The output identifies next-start scope. The current sandbox keeps its existing
workspace and memory until one `agent stop work` / `agent start work` cycle.
Repeat `--mount HOST:GUEST[:ro]` for explicit shares. Read-only shares reject guest
writes. An unowned workspace requires the existing explicit
`--dangerously-allow-unowned` override.

If a shell fails, run `agent diagnostics work`. The result names runtime and
control failures independently of proxy availability. On macOS it also checks
the private helper control and the SSH banner. A connection without a banner
reports the failed shell hop after the existing three-second deadline.
`agent recover work` uses the independent shared-home/PID-1 command probe;
it requires a running guest and idle command supervision, without SSH or a model.
If control recovery is unavailable, `agent stop work` still uses verified backend
identity. It does not signal an unrelated PID from a stale record.

Commander discovers the installed native executable from its authenticated
instance endpoint. Named launch and status use the Admin API. Remote terminal
operations require the configured SSH route separately; the admin token supplies
no SSH access. Closing a terminal or Commander does not stop the background run.

## Check, show and apply

In another host terminal, check the installed policy and read the effective
policy from the running process:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" policy check "$HOME/.safeyolo-native/policy.toml"
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" policy show
```

Check validates without writing the saved policy or evaluating live requests.
Show reads the active values and their source. Neither command spends quotas.
Show reports `active` when the saved source matches the active source.
Activation also prepares the runtime detectors. A policy-model check does not
guarantee that the running process can activate every detector configuration.

Prepare a separate TOML candidate before applying it. For example, if Alice
needs one host-owned HTTP origin at `127.0.0.1:8081`, the following policy allows
that endpoint for Alice and denies other network destinations. The origin and
port are inputs you must select for your own environment.

```toml
budget = 12000

[hosts]
"*" = { egress = "deny", unknown_creds = "prompt" }

[agents.alice.hosts]
"127.0.0.1:8081" = { egress = "allow" }
```

Save the candidate as `candidate.toml` in your current directory. Apply it and
read the process state back:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" policy apply candidate.toml
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" policy show
```

Apply validates the candidate, saves it atomically, and activates through the
authenticated Admin API. Exit zero and `status: active` confirm activation.
Persistence or activation failure returns nonzero. The existing transaction
restores the previous saved source after a failed activation. The allowed and
denied controls in the active policy remain effective.
If the saved policy was already inactive, rollback restores those saved bytes
and retains the actual pre-apply live generation. The saved/live mismatch
remains visible until you apply or restore the intended inputs.

When an external edit is invalid or activation cannot complete, show reports
`saved_differs` or `saved_unreadable`, preserves the active values in `effective`,
and names a repair action. Correct the input or filesystem access, then apply a
valid candidate. A whole replacement can repair an invalid saved document
without restarting the process. If the Admin API connection fails, the CLI
reports that activation is unconfirmed and tells you to restore that connection
before reading the active policy.

## Format and declare test context

In a host terminal, format context or atomically replace a file watched by your
test client. `run` and `agent` are required annotations. Values use
`[A-Za-z0-9_.:-]`; duplicate keys or more than 20 pairs are rejected. Named fields
are `run`, `agent`, `role`, `suite`, `subject`, `step`, `test`, `intent` and
`expect`. Repeat `--field KEY=VALUE` for additional safe fields. `--header` prints
the complete `X-SafeYolo-Test-Context` header line.

```sh
"$HOME/.safeyolo-native/bin/safeyolo" test-context --run local-proof --agent alice --step one --write "$HOME/.safeyolo-native/context"
```

The file and stdout contain `run=local-proof;agent=alice;step=one`. A watcher
sees a complete old or new value. Validation or replacement failure returns
nonzero and preserves the previous file. Context is annotation; the listener
still supplies the trusted agent identity and evidence owner.

For declarations, use the private `data/agent_token` created by native init,
and the chosen agent socket. This token has Agent API scope and cannot replace
the operator token. The following commands declare context on Alice's listener,
read it back, then clear it:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" test-context declare --socket "$HOME/.safeyolo-native/data/alice.sock" --token-file "$HOME/.safeyolo-native/data/agent_token" --run local-proof --agent alice --ttl 60
"$HOME/.safeyolo-native/bin/safeyolo" test-context current --socket "$HOME/.safeyolo-native/data/alice.sock" --token-file "$HOME/.safeyolo-native/data/agent_token"
"$HOME/.safeyolo-native/bin/safeyolo" test-context clear --socket "$HOME/.safeyolo-native/data/alice.sock" --token-file "$HOME/.safeyolo-native/data/agent_token"
```

Each command returns its Agent API JSON result. Declarations are process-local,
belong to the trusted source/agent pair, and expire at their granted TTL. The
policy caps TTL at `controls.test_context.declared_ttl`, default 900 seconds.
Declaring context does not itself enable injection. Select injection and target
hosts in your policy candidate, then apply it:

```toml
[controls.test_context]
action = "block"
inject_declared = true
declared_ttl = 900
target_hosts = ["origin.example"]
```

Replace `origin.example` with your intended host. Matching requests without valid
context return 428 under `block`; this response does not create a network approval.
An explicit valid header takes precedence over declared context. Clearing or
expiry removes the declaration from later requests. Bob cannot inherit Alice's
declaration or read Alice's trace, explanation or stored flows. The supported
Agent API readback paths are `/trace`, `/explain`, and `/api/flows/*`, with the
same bearer authentication and evidence scope.

## Policy and runtime settings

`config.toml` owns paths, listeners and runtime settings. `policy.toml` owns
network and credential decisions, named lists, agent overrides, budgets,
advanced host rules, service policy and named controls. The fresh loader does
not read `addons.yaml`. Replaced fields, such as `addons`, `required`, `bypass`
and `global_budget`, produce named validation errors.

The [settings reference](native-settings.md) lists retained keys, defaults,
precedence, consumers and remaining host/helper owners. Capture, trace and audit
storage settings use their runtime tables in `config.toml`. Scanner, circuit and
test-context settings use named controls in `policy.toml`. Native help, effective
policy, API reports and audit envelopes use these control names.

Check resolves named list files relative to the checked policy. Apply records
those file references as absolute paths so saving the candidate under the
instance root does not change which list the native process loads.
Show displays the loaded members in `effective.lists`, their file paths in
`sources`, and each referenced file's current status in `list_files`. A changed
or unreadable list produces a saved/live mismatch, including changes that retain
the original file timestamp. The displayed members remain those used by the
active compiler until a valid policy reload or apply succeeds.

For example, network enforcement and credential enforcement have separate
actions. These explicit values retain the default blocking behavior:

```toml
[controls.network]
enabled = true
action = "block"
homoglyph = true

[controls.credentials]
enabled = true
action = "block"
```

The alternative `warn` action records a finding while permitting forwarding.
Networking permission does not grant credential permission. An approved
credential remains scoped to its destination and fingerprint; show includes
the actual saved grant in the effective host entry. Existing service and
approval operations retain their separate native owners.
