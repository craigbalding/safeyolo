# Native agents and policy commands

The native CLI validates, displays and applies host-centred policy through the
existing native proxy. It also configures agents, controls their lifecycle,
opens terminals and reads operator evidence. Native bundles extend the same
installation layout. Final release and whole-product Python removal remain open.

## Install and start

On supported Ubuntu or Apple Silicon macOS, use your ordinary host account.
Obtain a native bundle for your host from the source build below. Public release
publication is stopped; existing wheel downloads are earlier packages.
A bundle's `package-info` records its source, profile, platform and actual
minimum glibc or macOS version. Unpacking and installation need Bash, tar and
the host's SHA-256 tool. They need no compiler, Python, wheel, virtual
environment or uv tool installation.

This Ubuntu example uses an arm64 production archive in your current directory.
On x86_64 Ubuntu, use `linux-amd64`; on Apple Silicon macOS, use `darwin-arm64`.
The instance directory `$HOME/.safeyolo-native` must have no existing instance
configuration. Prepared platform assets may already be present.
Installation checks bundle checksums and executable identities, then creates
configuration, trust, private tokens and runtime directories internally.
There is no separate init, build or setup command after unpacking.

```sh
tar -xzf safeyolo-linux-arm64-production.tar.gz
./safeyolo-linux-arm64-production/install.sh --root "$HOME/.safeyolo-native"
```

The installer prints the full source commit and build profile. Host executables
are in `bin`, with the private tmux executable in `libexec` and its non-system
libraries in `lib`. Guest helpers and boot scripts are in `assets/guest`;
launchers, skills, host scripts and service definitions are under `assets`.
macOS bundles also contain the signed VM helper, metadata and symbols, and the
Linux terminal helper. This package/install/start path uses no first-party
Python execution. Remaining helper and workflow dependencies are listed in the
[entry responsibility map](native-settings.md#operator-entry-responsibilities).

Before startup, make curl and tar available and permit the configured network
route to acquire the pinned NATS runtime. Native Coord verifies the archive,
binary and instance ownership. Its existing `coord start --binary PATH` option
can supply the same pinned executable when acquisition is unavailable.

The generated policy retains the existing wildcard network allowance,
credential approval prompt, global budget of 12,000 requests per minute and
host rate of 600. Edit `policy.toml` to select policy for your agent listeners.

If you need different endpoints, edit `config.toml` before startup. Relative
paths belong to this configuration directory. The default Admin API port is
9090; its listener binds IPv4 loopback and requires `data/admin_token`.
Keep that token on the host. The following optional configuration illustrates
two host-owned test listeners. An agent name supplies trusted identity;
a request header cannot replace it.

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
From a host terminal, check the configuration and start the selected instance:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" config check "$HOME/.safeyolo-native/config.toml"
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" start
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" status
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" doctor
"$HOME/.safeyolo-native/bin/safeyolo" --version
```

Startup runs the proxy in the background. Status reports `proxy_state` as
`running`; version prints the installed source and profile. Status and doctor
report the proxy process separately from each agent's runtime, control, command
and terminal state. These observations remain available when the Admin API is
down. An occupied endpoint or unreadable input fails startup and points to
`logs/proxy.log`. Resolve that named cause before repeating start.

When you finish using the instance, stop its proxy and owned Coord runtime.
Stop each agent separately; the top-level command leaves its sandbox intact.

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" stop
```

### Build a native bundle

From a clean committed checkout on the target host, use Bash and the Rust
toolchain pinned in `proxy/rust-toolchain.toml`. Linux also needs readelf and
ldd. macOS needs Command Line Tools and a signed VM helper build. Prepared
runtime inputs contain the native `tmux` executable for this host. The assembler
copies its resolved non-system libraries. This Ubuntu example selects
`/usr/bin/tmux`, so `/usr/bin` is the runtime input directory.
For prepared runtime inputs, keep their required notices in a `licenses`
directory alongside `tmux`. The assembler includes those notices and the
project's license in the bundle.

```sh
./scripts/build_host_packages.sh --output "$HOME/native-packages" --runtime-artifacts /usr/bin
```

The command builds the three host executables and matching Linux guest helpers,
then writes one production archive. Use `--profile debug` for the debug profile.
If matching binaries already exist, supply `--artifacts HOST_DIRECTORY` and
`--guest-artifacts LINUX_DIRECTORY`. Each guest executable requires its
`.version` and `.sha256` receipt from `scripts/build_guest_command.sh`.
Host and guest source/profile identities must match the clean checkout.

On macOS, also supply `--vm-artifacts DIRECTORY`. Build the signed helper with
`make -C vm build`, then stage `safeyolo-vm`, its `.dSYM` and build-info JSON,
and the prepared Linux `vsock-term` executable in that directory. The terminal
helper's `.version` receipt is `vsock-term commit=FULL_SOURCE_COMMIT`; its
`.sha256` receipt contains the built executable's SHA-256. Supply matching
arm64 Linux guest artifacts with `--guest-artifacts`; cross-building their
Rust target needs an explicitly prepared Linux cross toolchain. The assembler
verifies the helper's signing posture and source before packaging. Artifact
rebuilding is a developer operation, separate from ordinary installation.

Source installation runs the same assembler and installer without retaining an
archive. On Ubuntu with the inputs above:

```sh
./scripts/install_native.sh --root "$HOME/.safeyolo-native" --runtime-artifacts /usr/bin
```

## Configure and use an agent

Run these commands on the host as the account that owns the workspace.
The native installation above supplies guest helpers and launchers. Before
starting a sandbox, also install the platform's guest images: Ubuntu uses
`share/rootfs-tree`; macOS uses `share/Image`, `share/initramfs.cpio.gz` and
`share/rootfs-base.ext4`. Ubuntu needs the maintained runsc and user-namespace
setup. macOS needs the installed `bin/safeyolo-vm` and `bin/vsock-term` helpers.
See the [guest build instructions](../guest/README.md) for these prerequisites.
Supply their directory with `install.sh --root ROOT --platform-assets DIRECTORY`
at the fresh installation step. macOS copies the three image files with APFS
clones. Ubuntu links the prepared `rootfs-tree`, preserving its sandbox ownership;
keep that shared tree available and immutable for the instance's lifetime.

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
declaration or read Alice's trace or stored flows. Explanations also belong to
their agent unless the operator selects the limited peer read described below. The supported
Agent API readback paths are `/trace`, `/explain`, and `/api/flows/*`, with the
same bearer authentication and evidence scope.

## Selected evidence and network approvals

An operator can let Helper read one Worker's network approval and its diagnostic.
Helper can prepare that fixed action for a human decision. Approval grants
reusable network access for Worker at the recorded host and port until explicitly
removed. Rejection records a terminal disposition and leaves permissions unchanged.

Use the running native instance and its trusted agent listeners. The operator
assigns a durable `agent_id` in each agent's policy metadata. Keep that identity
when editing its policy; assign a new identity when recreating the agent. Helper
uses its normal Agent API token. Keep `data/admin_token` on the host.

First, read Worker's pending request with the native operator client:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" approvals list --agent worker
```

A native network prompt records `request_id` and
`details.network_action`. The action binds Worker's durable identity, the host,
the port and the relevant network-policy revision. Historical prompts without
that binding remain available through their existing operator actions.

Replace `REQUEST_ID` with the selected pending request and grant Helper its
diagnostic and approval reads:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" approvals share REQUEST_ID --agent worker --helper helper
```

The existing native policy operation records only those selected reads. It
retains the rest of the policy and does not grant network permission. See the
[Helper commands](native-operator.md#helper-preparation) to read the evidence,
prepare the exact action, and return it to the human decision.

For operators editing policy directly, the saved schema remains available. This
example is illustrative: replace both durable identities and `request_id` with
the host-owned identities and pending request you selected. Retain the rest of
your current policy.

```toml
[agents.worker]
agent_id = "ag-11111111111111111111111111111111"

[agents.helper]
agent_id = "ag-22222222222222222222222222222222"
evidence_reads = [{reader_id="ag-22222222222222222222222222222222", agent="worker", agent_id="ag-11111111111111111111111111111111", request_id="req-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", reads=["diagnostic", "approval"]}]
```

To use the policy-editing path, save the candidate as `selected-policy.toml` on
the host and apply it through the existing native command:

```sh
"$HOME/.safeyolo-native/bin/safeyolo" --root "$HOME/.safeyolo-native" policy apply selected-policy.toml
```

The result reports `active`. Adding selected reads does not invalidate Worker's
network action. Removing a selected read or changing either agent identity
withdraws Helper's access. These reads return the fixed diagnostic and approval
projection. They do not expose captured bodies, headers, raw audit rows, other
requests or the untrusted preparation reason.

The shared operations use the following authenticated routes. Replace `ID` with
the selected request ID. Agent routes use the plain-HTTP internal Agent API
through Helper's configured proxy; operator routes use the host Admin API.

| Caller | Request | Result |
| --- | --- | --- |
| Helper | `GET /explain?request_id=ID` | Selected network diagnostic, action and trusted effect. |
| Helper | `GET /approvals/ID` | Canonical action and disposition. |
| Helper | `POST /approvals/ID/prepare` with `{"action":ACTION,"reason":"literal explanation"}` | Pending preparation of the exact action returned by the read; no policy change. |
| Operator | `GET /admin/approvals/ID` | Canonical action, actual reusable effect and separately labelled `untrusted_reason_text`, when retained. |
| Operator | `POST /admin/approvals/ID/readers` with `{"helper":"helper","helper_id":"CURRENT_DURABLE_ID"}` | Idempotent selected diagnostic and approval reads; no network grant. |
| Operator | `POST /admin/approvals/ID` with `{"decision":"approve"}` or `{"decision":"reject"}` | Canonical terminal disposition and exact action; the resolver does not accept caller-supplied scope. |

CLI and Commander network decisions use this common resolver for bound native
prompts. Repeat or concurrent decisions return the first terminal disposition.
A relevant policy change or recreated Worker makes a pending action stale;
approval returns 409 and needs a new request and human decision. The operator
can still reject that stale request without changing permissions. A changed
action cannot be substituted during preparation. Helper cannot call the operator
mutation or grant itself evidence reads.

If the resolution response is lost, read `GET /admin/approvals/ID` before taking
another action. A committed allow rule carries its request and action identity,
so the canonical approved outcome remains readable if its audit receipt fails.
Unavailable evidence returns 503. Direct operator policy commands remain usable.
Raw audit files and separately authorised flow reads and exports retain their
existing access; selected Helper reads do not redact that operator evidence.

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
