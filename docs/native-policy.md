# Native policy commands

The native CLI validates, displays and applies host-centred policy through the
existing native proxy. Use a fresh instance directory. This first increment
supplies policy commands; the remaining host commands and final release packages
have separate implementation work.

## Install and start

On supported Ubuntu, run the following command as your ordinary host account
from the repository checkout. The source installation requires Bash and Rust
1.94. The directory `$HOME/.safeyolo-native` must have no existing instance
configuration or operator token. Installation builds the production CLI and
proxy, installs both in `bin`, and creates `config.toml`, `policy.toml`, a private
operator token, and separate runtime and log directories.

```sh
./scripts/install_native.sh --root "$HOME/.safeyolo-native"
```

The installer prints the full source commit and build profile. If matching
native binaries are already built, supply their directory with `--artifacts`;
installation then copies those binaries without compiling. The installed
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

[[listeners]]
agent_id = "bob"
socket_path = "data/bob.sock"
```

The Admin API binds IPv4 loopback and requires the token in `data/admin_token`.
Keep that token on the host. Start the proxy in a host terminal:

```sh
"$HOME/.safeyolo-native/bin/safeyolo-proxy" --config "$HOME/.safeyolo-native/config.toml"
```

The process remains in that terminal. A usable instance has an accepted
`data/ready.json` marker and accepting agent sockets. An occupied endpoint or
unreadable input produces a startup error. Press Ctrl-C in that terminal to stop
the proxy after using the commands below.

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

When an external edit is invalid or activation cannot complete, show reports
`saved_differs` or `saved_unreadable`, preserves the active values in `effective`,
and names a repair action. Correct the input or filesystem access, then apply a
valid candidate. A whole replacement can repair an invalid saved document
without restarting the process. If the Admin API connection fails, the CLI
reports that activation is unconfirmed and tells you to restore that connection
before reading the active policy.

## Policy and runtime settings

`config.toml` owns paths, listeners and runtime settings. `policy.toml` owns
network and credential decisions, named lists, agent overrides, budgets,
advanced host rules, service policy and named controls. The fresh loader does
not read `addons.yaml`. Replaced fields, such as `addons`, `required`, `bypass`
and `global_budget`, produce named validation errors.

Check resolves named list files relative to the checked policy. Apply records
those file references as absolute paths so saving the candidate under the
instance root does not change which list the native process loads.

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
