# Native SafeYolo CLI

The installed `safeyolo` executable controls the native proxy, agents, policy,
operator evidence and Coord. Select an instance with `--root ROOT` before the
command, or set `SAFEYOLO_CONFIG_DIR`. The default root is `$HOME/.safeyolo`.
The configuration is `config.toml`; policy and agent settings are in
`policy.toml`. No Python CLI, wheel or generated YAML configuration is loaded.

## Installation

Use [native installation](../docs/native-policy.md#install-and-start) on a
supported host. The unpacked bundle and the repository's `install.sh` invoke
the same installer. Supply a fresh root and either `--bundle UNPACKED_BUNDLE`
or the prepared native build inputs described in the
[source build instructions](../docs/native-policy.md#build-a-native-bundle).
Prepare the [guest runtime](../docs/native-policy.md#guest-prerequisites)
before starting an agent. There is no migration or Python-package rollback
operation in this fresh-state product.

```sh
./install.sh --root "$HOME/.safeyolo-native" --bundle "$HOME/native-bundle"
export PATH="$HOME/.safeyolo-native/bin:$PATH"
export SAFEYOLO_CONFIG_DIR="$HOME/.safeyolo-native"
safeyolo start
safeyolo status
safeyolo doctor
```

Start returns after the proxy publishes readiness. Status/doctor emit JSON
and distinguish proxy, sandbox, coding command, terminal and control state.
An occupied endpoint or missing artifact fails visibly; inspect the named
error and `logs/proxy.log` before retrying. Version reports source and profile.

## Agents

Create an agent with an existing owned workspace and a trusted host script.
Installed scripts are under `ROOT/assets/contrib`. Relative saved paths are
resolved by the native configuration owner, not by the later shell's directory.

```sh
safeyolo agent create work --workspace "$HOME/code" --host-script "$SAFEYOLO_CONFIG_DIR/assets/contrib/codex-host-setup.sh"
safeyolo agent start work
safeyolo agent status work
safeyolo agent attach work
safeyolo agent shell work -c 'ls -la /workspace'
safeyolo agent diagnostics work
safeyolo agent stop work
```

Use `agent configure` to change the saved workspace, memory, mounts, host
script, command or launcher. Changes affect the next sandbox start. Use
`--foreground` for a foreground coding terminal, `--sandbox-only` to boot
without a harness, and `-- ARGUMENTS...` for that launch's harness arguments.
Attach only reconnects to an existing terminal. `agent shell --persistent NAME`
opens an independent persistent shell. Supported launcher choices and explicit
supervision are in [agent launchers](../docs/agent-launchers.md).

`agent present NAME` opens the running native desktop through the existing
operator presentation owner. Set remembered geometry and permitted host port
in the [desktop settings](../docs/native-settings.md#runtime-settings).
Guest desktop/browser commands remain described in the
[desktop skill](src/safeyolo/agent_context/skills/safeyolo/references/desktop.md).

Stop each agent separately before `safeyolo stop`. The top-level stop shuts
down the proxy and owned Coord runtime, while leaving sandboxes intact.
`agent cleanup NAME` reconciles stopped run state; it is not an instruction
to delete a persistent home or erase forensic evidence.

## Policy and service gateway

[Native policy commands](../docs/native-policy.md) validate, show and apply
host-centred policy. Controls keep their existing network, credential, pattern,
test-context and circuit semantics. Lists resolve relative to their policy.
Edit a candidate TOML file, check it, then apply it to the running instance:

```sh
safeyolo policy check "$HOME/reviewed-policy.toml"
safeyolo policy apply "$HOME/reviewed-policy.toml"
safeyolo policy show
```

Show reports loaded effective policy and saved/live differences. Network
permission does not grant credential permission. [Native credentials and
services](../docs/native-credentials.md) store local values or host-controlled
1Password references, then authorize the selected service capability. OAuth
credentials accept the operator's token and refresh fields; refresh uses the
same native store. Service authorization, contract binding, credential approval
and risky-route approval remain distinct. See [service discovery](../docs/SERVICE_DISCOVERY.md)
and [the responsibility map](../docs/native-settings.md#operator-entry-responsibilities).

## Operator evidence and approvals

Use [native operator commands](../docs/native-operator.md) for `inspect`,
`traffic`, `approvals`, `logs`, `diagnose` and `helper`. They use explicit
instance/agent selection and the existing evidence and decision authorities.
Logs and diagnosis remain available when the Admin API is down. The retained
exports are raw, raw_request, raw_response, curl, httpie, har and zhar.
Commander provides the Mac GUI with the same native owners.

## Coord and factories

[Coord operations](../docs/coord-operations.md) and
[native communication](../docs/native-coord.md) cover room setup, scripted
send, chat, canonical history and event observation. The installed native
`safeyolo-coord` supplies guest commands, MCP stdio and bounded supervision.
[Factories](../docs/factories.md) reuse these rooms and role contracts.
[Mattermost](../docs/coord-mattermost.md) and [Dispatch](../docs/dispatch-generation.md)
retain their selected native adapter paths.

## Lab

[The native Lab](../docs/agent-debugging.md) prepares and observes controlled
experiments in an owned agent. Use `safeyolo lab --help` for workspace,
objective, existing-agent, status and teardown options. Guest evidence capture
is native; selected test instruments may use Python outside the product.

## Repository tests

Python `>=3.12,<3.14` is required only for repository tests and black-box
drivers. `uv sync --frozen --group dev` prepares a non-package test environment;
it does not publish a `safeyolo` entry point. Retained behavior references
under `tests/reference` construct protocol/storage fixtures. Native behavior
is tested through `proxy/tests`, `tests/proxy_contracts` and the
[installed suite](../tests/blackbox/README.md).
