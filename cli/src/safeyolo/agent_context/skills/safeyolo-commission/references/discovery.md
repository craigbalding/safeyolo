# Discover the selected setup

Use the interfaces available to the selected agent. A preferred agent can run
on the owning host or inside an authorized guest. Do not assume host access,
universal read-only access or permission to inspect another worker's home.
The [operator interaction contract](https://github.com/craigbalding/safeyolo/blob/master/docs/operator-interaction-contract.md)
defines context, decision, activation, evidence, outcome and continuity.

## On the owning host

Use the installed native command under the account that owns the instance.
Resolve the executable and root from the retained selection. Keep that command
prefix for every read, including after interruption. For an explicitly selected
instance, set these variables to its actual executable and root before running
the read-only identity and status commands:

```sh
selected_cli=/absolute/path/to/installed/bin/safeyolo
selected_root=/absolute/path/to/selected/instance
"$selected_cli" --version
"$selected_cli" --instance-dir "$selected_root" status
```

Status reports the selected root, proxy state and configured agents. Verify
that the returned root matches the retained selection before using the report.
If the roots differ, inspect and correct the invocation; do not silently adopt
the default instance or ask the operator to choose an already known target.
Preserve an existing explicit `--config` selection in the same way. A running
proxy does not establish that a
worker, provider or control is operational. The host command reads the saved
configured-agent list independently of proxy availability. A successful empty
configured list remains an empty list even when `proxy_state` is unavailable;
do not label the whole status response unavailable. Active policy can still
be unavailable while saved configuration and local task work are usable.

Within the selected host authority, inspect the relevant saved configuration,
active `policy show`, source status, service definitions and credential/grant
references. Use command help and structured output for the installed version.
Inspect only metadata needed for the task; do not dump credential stores,
tokens, raw sessions or unrelated configuration into a briefing. A compile
check establishes neither activation nor a provider's live behavior.

## Inside a guest

Use the installed [SafeYOLO skill](../../safeyolo/SKILL.md) and its
[Agent API reference](../../safeyolo/references/agent-api.md) for authenticated
read shapes. Preserve the proxy and certificate authority configuration.
Choose the [discovery surface](../../safeyolo/references/agent-api.md#discover-the-right-capability)
for the task. Installed policy capabilities and current support grants expose
product paths beyond external services and typed operator actions.
Useful reads also include `/health`, `/status`, `/agents` and `/operator-actions`.
The Agent API's `/agents` reports discovered agents and last-seen information;
it is not the host's saved configured-agent list. Its visible inventory is
scoped discovery, not proof of all configured workers. `/operator-actions`
lists the calling agent's offered action
vocabulary; it does not authorize an effect. A gateway service listing contains
scoped tokens: select only required nonsecret metadata before displaying or
retaining it.

For existing collaborative work, read selected Coord room state and the
canonical Work, output, review and signal records. Read the installed
[Coord reference](../../safeyolo/references/coord.md) when choosing those
operations. Membership or a capability declaration establishes neither peer
administration nor a working integration. Current grants and actual consumer
results determine the next usable operation.

A missing host view stays unavailable. Reuse an already authorized servicing or
configuration path when it supplies the required effect. If an operator step
is necessary, prepare the documented command or approval request for the exact
selected target, explain what it enables, and resume after effective access
changes. For creation and support of another worker, use the
[agent handoff](../../safeyolo/references/agent-launchers.md).
Do not ask for Admin credentials or substitute arbitrary host execution for a
denied operation. A missing grant is not evidence that the product lacks a
supported way to grant it.

## Saved choices and evidence

Locate the existing task document from the current workspace, retained work
reference or operator-selected path. Read only the task-relevant files. Do not
scan other homes to guess an identity. Recover source/version references and
saved versus active settings before making another proposal.

Record where a fact came from and when freshness matters. Keep these meanings
distinct: observed now; retained but not rechecked; successful empty result;
unavailable read; proposed and not installed. Reuse a retained result when its
inputs and validity still fit. To test a provider or active scan, first establish
the authority for that separate effect; do not disguise it as inventory.
