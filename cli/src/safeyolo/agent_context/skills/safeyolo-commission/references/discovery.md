# Discover the selected setup

Use the interfaces available to the selected agent. A preferred agent can run
on the owning host or inside an authorized guest. Do not assume host access,
universal read-only access or permission to inspect another worker's home.
The [operator interaction contract](https://github.com/craigbalding/safeyolo/blob/master/docs/operator-interaction-contract.md)
defines context, decision, activation, evidence, outcome and continuity.

## On the owning host

Use the installed native command under the account that owns the instance.
First identify the executable and selected root. For the ordinary default
instance, these commands read identity and status without starting it:

```sh
safeyolo --version
safeyolo status
```

Status reports the selected root, proxy state and configured agents. For a
different selected instance, preserve its explicit `--root` or `--config`
selection on subsequent commands. A running proxy does not establish that a
worker, provider or control is operational.

Within the selected host authority, inspect the relevant saved configuration,
active `policy show`, source status, service definitions and credential/grant
references. Use command help and structured output for the installed version.
Inspect only metadata needed for the task; do not dump credential stores,
tokens, raw sessions or unrelated configuration into a briefing. A compile
check establishes neither activation nor a provider's live behavior.

## Inside a guest

Use the installed [SafeYolo skill](../../safeyolo/SKILL.md) and its
[Agent API reference](../../safeyolo/references/agent-api.md) for authenticated
read shapes. Preserve the proxy and certificate authority configuration.
Useful reads include `/health`, `/status`, `/agents` and `/operator-actions`.
The visible agent inventory is scoped discovery, not proof of all configured
workers. `/operator-actions` lists the calling agent's offered action
vocabulary; it does not authorize an effect. A gateway service listing contains
scoped tokens: select only required nonsecret metadata before displaying or
retaining it.

For existing collaborative work, read selected Coord room state and the
canonical Work, output, review and signal records. Read the installed
[Coord reference](../../safeyolo/references/coord.md) when choosing those
operations. Membership or a capability declaration establishes neither peer
administration nor a working integration. Current grants and actual consumer
results determine the next usable operation.

A missing host view stays unavailable. Keep the exact selected target and
needed operand in an existing request to its authorized owner. Do not ask for
Admin credentials or substitute arbitrary host commands. Reuse an already
authorized servicing/configuration path when it supplies the required effect.

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
