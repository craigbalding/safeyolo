# Discover and compose a policy change

An ordinary installed guest can read the installed capability vocabulary before
policy disclosure. Use the guest's existing proxy, certificate configuration
and Agent API token. The installed `safeyolo-coord` tools keep the token out of
arguments and output. These commands write proposal files in the current guest
working directory. They do not read full policy, contact a protected target,
change policy or issue access.

## Discover

Call `discover_policy_capabilities` through the installed Model Context Protocol
(MCP) tools, or use the same native command:

```sh
printf '%s\n' '{}' | safeyolo-coord call discover_policy_capabilities > capabilities.json
```

Read `definitions`. Each entry identifies its owner, generated schema, scope,
lifetime, declared effects, dependencies, validator reference and coverage gaps.
`operation_definitions` contains the installed tool schemas. `definition_version`
identifies the implementation sources and lockfile compiled into this executable.
`build_revision` identifies the declared source commit separately.

Generic results contain no agent identities, grants, configured service bindings
or secret values. Current permission and readiness are unknown. To request only
observations already readable by this caller, run:

```sh
printf '%s\n' '{"observe":true}' | safeyolo-coord call discover_policy_capabilities
```

Support grants come from `support_grants`. Services project the existing
`GET /gateway/services` view without its secret fields. Desktop availability
comes from the existing operator-action owner. Current observations carry a
policy or grant/definition revision and observation time where applicable.
An unavailable or undisclosed read remains unknown. It does not mean the
operation is prohibited or unsupported. Service readiness and configured effect
contents can remain unknown or undisclosed even when access is granted.

For a support operation, use `observe_support_capability` with
`definition_version` and a `request` matching the returned support request
schema. Select the grant and durable target from your own current support
read. The observation uses the support owner's permission check and runtime
observer. It does not execute the request or create an operation receipt.
Supported, granted, requestable, prohibited and unavailable facts are separate.
For example, a granted guest command can be unavailable because the sandbox is
stopped. An explicit scope prohibition still permits an operator-directed
proposal to change that scope. Forged, undisclosed or replaced targets remain
unknown. Refresh after a policy, definition, identity or runtime change.

## Compose and check the accepted form

This example proposes warning behavior for the network control. It is an
example choice, not a default or a recommendation to weaken an existing
control. Python 3 reads the returned schema and validator reference and writes
a component proposal. No operator-authored schema is required.

```sh
python3 - <<'PY'
import json
from pathlib import Path
catalog = json.loads(Path('capabilities.json').read_text())
control = next(item for item in catalog['definitions']
               if item['definition'] == 'controls')
assert 'warn' in control['schema']['$defs']['Action']['enum']
proposal = {
    'definition': control['validator']['definition'],
    'definition_version': catalog['definition_version'],
    'value': {'network': {'action': 'warn'}},
}
Path('control-proposal.json').write_text(json.dumps(proposal))
PY
safeyolo-coord call validate_policy_capability < control-proposal.json
```

Expected result: `valid: true`, `authorized: false`, `activated: false` and
`assessment: not_performed`. The existing native control validator checks the
form. An obsolete definition version is refused. Support, delegation, desktop,
diagnostic-sharing and service forms use their named parsers and validators.
Read each definition's limits: effect-model shape checking alone does not
validate service references, identities or a complete policy. A dynamic service
definition uses the service parser rather than an invented parallel schema.

## Assess, revise and submit

Explain the proposed behavior and why the operator's outcome needs it. Review
effects, audience, lifetime, dependencies, credential custody, disruption and
what remains unknown. Use the existing service effect model and current
operator previews where relevant. Component validation and offline network
simulation are not a complete analysis of combined authority. Candidate-wide
assessment and adoption remain separate capabilities; discovery does not
claim those outcomes.

Within existing disclosure authority, obtain the current authored source and
preserve unrelated fields. The compiled `/policy` baseline is not a complete
copy of authored policy. Do not reconstruct hidden authored fields from an
undisclosed result. Revise the proposal or discuss a material choice with the
operator when necessary. Ordinary work within existing approval needs no new
confirmation ritual.

Send the component, definition version, intended behavior and relevant current
references to the existing policy owner. On the owning host, that owner combines
the change with the authorized current source, runs `policy check` and relevant
`policy evaluate` cases, and uses the current preview/apply operation under its
existing authority. Support and delegation changes retain their exact preview
acknowledgments. Services retain their existing definition/reference checks.
Execution revalidates current policy, identity and runtime prerequisites.

After an authorized apply, inspect `policy show` and the affected consumer.
Saving, activation and actual behavior are separate results. Inspect an
uncertain effect before retrying it. Reading or replaying discovery never grants
permission or substitutes for an apply.

On the owning host, the readable view is `safeyolo policy capabilities`.
`--json` returns the same generated vocabulary and validator references for the
selected executable. Instance observations use the installed agent tools above.
