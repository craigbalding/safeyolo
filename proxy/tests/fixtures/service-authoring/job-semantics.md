# Controlled job API semantics, version 1.0.0

This maintained fixture defines a local application programming interface (API)
for service-authoring tests. Its paths and semantics are illustrative. They are
not verified Rundeck API facts. The OpenAPI document and this text are the
authoritative inputs for this controlled model. No live service is required.

## Identity and authority

A stored job has the composite identity `(project, job)`. A job in another
project is a different resource, even when its job identifier is equal.
Definition replacement, partial editing, execution and inspection use this same
identity. An alias can select a job, but this fixture supplies no alias-resolution
evidence. An alias operation therefore has an unresolved job identity.

The upstream credential needs the applicable definition-read, definition-write
or run permission. When execution occurs, the configured job runner account runs
the stored steps. That account can differ from the API caller. The model does not
verify the runner's credentials, external permissions or selected steps.

## Operations and arguments

| Operation reference | Defined behavior |
|---|---|
| `replace_definition` | A PUT replaces the stored definition. Omitted `steps` installs `['diagnostic']`; omitted `description` installs an empty string. Replacement can change executable steps and descriptive text. |
| `edit_definition` | A PATCH changes only supplied fields. Supplied `steps`, including an empty array, can change executable behavior. Supplied `description` changes descriptive text. Omitted fields stay unchanged. |
| `execute_job` | A POST with query `mode=execute` can execute stored steps. `mode=preview` validates stored syntax without running steps. Omitted `mode` defaults to `execute`. The upstream API accepts only these two mode values. |
| `inspect_definition` | A GET reads the stored definition. It does not execute steps or prove that the runner works. |
| `execute_alias` | A POST can execute the job selected by an alias. The target job is unresolved in the supplied evidence. |
| `status` | The operation is in the supplied inventory, but its effects are uncharacterised. |

The upstream requirements and defaults are semantic facts of this controlled
API. They do not add SafeYolo request enforcement. In particular, the native
request executor does not require a query or body field merely because OpenAPI
marks it required.

## Shared effects and persistence

Both replacement and partial executable editing produce the named possibility
`executable_changed`. The one `changed_job_execution` rule combines that effect
with `executed` for the same project/job. The rule does not depend on an endpoint
pair or permission-addition order. Its prerequisites include upstream execution
access and steps that can perform the action in question.

Definition edits persist in upstream storage after SafeYolo access expires.
Access expiry does not stop a launched run or reverse its external writes.
A caller can retain a definition received through inspection. Preview avoids
step execution under the represented API semantics; unmodeled upstream logging
and other side effects remain outside this partial inventory.

## Enforcement evidence

The tests in `proxy/tests/service_authoring.rs` run the current native
`enforce_request` function on the generated contracts. They establish these
request-check facts:

- Approved project/job path bindings exclude a different job path.
- The `describe_job` body allowlist permits `description` and rejects `steps`.
  The `edit_job` contract permits `steps`.
- The allowlist accepts an empty JSON object. It does not require allowed fields.
- A query equality binding for `mode=preview` rejects a supplied `mode=execute`.
  It accepts omission of `mode`. Because omission defaults to execution, the
  binding alone cannot exclude execution from the possible grant effects.
- The diagnostic inspection request passes its generated read contract.

These tests do not run an upstream job API or evaluate consequence rules.
Regression expected effects and overlap results are reviewed authoring inputs
for a future evaluator. Loading checks their references and scope claims against
current path enforcement. Validation does not prove that each semantic claim or
regression expectation is correct.

## Coverage and assumptions

Every supplied operation is either modeled or explicitly uncharacterised.
The inventory does not cover undocumented upstream behavior. OpenAPI parameter
and body declarations alone cannot establish business effects. The reviewed
annotations supply those effects and identify the source of each claim.

The diagnostic alternative reads a stored definition. It requires a real job and
an upstream credential with read access; neither prerequisite was tested here.
It can help inspect syntax and configuration. It cannot establish runner
connectivity, successful execution or general suitability for an operator's task.

All effects are possibilities, not evidence that an operation occurred.
Unknown semantics and absent rules establish no safety guarantee and introduce
no automatic denial. Definitions grant no access. Operator adoption, service
authorization, credentials and request policy remain separate.
