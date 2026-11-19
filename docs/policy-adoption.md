# Review and adopt an agent's exact policy change

An agent can prepare a multi-section change from an
[approved full-policy snapshot](policy-snapshots.md),
[assess and revise it privately](policy-assessment.md), then explicitly submit
one immutable candidate. The human operator reviews the trusted consequences
and complete redacted source diff through ordinary approvals. Disclosure,
assessment and submission grant no application authority. The agent receives
no Admin credential and cannot approve its own change.

## Submit from the agent

Use `submit_policy_change` with a new `operation_id` chosen before the request.
The `candidate` is the same object supplied to `assess_policy`:

```json
{
  "operation_id": "req-0123456789abcdef0123456789abcdef",
  "candidate": {
    "snapshot_request_id": "req-11111111111111111111111111111111",
    "source": "COMPLETE AUTHORED CANDIDATE TOML",
    "definition_version": "EXACT VERSION FROM CAPABILITY DISCOVERY"
  }
}
```

The values above are placeholders. Keep the approved snapshot's preservation
markers at their original fields. The host materializes the complete source
with its retained secret values. Removing or replacing a hidden value requires
an explicit authorized change through the host policy owner; a marker cannot
become a literal policy value. Unrelated authored fields and comments remain
part of the candidate. Candidate-provided instructions and explanations cannot
change the host-computed effects or decision authority.

The installed shell interface accepts the same structured tool input:

```sh
safeyolo-coord call submit_policy_change < submission.json
```

Only explicit submission creates a canonical pending approval. Invalid forms
and new dependencies that need trusted adoption are refused before submission.
Candidate validation never opens an arbitrary candidate-supplied host file,
fetches a dependency or executes a check. Adopt new list, check and service
inputs through their existing owners first. No universal risk threshold or
restriction to predefined permission tweaks is imposed.

Retain the returned approval ID and original operation ID. Equivalent pending
submissions reuse canonical deduplication. Different source bytes, including
new hidden literal values, have different candidate identities and decisions.
A retry with changed content under the same operation ID is refused.

## Review and decide on the owning host

Select the intended instance with the ordinary `--root` or `--config` option.
Use its existing `watch` interface, or these explicit commands:

```sh
safeyolo approvals show APPROVAL_ID --json
safeyolo approvals explain APPROVAL_ID --option apply
safeyolo approvals approve APPROVAL_ID --option apply --json
```

Use `safeyolo approvals reject APPROVAL_ID --json` to decline. In `watch`, select
the displayed request and use `approve apply` or `reject`. Review the affected
identities, scope, lifetime, combined effects, limitations and complete
`assessment.exact_diff` before deciding. The source's comments and the agent's
separately labelled rationale are untrusted data. Secret fields remain redacted.
`prior_revision` contains the protected previous source's redacted view.

If the candidate changes request budgets, review the effect on run-scoped
credential approvals. Those grants are bound to a policy revision that includes
the request budgets. After adoption, the same credential, destination and run
can require a fresh credential decision, even when the authored grant remains.
Read that canonical request and its scope before deciding through ordinary
approvals. A harness model request can pause at this boundary. Recover the
policy result by its original operation ID; do not resubmit or replay the
policy decision to resume the harness.

The retained assessment is the review basis. `observed_policy_state` identifies
the currently observed saved and active bytes. For a pending request,
`reviewed_inputs_match_current: false` means the review is stale. The operator
view marks its option unavailable. The final transaction repeats the checks;
a view alone cannot reserve policy state.

For worker configuration, review `assessment.configured_agents`. It identifies
each affected worker, before/after durable identity, changed settings, workspace
and mount access. Saving these settings does not start a sandbox, stage a host
setup script, change a running mount or give the proposer administration.
Sandbox resources and launch settings apply on a later authorized start.
Identity and policy-permission changes can affect current authority through
their existing owners. The report does not inspect host path contents, scripts,
launcher defaults or runtime readiness; the ordinary setup/start owners still
validate their actual inputs.

Only the human decision owner can approve full-policy adoption. Reading the
policy, approving another candidate, agent prose and unrelated approval
delegations supply no authority. Proposed approval or risk rules cannot admit
their own adoption. Existing operator-owned `policy apply FILE` remains usable.

## Read the result and recover

The policy owner compares the exact saved/active base, instance, current
requester/run, definition version, relevant service definitions, temporary
grants and adopted inputs. It holds the existing store, file and runtime locks
through save, activation and receipt recording. A changed base or material
input produces `stale` before policy replacement. The owner never silently
rebases the candidate or overwrites intervening work.

After a lost reply, read the original ID through the installed agent tool:

```sh
printf '%s\n' '{"request_id":"req-0123456789abcdef0123456789abcdef"}' |
  safeyolo-coord call read_policy_change
```

The original current requester/run can read its scoped receipt. The operator
can always use `approvals show` within the selected instance. Readback does not
apply policy. A result notification is a private reference, not permission or
proof of receipt.

| Canonical status | Meaning and next action |
|---|---|
| `pending` | No human decision has applied the candidate. |
| `rejected` | The human declined; policy is unchanged. |
| `approved`, result `active` | The exact materialized source was saved and activated. The receipt names both source revisions and `activation_required: false`. |
| `stale` | The reviewed base or material inputs changed. Obtain a fresh approved snapshot, prepare and assess a new candidate, then request a new decision. |
| `failed` | Admission, saving or activation failed. Inspect the receipt and `policy show`; the existing transaction retains or restores the previous consistent state. |
| `applying` | A decision is in progress or its owner was interrupted. Read the same ID; do not start a second apply. |
| `unresolved` | Consistent recovery could not be established. Inspect saved/live state and use the owning operator's existing policy repair path. Do not replay the decision. |

A terminal receipt records the reached outcome, even after a later policy edit.
Its `observed_policy_state.recorded_result_is_current` distinguishes that
historical outcome from the current source. Replaying a decided approval
returns its receipt and performs no second apply. On a proxy restart, an
interrupted decision is reconciled against the exact saved/live pair; it is
never automatically reapplied. An uncertain or failed recovery remains explicit.

## Deliberately restore the previous source

Inspect the original approval's `prior_revision` and current policy first. Then
prepare a restore with a fresh operation ID on the owning host:

```sh
safeyolo policy restore APPROVAL_ID --operation-id req-22222222222222222222222222222222 --json
```

The host API equivalent is `POST /admin/policy/restore` with `approval_id`
and the new `operation_id`. This prepares another canonical policy candidate.
It does not apply it.
Its complete diff compares the current source with the retained prior source,
including any intervening work. Inspect the returned approval, then approve or
decline it through the same commands. The decision explicitly reinstates that
prior content, including its retained hidden values. It uses current models
and adopted inputs; unavailable dependencies need their existing adoption path.
If another edit occurs after restore preparation, the restore is stale and
cannot overwrite that edit. Prepare a new restore and review its new diff.

Restoring policy cannot retract disclosed information, reverse external
effects or cancel every operation already admitted under the former policy.

## Retention and access

Candidate source, snapshot restoration values, the review and prior source
remain in the existing private approval database, `approvals.sqlite3`, in the
selected instance's data directory. They are not another policy file or source
of truth. The database is host-owned mode `0600`. Shared attention
and ordinary audit events carry identities and outcomes, never full source or
literal credentials. Broader diagnostic or approval-read grants do not expose
the operator-only assessment through the generic agent approval view.

Candidate and restore preparation use the existing seven-day retained-result
period. An exact equivalent request does not extend its deadline. Expired or
missing private content cannot be applied or restored. The existing approval
result cleanup removes retained policy data after the terminal retention
period; canonical outcome metadata remains. Retention is not a promise that
broker attention was delivered or read.
