# Approved full local policy snapshots

An ordinary agent can request the selected local instance's complete authored
policy through `request_policy_snapshot`. The human operator decides through
the existing approval interface. `read_policy_snapshot` returns the approved
source only to its original current agent/run. The installed
[policy-authoring skill](../cli/src/safeyolo/agent_context/skills/policy-authoring/SKILL.md#read-the-full-local-policy-in-a-guest)
provides the guest commands.

The request accepts a caller-chosen operation ID. It accepts no file path,
instance selection, source text or requester identity. Source capture uses the
native policy owner and selected `policy_file`, with the normal policy file
lock and runtime lock order. Snapshot data is committed privately alongside
the existing pending approval. There is no additional approval queue or policy
source of truth. Disclosure and reads make no policy or grant changes.

The operator sees the requester/run, instance, exact source revisions,
saved/active agreement, redaction field identities and disclosure scope. This
decision requires the human operator; existing agent deciding delegations do
not authorize full-policy disclosure. The approval permits this identified
snapshot, not a later revision or policy application. A changed approval basis
before the decision produces `superseded`; prepare a new request.

## Source and identity

The approved response contains `snapshot` with these fields:

| Field | Meaning |
|---|---|
| `snapshot_id`, `instance_id`, `requester` | Snapshot identity and its bound local instance, durable agent and run. |
| `source_kind` | `saved_authored_toml`; the returned document is the captured saved source. |
| `source_revision`, `saved_source_revision` | SHA-256 of the original saved authored bytes, before redaction. |
| `active_source_revision`, `saved_matches_active` | Active authored-source identity and comparison at capture. |
| `source`, `disclosed_source_revision` | Disclosed TOML and SHA-256 of those bytes after required redactions. |
| `effective`, `expanded_inputs`, `effective_source` | Separate observations of active controls/defaults, logging and expanded lists. These are not authored source bytes. |
| `assessment_inputs_revision` | Identity of captured adopted list contents, scope and expiry semantics used by private assessment. It grants no read of later inputs. |
| `redactions`, `preservation_ref` | Hidden field paths and markers, with a reference to private host-held restoration data. |

The snapshot includes all agents' authored controls, settings, grants and
support/delegation definitions. It does not select the requester's subset.
The existing `GET /policy` remains a compiled baseline read; it omits some of
these authored fields. Existing authorized policy and diagnostic reads retain
their behavior.

Credential references, including service `token` references, remain visible.
Literal string fields named `password`, `passphrase`, `client_secret`, `api_key`,
`access_token`, `refresh_token`, `authorization` or `admin_api_token` are
redacted, including fields inside JSON-encoded policy records. Their other
fields and structure remain visible. Classifier definitions and references are not resolved. This is not a
credential-store or configuration-file export, or a general secret scanner for
arbitrary authored prose/comments. Native service credentials and generated
gateway/Admin tokens are not fetched into the snapshot.

## Materialization contract

The host retains original authored bytes in the private canonical approval
database. Each redaction records a path of TOML keys/array indices, an optional
`json_path` within an encoded policy record, and a snapshot-bound string marker.
The host materializer restores a hidden value
only when its original field still contains its own marker. Removing the field,
replacing its marker, moving/copying markers or inventing one is refused.
Unchanged disclosed source materializes to the exact original bytes. Ordinary
edits retain unrelated source fields and comments through the existing TOML
editor. Materialization itself performs no policy application or file write.

The [private policy assessment](policy-assessment.md) uses this materializer
and captured adopted list contents. The adoption owner must separately authorize explicit hidden-field changes, bind the
materialized candidate and compare its exact saved/active base before applying
it through the existing transaction. A disclosure approval grants none of
those permissions.

## Reconciliation and retention

Read the original operation ID or returned approval ID after a lost response.
An approved read returns the retained snapshot even if the live policy has
changed. Another agent, a replaced durable identity or a different run cannot
use the request identifier to read its source. The existing terminal
approval-result retention is seven days. Expired private snapshot data is
removed by the existing approval-result scan; canonical identity and outcome
remain. Logs and shared attention contain references and outcomes, not source
or restoration values. Keep disclosed source private in the agent workspace.
