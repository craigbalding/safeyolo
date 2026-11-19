---
name: policy-authoring
description: Turn an operator's cyber brief or research workload and risk choices into a reviewable SafeYolo policy, source and check configuration. Discover installed policy capabilities and request an operator-approved full local policy snapshot in an ordinary guest. Author and apply through the owning host's existing policy authority. Keep administrative credentials outside the research workload.
---

# Author a research policy

Use the installed `safeyolo` commands and the selected instance's current
configuration. This skill supplies the first cyber research recipe. It grants
no host or policy access. Inside an ordinary guest, use the approved snapshot
workflow below to prepare proposed choices. The host owner still performs
privileged operations and policy application.

Read [capability discovery](references/capabilities.md) for the guest sequence:
discover → compose → validate the accepted form → assess → revise or discuss
with the operator → submit through the existing owner. Discovery and component
validation grant no permission. A valid component is not a complete candidate
safety assessment. Discovery is available before full-policy disclosure.

## Read the full local policy in a guest

Use the installed `request_policy_snapshot` and `read_policy_snapshot` tools.
Choose a fresh operation ID (`req-` followed by 32 lowercase hexadecimal
digits) before submitting. Retain that ID if the response is lost. The tools
select the authenticated local instance and current requester; they accept no
host path, remote home or identity override.

For a shell invocation in the ordinary Linux guest, replace the example ID
with your chosen operation ID. The following command creates a canonical
request for the human operator; it grants no permission by itself:

```sh
printf '%s\n' '{"operation_id":"req-0123456789abcdef0123456789abcdef"}' |
  safeyolo-coord call request_policy_snapshot
```

The response identifies the canonical approval and snapshot, source revision
and saved/active status. Ask the existing operator to inspect that approval
through the normal approval interface. Send the approval reference and purpose,
not policy contents. An agent deciding delegation cannot approve this request.

After the human approves, read the same operation ID or returned approval ID:

```sh
printf '%s\n' '{"request_id":"req-0123456789abcdef0123456789abcdef"}' |
  safeyolo-coord call read_policy_snapshot
```

Only an approved response contains `snapshot.source`. Pending, rejected,
superseded, expired or unavailable state supplies no source. Reconcile an
uncertain request or read with its original ID. Repeated reads return the same
approved bytes, including after the live policy changes. Request a new snapshot
when different source bytes are needed. Reads require the original current
requester/run and use the existing seven-day terminal approval-result retention.

`source_kind: saved_authored_toml` identifies the saved authored document.
`source_revision`, `saved_source_revision` and `active_source_revision` identify
its SHA-256 source bytes and active basis. A mismatch is explicit. Effective
controls/defaults and expanded inputs describe active observations separately;
do not insert them into authored text by accident. `/policy` remains the
existing compiled baseline read and omits authored support/delegation settings.

Keep the complete snapshot and candidate private. Preserve its identity,
credential references and `redactions` field paths. Each hidden literal
credential has a snapshot-bound preservation marker. Leave that marker at its
original field; deleting, moving or substituting it cannot authorize a hidden
value change. The host retains restoration data. Use `assess_policy` with the
original snapshot request ID, complete candidate source and installed
`definition_version` from discovery. Assessment is private and read-only.
Read its consequences, narrower alternatives and coverage limits, then revise
or discuss the tradeoff. Private assessment does not submit an approval or
apply a policy. The authorized host owner can inspect the same candidate with
`policy assess SNAPSHOT_REQUEST_ID FILE`. Final adoption needs that owner's
explicit current authority. Never request an Admin token or copy host
configuration into the guest.

Read [the walkthrough](references/recipe.md) for the complete first run,
host discovery, prerequisites, helper commands and saved-choice updates.
Read [sources and controls](references/sources-and-controls.md) when choosing
a provider or explaining coverage, disclosure, precedence or unsupported cases.

Discover before authoring. Identify the installed executable/version and the
intended root, `config.toml`'s selected `policy_file`, saved policy, active
`policy show`, `policy feeds status`, service catalogue, relevant grants and
saved preferences. An unavailable read remains unknown. A directory name or
successful compile does not establish activation or a usable provider.

Resolve only material missing choices: focused or periodic work, required
reporting destinations, exclusions versus advisory findings, registration-age
threshold, evidence freshness, unavailable/error actions, privacy/cost limits
and relative advisory priorities. Preserve existing controls and reuse current
authorization. The bundled preferences are an optional example, not defaults
for all operators. A bounded change can reuse saved choices without repeating
the questionnaire or adding a confirmation ritual.

Research providers from primary documentation. Distinguish passive lookup,
input retention and active subject scanning. Identify disclosed data, coverage,
score meaning, freshness and access requirements. Select an explicit provider
and endpoint; do not turn an example into a universal requirement. RDAP
registration, provider first-seen and SafeYolo local first-seen are different
facts. A finite-window list no-match cannot establish an older domain.

Generate with [author.py](scripts/author.py), using TOMLKit to retain unrelated
controls and inline agent settings. It writes private candidate files, selected
preferences, source/service configuration and a rationale; it does not contact
providers or activate policy. Preserve material existing controls. Reconcile a
reported collision instead of deleting a control to make generation succeed.
Explain any new authority, removals, fallback and expected approval behavior.

Run `policy check` and representative `policy evaluate` cases. Check is
compile-only. Evaluate is an offline decision simulation using captured
records/feed snapshots; service/job evidence remains unavailable. Never visit,
scan, crawl or indirectly fetch the subject to improve a preview. An explicitly
authorized passive provider capture is a separate data-disclosing operation;
do not call it offline or silently add it. Deterministic adverse cases are
fixtures, not evidence that a live integration works.

Within existing operator authorization, configure sources, install the reviewed
service definition and apply the candidate through existing host controls.
Verify `policy show`, accepted source status and the actual research request.
If activation is uncertain, inspect the selected root before another write.
Keep saved, active and unknown states distinct; preserve the previous policy
and source definitions for their existing rollback mechanisms.

Use [brief.py](scripts/brief.py) for a bounded real periodic/focused example.
Run it in the research guest through ordinary proxy authority. It fetches only
CISA's public catalogue and writes a short referenced brief. It never fetches
URLs embedded in reports. Reuse existing cron/at or host scheduling; do not
build a scheduler or require repeated approvals for authorized work.
