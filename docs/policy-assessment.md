# Privately assess a complete policy candidate

An agent with an [approved full local policy snapshot](policy-snapshots.md) can
call `assess_policy` before requesting any policy change. The preparation loop
is discover → compose → assess → revise or discuss the tradeoff → explicitly
submit. Assessment creates no approval, operator attention, grant or policy
write. It does not contact an upstream system or execute a check or job.

## Agent preparation

In the ordinary installed guest, use the matching `safeyolo-coord` client and
the per-run proxy and token-file settings from the shipped
[policy authoring guide](../cli/src/safeyolo/agent_context/skills/policy-authoring/references/capabilities.md).
First obtain the approved snapshot through `request_policy_snapshot` and
`read_policy_snapshot`. Keep its original request ID and field markers. Save
the complete proposed TOML as `candidate.toml` in the private guest workspace.
Save current discovery output as `capabilities.json`.

Set `SNAPSHOT_REQUEST_ID` to that original `req-` identifier. In an environment
with Python 3, the following command writes a private assessment request and
reads its result. If the guest has no JSON encoder, prepare the request on the
owning host and transfer it privately to the guest. Run `safeyolo-coord` in the
same guest run as the approved disclosure. Python is not a SafeYolo runtime
dependency.

```sh
export SNAPSHOT_REQUEST_ID=req-REPLACE_WITH_YOUR_ORIGINAL_REQUEST_ID
python3 - <<'PY'
import json
import os
from pathlib import Path
request = {
    'snapshot_request_id': os.environ['SNAPSHOT_REQUEST_ID'],
    'source': Path('candidate.toml').read_text(),
    'definition_version': json.loads(Path('capabilities.json').read_text())['definition_version'],
}
Path('assessment-request.json').write_text(json.dumps(request))
PY
safeyolo-coord call assess_policy < assessment-request.json > assessment.json
```

Read `consequences`, `effective`, `configured_agents`, `authority`, `alternatives`
and `limitations`. `configured_agents` explains changed worker identities,
settings, writable workspace and declared mount access. It separates saved
configuration from the next authorized sandbox start and grants no peer
administration. Host path contents, scripts, launcher defaults and installed
readiness remain outside this source-only assessment.
The source diff includes the complete redacted before/after TOML.
`valid: true` means that the installed compiler accepted the redacted form
using the available inputs. Hidden literal credentials remain opaque during
validation and analysis. Their contents do not alter unrelated candidate text
or derived explanations. Validity and effects that depend on those contents
remain unknown and need authorized inspection before adoption. A valid result
does not mean the change is safe, approved or active.
`valid: null` identifies an incomplete effective assessment, such as a list
that needs trusted adoption. Invalid forms return a bounded error.

For a support grant, an `inspection_only` alternative includes a replacement
encoded grant for its exact `path`. It removes guest commands, guest log
content, lifecycle, notifications and factory directions. It preserves
host-observed inspection of the selected peers and the selected expiry. This
choice cannot inspect guest log text or repair a guest. Fixed diagnostic reads
instead need exact reader, subject and retained request IDs through
`evidence_reads`. A policy snapshot does not disclose those runtime records.
Choose an alternative only if its omissions still meet the operator's need.
Reassess the revised complete source before explicit submission.

## Trusted operator review

On the owning host, use the account and root that own the running instance.
Obtain the exact candidate privately from its proposer. Keep the same original
snapshot request ID. The following read uses the authenticated Admin API and
does not apply the candidate:

```sh
safeyolo --instance-dir /path/to/instance policy assess SNAPSHOT_REQUEST_ID candidate.toml
```

The readable view leads with trusted consequences and affected authority, then
shows the exact redacted diff, dependencies and evidence. `--json` returns the
structured result. Both use the existing approval renderer and its display
escaping. Authored comments, labels and rationale remain untrusted data.

Operator review includes currently adopted list contents and service definitions,
applicable temporary grants and the active task policy. It uses the existing service-effect path partitions,
contract constraints, composed effect rules and configured risk decisions.
The native support/delegation graph shows direct and indirect guest authority.
It reports source-derived potential reach; current identities, peer trust,
factory bindings, runtime readiness and final issuance still need their owners'
checks. Expiry or revocation cannot undo disclosed data, file changes or
external effects, and does not prove that admitted commands stopped.

`authorized_projection` is the exact result available to the proposing agent.
That projection uses only the approved source and captured list contents.
Private service-model contents, current temporary grants and later policy
revisions remain undisclosed. The projection reports this coverage limit; it
does not infer that no extra authority exists. The operator's `current_state`
reports whether the disclosed base still matches saved and active source and
captured list inputs.

## Identity, dependencies and limits

`assessment_id` binds `input_identity`: the complete submitted source revision
(`candidate_revision`), base revision, captured inputs, relevant temporary grants,
adopted service-definition revisions, implementation definition version and
reached analysis. The submitted source retains approved preservation markers for
hidden base data. A newly authored credential changes the candidate identity;
the compiler and visible analysis still use field-redacted source. The operator
result also binds its current policy revision. Observation time is separate.
A change to a relevant input requires a fresh assessment. The adoption owner
must compare these identities and revalidate saved/active state at decision;
an assessment is not a final adoption receipt.

Candidate list references resolve only to list contents already captured by
the approved snapshot. New references report `trusted_adoption_required`.
Check sources are validated as forms, without opening recorded evidence,
loading a feed, fetching a URL or executing a job. New check sources also
report a trusted adoption requirement. Candidate-supplied effect models and
documentation cannot replace separately adopted service definitions or change
the current admission rules.

Broad transforms remain supported. Fields without a complete effect model keep
their structural changes and explicit uncertainty. Missing warnings are not a
safety certificate. Assessment accepts at most 1 MiB of candidate source and
2 MiB of analysis per projection. Structural detail and authority/path traversal
have finite budgets. Reached limits report incomplete coverage or an error;
they do not silently label the remaining scope safe.

The native routes are `POST /policy/assess` for the authenticated snapshot
requester/run and `POST /admin/policy/assess` for the authenticated operator.
Both accept only `snapshot_request_id`, `source` and `definition_version`.
There is no host path, remote instance, rationale or model override in the
request. Full-policy disclosure and final candidate adoption retain their
existing separate authority boundaries.

After private revision, use [exact policy adoption](policy-adoption.md) to
explicitly submit the same candidate, review trusted consequences through the
existing human approval interface, read the saved/active receipt and deliberately
prepare a restore. Assessment itself remains quiet and read-only.
