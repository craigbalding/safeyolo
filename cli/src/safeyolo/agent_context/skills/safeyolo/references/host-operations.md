# Use an adopted host target

The operator enrols a target and adopts a binding for your current run and active
task. Installation, operation discovery and proposals grant no authority.
Use the ordinary Agent API and its existing bearer, not a target signing key.

Resolve this skill's `scripts/host-operation.py` path and set `HOST_CLIENT` to
that path. The helper requires Python 3 inside the agent sandbox. It adds no
target-side Python dependency or daemon. Keep successful and failed JSON results
with their original request IDs in the existing task evidence.

```sh
python3 "$HOST_CLIENT" bindings
python3 "$HOST_CLIENT" discover case --request-id case-discovery-1
```

Replace `case` with the returned binding. The listing identifies the target,
trusted principal and service; it contains only bindings available to this
current run/task. An empty successful list does not prove that a target has no
other operations or grants. Discovery returns current package/authority
revisions, supported features, definitions, bounds and scope indicators.
Unavailable binding, expired authority, unsupported guarantee and denied
invocation are different from an empty result.

Select a listed literal operation and resource. Typed arguments go in a JSON
object, passed with `--arguments FILE`; omitted arguments use the operation's
declared defaults only when the actual grant permits those defaults.

```sh
python3 "$HOST_CLIENT" propose case --request-id metadata-proposal-1 --operation bundle-metadata --resource evidence:bundle-metadata > prepared.json
```

Read the normalized invocation, intersected budgets, expiry and assessment digest.
The helper derives exact operation/revision pins from discovery. A proposal does
not reserve budget or execute code. Within the task's existing authority, invoke
the unchanged preparation without another routine confirmation.

```sh
python3 "$HOST_CLIENT" invoke case --request-id metadata-invoke-1 --prepared prepared.json
```

Retain `receipt.job_id` and the original invocation request ID. Use the same
binding and substitute the returned job ID below. `output` reports bounded
base64 bytes, offsets, end indicator and retained digest. Preserve operation
completeness and native truncation separately; a successful read is not a
successful job or proof of a forensic conclusion.

```sh
python3 "$HOST_CLIENT" job case --request-id metadata-status-1 --job JOB_ID
python3 "$HOST_CLIENT" output case --request-id metadata-output-1 --job JOB_ID --offset 0 --bytes 65536
```

For cancellation, read the current job revision, then use `cancel BINDING
--request-id ID --job JOB_ID --revision REVISION`. Inspect the next receipt;
requesting cancellation is not observed termination.

A lost reply can include `possible_job_id`. Inspect that original job before
any retry. Changed content with an old mutation ID conflicts; a new ID can
repeat a real effect. If grant revocation removes read access, the target
operator must inspect retained state. Neither revocation nor expiry undoes an
admitted effect. The helper never automatically retries a failed call.

For missing capability, prepare an untrusted operation/scope proposal and use
the existing [policy-capability discovery and private assessment sequence](../../policy-authoring/references/capabilities.md). Reuse the
adopted effects, narrower alternatives and explicit unresolved dependencies.
An absent operation cannot execute just because a proposal names it. Target
ceiling, package adoption, issuer policy and credential changes belong to their
existing owners. Do not install executable bytes or create a route through a
discovery/proposal request.

A required check's unavailable/negative result follows the selected policy
fallback. Inspect the private challenge/finding, revise or abandon, or explicitly
escalate through its existing eligible approval route. An approval notification
grants no permission and does not retry the request. Read current approval and
effective access before any authorized next action. Model evidence is optional
by adopted policy, supplementary and fallible; explain selected provider/data
scope when it matters to a decision.

For stale revisions, rediscover the same target and prepare anew. For unsupported
version/enforcement, report the exact mismatch to its owner. Keep desired,
observed and active catalogue status distinct. Routine permitted execution and
authorized catalogue updates remain quiet. Use the packaged platform index and
operator guide for actual installation, account exposure and source/dependency
limits; target metadata alone cannot prove containment.
