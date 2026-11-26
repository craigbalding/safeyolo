# Named policy checks

Named checks supply typed evidence to the native network policy. The operator
selects each source, meaning, scope and influence in `policy.toml`. A check
result does not grant service or credential access. Those controls still apply.

The shared implementation is [checks.rs](../proxy/src/policy/checks.rs).
Live collection reads captured JSON files, uses accepted managed-feed snapshots,
or runs an adopted job or Service Gateway operation. The shared evaluator
validates and composes the resulting evidence. Offline candidate evaluation
reads captured files and feed snapshots and leaves live operations unavailable.
The workload cannot select an executable or callback.

## Define checks and rules

On the host that owns the instance, copy its current policy to a separate
candidate. Retain its agent identities, grants and other controls. Merge the
following fragment into that candidate. Replace `research` with the configured
agent and `threat-results.json` with a trusted captured-evidence file. Relative
evidence paths resolve from the candidate file's directory. Apply preserves
that location when saving the candidate under the instance root.

```toml
[checks.threats]
source_id = "selected-threat-source"
meaning = "positive means a threat finding for this exact hostname"
subject = "hostname"
result_type = "finding"
influences = ["hard_exclusion"]
implementation_version = "hostname-adapter-1"
configuration_version = "research-1"
max_age_seconds = 3600
max_source_age_seconds = 86400
source = { kind = "recorded", path = "threat-results.json" }

[[check_rules]]
name = "never-visit"
host = "*"
agent = "research"
stage = "connect"
influence = "hard_exclusion"
priority = 0
required = true
when = { op = "finding", check = "threats" }
on_match = "deny"
on_unavailable = "unresolved"
```

A check declares a normalized subject, result type, meaning, permitted
influences, implementation/configuration versions, freshness and source.
Optional `inputs` are a string map of policy-owned input values, such as an
expected GitHub issue author. The workload cannot select that expected author
or replace the captured result with its own PASS text.

Supported subjects are `hostname`, `ip`, `http_path` and a non-network `value`.
Hostname evidence uses lowercase Internationalized Domain Names in Applications
(IDNA) ASCII form, without a terminal DNS root dot. IP evidence uses the
canonical address. HTTP path evidence also binds hostname, port, scheme and
method. Its path excludes the query. There is no automatic mapping from a
hostname to its registrable parent or from a hosted tenant to its owner's
registration age.

A required rule rejects a check that cannot run at its declared stage.
A non-required rule can name `source = { kind = "unavailable", reason = "..." }`
with an explicit unavailable fallback. Unknown subject kinds, full URL/query
checks and TLS/post-response stages are rejected. Such constraints are not
silently treated as hostname or path checks.

## Use managed-feed evidence

On the host that owns the instance, first configure a source through
[policy feeds](policy-feeds.md). In the hostname check above, replace `source`
with the adopted source name:

```toml
source = { kind = "feed", name = "hagezi" }
```

The feed name resolves in the selected policy file's directory, including
candidate checking, preview and apply. A nondefault `policy_file` selects its
own feed configuration and snapshots. No local-list host rule is needed.
The check uses result type `finding`: positive means membership in the adopted
hostname/suffix scope. Explicit negative membership means only absence from
that list. Missing data, failed reads and unsupported subjects remain
unavailable; negation cannot turn them into permission. `no_match` keeps its
ordinary unavailable meaning.

Each compiled policy captures entries and provenance from one accepted version.
Evidence binds the normalized hostname, input digest, check versions, local
snapshot version, source configuration and content digest. Provider revision
and time remain optional actual provider facts. Source expiry uses provider
time or retained first observation, bounded further by the check's age limits.
Retrieval, repeated collection, HTTP 304, restart and rollback cannot renew the
source deadline. Both positive and negative membership expire together.

An outage retains usable accepted data until expiry. Missing or expired evidence
selects the named rule's `on_unavailable`, including when the source specifies
local-list `on_stale = "retain"`. Hard exclusions and advisory rules retain
the shared evaluator's precedence. Named-feed collection uses the existing
check cache for the latest subject; snapshot/configuration changes invalidate
reuse and pending evidence before admission. A new policy owns a new cache.
Preview reads snapshots without refreshing or contacting their members.

## Execute adopted checks

The same executor qualifies and runs checks in
[versioned control updates](signals.md#adopt-versioned-checks-and-challenges).
Native `route_challenges` compose ordered questions and typed job/service
findings before missing-route escalation. Their host-generated subject binds
the request/effect identity and selected revision. Agent answers are explicitly
untrusted context. Missing or failed required evidence prevents escalation;
it is not a negative finding or permission grant.

An active native policy can use `source.kind = "job"` or `"service"`. Each
source declares its effects and execution limits. Effects are `passive`,
`retains_input`, `active` or `unknown`. These are the operator's adopted
provider contract, not a guarantee of provider accuracy. Offline preview never
executes any of these operations, including an operation declared passive.

For a job source, the host selects a JSON specification accepted by the
existing [job command](operator-guide.md#run-a-disposable-sandbox-job). Use an absolute path or a path relative to the
policy file. This fragment replaces the `source` of a named check:

```toml
[checks.threats.source]
kind = "job"
spec = "hostname-check.json"
effects = "passive"

[checks.threats.source.limits]
timeout_ms = 5000
max_input_bytes = 8192
max_output_bytes = 8192
max_concurrent = 2
max_pending = 4
max_cached = 128
```

The specification fixes `gate_id`, executable `argv`, guest privilege, network
selection and the existing job bounds. Its input and retained-output bounds
must fit the adopted check bounds. The check copies one host-generated
`request.json` into the job's read-only `/input`. It contains the normalized
`subject`, `input_digest`, policy-owned `inputs` and implementation/configuration
versions. There are no workload-selected mount paths. The existing job runner
retains isolation, rootfs/input hashes, observed wait status and cleanup.
An optional `source.spec_sha256` pins the complete job specification bytes.
Versioned control updates set this pin from the signed bundled job. A mismatch
is unavailable evidence and starts no execution.
The check retains those execution facts and the specification digest in its
explanation. The existing audit stream records reached execution and result
provenance before admission revalidates current policy. Discarded results remain
inspectable and grant no decision authority. A changed specification
invalidates pending evidence and reuse.

The job's stdout must be one typed JSON result, for example:

```json
{"finding":{"kind":"finding","positive":false},"source_revision":"dataset-42"}
```

Optional fields are `source_observed_at_ms` and `valid_until_ms`. The host adds
subject/input/version bindings, collection time and the digest of the returned
bytes. Exit zero is only successful execution. PASS text, a malformed result,
an incompatible finding type, an incomplete observation and a nonzero exit do
not become a favorable finding. Negative findings remain distinct from these
failures. Job streams retain at most the specification's `retain_bytes` per
stream; byte counts and hashes cover complete streams. A truncated or oversized
result is unavailable evidence.

Hyperlight jobs can select [mediated service access](hyperlight-jobs.md#mediated-service-access).
The host retains the full bounded captures with the execution facts. The typed
result uses host-observed capture identity and collection time. The adapter
ignores guest-written source revisions and source observation timestamps.
Missing source metadata remains explicit. A failed delegated call or absent
capture cannot supply a favorable mediated finding.

### Invoke an adopted check as an agent

An operator can add `invokers = ["forge"]` to a named job or service check.
The field defaults to an empty list. Use `"*"` to permit every identified
agent to invoke that definition. Invocation authority does not grant its
service dependencies; the adopted gate still needs its own standing grants.
The agent supplies only the adopted name and normalized typed subject.
Policy-owned `inputs`, expectations, engine, artifacts and host paths remain
in the adopted definition.

An authenticated `POST /checks/invoke` on the selected instance's Agent API
accepts an uncompressed JSON body of at most 48 KiB, for example:

```json
{"check":"issue_author","subject":{"kind":"value","value":"123"}}
```

The check's subject type must match the supplied subject. The response contains
the shared typed evidence and host execution facts. A completed invocation
does not itself authorize another operation or replace independent acceptance.
Unknown definitions, unpermitted invokers, invalid inputs, execution failure
and authority replacement return explicit errors. Policy replacement cancels
pending work and discards late results. This route accepts no JobSpec,
executable path, replacement expected identity or caller-authored result.

### Check task relevance and proportionality

An operator can adopt an optional independent task/action check before host
invocation. The issuing host supplies the activated task's
`metadata.description` as the objective, its revision and permissions, the
authenticated requester/run, normalized invocation and implementation revision,
prepared effects and intersected authority, and retained action/refusal history.
The model receives a structured action; the prompt contains no host-command
policy. Other trusted action owners can supply the same `task_action.v1`
envelope. A caller-authored value submitted to `checks/invoke` remains a caller's
fixture and does not establish canonical host authority.

The shipped `assets/hyperlight/task_action_checker.py` uses the existing
Hyperlight-Unikraft runtime and mediated Service Gateway calls. Its installed
`task-action-check.json` pins the checker and runtime, disables guest networking,
and selects one model call per invocation. The target host needs only its
existing executor. The checker runs on the issuing host.

On the owning host, first review and retain the installed job definition at a
stable path. The existing service owner must grant `claude/inference` to
`gate:task-action-check` for the selected Messages endpoint. Select the provider
credential, exact model revision and disclosed data before adopting the check.
An assessed agent's coding-client grant does not grant the check that access.
No credential enters the checker. The example below sends the task description,
selected action/effects/constraints and retained history metadata. It withholds
agent rationale and answers from the model. Raw host log access does not grant
model disclosure.

Merge this fragment into a candidate for that same instance. Replace
`REVIEWED_JOB_SPEC_SHA256` with the SHA-256 of the retained job definition,
`task-action-check.json` with its stable path, and `research` / `local-host`
with the intended configured agent and host service. The model is a pinned
example; select an available revision through the existing service owner.
Retain the candidate's other policy and credential controls.

```toml
[checks.task_action]
source_id = "independent-task-action"
meaning = "Typed relevance and proportionality signal for this exact task/action"
subject = "value"
result_type = "task_action"
influences = ["advisory"]
implementation_version = "task-action-2"
configuration_version = "research-model-1"
max_age_seconds = 60
inputs = { service = "claude", endpoint = "https://api.anthropic.com/v1/messages", model = "claude-haiku-4-5-20251001", model_revision = "claude-haiku-4-5-20251001", input_revision = "task-action.v1", prompt_revision = "task-action-2" }
source = { kind = "job", spec = "task-action-check.json", spec_sha256 = "REVIEWED_JOB_SPEC_SHA256", effects = "retains_input", limits = { timeout_ms = 65000, max_input_bytes = 32768, max_output_bytes = 16384, max_concurrent = 1, max_pending = 2, max_cached = 0 } }

[route_challenges.task_action]
agents = ["research"]
service = "local-host"
capability = "*"
methods = ["POST"]
path = "/v1/host-execution/invoke"
revision = "research-task-action-1"
steps = [{ kind = "task_action", check = "task_action", on_concern = { kind = "question", field = "alternatives", question = "Explain the relevant evidence and alternatives, or propose a narrower action." }, on_unavailable = { kind = "deny" }, max_attempts = 3, disclose_rationale = false }]
```

Use the existing policy check/show/apply workflow to adopt the candidate.
The check then runs before host dispatch, including on an allowed route.
`on_concern` chooses refusal or a private question. When policy selects a
question, explicit escalation reassesses the action with the bounded answer.
A continuing concern remains visible to the operator; an answer is not a
favorable finding. An exact operator approval still cannot bypass a hard denial
or the target's independent ceiling. A changed action requires a new assessment.
`on_unavailable` selects refusal or a private question while evidence is missing;
missing evidence cannot satisfy escalation. No approval or question retries an
operation automatically.

The result contains typed `relevance` (`relevant`, `irrelevant`, `uncertain`),
`proportionality` (`proportionate`, `excessive`, `uncertain`), supporting
`evidence_refs`, optional `clarification`, and an `uncertainty` list. There are
no probability scores. Invalid fields/references, incomplete provider responses,
model substitution, timeouts and unavailable dependencies remain explicit.
An uncertain finding supplies no favorable evidence.

The adapter requests the selected provider's JSON-schema output format. Its
schema permits only the typed fields and disclosed top-level evidence keys.
The adapter still validates complete responses, exact references and size bounds.
Fenced JSON, extra prose and dotted references remain invalid findings.

The canonical subject and existing evidence owner bind the task, action,
history, policy/challenge/check, model/input revisions and freshness. Changing
these bindings invalidates prior evidence. Attempts and findings remain in the
existing private approval record. `max_attempts` bounds model reconsideration
for the same unresolved run/task/action episode and check configuration,
including under a new request ID. A successful check ends that episode;
later operations receive a new budget while prior attempts and refusals remain
in retained history. An older challenge cannot reopen a completed episode.
A narrower action has its own budget and retains prior refusal
metadata. Retained history describes the current validated audit tail and
approval records; unavailable or omitted history is explicit. It does not claim
complete lifetime history or disclose target output as trusted instructions.

The existing host-binding assessment shows the selected checker definitions,
model inputs, source pins, full grant and modeled combined authority. Review
those together. A broad host grant can permit changing the checker, policy or
credentials. Separate configuration owners alone do not prove independence.
Another model can share failure modes or be misled. Its finding is an additional
signal, not a containment guarantee.

The maintained [synthetic cases](../tests/fixtures/task-action-cases.json) cover
adaptive host investigation and structured artifact publication. The
[measurement runner](../tests/blackbox/host/task_action_assessment.py) exercises an
installed check and reports
false positives, false negatives, unavailable/uncertain cases, exact input/spec
identities and observed durations for its selected model run. Controlled
protocol tests do not measure model accuracy. Results from these finite cases
do not establish general prompt-injection detection.

For a passive Registration Data Access Protocol (RDAP) service, use
`mapping = "rdap_registration"`. It reads only the exact domain object's
`registration` event as a timestamp. A parent-domain response, missing or
ambiguous event, malformed timestamp or future registration remains unavailable.
Transfer, update, certificate and first-seen dates are not registration age.
Collection freshness applies; the adapter does not invent a provider revision
or dataset observation time. The complete installed
[cyber research recipe](../cli/src/safeyolo/agent_context/skills/policy-authoring/references/recipe.md)
supplies configurable source/check/service examples and explains their coverage.

For a service source, adopt the service and capability through the existing
Service Gateway policy for `gate:<gate_id>`. The source also fixes its endpoint,
HTTP method, path mapping, result mapping and effects. For example, after the
operator has adopted an `assessor` service at `assessor.example` with a `reader`
capability covering the operation, this source calls it:

```toml
[checks.threats.source]
kind = "service"
[checks.threats.source.operation]
gate_id = "hostname-assessment"
service = "assessor"
capability = "reader"
endpoint = "https://assessor.example"
method = "GET"
path = "/assessment/{subject}"
effects = "passive"
mapping = "typed"
[checks.threats.source.limits]
timeout_ms = 2000
max_input_bytes = 8192
max_output_bytes = 8192
max_concurrent = 2
max_pending = 4
max_cached = 128
```

The endpoint must match the adopted service host. `{subject}` expands to an
escaped hostname, IP or value. `{input.NAME}` expands to an escaped policy-owned
input. `{path}` copies a visible HTTP-path subject. The workload cannot replace
the endpoint. GET and HEAD send no body; other methods send JSON containing the
subject, input digest and policy-owned inputs. `typed` uses the same result
format as a job.

A service check creates its temporary listener directory with owner-only access
before binding the delegated socket, independent of the host umask. It uses the
ordinary proxy transport, network policy, gateway route/credential controls and
provider routing. Missing capability or operation
grants fail explicitly. Check dependencies receive no blanket policy bypass.
Scope assessed-workload rules to their intended agents: if dependency traffic
requires a check already in its ancestry, that dependency fails as recursive
or cyclic. Authorizing the assessed destination does not authorize a dependency.
Existing authorized dependencies need no recurring approval or saved agent
record per execution.

An agent-provided service receives its authenticated caller's transient
`job-<run-id>` in `X-SafeYolo-Agent-ID`, and the stable `gate:<gate_id>` in
`X-SafeYolo-Agent-Name`. The proxy overwrites caller-supplied identity headers.
The temporary listener and delegation end with the operation. No configured
workload agent is impersonated.

The deadline includes pending-slot wait and execution. `max_concurrent` bounds
running operations; `max_pending` bounds additional waiting operations.
Excess work returns unavailable evidence. Cancellation or deadline expiry stops
the owned transport/job and discards late evidence. Platform cleanup finishes
before its execution slot is released. Cancellation cannot reverse an active
operation already submitted to a provider. No network wait or VM startup holds
the global policy lock. Admission still checks current policy and run authority
after collection.

Completed valid evidence is reused for equivalent normalized subject, owned
inputs, versions and source definition. The shared evaluator applies its
freshness/type/binding validation on every reuse. The service capability and
operation must still be authorized. `max_cached` bounds retained entries;
zero disables reuse. A new policy has a new execution cache. There is no
always-on checker, separate scheduler or persistent result store. Service
checks need no fresh sandbox for each URL.

### GitHub provenance example

The `github_issue` service mapping accepts the authoritative external
`https://api.github.com` issue GET operation. Adopt the GitHub service and its
read capability for the selected gate, then use `path = "{path}"` with an
`http_path` subject. Set `inputs.expected_author` and
`inputs.expected_repository_owner` in the named check. These expected identities
come from policy, rather than the assessed issue. The check's result type is
`finding`: positive means both identities match.

The adapter requires the exact API issue URL, issue ID, author, title, body and
revision. It records the captured response's content digest and issue
ID/`updated_at` revision. Mismatch is a negative finding; missing data, malformed
responses and unavailable GitHub remain unavailable evidence. The captured
fixture in the adapter tests retains actual GitHub issue content. The finding
attests only the exact captured revision consumed by the check. It does not
attest a later fetch, comments, linked resources or all author-written content
as safe.

## Compose evidence

Conditions use the following forms. Every referenced check must exist and have
the corresponding result type.

| Condition | Meaning |
|---|---|
| `{ op = "finding", check = "threats" }` | The observed finding is positive. |
| `{ op = "fact", check = "author", equals = "expected" }` | The observed string fact equals the selected value. |
| `{ op = "score", check = "reputation", comparison = "ge", threshold = 70 }` | Compare the provider's score on its declared scale. |
| `{ op = "age", check = "registered", comparison = "lt", seconds = 2592000 }` | Compare decision time minus the observed timestamp. |
| `{ op = "aggregate", checks = ["a", "b"], method = "mean", comparison = "ge", threshold = 70 }` | Aggregate scores with compatible scales. |
| `{ op = "all", conditions = [...] }` | Every condition is true. |
| `{ op = "any", conditions = [...] }` | At least one condition is true. |
| `{ op = "not", condition = {...} }` | Negate a known boolean result. |

Comparisons are `lt`, `le`, `eq`, `ge` and `gt`. Aggregation methods are `mean`,
`minimum` and `maximum`. A score check must declare `scale` with `name`,
`minimum`, `maximum`, `direction` (`higher` or `lower`) and
`confidence_meaning`. The scale name identifies the quantity; direction describes
that quantity, not a universal risk interpretation. Conditions explicitly
choose their comparisons. Aggregation requires identical scale declarations.
A provider's confidence is retained separately from its score.

Conditions distinguish true, false and unavailable. Negating unavailable
remains unavailable. In an `all`, a known false determines false; otherwise an
unavailable input leaves the result unavailable. In an `any`, a known true
determines true; otherwise an unavailable input leaves the result unavailable.
Aggregation with an unavailable input or a non-finite derived value remains
unavailable. No-match is
unavailable evidence, not an explicit negative finding or proof of safety.

Each rule requires `on_match` and `on_unavailable`. Match actions are `allow`,
`deny`, `approval` and `unresolved`. Unavailable fallbacks are `continue`,
`deny`, `approval` and `unresolved`. Continue leaves ordinary network policy in
control and records the unavailable evidence; it asserts no positive finding.

Precedence is explicit:

1. A hard exclusion must use `on_match = "deny"`. Its matched action or
   unavailable fallback dominates ordinary host/per-agent allows, advisory
   evidence and exceptions.
2. Advisory rules use larger `priority` values first. Equal priorities prefer
   deny, then unresolved, then approval, then allow.
3. An exception must use `on_match = "allow"` and `overrides = ["RULE", ...]`.
   It overrides only the named advisory rules at the same stage and only in
   the exception's host/agent scope. It cannot override a hard exclusion.
   Unavailable exception evidence applies its own configured fallback.
4. Check-layer allow still requires the existing network guard to permit the
   operation. Existing exact/per-agent host precedence remains within that
   guard. Credential and service grants remain independent.

An `approval` result pauses the operation with HTTP 428 and identifies the
named rule. The operator can apply an explicit scoped exception or revise the
selected policy through the existing policy workflow. This is not an ordinary
host approval: adding a host allow cannot bypass a named hard exclusion.
No new approval service or implicit persistent permission is created.
`unresolved` pauses with HTTP 503; deny returns HTTP 403. If CONNECT has
already established an opaque tunnel, a refusal closes it before byte relay.

## Captured result contract

An evidence file is a JSON array of `CheckResult` records. Each record contains:

- `subject`: a normalized tagged subject, such as
  `{"kind":"hostname","hostname":"example.test"}`;
- `input_digest`: the SHA-256 digest from `Check::input_digest`, which binds
  the normalized subject and the check's policy-owned `inputs`;
- `implementation_version` and `configuration_version`, matching the selected
  check definition;
- `collected_at_ms`: the host-observed collection time in Unix milliseconds;
- `valid_until_ms`: an optional earlier validity deadline;
- `source`: `source_id`, matching the selected check, plus `source_revision`,
  `content_digest` and `source_observed_at_ms`; unavailable source metadata
  serializes as null; and
- `finding`: the tagged typed result.

Finding kinds are `finding` with `positive`, `score` with `value` and optional
`confidence`, `timestamp` with `unix_ms`, or `fact` with a string `value`.
`no_match`, `unknown`, `unsupported` and `failure` remain distinct states.
The last three carry a `reason`. An exit status is an execution fact, not a
finding. A negative membership result means only the declared negative finding.
It does not attest that a destination or its content is safe.

A trusted adapter records collection time. Do not accept a workload-supplied
clock or result as authoritative evidence. Source observation time describes
the underlying evidence when known. Retrieval time does not establish that a
provider's dataset is current. Never invent a provider revision or exact domain
age from missing metadata, a first-seen date or a finite-window list no-match.

Every decision applies `max_age_seconds` from collection time. If
`max_source_age_seconds` is configured, source observation time also limits
validity; when absent, collection time is the available freshness bound and
that absence remains visible. An earlier `valid_until_ms` also applies.
Evidence expires at the boundary, not one request later. Registration-age
conditions use decision time. Explanations expire no later than their next
threshold transition or evidence deadline.

Recorded collection reads a fresh file snapshot for each admission. The captured bytes have a host-computed file digest;
file replacement/change and subject/input/version mismatches prevent reuse.
Live evidence reuse preserves these bindings and current policy/authority
checks. Producers should replace complete files atomically, with entries and
provenance from the same accepted snapshot. Malformed, missing, duplicate and
expired records enact the selected unavailable fallback.

## Enforcement stages and visibility

The existing [HTTP transport](../proxy/src/http.rs) checks required connect
rules after resolution and before opening the actual selected socket. Each
attempted IP is checked; another DNS lookup cannot substitute a different
unchecked address. A parent proxy or agent-provided route hides the origin IP.
Such a route receives unavailable endpoint evidence and the explicit fallback,
even if the parent itself has a known IP.

Visible request rules finish before HTTP request forwarding, including after
body preparation and target rewriting. A path denial can occur after TCP/TLS
setup; it prevents that HTTP operation, not the earlier connection. Reused
connections retain their actual endpoint evidence. Redirects do not confer
permission on the next destination: the proxy does not follow them, and the
client's next request passes the gates again. Logical TLS target changes also
pass the connect checks before further forwarding. An earlier numeric CONNECT
can have been admitted under the explicit direct-IP fallback before its TLS
hostname becomes visible.

Direct-IP requests have an IP subject and unavailable hostname evidence.
Supported IPv6 zone IDs select an interface. Named-check host scopes and HTTP
path subjects use the canonical address without the zone ID; IP evidence still
binds the actual connected address. A subject-normalization failure uses the
configured unavailable fallback instead of removing the rule.
Opaque/passthrough traffic has no visible HTTP path. Before relaying its bytes,
the proxy applies request rules with unavailable path evidence. Required
hostname/IP checks cannot use later TLS observations or completed-response
Network Security Monitoring (NSM) findings as pre-connect evidence.

Collection runs outside the global runtime lock. After an evidence wait, the
proxy verifies the current policy, agent-run authority and available file
versions. A changed policy/authority or superseded snapshot cancels that
admission. Late favorable evidence cannot restore the old permission.

## Validate, preview and apply

On the host that owns the selected instance, save the candidate policy as
`candidate.toml`. Save a separate `request.json` simulation input. Replace the
agent, hostname, address and port for your case. The optional IP is an explicit
offline scenario input; preview does not resolve or contact the destination.
Omitting it leaves required endpoint evidence unresolved.

```json
{
  "agent": "research",
  "host": "example.test",
  "port": 443,
  "scheme": "https",
  "method": "GET",
  "path": "/report",
  "ip": "192.0.2.7"
}
```

Run these commands from the directory containing those files. Replace
`/path/to/instance` with the intended instance root. Check validates the model;
evaluate reads captured evidence and reports network decisions. Neither command
saves policy, grants access, invokes a provider or consumes live quotas.

```sh
safeyolo --instance-dir /path/to/instance policy check candidate.toml
safeyolo --instance-dir /path/to/instance policy evaluate candidate.toml request.json
```

The JSON preview identifies `recorded_offline` evidence, the applied condition
and fallback, check meaning/scale, rule results, source
metadata, freshness, guard outcome and the final allow/deny/approval/unresolved
action. It performs no direct or dependency-mediated target contact. Offline
preview has no live provider operation. Already captured scanner evidence can
be used within its freshness; preview never starts a scan, crawl or visit.
Credential/service controls may further restrict a live request. Preview does
not establish that a running instance has activated the candidate. The CLI
loads a fresh candidate and does not import the running instance's quota usage
or agent-run authority; its result describes the supplied offline scenario.

Within the operator's existing authorization, use the current
[check/show/apply workflow](installation.md#check-show-and-apply) to activate
and verify the candidate. Keep saved, active and unconfirmed states distinct.
The model and transport tests are source proof; installed backend, managed-feed
and complete cyber-recipe acceptance require their actual implementations.

## Automatic requirements on native Work

An operator can adopt `work_bindings` in the selected instance's `policy.toml`.
Each binding names an existing executable job or service under `checks`. The
job retains its own engine, artifact, input limits, freshness and dependency
grants. A binding grants no network or service access to the invoking job.
Normal invocation uses the standing adopted authority and creates no recurring
approval. Role instructions are explanatory; the proxy enforces the binding.

Before a protected Work mutation acquires automatic evidence, Coord validates
the caller, request and current Work state through the same rules used at
commit. An already unauthorized or invalid operation starts no job and contacts
no provider. Coord recovers an exact committed operation receipt before acquiring new evidence; changed input
under that operation ID remains a conflict. Retained follow-up obligations keep
their existing recovery rules. Preflight grants no later commit authority:
Coord revalidates state, selected requirements and effective authority after
evidence collection. Job execution and provider I/O hold neither the Coord
transaction nor the global policy lock.

The supported Coord boundaries are:

| `boundary` | `input` | Protected transition and result |
|---|---|---|
| `admit_issue` | `github_issue` | Before creating ordinary issue Work, claiming it, reassigning it or continuing it, require the adopted predicate or effectful prerequisite. The value subject is the canonical positive issue number. The binding's repository must equal the job's policy-owned `inputs.repository`. |
| `verify_output` | `published_artifact` | Retain the output and a verification obligation together. Invoke the job automatically, then hold `decide_acceptance` approval until its predicate qualifies for those exact bytes and that output generation. |
| `after_complete` | `completed_work` | Retain a follow-up with ordinary Work completion. Dispatch the action under its separately adopted capabilities. Its failure or uncertain result cannot prevent or undo the committed completion. |

Bindings also name the room and approved factory. Issue admission applies to
the configured repository in that room even when a caller omits `factory`.
Equivalent GitHub web and API issue URLs select the same requirement. Successful
admission selects the approved factory and retains the finding and its source
provenance. The Hyperlight GitHub example also retains its exact captured
response as `automatic[].evidence.execution.checked_input`, with Base64 bytes
and their SHA-256 digest. The worker consumes that checked title/body snapshot.
Admission and later delegation perform fresh reads instead of reusing earlier
admission results. A new relevant issue revision therefore supplies new input;
the observation does not promise GitHub stays unchanged after collection.
Other adopted service/check implementations do not imply this captured-input
contract merely by returning a positive finding. Existing ordinary issue Work must pass the same check before
execution delegation. Work without a matching issue reference remains generic;
review/check assignments are separate operations. These bindings do not inspect
an agent's unmediated intentions or discover an issue reference hidden in prose.

Before using the following example, the operator must approve factory `example`
for room `engineering` and adopt the three named executable sources. The
`issue_author` source must check authoritative GitHub evidence for repository
`owner/repository` against the operator's expected stable author ID. Its
`inputs.repository` must be `owner/repository`. `artifact_check` evaluates the
retained bytes. `completion_notice` performs the explicitly authorized effect.
Both predicate sources must declare `effects = "passive"`. Add these root array
tables to the selected instance's policy, then use the existing policy
check/show/apply workflow:

```toml
[[work_bindings]]
name = "required_issue_author"
room = "engineering"
factory = "example"
boundary = "admit_issue"
job = "issue_author"
repository = "owner/repository"
input = "github_issue"
on_failure = "hold"
require = { op = "finding", check = "issue_author" }

[[work_bindings]]
name = "required_artifact"
room = "engineering"
factory = "example"
boundary = "verify_output"
job = "artifact_check"
input = "published_artifact"
on_failure = "hold"
require = { op = "finding", check = "artifact_check" }

[[work_bindings]]
name = "notify_completion"
room = "engineering"
factory = "example"
boundary = "after_complete"
job = "completion_notice"
input = "completed_work"
on_failure = "report"
retry = "never"
```

A check can use the shared typed predicate operators, including explicit
negative conditions and declared score thresholds. It must use its named job.
An action has no `require` predicate. Its result records reached execution and
acknowledgment, rather than a boolean finding. Action invocation bypasses the
check-result cache. Unknown jobs, unsupported boundaries or mappings, invalid
predicate types, effectful predicate sources and unsupported retry policies
fail validation. Bindings have no dependency edges to other bindings; unknown
fields such as `depends_on` are rejected. Job/service dependencies retain the
shared cycle detection and bounded failure behavior.

### Require an action before issue admission

An effectful `admit_issue` binding can reserve external capacity before the
protected transition. The operator first adopts an executable job or service
named `reserve_issue` with explicit effects, limits, immutable implementation
and dependency capabilities. Its `inputs.repository` must be
`owner/repository`. In this example, the external reservation implementation
deduplicates requests by the proxy-supplied `invocation_id`; verify that
guarantee before adopting `retry = "idempotent"`. An HTTP acknowledgment or
successful job completion is the action's completion condition. The action
does not return a predicate and cannot replace an independent review.

For the selected instance, the operator adds this binding alongside the
adopted source and applies it through the existing policy check/show/apply
workflow. Factory `example` must already be approved for room `engineering`.
Replace `ag-reservation-recovery` with the recovery agent's durable ID:

```toml
[[work_bindings]]
name = "reserve_before_admission"
room = "engineering"
factory = "example"
boundary = "admit_issue"
job = "reserve_issue"
repository = "owner/repository"
input = "github_issue"
on_failure = "hold"
retry = "idempotent"
recovery = { reconcilers = ["ag-reservation-recovery"], retryers = ["ag-reservation-recovery"], max_retries = 1 }
```

Use `retry = "never"` when safe repetition is not established. Recovery is
optional. Its `reconcilers` and `retryers` lists grant separate permissions to
named agents with current room access. `max_retries` bounds additional attempts
after the first dispatch. Selecting a retry performs no external operation.
The original requester must resume the exact protected request with the same
operation ID. Normal adopted execution and recovery need no recurring approval.
Recovery grants no execution authority for another agent's protected transition.

Before an effectful admission, the requester must select an operation ID.
Coord retains the logical invocation in its immutable operation ledger before
dispatch, including when the protected Work does not yet exist. Job input and
service request bodies carry `invocation_id`; the subject and adopted inputs
remain unchanged. The invocation binds the requester, complete mutation,
operation ID, binding, policy, service definitions and selected job definition.
Passive preflight and previews dispatch nothing. Already invalid or
unauthorized requests dispatch nothing. Commit rechecks current actor, Work,
requirements, factory and authority through the shared mutation rules.

A lost reply or restart preserves that invocation. An interrupted dispatch is
`uncertain`; it is never blindly repeated. A retained successful action is
reused if the later protected commit fails. Changed inputs under the original
operation ID conflict. A changed authority or subject cannot reuse or retarget
the invocation. An unknown result does not establish exactly-once remote
execution, rollback or failure of the external effect.

For diagnosis, the refused operation names its prerequisite invocation ID.
On the owning host, read it with
`safeyolo coord work prerequisite engineering INVOCATION_ID`. The record shows
its version, original request, attempts, reached state, evidence and recovery
observation. Replace `INVOCATION_ID` with the reported ID. The authenticated
Agent API exposes the same read at
`GET /api/coord/rooms/engineering/work?invocation_id=INVOCATION_ID`.

After inspecting that exact invocation at the external reservation authority,
an adopted reconciler can POST to the room's Work endpoint with
`action = "resolve_prerequisite"`, `invocation_id`, current
`expected_version`, `outcome` (`completed`, `failed` or `uncertain`),
`summary`, a nonempty `evidence_refs` array and a caller-selected
`operation_id`. The owning host uses `coord work resolve-prerequisite` with
the corresponding named options. A completed observation satisfies only that
invocation; the protected transition still needs current authority.

For example, after the reservation authority confirms completion, the adopted
reconciler calls `resolve_work_prerequisite` with the following arguments.
Replace `INVOCATION_ID`, version `2` and the receipt reference with the exact
values from the current invocation and external observation:

```json
{
  "room_name": "engineering",
  "invocation_id": "INVOCATION_ID",
  "expected_version": 2,
  "outcome": "completed",
  "summary": "The reservation authority confirms this exact invocation",
  "evidence_refs": ["reservation://observed-receipt"],
  "operation_id": "reservation-observation-1"
}
```

If the result remains failed or uncertain and adopted idempotent retry is
available, a named retry actor can use `action = "retry_prerequisite"` with
the same fields except `outcome`. The host equivalent is
`coord work retry-prerequisite`. This retains `pending` and consumes no effect;
the next valid original request dispatches another attempt with the same
invocation ID and external inputs. The retry bound applies even when replies
are lost again. Removing recovery permission or changing adopted authority
prevents further recovery. A recovery actor cannot change capabilities,
replace the subject or remove the prerequisite.

Effectful prerequisites are supported at `admit_issue`. `verify_output`
retains its passive predicate semantics. `after_complete` retains its
operator-only reconciliation and `retry = "never"` semantics described below.

### Retain and verify an exact small artifact

For a selected `verify_output` binding, the producer passes `artifact_base64`
to `publish_work_output` and uses `sha256:HEX_DIGEST` as `target_ref`. The digest
must be the SHA-256 of the decoded bytes. The existing 32,768-byte serialized
publication limit includes the artifact. An inconsistent digest or malformed
base64 rejects publication. This concrete binding supports small inline
artifacts; it does not fetch arbitrary output references or claim to verify
external files that can change behind a reference.

The canonical output and immutable Work revision retain the bytes. The checker
receives a `value` subject containing a JSON object with `work_id`,
`target_generation`, `target_ref` and `artifact_base64`. It cannot authorize a
replacement output, including another generation containing identical bytes.
Publication without the required artifact remains retained with an unmet
verification obligation. Missing, negative, stale, malformed or failed evidence
holds approval. Independent participant checks and their independence rules
remain separate and still apply. Amending participant review requirements does
not supply a machine finding.

Evidence acquisition and job execution occur outside Coord transactions and
runtime policy locks. The final commit checks the exact mutation, output and
claim generations, current policy, approved admission snapshot, job definition
and authority. Changed policy or revoked authority invalidates pending evidence.
Approval reevaluates evidence freshness and applicable authority; a manual
preview or caller-supplied result cannot satisfy the requirement. Current Agent
API reads and room status evaluate retained findings against active authority.
The host `coord work show` command also reads active authority for current
factory Work, including Work with no earlier automatic records. If the proxy
is unavailable, `show` retains the local data and reports acceptance as
`pending`, with `recorded_state` and an explanation that current automatic
authority has not been read. `coord work list` uses the same recorded view for
factory Work and retained verification requirements. Use `show` with the proxy
running to inspect current applicability. `show --version` returns the selected
historical revision.
Removing a verifier from adopted policy cancels that requirement at the next
acceptance decision through the running proxy; earlier evidence remains in Work
revisions. A newly selected verifier makes acceptance pending until it qualifies.
An operation receipt describes its original committed revision; read current
Work after recovery or automatic execution changes its version.

### Recover a follow-up action

A completed transition retains its action's logical obligation ID, adopted
binding, authority, subject and pending state in the same Work transaction.
The action input identifies the Work, claim generation, output generation,
output reference, completion summary and `obligation_id`. An external action
can use that ID for its own reconciliation. This does not assert that every
external service implements idempotency.

The proxy retains `dispatching` before invoking the action. Startup recovers
pending obligations. An interrupted passive verification can run again. An
action left dispatching at restart becomes `uncertain` and is not automatically
retried. Lost replies and unavailable completion observations also remain
uncertain. A local receipt does not establish exactly-once remote execution or
rollback. Completed actions are not repeated after redelivery or restart.

Read the Work's `automatic` records to inspect the binding, reached result,
authority and recovery explanation. After inspecting the effect at its external
authority, the owning host operator can record a resolution with
`safeyolo coord work resolve-action`. Supply the current Work version and claim
generation, exact `--obligation-id`, `--outcome completed|failed|uncertain`,
`--summary`, external `--evidence-refs` JSON array and an `--operation-id`.
This records the observation under the operator's identity. It performs no
external action and grants no retry permission.

The host Work CLI routes applicable mutations through the authenticated Admin
API on the selected instance. The Agent API and direct transactional core enforce
the same requirement; import and omission of the optional factory selector do
not bypass it. The source implementation does not change a running factory's
contracts or install a candidate.

### Service requests and release limits

The [installed walkthrough](../cli/src/safeyolo/agent_context/skills/job-authoring/references/walkthrough.md)
provides scoped GitHub setup and both-engine artifact examples using these
boundaries, with the authorship/autonomy note beside capability adoption.

For an ordinary mediated service request, use the existing required
`check_rules` at the visible `request` stage. Select the actual host, agent and
HTTP-path predicate. The shared enforcement path completes the required check
before forwarding; a denial prevents origin contact for that request. The
job's dependency traffic retains its own capability and credential controls.
No second service evaluator is required.

Output verification protects native output acceptance, which SafeYOLO controls.
It does not withdraw artifacts already exposed elsewhere. A final GitHub merge,
external release or publication must enforce the required revision and authority
at that system's boundary. The controlled native tests establish these source
boundaries. They do not establish installed factory adoption or both-engine
runtime acceptance; those outcomes require their own supplied runtime evidence.
