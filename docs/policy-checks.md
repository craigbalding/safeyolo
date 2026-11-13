# Named policy checks

Named checks supply typed evidence to the native network policy. The operator
selects each source, meaning, scope and influence in `policy.toml`. A check
result does not grant service or credential access. Those controls still apply.

The shared implementation is [checks.rs](../proxy/src/policy/checks.rs).
Current evidence acquisition reads operator-selected, captured JSON files.
Job/service execution and managed feed acquisition supply those results through
their own authorized mechanisms. The named-check evaluator does not execute a
callback, start a sandbox, download a feed or call a provider.

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
Aggregation with an unavailable input remains unavailable. No-match is
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

Current collection reads a fresh file snapshot for each admission. There is no
separate result cache. The captured bytes have a host-computed file digest;
file replacement/change and subject/input/version mismatches prevent reuse.
Future backend caches must preserve these bindings and current policy/authority
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
safeyolo --root /path/to/instance policy check candidate.toml
safeyolo --root /path/to/instance policy evaluate candidate.toml request.json
```

The JSON preview identifies `recorded_offline` evidence, rule results, source
metadata, freshness, guard outcome and the final allow/deny/approval/unresolved
action. It performs no direct or dependency-mediated target contact. Current
preview has no live provider operation. Already captured scanner evidence can
be used within its freshness; preview never starts a scan, crawl or visit.
Credential/service controls may further restrict a live request. Preview does
not establish that a running instance has activated the candidate.

Within the operator's existing authorization, use the current
[check/show/apply workflow](installation.md#check-show-and-apply) to activate
and verify the candidate. Keep saved, active and unconfirmed states distinct.
The model and transport tests are source proof; installed backend, managed-feed
and complete cyber-recipe acceptance require their actual implementations.
