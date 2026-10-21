# Delegate approval decisions

A host operator can let named local reviewer agents decide network, credential
and gateway-route requests for named workers. Any one eligible reviewer can
decide. This does not give the reviewer policy administration, a worker's
credentials, or the permissions that it can issue.

Use the native host CLI and Agent API. The requesting and deciding agents must
have a current native sandbox generation with a matching durable identity and
live backend. Names are display and configuration handles. Headers, JSON
identity fields and possession of an Agent API bearer cannot select an agent.
An unverified run cannot receive or exercise a delegated permission.

## Configure and preview

On the host, select the running instance with `--root ROOT`. Run
`safeyolo --root ROOT status` to obtain the configured names and durable
IDs. The two guests must already exist. Replace the names, IDs, destination and
ports in this example with the intended local agents and destination.

Save `proposal.json`:

```json
{
  "expected_revision": null,
  "delegation": {
    "reviewers": [{"name": "reviewer", "agent_id": "ag-22222222222222222222222222222222"}],
    "beneficiaries": [{"name": "worker", "agent_id": "ag-11111111111111111111111111111111"}],
    "scopes": [{
      "type": "network_egress",
      "host": "build.example.test",
      "ports": [8443],
      "all_ports": false,
      "actions": ["request", "connect"]
    }],
    "expires_at": null,
    "grant_seconds": null,
    "gateway_once": true,
    "acknowledgment": null
  }
}
```

`expires_at` bounds the delegation. A null value leaves it configured until
change or revocation. `grant_seconds` optionally bounds each issued permission,
starting at its decision. A null value permits the worker's current run.
Stopping or replacing that run ends its access. Gateway grants also retain the
existing gateway expiry. Pending-request expiry is separate from both limits.
Checks reject a `grant_seconds` value whose expiry cannot fit the supported
timestamp range. Supported long lifetimes remain available.

Preview the exact proposal before applying it:

```sh
safeyolo --root ROOT approvals delegation preview local --file proposal.json
safeyolo --root ROOT approvals delegation check local --file proposal.json --json > preview.json
```

The preview shows the before and after configuration, deciding agents,
beneficiaries, scope, lifetimes, warnings and known independent permissions.
Unknown effects remain explicit. Port 443, GET and a capability name do not
establish business safety. Known worker write paths into reviewer startup files
are warnings. A shared source workspace alone does not imply such a path.

After inspecting these findings, create the apply input from the host's `after`
projection. This keeps its definition revisions and acknowledges this specific
proposal. The following command changes only the local proposal file:

```sh
python3 - <<'PY'
import json
from pathlib import Path
original = json.loads(Path('proposal.json').read_text())
preview = json.loads(Path('preview.json').read_text())
original['delegation'] = preview['after']
original['delegation']['acknowledgment'] = preview['acknowledgment']
Path('proposal.json').write_text(json.dumps(original, indent=2) + '\n')
PY
safeyolo --root ROOT approvals delegation apply local --file proposal.json --json
safeyolo --root ROOT approvals delegations --json
```

No generic force flag bypasses checks. Stale revisions, unknown fields,
self-benefit and unsupported bounds fail before mutation. Policy reloads also
validate the stored delegation and permission records. The host stores named
delegations in `approval_delegations` in `policy.toml`; use the preview and
apply commands to produce their encoded records.

## Select scope

Each `scopes` entry uses one of these shapes:

| Type | Fields and actual effect |
|---|---|
| `network_egress` | `host` is a supported destination pattern. `ports` and `all_ports` are required. Select either a nonempty port list with `all_ports: false`, or an empty list with `all_ports: true`. `actions` contains `request`, `connect`, or both. Each decision issues the canonical destination, port and action, rather than the whole envelope. Ordinary requests can reuse that permission across methods and paths. Existing budgets remain. |
| `credential` | `host` is an exact destination. `fingerprints` contains exact `hmac:` fingerprints. Each decision permits those observed fingerprints only for the worker's current run. It covers all ports, methods and paths at that host. It does not change the shared baseline credential approval. Port, operation, family and once bounds are unsupported and rejected. Network and service controls still apply. |
| `gateway_route` | `service`, `capability`, `method`, `path` and optional `binding_id` bound the envelope. Supported method/path patterns can cover several routes. Each issued grant binds the canonical method and literal path, current service/capability/binding definitions and worker run. It does not bind an exact payload. Existing service authorization and contract checks remain. |

Wildcard destinations, all ports, reusable access, multiple reviewers and
reciprocal approval relationships have specific preview warnings. They remain
usable after the proposal is acknowledged. The selected request must fit
entirely within one current delegation. Two partial delegations cannot be
combined to approve it.

## Reviewer workflow

The worker receives a normal 428 with an `x-safeyolo-approval-id` header. Its
request is not held for automatic replay. The existing Coord attention path
sends eligible reviewers a reference in their configured `NAME-agent` room.
It sends no secret evidence or permission in the message. Other room members
can see the reference; this does not let them read or decide the approval.

In the reviewer's normal native Coord MCP session:

1. Resolve attention through the existing attention tools.
2. Call `read_approval` with the supplied `approval_id`.
3. Inspect trusted facts and `choices`. Raw peer URLs, headers, bodies and
   credential values are omitted. Agent-supplied explanations are untrusted.
4. Call `resolve_approval` with `approval_id`, one offered `delegation`, its
   `option`, and `decision: approve`, `reject`, or `defer`.
5. Use `list_approvals` to reconcile after reconnect or unavailable attention.

Network and credential decisions use the offered `run` option. Gateway decisions
can use `run`, or `delegated_once` when the delegation permits it. Routine
in-envelope decisions require no further human confirmation. The reviewer
cannot replace the destination, identity, fingerprint, service, payload or
policy fields. Direct reads and decisions each recheck authority.

The Agent API equivalents are `GET /approvals`, `GET /approvals/APPROVAL_ID`
and `POST /approvals/APPROVAL_ID/resolve`. A decision body contains only
`decision`, `delegation` and `option`. Use the normal guest proxy and the
reviewer's own Agent API token. Do not give guests an Admin API token or NATS
credentials. Where the native CLI is installed, `safeyolo helper list`,
`helper show ID`, and `helper approve|reject|defer ID --delegation NAME
--option ID` use the same endpoints. Helper output is JSON.

After approval, the worker retries its request. Refresh a gateway bearer through
`GET /gateway/services` after native policy publication. Rejection is terminal
for that approval and installs no deny rule. Deferral leaves it pending.
Equivalent pending operations share one material approval. Attention for the
same reviewer, run and permission is coalesced, including after a refusal.
A later traffic request can remain pending in the canonical list without
repeated notifications. A terminal ID cannot issue another permission.

## Change, revoke and recover

Inspect `approvals delegations --json` for revisions and issued access. For a
change, use the current revision as `expected_revision`, edit the proposal,
clear its acknowledgment and old `definition_revisions`, then preview again.
If a reciprocal delegation changes the relationship between reviewers and
beneficiaries, the old acknowledgment is stale. Preview and acknowledge the
updated proposal before applying it.
Changing a delegation conservatively removes its issued permissions.

For revocation, save `{"expected_revision":"CURRENT_REVISION"}` in
`revoke.json`, then run:

```sh
safeyolo --root ROOT approvals delegation revoke local --file revoke.json --json
```

Revocation removes only that delegation's issued access. Independent operator
policy and other valid grants remain. The preview describes known residual
network permissions and the limits of its credential/service analysis.
Revocation and expiry apply to new authorizations, including later inspected
requests on the same client connection and new CONNECT admissions. An already
admitted opaque tunnel can continue. Revocation cannot reverse upstream writes
or recover disclosed data.

A proxy restart retains issued run permissions only while the same worker run,
delegation, definitions and expiry remain valid. Gateway once grants use the
existing reservation, completion and release rules. They do not guarantee
exactly-once external effects after a crash or an ambiguous response.

If a decision response is lost, read the canonical approval before another
call. An approved decision remains approved after its access is consumed,
removed or expired. `grant_active` reports whether the issued permission still
exists and has current authority. Repeating the decision does not restore it.
Policy receipts recover a committed decision when its final database
status write was lost. An unconfirmed activation is reported explicitly;
inspect `policy show` and the canonical grant before repairing policy. No
held request or uncertain external write is replayed automatically.

If the reviewer is missing, busy, offline, lacks model access, or cannot obtain
evidence or attention, the worker stays blocked. The operator can still use
`approvals list`, `approvals show`, `approvals explain`, `approvals approve` and
`approvals reject`, including the offered run option. The native interactive
view is `safeyolo --root ROOT inspect --agent WORKER`. Use `pending`,
`approval APPROVAL_ID`, `explain APPROVAL_ID --option run`, or `review` there.
The inspect session and Command Centre use the same host resolver. Direct
policy controls remain operator-only.

For a live client check, use the installed runner's existing
`--interfaces --wait-for-operator --operator-timeout 600 --reconcile-seconds 180`
mode without `--real-helper`. This mode requires both owned guests and the
proxy to be running, with the same test preparation as the workflow below.
Use the native inspect session and an operator-owned Command Centre connection
to that exact instance. Disconnect and reconnect each client while the request
is pending. Check that the same canonical approval returns. Select an offered
option in one client. Check the terminal result from the other client and the
worker's retry at the owned origin. The runner's later `client_reconciliation`
message identifies the canonical outcome and keeps the instance live for the
selected observation window. Record the actual client observations; the
window alone does not establish a client result. Use the normal Command Centre
connection setup in [installation](installation.md), and keep the operator
credential on the operator's host.

To exercise the remaining delegated client choices without a model, use
`--delegated-clients`. Use the same marked Ubuntu/systrap instance, with its
proxy, both guests and isolated Coord already running. Both guests need the
existing Python request preparation. The host needs the existing `tomlkit`
dependency. Stage the `delegated-fixture` service before proxy start as described
below. The reviewer must have receive access to `helper-agent`. Connect Command
Centre to that exact instance through its supported authenticated connection.
Keep its operator credential outside the guests.
Use a Command Centre build that includes the canonical option picker in
`command-centre/macos/Sources/UI.swift` and the selected-option request in
`Models.swift`. The retained Commander at `cb587fcc` has neither feature.
Its network default-approval result remains valid, but that executable cannot
perform these lifetime and gateway choices. Build the current client through
`command-centre/macos/build-app.sh` on the supported Mac build route. Do not
replace a requested run option with that older client's persistent default.

From the prepared driver checkout, set `ROOT` to that disposable installation
and `NATIVE_COMMIT` to its verified full native source commit. The driver source
and native source can differ only when that reuse has been assessed. Run:

```sh
timeout 720s python3 tests/blackbox/installed_shared_approvals.py \
  --config-dir "$ROOT" --transport-cli "$ROOT/bin/safeyolo" \
  --native-cli "$ROOT/bin/safeyolo" --native-proxy "$ROOT/bin/safeyolo-proxy" \
  --commit "$NATIVE_COMMIT" --worker worker --helper helper \
  --delegated-clients --operator-timeout 180 --reconcile-seconds 30
```

The driver stops only this disposable instance's Coord before making requests.
It records failed delegated delivery, the still-pending canonical approval,
authorized reviewer lookup/list results and unchanged origin hits. It does not
start a model. When each `client_pending` record appears, check its exact
approval ID and effect in Command Centre. Select these offered options, then
select Allow. Leave other cards and the later consumed-once request pending:

| Request | Option | Effect to check |
|---|---|---|
| Network | `run` | Only this worker run, destination, selected port and request action. |
| Credential | `run` | Only this worker run and the exact fingerprint at the destination; all ports, methods and paths at that host. Shared baseline credential approval stays unchanged. |
| Gateway | `delegated_once` | One route grant for the exact method/path and current worker run, with the existing service and contract checks. The grant does not bind a payload. |

These are explicit operator decisions on requests that have eligible delegated
reviewers. The operator uses its own authority; these decisions are not
attributed to the unavailable reviewer. Record the actual app connection,
displayed ID/effect, selected option and action separately. A driver result
alone cannot establish that a GUI action occurred.

The driver emits `client_decision` with the canonical result, then
`client_retry` with the selected origin effect and the raw self-decision,
reviewer, wrong-port and gateway-consumption refusals. The first request and
failed attention do not reach the origin. Each explicit retry adds one selected
origin hit. A wrong lifetime or missing failed-delivery result fails the run.
The final 30-second window permits client readback before cleanup. This check
does not replace the retained network reconnect or real model results.
The driver restores the original policy and stops both guests, proxy and
origins. After an outer timeout, the operator must separately stop both owned
guests and the proxy, verify stopped state and absent readiness/listeners, and
restore the saved policy through the existing fixture cleanup procedure.

## Exercise the real reviewer workflow

The maintained `tests/blackbox/installed_shared_approvals.py` runner has a
`--delegated` mode for an owned disposable Linux instance. It requires the
selected native proxy and two real guests to be running. The reviewer must
already have its normal Codex login, saved model configuration and current
native Coord MCP adapter. The reviewer guest must run, but its coding session
must be stopped, exited or failed. The runner starts its own foreground coding
session and refuses to replace an existing live session. No model choice or
new login is required by this feature.

Before starting that disposable proxy, read `gateway_services_dir` from the
selected installed `ROOT/config.toml`. Resolve a relative value against `ROOT`;
keep an absolute value unchanged. Install
`tests/blackbox/fixtures/delegated-approval-service.yaml` in that directory as
`delegated-fixture.yaml`. For example, `gateway_services_dir = "data/services"`
uses `ROOT/data/services/delegated-fixture.yaml`. Check that the authenticated
service catalogue lists `delegated-fixture` before running the consumer.
Use the existing Coord server and grant
the reviewer receive access to its `helper-agent` room. Use different room and
agent names together if the reviewer is not named `helper`. Keep the instance's
normal model-route policy. The runner checks source/profile identity and the
disposable marker used by the existing platform probes.

From the selected source checkout, run:

```sh
.venv/bin/python tests/blackbox/installed_shared_approvals.py \
  --config-dir "$ROOT" --transport-cli "$ROOT/bin/safeyolo" \
  --native-cli "$ROOT/bin/safeyolo" --native-proxy "$ROOT/bin/safeyolo-proxy" \
  --commit "$(git rev-parse HEAD)" --worker worker --helper helper \
  --interfaces --real-helper --delegated
```

This mode configures three typed delegations, starts a reviewer coding session
in its supported attention wait, and exercises network, synthetic credential and
gateway-once decisions. It checks canonical decisions and independently
observes origin requests. It also checks the reviewer and a second port remain
blocked. Model events stay in private files under the instance's logs. The
runner restores its saved policy and stops both owned guests, origins and
proxy, including on failure. A failed or unavailable run is unproved. Separate
race, lifecycle, failure-recovery and client checks are still required.

To check lifecycle without a model session, use the same marked Ubuntu/systrap
instance with both guests, the proxy and its existing isolated Coord running.
Both guests need the existing test preparation. The worker must have a
configured workspace. The runner uses
the supported stop/start commands and keeps the same worker home for the
same-name replacement. Use the prepared source checkout and its matching native
installation:

```sh
.venv/bin/python tests/blackbox/installed_shared_approvals.py \
  --config-dir "$ROOT" --transport-cli "$ROOT/bin/safeyolo" \
  --native-cli "$ROOT/bin/safeyolo" --native-proxy "$ROOT/bin/safeyolo-proxy" \
  --commit "$(git rev-parse HEAD)" --worker worker --helper helper \
  --delegated-lifecycle
```

This mode uses real guest API calls for reviewer decisions. It prevents the
final canonical database update after a policy commit, kills the verified owned
proxy, then starts the proxy through the native CLI. It checks that recovery
preserves the same permission and expiry without replaying the held request.
It checks that worker
stop/start, stale launch context and same-name replacement cannot inherit that
permission. It also checks that a configured reviewer can decide after its own
restart. At the stale-context step, a new native shell may refuse to select the
current sandbox before HTTP runs. The runner accepts only the specific
unavailable-sandbox diagnosis or an HTTP 403/428. In either case, the origin must
remain unchanged and the same old approval must show an inactive grant. The
result records the actual outcome, native exit and output, approval and run
IDs, origin counts and grant readback. The runner restores the launch context
in `finally`. A later canonical read, decision and origin retry check the restored
route. Unrelated transport failures and timeouts still fail.
The runner also flushes the stale attempt to standard output after restoring
the context, including when the attempt fails. It emits the completed
reviewer-restart observation before the next lifecycle operation. The remainder
selection also emits its ordinary setup grant before worker turnover. These
partial records preserve actual operands if a later check fails. They do not
claim that the remaining checks or cleanup passed.
Snapshot phases record operands before their assertions and make no passing
claim. Completed lifecycle checks set `phase_passed=true`. The runner emits
their result before cleanup. Only the final result after
successful cleanup contains `owned_guests_proxy_and_origins_stopped=true`.

If a prior run already reached the proxy crash and worker restart but stopped
at the stale-context observer, retain that result. To run only the remaining
checks, use the same prerequisites and command with
`--delegated-lifecycle --delegated-lifecycle-remainder`. The remaining checks
create one ordinary grant and turn over the worker to establish an inactive old
grant, then check stale context, reviewer restart and same-name replacement.
They do not repeat the proxy crash or run a model. The result identifies this
selection and makes no crash-recovery claim for that invocation. Keep the driver
source commit separate from `--commit`, which checks the native binary commit.
Retained results keep their actual source and platform attribution; this
continuation does not supply missing operands from an earlier run.

If only the crash/recovery relationship is missing, select
`--delegated-lifecycle --delegated-lifecycle-crash-only`. Use the same lifecycle
prerequisites. From the prepared driver checkout, set `ROOT` and
`NATIVE_COMMIT` to the verified native installation, then run:

```sh
timeout 600s python3 tests/blackbox/installed_shared_approvals.py \
  --config-dir "$ROOT" --transport-cli "$ROOT/bin/safeyolo" \
  --native-cli "$ROOT/bin/safeyolo" --native-proxy "$ROOT/bin/safeyolo-proxy" \
  --commit "$NATIVE_COMMIT" --worker worker --helper helper \
  --delegated-lifecycle --delegated-lifecycle-crash-only
```

This selection uses the existing canonical-write failure and owned proxy crash.
It emits `proxy_crash_before` with the approval, saved policy receipt, typed
network grant and origin snapshots. After restart, `proxy_crash_recovered`
records the same operands and the new proxy process identity before comparison.
The approval ID, issued result, effective receipt and grant must stay the same.
No origin request may occur before the explicit retry. `proxy_crash_retry`
records that retry's response and the one selected origin request. These raw
records are flushed before later assertions or cleanup. The final result has
`lifecycle_selection=crash_only`. It does not perform worker/reviewer turnover,
same-name replacement or a model exchange. Retain the independently observed
remainder instead of repeating it to obtain a full-run summary.

All lifecycle selections restore the original policy and stop both owned guests, proxy
and origins. Keep the instance's isolated Coord configuration when restarting;
do not use another instance's default ports. This mode does not establish a
model exchange or a Command Centre reconnect result.
