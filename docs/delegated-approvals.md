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
`approvals reject`, including the offered run option. Watch and Command Centre
use that same host resolver. Direct policy controls remain operator-only.

## Exercise the real reviewer workflow

The maintained `tests/blackbox/installed_shared_approvals.py` runner has a
`--delegated` mode for an owned disposable Linux instance. It requires the
selected native proxy and two real guests to be running. The reviewer must
already have its normal Codex login, saved model configuration and current
native Coord MCP adapter. Its coding session must be idle. No model choice or
new login is required by this feature.

Before starting that disposable proxy, install
`tests/blackbox/fixtures/delegated-approval-service.yaml` as
`ROOT/services/delegated-fixture.yaml`. Use the existing Coord server and grant
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

This mode configures three typed delegations, starts the idle reviewer in its
supported attention wait, and exercises network, synthetic credential and
gateway-once decisions. It checks canonical decisions and independently
observes origin requests. It also checks the reviewer and a second port remain
blocked. Model events stay in private files under the instance's logs. The
runner restores its saved policy and stops both owned guests, origins and
proxy, including on failure. A failed or unavailable run is unproved. Separate
race, lifecycle, failure-recovery and client checks are still required.
