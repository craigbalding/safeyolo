# Temporary service route approval

For an established approved service, an agent can ask for temporary access to
one missing route with the existing host credential. An explicit policy denial
cannot use this flow. Network, credential, contract and risk controls still
apply. An existing risky-route grant or reviewer delegation does not authorize
missing route admission.

## Reconsider a denied request

In a current agent run, send the service request through the proxy with the
service's gateway token. If the route has no allow rule and other controls
permit the request, HTTP 403 returns `GATEWAY_ROUTE_CHALLENGE`. The response
contains a `challenge_id`, host-recorded `scope`, `guidance` and an `escalate`
path. The blocked operation has not reached the upstream service. A challenge
creates no pending operator approval or notification.

Read the scope before proceeding. SafeYolo records the agent and run, service
and destination, capability, account, credential reference and binding, method
and literal path. The upstream credential value remains secret. Scope fields
come from the host; the agent cannot replace them during escalation.

Read the available service, capability and risk descriptions. Missing guidance
means unknown effects; it does not establish safety or create another denial
rule. Alternative routes show the current gateway permission assessment.
`allowed` describes route permission only. A different capability or a missing
route may require access. Concrete arguments, contract values, network,
credential, risk and upstream prerequisites still need checking. An alternative
request passes the ordinary controls.

Decide whether the operation is needed for the operator's task. Distinguish a
direct operator request, an inference during troubleshooting, and a suggestion
from untrusted content. Abandon an unnecessary operation, use an applicable
alternative, or explicitly escalate. SafeYolo treats the agent's source label
and explanation as untrusted context. Completing reconsideration or claiming
absence of prompt injection grants no authority.

Inside the agent, read its Agent API bearer from `/app/agent_token` for this
command without printing or saving the value. Replace `CHALLENGE_ID` with the
returned identifier. Adapt the task, reason, fallback and source to the actual
request. `fallback` explains why applicable alternatives are insufficient;
`source` can name `directly_requested`, `inferred` or `untrusted_content`, or
describe uncertain or mixed origin. Each context field is limited to 2048 UTF-8
bytes, as in the existing pending-approval context interaction.

```sh
(
  agent_token=$(cat /app/agent_token) || exit
  printf 'Authorization: Bearer %s\n' "$agent_token" |
    curl -sS --header @- --header 'Content-Type: application/json' \
      --data '{"source":"inferred","context":{"task":"Diagnose the failed job","reason":"The next diagnostic needs this operation","fallback":"The permitted status route does not show the needed detail"}}' \
      http://_safeyolo.proxy.internal/gateway/challenges/CHALLENGE_ID/escalate
)
```

An eligible escalation returns HTTP 202 and one canonical pending approval.
Read `GET /gateway/challenges/CHALLENGE_ID` with the same Agent API bearer to
inspect current status. Equivalent requests coalesce independently of reason
wording and query/body values. Refusal history and existing notification limits
remain. After refusal or expiry, another challenge and explicit escalation may
request a new decision; neither renews access automatically.

## Decide on the host

On the operator's host, use the installed instance and replace `APPROVAL_ID`
with the canonical identifier returned by escalation. These commands inspect
and explain the request without granting access:

```sh
safeyolo approvals list --json
safeyolo approvals show APPROVAL_ID --json
safeyolo approvals explain APPROVAL_ID --json
```

Inspect the host-derived scope, risk assessment, effects, uncertainty and offered
expiry separately from the untrusted reason. The `run` option expires after the
reported number of seconds from approval, or earlier when the credential
expires. The operator decides whether the reason is sufficient. For additional
context, use `safeyolo approvals ask APPROVAL_ID` and
`safeyolo approvals context APPROVAL_ID`; this separate pending-approval
interaction does not alter authority.

After reviewing the complete scope, grant the offered exception or reject it:

```sh
safeyolo approvals approve APPROVAL_ID --option run --json
# To refuse instead:
safeyolo approvals reject APPROVAL_ID --json
```

Approval permits the agent to retry explicitly. SafeYolo never stores and
replays the blocked request. The exception applies only to the recorded run,
destination, capability, account, credential binding, method and literal path.
It uses the existing upstream credential. Other paths, methods, agents and
bindings remain outside the grant. Ordinary service permissions remain usable.

Query and body values, including job IDs, are unrestricted by the route grant.
Only an existing enforced contract can make such values access bounds. A literal
trailing slash is part of an exception's path; a normalized ordinary route does
not authorize a different trailing-slash path. Other path-trick checks remain.

SafeYolo rechecks current policy, definitions, binding and credential at use.
Expiry, revocation or run replacement prevents subsequent use without agent
cleanup. Restart and retries do not extend an approved expiry. Expiry does not
undo upstream effects or promise cancellation of an already admitted operation.
Use `safeyolo services grants` and `safeyolo services revoke-grant GRANT_ID` on
the host to inspect or revoke the stored grant. A revoked or expired grant needs
a new explicit decision; an old approval cannot restore it by retry.

The canonical audit log records `gateway.route_challenged`,
`gateway.route_escalated`, `admin.approval_decided` and
`gateway.route_exception_used`. Existing grant revocation, policy and request
events remain available. Join these records by the canonical approval, grant
and request identifiers. Notification or an audit append does not establish
requester receipt or upstream success.

## Local proof

The maintained [service fixture](../tests/blackbox/fixtures/service-route-challenge.yaml)
uses a local controlled sink. It offers a permitted status diagnostic and a
separate diagnostic capability needing access. Its execution and deletion
operations illustrate the operator's `POST /api/59/executions/` versus
`POST /api/delete` boundary. These paths do not claim verified Rundeck API
semantics. No live Rundeck mutation is part of this proof.

From the repository root on Linux, select the built native proxy with
`SAFEYOLO_RUST_PROXY` and the credential-writing native CLI with
`SAFEYOLO_NATIVE_CLI`. With the frozen development environment prepared, run:

```sh
uv run --frozen --no-sync pytest -q tests/proxy_contracts/test_service_route_challenge.py
```

The tests exercise real proxy listeners, the canonical operator API, the grant
store and the local sink. A separate agent exercise can demonstrate reading the
challenge, reconsidering alternatives, escalation and explicit retry. Such an
exercise supplements enforcement tests; it does not prove injection detection.

To repeat the supplemental exercise, replace `CLIENT` with a provisioned native
coding-client wrapper and `OUTPUT` with a new owned directory outside the
checkout. The driver reads the canonical fixture scope and makes the fixture's
operator decision with its synthetic operator credential:

```sh
PYTHONPATH="$PWD/tests/reference" uv run --frozen --no-sync python -m tests.proxy_contracts.service_route_agent_exercise OUTPUT --client CLIENT
```

Expected result: one status diagnostic, one explicitly approved execution and no
replay or deletion. The output directory retains the agent interaction and sink
observations. These results establish this controlled interaction only.
