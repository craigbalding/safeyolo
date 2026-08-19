# Troubleshooting and escalation

## Contents

- [Classify blocked responses](#classify-blocked-responses)
- [Proxy and TLS failures](#proxy-and-tls-failures)
- [Logs and correlation](#logs-and-correlation)
- [Ask the operator](#ask-the-operator)
- [Protect administrative credentials](#protect-administrative-credentials)

## Classify blocked responses

Most SafeYolo block responses are JSON and include `X-Blocked-By`. The 508
loop-guard response is an exception and may omit that header. Prefer the JSON
`action` and `reflection` fields over guessing from status alone.

| Status | Common meaning | Response |
|---|---|---|
| `403` | Policy, route, token, contract, homoglyph, pattern, or admin-port denial | Self-correct the destination/request; do not request a blanket bypass |
| `428` | Approval required or credential destination mismatch | Inspect `type` and `action`; wait only when `action` is `wait_for_approval` |
| `429` | Rate or budget exhausted | Honor `Retry-After`, inspect `/budgets`, and back off |
| `503` | PDP, registry, vault, circuit, or proxy dependency unavailable | Inspect `X-Blocked-By`, body, `/health`, and `/circuits` |
| `508` | Request re-entered the SafeYolo proxy | Stop and report a proxy loop or double-proxy configuration |

Important 428 distinctions:

- `credential-guard` + `type: destination_mismatch` +
  `action: self_correct`: fix the destination URL. Approval is not the remedy.
- `credential-guard` + `type: requires_approval`: stop retrying and ask the
  operator to run `safeyolo watch`.
- `network-guard` + `type: egress_approval_required`: verify the host is
  expected, then ask the operator to approve or deny it in `safeyolo watch`.
- `service-gateway`: follow the response's requested capability, grant, or
  contract-binding workflow; do not substitute a broader route.

For a 403 network denial, call `/lookup?host=HOST` before asking for policy
changes. For a 503 from `circuit-breaker`, honor `Retry-After` rather than
asking for policy changes.

## Proxy and TLS failures

Check the internal route first:

```sh
curl -sS http://_safeyolo.proxy.internal/health \
  -H "Authorization: Bearer $(cat /app/agent_token)"
```

Then inspect the environment without printing token values:

```sh
env | grep -E '^(HTTP|HTTPS|NO)_PROXY=|^(SSL_CERT_FILE|REQUESTS_CA_BUNDLE|NODE_EXTRA_CA_CERTS)='
test -r /usr/local/share/ca-certificates/safeyolo.crt
```

- If the Agent API works but one external host fails, inspect policy, budgets,
  circuits, and the external response.
- If the Agent API itself fails, ask for `safeyolo agent diag <name>` and
  `safeyolo doctor` on the host.
- For Python TLS failures, preserve `SSL_CERT_FILE` and
  `REQUESTS_CA_BUNDLE`.
- For Node.js TLS failures, preserve `NODE_EXTRA_CA_CERTS`.
- Do not use `--noproxy`, unset proxy variables, or install an untrusted CA as
  a workaround.

## Logs and correlation

The audit JSONL lives in the operator's SafeYolo state directory and is not
mounted into the sandbox. Ask the operator to use the CLI rather than guessing
its filesystem path:

```sh
safeyolo logs --tail 20
safeyolo logs --event security --tail 20
safeyolo logs --agent AGENT --tail 50
safeyolo logs --request-id req-... --raw
```

Current event prefixes include `traffic.*`, `security.*`, `gateway.*`,
`plumb.*`, `agent.*`, `ops.*`, and `admin.*`. Audit decisions include
`allow`, `deny`, `warn`, `require_approval`, `budget_exceeded`, and `log`.

Use `/explain?request_id=req-<32hex>` when a request ID is known. Block
responses do not currently expose the request ID in a response header, so ask
the operator to obtain it from `safeyolo logs` when necessary.

## Ask the operator

Request the narrowest relevant host-side action and explain the evidence:

| Command | Ask for it when |
|---|---|
| `safeyolo watch` | A 428, gateway request, contract binding, risky route, credential, or plumb chat awaits approval |
| `safeyolo agent diag <name>` | The agent-to-proxy socket, attribution, bridge, or end-to-end route may be broken |
| `safeyolo doctor` | Proxy dependencies, addons, runtime, image, CA, or isolation may be unhealthy |
| `safeyolo check` | A quick host proxy/config/CA sanity check is sufficient |
| `safeyolo status` | You need proxy and running-agent state |
| `safeyolo logs --event security --tail 20` | You need recent security decisions |
| `safeyolo mode` | You need to view enforcement modes; never ask the agent to change them |
| `safeyolo policy show` | You need the operator to inspect compiled policy |
| `safeyolo policy host add HOST --agent AGENT` | `/lookup` confirms a specific expected host is missing |
| `safeyolo services show SERVICE` | You need capability, route, auth-header, or risk details |
| `safeyolo agent shell AGENT --root` | The guest sudo helper is missing or broken and needs narrow operator repair; never use this for a policy or approval block |

Do not tell the operator merely to "disable SafeYolo" or switch a guard to
warn mode. State the exact host, capability, approval, or failing hop needed.

## Protect administrative credentials

The admin token is host-only. Never request it or suggest copying it into the
sandbox. If the operator accidentally discloses it in chat, tell them to rotate
it on the host without repeating the value:

```sh
safeyolo stop
rm ~/.safeyolo/data/admin_token
safeyolo start
```

Do not execute those host commands from the sandbox.
