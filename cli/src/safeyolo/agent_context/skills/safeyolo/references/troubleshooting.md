# Troubleshooting and escalation

## Contents

- [Classify blocked responses](#classify-blocked-responses)
- [Custom credential authoring](#custom-credential-authoring)
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
| `503` | Policy, registry, vault, circuit, or proxy dependency unavailable | Inspect `X-Blocked-By`, body, `/health`, and `/circuits` |
| `508` | Request re-entered the SafeYolo proxy | Stop and report a proxy loop or double-proxy configuration |

Important 428 distinctions:

- `credential-guard` + `type: destination_mismatch` +
  `action: self_correct`: fix the destination URL. Approval is not the remedy.
- `credential-guard` + `type: requires_approval`: stop retrying and ask the
  operator to run `safeyolo inspect`.
- `network-guard` + `type: egress_approval_required`: verify the host is
  expected, then ask the operator to approve or deny it in `safeyolo inspect`.
- `service-gateway`: follow the response's requested capability, grant, or
  contract-binding workflow; do not substitute a broader route.

For a 403 network denial, call `/lookup?host=HOST` before asking for policy
changes. For a 503 from `circuit-breaker`, honor `Retry-After` rather than
asking for policy changes.

## Custom credential authoring

If `policy check` rejects top-level `credential_rules` or `credentials`, the
input uses an internal or legacy shape. The supported source is
`[credential.<name>]` with `match`, `headers` and optional `allowed_hosts`.
Use the [current reference and synthetic example](https://github.com/craigbalding/safeyolo/blob/master/docs/CONFIGURATION.md#custom-credential-classifiers).
TOML literal patterns use one backslash in `\A` and `\Z`. Custom classifiers
append to the built-in catalogue; the first match wins.

The host operator checks and applies a complete candidate with `safeyolo policy
check FILE`, `safeyolo policy apply FILE` and `safeyolo policy show`. Apply
reloads detection without restarting. Check success alone does not prove a
regex match: malformed regexes currently pass validation but are skipped.
Use a synthetic request, its `security.credential_guard` audit event and the
controlled origin's received requests to check the actual result. The audit
uses the rule name and a fingerprint, not the token value.

Classification does not grant permission. A host `allow = ["name:*"]` or an
exact-token approval is a separate operator decision. Keep unknown-secret
prompts, destination scope and explicit denials in effect. Do not change the
live policy from the sandbox or ask for the admin token. For `428`, follow the
response-specific steps above and ask the operator to use `safeyolo inspect`
when approval is required.

The Agent API's `/config` contains compiled sensor `credential_rules`, not
authorable policy. Historical `addons.yaml`, Python and JSON examples are not
current `policy.toml` syntax. A rejected internal shape does not establish a
missing classifier capability or a migration regression. Record the command,
redacted error and CLI/proxy versions before drawing that conclusion.
Codex subscription OAuth support is separate [#1123](https://github.com/craigbalding/safeyolo/issues/1123);
do not guess a Codex regex or allow arbitrary opaque tokens.

## Proxy and TLS failures

Check the internal route first:

```sh
(
  agent_token=$(cat /app/agent_token) || exit
  printf 'Authorization: Bearer %s\n' "$agent_token" |
    curl -sS --header @- http://_safeyolo.proxy.internal/health
)
```

Then inspect the environment without printing token values:

```sh
env | grep -E '^(HTTP|HTTPS|NO)_PROXY=|^(SSL_CERT_FILE|REQUESTS_CA_BUNDLE|NODE_EXTRA_CA_CERTS)='
test -r /usr/local/share/ca-certificates/safeyolo.crt
```

- If the Agent API works but one external host fails, inspect policy, budgets,
  circuits, and the external response.
- If the Agent API itself fails, ask for `safeyolo agent diagnostics <name>` and
  `safeyolo doctor` on the host.
- For Python TLS failures, preserve `SSL_CERT_FILE` and
  `REQUESTS_CA_BUNDLE`.
- For Node.js TLS failures, preserve `NODE_EXTRA_CA_CERTS`.
- Do not use `--noproxy`, unset proxy variables, or install an untrusted CA as
  a workaround.

## Logs and correlation

The audit JSONL lives at the selected audit_log_path and is not
mounted into the sandbox. Ask the operator to use the CLI rather than guessing
its filesystem path:

```sh
safeyolo logs --lines 20 --json
safeyolo logs --agent AGENT --lines 50
safeyolo diagnose --agent AGENT --json
```

Current event prefixes include `traffic.*`, `security.*`, `gateway.*`,
`plumb.*`, `agent.*`, `ops.*`, and `admin.*`. Audit decisions include
`allow`, `deny`, `warn`, `require_approval`, `budget_exceeded`, and `log`.

The Rust proxy generates a canonical request ID at ingress; a caller-supplied
request ID does not select it. Use `/explain?request_id=req-<32hex>` when a
request ID is known. Block and upstream responses expose that ID in the
`X-SafeYolo-Request-Id` response header. When a response cannot carry that
header, ask the operator to obtain the ID from `safeyolo logs`.

## Ask the operator

Request the narrowest relevant host-side action and explain the evidence:

| Command | Ask for it when |
|---|---|
| `safeyolo inspect` | A 428, gateway request, contract binding, risky route, credential, or plumb chat awaits approval |
| `safeyolo agent diagnostics <name>` | Runtime control, the shell bridge, or proxy attachment may be unavailable |
| `safeyolo doctor` | Proxy dependencies, runtime, image, CA, or isolation may be unhealthy |
| `safeyolo status` | You need the reconciled runtime, control, coding-agent and terminal observations |
| `safeyolo logs --lines 20` | You need recent security decisions |
| `safeyolo policy show` | You need to view enforcement modes; never ask the agent to change them |
| `safeyolo policy show` | You need the operator to inspect compiled policy |
| `safeyolo policy show` | `/lookup` confirms a specific expected host is missing |
| `safeyolo policy show` | You need capability, route, auth-header, or risk details |

If the guest sudo helper is missing or broken, report that specific prerequisite
for operator repair. The shell command has no guest-root flag. Do not use
a recovery request to bypass a policy or approval block.

Do not tell the operator merely to "disable SafeYolo" or switch a guard to
warn mode. State the exact host, capability, approval, or failing hop needed.

## Protect administrative credentials

The admin token is host-only. Never request it or suggest copying it into the
sandbox. If the operator accidentally discloses it in chat, tell them to rotate
it on the host without repeating the value. In a host terminal, select the
instance with SAFEYOLO_CONFIG_DIR first. This example assumes its ordinary
admin_api_token_file is data/admin_token; use the configured path otherwise:

```sh
safeyolo stop
umask 077
openssl rand -hex 32 > "$SAFEYOLO_CONFIG_DIR/data/admin_token"
safeyolo start
```

Do not execute those host commands from the sandbox.
