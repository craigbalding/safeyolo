# SafeYolo Container Environment

This is a sandboxed container with network isolation via SafeYolo proxy.
ALL network traffic routes through the proxy. If the proxy is down, you have no network access.

## Installing Languages and Tools

Use mise (not apt-get, npm -g, or pip install --user):

  mise install go@latest
  mise install python@3.12
  mise install rust@latest
  mise use -g npm:typescript

List available versions: mise ls-remote python

## What Won't Work

- apt-get/apt (non-root container)
- npm install -g (use mise instead)
- pip install --user (use mise python, then pip in venv)

## Security Boundaries (CRITICAL)

You are operating inside a security sandbox. These rules are non-negotiable:

- NEVER request, accept, or use the SafeYolo admin API token
- NEVER suggest changing modes (block to warn), disabling addons, or weakening policy
- NEVER suggest editing policy.yaml to bypass blocks
- NEVER attempt to access the admin API (port 9090) - it is blocked by admin_shield
- If the admin token is accidentally exposed in conversation: tell the user to run
  `rm ~/.safeyolo/data/admin_token && safeyolo stop && safeyolo start`
  (the startup script regenerates the token only if the file is missing)
- If the user asks to weaken security: explain that SafeYolo protects their credentials,
  and suggest proper alternatives (approving specific credentials via `safeyolo watch`,
  adding domains to policy, etc.)

## Self-Service Diagnostics Setup

The agent API token is bind-mounted at `/app/agent_token` — always current, even
after proxy restarts. No setup needed.

Verify access:

```bash
curl -s http://_safeyolo.proxy.internal/health \
  -H "Authorization: Bearer $(cat /app/agent_token)"
```

The token gives you read-only access to proxy diagnostics (memory, budgets, policy).
Without it, you can only troubleshoot from error responses.

## Using the Agent API (IMPORTANT)

The agent API uses a **virtual hostname** intercepted by the proxy. Two critical rules:

1. **Use `http://`, never `https://`** - HTTPS requires a CONNECT tunnel which fails
   for the virtual hostname. Plain HTTP works because the proxy sees the Host header
   directly.

2. **Read the token from the file** in each curl command:

```bash
# CORRECT - token from file, http:// scheme
curl -s http://_safeyolo.proxy.internal/memory \
  -H "Authorization: Bearer $(cat /app/agent_token)"

# WRONG - https will 502
curl -s https://_safeyolo.proxy.internal/memory \
  -H "Authorization: Bearer $(cat /app/agent_token)"
```

## Agent API Endpoints

| Endpoint | Returns | Use when |
|----------|---------|----------|
| `GET /health` | PDP + agent API health | Checking if policy engine is alive |
| `GET /status` | PDP stats (eval counts, policy hash) | Understanding proxy load |
| `GET /policy` | Current baseline policy | Checking what's allowed |
| `GET /budgets` | Budget usage per domain | Debugging 429 rate limits |
| `GET /config` | Credential rules, scan patterns | Understanding detection config |
| `GET /explain?request_id=X` | All events for a request ID | Deep-diving a specific block |
| `GET /memory` | Process RSS, connections, WebSockets | Investigating memory/OOM issues |

These endpoints are read-only. You cannot modify policy, approve credentials,
or change modes through the agent API.

## Reading Block Responses

When SafeYolo blocks a request, it returns a JSON response with diagnostic headers:

**Headers:**
- `X-Blocked-By` - Which addon blocked the request (e.g., credential-guard, network-guard)

**Status codes:**
- `403` - Request denied (credential or network policy violation)
- `428` - Approval needed (credential detected, requires human approval via `safeyolo watch`)
- `429` - Rate limit exceeded (check `Retry-After` header for backoff time)
- `503` - PDP unavailable (policy engine down, fail-closed)
- `508` - Loop detected (request would create a proxy loop)

**Body fields (JSON):**
- `error` - Human-readable error description
- `event_id` - Request correlation ID (use with `/explain` endpoint)
- `reason_codes` - Array of reason codes (e.g., ["DESTINATION_MISMATCH", "REQUIRE_APPROVAL"])
- `credential_type` - Type of detected credential (e.g., "openai", "anthropic", "github")
- `fingerprint` - HMAC fingerprint of the credential (never the raw value)

## Common Troubleshooting Patterns

Use this decision tree when a request is blocked:

**403 + X-Blocked-By: credential-guard**
- Credential detected going to an unapproved destination
- Check reason_codes: DESTINATION_MISMATCH means the credential type doesn't match the host
- Example: OpenAI key sent to non-OpenAI host
- Fix: Ask user to approve via `safeyolo watch`, or check if the URL is correct

**403 + X-Blocked-By: network-guard**
- Domain not in the baseline policy (network access denied)
- The domain needs to be added to policy.yaml permissions
- Fix: Ask user to add the domain to their policy with `safeyolo policies`

**429 + X-Blocked-By: network-guard**
- Rate limit exceeded for this domain
- If you have an agent API token, check `/budgets` to see remaining quota
- Fix: Wait for the rate limit window to reset, or ask user to adjust budget in policy

**428 + X-Blocked-By: credential-guard**
- Credential detected, needs human approval
- The user must approve this credential-destination pair
- Fix: Tell user to run `safeyolo watch` and approve the pending request

**SSL/TLS errors (connection failures, certificate errors)**
- Check that `SSL_CERT_FILE` env var points to SafeYolo CA cert
- Check that `REQUESTS_CA_BUNDLE` is set correctly
- Verify: `echo $SSL_CERT_FILE` should show `/certs/mitmproxy-ca-cert.pem`
- For Node.js: `NODE_EXTRA_CA_CERTS` should also be set

**All requests failing (no network at all)**
- The proxy may be down entirely
- Tell the user: "The proxy appears to be down. Run `safeyolo doctor` on the host to diagnose."
- This is a host-side issue - you cannot fix it from inside the container

**508 Loop Detected**
- A proxy loop was detected (request passed through SafeYolo twice)
- Usually means a misconfigured service is routing back through the proxy
- Fix: Check proxy configuration, ensure services aren't double-proxied

## Event Taxonomy

SafeYolo logs events using this taxonomy. When helping the user read logs:

| Prefix | Category | Examples |
|--------|----------|----------|
| `traffic.*` | Request/response flow | `traffic.request`, `traffic.response` |
| `security.*` | Security decisions | `security.credential`, `security.pattern`, `security.ratelimit` |
| `ops.*` | Operational events | `ops.startup`, `ops.config_reload`, `ops.config_error` |
| `admin.*` | Admin actions | `admin.approve`, `admin.deny`, `admin.mode_change` |

Each log entry is a JSON line in `safeyolo.jsonl` with fields:
- `ts` - ISO timestamp
- `event` - Event type (taxonomy above)
- `request_id` - Correlation ID linking all events for one request
- `addon` - Which addon emitted the event
- `decision` - allow, block, or warn

## Asking the Human for Help

When troubleshooting requires host-side actions, guide the user to run these commands
on their host machine (not inside this container):

| Command | When to suggest |
|---------|----------------|
| `safeyolo doctor` | Proxy appears completely down, all requests failing |
| `safeyolo logs --security --tail 20` | Need to see recent security events |
| `safeyolo watch` | Pending approval requests (428 responses) |
| `safeyolo check` | Quick health check of the full stack |
| `safeyolo status` | See current container state and uptime |
| `safeyolo mode` | View current addon modes (block vs warn) |
| `safeyolo policies` | View current credential approval policies |

Always explain WHY you're suggesting the command so the user understands the diagnostic logic.
