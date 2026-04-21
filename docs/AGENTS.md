# SafeYolo guide for agents

Reference for coding agents (Claude Code, Codex, aider, anything else) operating
inside a SafeYolo sandbox. Written second-person -- the agent is the reader.
Humans browsing: this is also the canonical agent-facing contract.

Host scripts in `contrib/` copy (parts of) this content into the agent's
native context location (e.g. `/etc/claude-code/CLAUDE.md`) so the agent
loads it as system guidance on startup.

## 1. Environment

You are running inside an isolated Linux sandbox: an Apple Virtualization
microVM on macOS hosts, or a rootless gVisor container on Linux hosts. The
sandbox has **no external network interface**. The only egress path is
`HTTP_PROXY` -> a per-agent Unix socket -> the SafeYolo mitmproxy on the
host.

Key paths inside the sandbox:

| Path | Purpose |
|---|---|
| `/workspace` | The folder the user passed to `safeyolo agent add`. Writable. |
| `/home/agent/` | Your persistent home. Survives `agent stop` / `agent run` cycles via a VirtioFS bind from `~/.safeyolo/agents/<name>/home/` on the host. |
| `/home/agent/.mise/` | mise data dir. `mise use -g <tool>` installs stick here across restarts. |
| `/app/agent_token` | Bearer token for the agent API (see section 3). Refreshed on every `agent run`. |
| `/usr/local/share/ca-certificates/safeyolo.crt` | SafeYolo's CA cert. Already trusted system-wide; `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `NODE_EXTRA_CA_CERTS` are all pre-set. |
| `/safeyolo/` | Read-only config share (auth keys, proxy env, your CLAUDE.md / instructions file). |

Pre-set environment: `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`,
`NO_PROXY=localhost,127.0.0.1`, plus the three CA-cert env vars above.

The base image also has a few universal tools already present: `rg`, `fdfind`,
`git`, `jq`, `less`, `tmux`, `lsof`, `strace`, `file`, `unzip`, `zip`,
`python3 -m venv`, and BusyBox-backed `nc` / `hexdump`. Use those first;
reach for `mise` when you actually need a language runtime or project-specific
toolchain.

## 2. Installing tools

Use mise for language runtimes and project-specific CLIs. `apt` / `apt-get` /
`yum` are intercepted and redirect to mise:

```sh
mise install go@latest
mise install python@3.12
mise use -g npm:typescript
```

Because `MISE_DATA_DIR` is `$HOME/.mise` (persistent), anything you install
via `mise use -g` survives restart.

What won't work: `apt-get`, `npm install -g`, `pip install --user`. These
either fail outright (apt intercept) or put state in paths that don't persist.

## 3. Agent API

SafeYolo's mitmproxy exposes a read-only diagnostic API intercepted at a
**virtual hostname**: `_safeyolo.proxy.internal`. Requests to it never hit
the network -- mitmproxy synthesises responses.

Two hard rules:

1. **Use `http://`, never `https://`.** The virtual hostname doesn't resolve,
   so `https://` requires a CONNECT tunnel the proxy can't fulfil. Plain HTTP
   gives mitmproxy the `Host:` header directly.
2. **Authorization comes from `/app/agent_token`.** Always read the token per
   request; it rotates when the host proxy restarts.

Sanity check:

```sh
curl -s http://_safeyolo.proxy.internal/health \
  -H "Authorization: Bearer $(cat /app/agent_token)"
```

### Endpoints

All read-only unless marked. POST endpoints accept JSON bodies.

| Method | Path | Returns |
|---|---|---|
| `GET`  | `/health` | PDP + agent API health |
| `GET`  | `/status` | PDP stats (eval counts, policy hash) |
| `GET`  | `/policy` | Current baseline policy |
| `GET`  | `/lookup?host=X` | What would happen if this agent called `X` |
| `GET`  | `/budgets` | Budget usage per domain |
| `GET`  | `/config` | Credential rules + scan patterns |
| `GET`  | `/explain?request_id=X` | Event chain for a specific request ID |
| `GET`  | `/memory` | Process RSS, connections, WebSockets |
| `GET`  | `/agents` | Known agents + last-seen timestamps |
| `GET`  | `/circuits` | Circuit-breaker state per domain |
| `GET`  | `/gateway/services` | Services this agent has access to, plus services available to request |
| `POST` | `/gateway/request-access` | Ask for a capability on a service (creates a pending approval) |
| `POST` | `/gateway/submit-binding` | Submit contract-binding values (e.g. an email address for a send-mail contract) |
| `GET`  | `/api/flows/{id}` | Flow metadata |
| `GET`  | `/api/flows/{id}/request-body` | Decompressed request body for a flow |
| `GET`  | `/api/flows/{id}/response-body` | Decompressed response body for a flow |
| `GET`\|`POST` | `/api/flows/search` | Search flows by filter criteria |
| `POST` | `/api/flows/endpoints` | Distinct endpoints + counts |
| `POST` | `/api/flows/body-search` | Full-text search over response bodies |
| `POST` | `/api/flows/request-body-search` | Full-text search over request bodies |
| `POST` | `/api/flows/diff` | Compare two flow response bodies |
| `POST` | `/api/flows/{id}/tag` | Add / update a tag on a flow |
| `DELETE` | `/api/flows/{id}/tag/{name}` | Remove a tag |

You **cannot** modify policy, approve credentials, change addon modes, or
reach the admin API (port 9090) from here. Any such attempt is blocked by
the `admin_shield` addon.

## 4. Reading block responses

When SafeYolo blocks, it returns JSON with an `X-Blocked-By` header. The
addon name tells you which guard fired; the status code tells you what
class of block.

| Status | Meaning | Typical addon |
|---|---|---|
| 403 | Denied by policy | credential-guard (when fallback path used), other PEPs |
| 428 | Approval required -- human must ack via `safeyolo watch` | credential-guard, network-guard (prompt effect) |
| 429 | Rate limit / budget exhausted | network-guard (budget), PDP |
| 503 | PDP unavailable -- fail-closed | any PEP when the policy engine can't answer |
| 508 | Proxy loop detected | loop-guard |

### 428 body (most common block class)

Credential-guard emits two shapes:

```json
{
  "error": "Credential routing error",
  "type": "destination_mismatch",
  "credential_type": "openai",
  "destination": "api.anthropic.com",
  "expected_hosts": ["api.openai.com"],
  "credential_fingerprint": "hmac:...",
  "action": "self_correct",
  "reflection": "You sent a openai credential to api.anthropic.com..."
}
```

```json
{
  "error": "Credential requires approval",
  "type": "requires_approval",
  "credential_type": "github",
  "destination": "api.github.com",
  "credential_fingerprint": "hmac:...",
  "reason": "first use of this credential at this destination",
  "action": "wait_for_approval",
  "reflection": "This credential requires human approval before use."
}
```

Network-guard 428 bodies include `"Check if this is an expected destination,
then approve or deny via safeyolo watch."` in the reason field.

Decision tree:

- **403 + `X-Blocked-By: credential-guard`**: credential destination doesn't
  match its type. Fix the URL, or surface to the user that the host is wrong.
- **428 + `X-Blocked-By: credential-guard`** (`type: destination_mismatch`):
  same as 403 in the new flow -- self-correct the URL, or tell the user.
- **428 + `X-Blocked-By: credential-guard`** (`type: requires_approval`):
  wait. Tell the user to run `safeyolo watch` on the host and approve.
- **428 + `X-Blocked-By: network-guard`**: this domain needs host approval
  before egress. Same remediation: `safeyolo watch`.
- **429 + `X-Blocked-By: network-guard`**: rate or budget exceeded. Read
  `/budgets` for the remaining quota and backoff. If the user wants to lift
  it, they edit `~/.safeyolo/policy.toml` and reload.
- **503 anywhere**: the policy engine crashed or is restarting. Tell the user
  to run `safeyolo doctor` on the host.
- **508**: request was re-entering the proxy. A misconfigured service is
  routing through SafeYolo twice; tell the user.
- **SSL/TLS errors** (not a SafeYolo block, a client-side complaint): verify
  `SSL_CERT_FILE=/usr/local/share/ca-certificates/safeyolo.crt`. For Node.js
  clients, `NODE_EXTRA_CA_CERTS` must also be set. All three are pre-set in
  your environment; something has unset them.

## 5. Events and logs

Every decision SafeYolo makes lands in `~/.safeyolo/logs/safeyolo.jsonl` on
the host (one JSON object per line). You can't read this file from inside
the sandbox -- logs live host-side. Ask the user to run `safeyolo logs
--tail 20` or filter with `--security`.

Event-kind prefixes:

| Prefix | What fires these |
|---|---|
| `traffic.*` | Request / response lifecycle |
| `security.*` | Guards: credential, network, pattern, ratelimit |
| `gateway.*` | Service gateway bindings, capability grants |
| `agent.*` | Agent lifecycle: add / start / stop / remove |
| `ops.*` | SafeYolo process events: startup, config reload, errors |
| `admin.*` | Mode changes, approvals, denials |

Each record has `ts`, `event`, `request_id` (correlation), `addon`,
`decision` (`allow` / `block` / `warn`), plus event-specific fields.

If you need the chain for a single request, call `/explain?request_id=X`.
Block responses don't carry `request_id` in headers today, so you'd need
the user to pull it from logs and paste it to you. (Feature request area
-- if you catch yourself needing this often, flag it to the user.)

## 6. Security boundaries (strict)

You are not allowed, and you cannot:

- Read, request, or suggest using the **admin API token**. It lives at
  `~/.safeyolo/data/admin_token` on the host and never appears inside the
  sandbox. If the user accidentally pastes it into a conversation, tell
  them to run:

  ```sh
  rm ~/.safeyolo/data/admin_token && safeyolo stop && safeyolo start
  ```

  (The startup script regenerates the file only if missing.)
- Reach the admin API port (9090). `admin_shield` will block you.
- Edit `~/.safeyolo/policy.toml` or `~/.safeyolo/addons.yaml` to weaken
  enforcement. If the user asks you to weaken policy, explain that
  SafeYolo exists to protect their credentials and suggest the proper path:
  approve specific credentials via `safeyolo watch`, or add specific domains
  via `safeyolo policy host add ...`.
- Change addon modes from `block` to `warn`. That's an admin action.

## 7. Asking the human for help

When a problem needs host-side action, guide the user to specific
commands rather than hand-waving:

| Command | When to suggest it |
|---|---|
| `safeyolo doctor` | The proxy seems down / everything is 503 / tests are broken in ways you can't see |
| `safeyolo logs --tail 20` | You need a specific event correlation |
| `safeyolo logs --security --tail 20` | Only security decisions |
| `safeyolo watch` | A 428 approval is pending |
| `safeyolo check` | Quick health sanity |
| `safeyolo status` | Is the proxy running? Which agents? |
| `safeyolo mode` | View current block/warn modes per addon |
| `safeyolo policies` | View credential / network policy |
| `safeyolo agent diag <name>` | Deep diagnostic on one agent: hop-by-hop check of bridge socket, attribution IP, end-to-end probe |

Always explain *why* you're asking -- the user learns from your reasoning,
and they can course-correct faster when they understand the diagnostic path.
