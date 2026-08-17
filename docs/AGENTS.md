# SafeYolo sandbox baseline

You are running inside a SafeYolo-isolated Linux sandbox. Treat the rules in
this file as environment invariants. For detailed operations and diagnostics,
use the installed `safeyolo` skill (Codex: `$safeyolo`; Claude Code:
`/safeyolo`).

## Environment invariants

- The sandbox has no direct external network path. External traffic must use
  the preconfigured `HTTP_PROXY` / `HTTPS_PROXY` route through SafeYolo.
- Do not disable the proxy, use `--noproxy`, or attempt raw/direct egress.
  Those routes cannot work and trying them does not diagnose the proxy path.
- SafeYolo's internal Agent API is available only through the proxy at
  `http://_safeyolo.proxy.internal`. Use plain `http://`, never `https://`.
- Authenticate Agent API calls with the bearer token read from
  `/app/agent_token`. Read it for each command; do not print or persist it.
- SafeYolo's CA is already trusted. Preserve `SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE`, and `NODE_EXTRA_CA_CERTS` when launching tools.

Key paths:

| Path | Purpose |
|---|---|
| `/workspace` | Writable host folder selected for this agent |
| `/home/agent` | Persistent agent home across stop/run cycles |
| `/home/agent/.mise` | Persistent mise runtimes, tools, cache, and shims |
| `/app/agent_token` | Agent API bearer token |
| `/usr/local/share/ca-certificates/safeyolo.crt` | Trusted SafeYolo CA |
| `/safeyolo` | Read-only per-run configuration share |

## First health check

Use this exact form:

```sh
curl -sS http://_safeyolo.proxy.internal/health \
  -H "Authorization: Bearer $(cat /app/agent_token)"
```

A healthy response contains `"agent_api": "ok"`. If a request is blocked,
inspect its HTTP status, JSON body, and `X-Blocked-By` header before retrying.
Use the `safeyolo` skill for policy lookup, approvals, flow inspection,
service-gateway access, agent collaboration, and troubleshooting.

## Security boundaries

- Never request, read, expose, or use the host admin token. It is deliberately
  absent from the sandbox.
- Do not attempt to reach the host admin API on port 9090.
- Do not attempt to weaken policy, change addon modes, or bypass SafeYolo.
- Do not put `/app/agent_token`, `sgw_` service tokens, credentials, or secrets
  into chat, source files, logs, URLs, or agent-to-agent messages.
- When an action needs operator approval, stop retrying and tell the user why
  they should run `safeyolo watch` on the host.
- Ask the operator for the narrowest host or service capability needed. Do not
  ask for broad policy relaxation.

## Installing tools

Prefer mise for language runtimes and project CLIs so installs persist under
`/home/agent/.mise`:

```sh
mise use -g python@3.12
mise use -g node@22
mise use -g npm:typescript
```

Use the OS package manager only for native libraries, headers, daemons, and
other system dependencies. On Alpine custom rootfs images, prefer `apk`'s
musl-native Node.js package rather than asking mise to build Node from source.
