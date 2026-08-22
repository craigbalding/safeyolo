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

## When to invoke the `safeyolo` skill

Auto-invoke on the *first turn* any of these come up — do not wait for the
operator to prompt you, and do not attempt a workaround before reading the
skill's references. The skill has authoritative, up-to-date answers that
supersede training-data guesses.

Triggers include, non-exhaustively:

- SafeYolo blocks: `X-Blocked-By`, HTTP 403 / 428 / 429 / 503 / 508 from a
  request that would normally succeed, `wait_for_approval`, `type:` /
  `action:` / `reflection:` JSON block bodies.
- TLS / CA failures behind the SafeYolo proxy (`SEC_ERROR_UNKNOWN_ISSUER`,
  `unable to get local issuer certificate`, unknown authority) that would
  succeed outside the sandbox.
- Guest package installation, `sudo`, `setpriv`, `apt`, `apk`, `pip`, `mise`
  behaviour that surprises you (blocked, missing, silently redirected).
- Debugger / profiler attach failures inside the guest: `ptrace: Operation
  not permitted`, `py-spy` / `rbspy` / `strace` / `gdb` denied against a
  same-uid process.
- `safeyolo agent shell --root` or operator-recovery-shell paths.
- Agent API queries (`/lookup`, `/budgets`, `/policy`, `/flows`, `/plumb`),
  flow inspection, budget or circuit-breaker state.
- Approved agent-to-agent plumb collaboration.
- General "am I inside a SafeYolo sandbox / what facilities are available /
  how do I debug this in-container" introspection.

If you find yourself typing an answer that starts with "I think" about any
of the above, stop and invoke the skill first.

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
other system dependencies. SafeYolo provides passwordless **guest** sudo for
that purpose; use `-n` so a broken configuration fails instead of waiting for
a password that does not exist:

```sh
# Debian, Ubuntu, or Kali
sudo -n apt-get update
sudo -n apt-get install -y PACKAGE

# Alpine
sudo -n apk add PACKAGE
```

This reaches root only inside the isolated guest. It does not invoke host sudo
or grant access beyond the guest's existing writable mounts and mediated
network path. Package downloads still traverse SafeYolo and can require normal
policy approval.

On rootless Linux gVisor, `/usr/local/bin/sudo` uses the agent's existing
namespace capabilities through `/usr/bin/setpriv`; guest uid 0 maps to an
unprivileged subordinate host uid. The underlying Linux-only diagnostic form
is `setpriv --reuid=0 --regid=0 --clear-groups COMMAND`, but prefer `sudo` for
normal work because it is portable to hardware microVMs and preserves the
configured proxy and CA environment. Do not ask the operator for
`safeyolo agent shell --root` for routine installs; that is a recovery path
when guest sudo itself is broken.

Only `/home/agent` and `/workspace` are guaranteed persistent. In particular,
Linux gVisor discards installed OS-package files when the agent stops, although
per-agent package-download caches keep reinstalls cheap. On Alpine custom
rootfs images, prefer `apk`'s musl-native Node.js package rather than asking
mise to build Node from source.
