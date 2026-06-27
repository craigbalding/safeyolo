# Agent Preview: explicit host access to agent-local HTTP

## Problem

Agents often run local development servers inside their sandbox. Operators need
to inspect those HTTP apps from the host browser without weakening SafeYolo's
main guarantee: agents operate naturally inside the sandbox, but any bridge to
other systems is explicit, scoped, attributable, and auditable.

This is not Docker-style port publishing. A service listening inside an agent
must not become reachable from the host merely because it bound a port.

## Goals

- Let an operator preview `http://127.0.0.1:<guest-port>` inside one named
  agent from the host.
- Reuse the same platform control path as `safeyolo agent shell`.
- Require an explicit operator action to open a route.
- Scope the route to one agent and one guest port.
- Bind the host listener to loopback only.
- Require an unguessable access token so hostile web pages cannot abuse
  browser localhost probing.
- Log route open, request, response, error, and close events.
- Close the route when the command exits.

## Non-goals for the MVP

- No ambient stable listener on the configured SafeYolo proxy port.
- No raw TCP forwarding.
- No WebSocket streaming guarantee.
- No public LAN exposure.
- No attempt to make this traffic look like ordinary agent egress.
- No mitmproxy add-on dependency for host ingress.

## Proposed command

```bash
safeyolo agent preview <agent> <guest-port>
```

Default behavior:

- Picks an available host loopback port.
- Prints a URL containing a session token.
- Runs until interrupted.

Example:

```bash
$ safeyolo agent preview codey 8000
Preview open:
  http://127.0.0.1:54321/?safeyolo_preview_token=...
Agent:
  codey -> 127.0.0.1:8000
```

Useful options:

```bash
safeyolo agent preview codey 8000 --host-port 54321
safeyolo agent preview codey 8000 --open
safeyolo agent preview codey 8000 --ttl 30m
```

## Transport model

The CLI owns a small host-local HTTP reverse proxy:

```text
host browser
  -> 127.0.0.1:<host-port>
  -> safeyolo CLI preview server
  -> platform bridge
  -> agent-local http://127.0.0.1:<guest-port>
```

Platform bridge:

- macOS: same shell bridge family as `safeyolo agent shell`
  (`ssh` over `ProxyCommand=nc -U <shell.sock>`).
- Linux: same sandbox execution family as `safeyolo agent shell`
  (`runsc exec` in the agent sandbox).

The MVP should establish a preview session when the command starts, not spawn a
new guest command for every HTTP request. Normal web apps fan out into many
asset requests; per-request shell startup would make the feature feel broken
and would hide the real lifecycle problem.

The session has two layers:

- **Host HTTP gate:** public loopback listener shown to the operator. It
  validates the preview token, strips it, logs/audits, and enforces HTTP
  policy.
- **Private platform bridge:** command-owned transport from the host gate to
  the agent-local service. On macOS this can be an SSH forwarding session over
  the existing shell socket. On Linux this should be a persistent runsc-backed
  bridge or the closest per-connection equivalent the platform can support.

For the MVP, the private bridge can be a persistent helper process inside the
agent. The host gate sends JSON-line request frames over stdin and receives
JSON-line response frames over stdout. That keeps the browser-facing token gate
on the host while avoiding per-request shell startup.

The host HTTP gate must remain in front of the bridge. A raw `ssh -L` style
listener exposed directly to the browser would bypass token checks and recreate
the localhost probing problem.

## Request handling

For each inbound host request:

1. Reject unless the request includes the preview token.
2. Strip the preview token before forwarding.
3. Reject methods outside an MVP allowlist if needed.
4. Forward the cleaned HTTP request over the established private bridge to
   `127.0.0.1:<guest-port>` inside the agent.
5. Return status, selected headers, and body to the host client.
6. Log request and response metadata.

Hop-by-hop headers are stripped. The host-facing proxy should also set response
headers such as:

```text
X-SafeYolo-Agent: <agent>
X-SafeYolo-Preview-Port: <guest-port>
```

## Safeguards

- **Explicit route creation:** the agent cannot open this bridge itself.
- **Loopback-only host bind:** the listener is not reachable from the LAN.
- **Session token:** protects against hostile web pages probing
  `127.0.0.1`.
- **Agent and port scope:** one command grants one guest port on one agent.
- **Reserved port denylist:** guest ports used by SafeYolo plumbing are
  rejected.
- **Lifecycle bound:** route closes on Ctrl-C, process exit, TTL expiry, or
  agent stop.
- **No credential forwarding by default:** the preview token is never sent to
  the guest app.

## Audit events

Emit structured events into SafeYolo's existing audit log:

- `agent.preview_open`
- `traffic.preview_request`
- `traffic.preview_response`
- `traffic.preview_error`
- `agent.preview_close`

Fields:

- `agent`
- `guest_port`
- `host_port`
- `method`
- `path`
- `status`
- `bytes_in`
- `bytes_out`
- `duration_ms`
- `reason` for errors/close

## MVP implementation sketch

1. Add `safeyolo agent preview <agent> <guest-port>` CLI command.
2. Validate the target agent, guest port, and reserved-port denylist.
3. Start a private platform bridge to the agent-local service.
4. Start a `ThreadingHTTPServer` bound to `127.0.0.1`.
5. Generate a high-entropy token with `secrets.token_urlsafe`.
6. Proxy validated HTTP requests through the private bridge.
7. Tear down the bridge on Ctrl-C, TTL expiry, or server error.
8. Log audit events.
9. Add focused unit tests for token enforcement, URL cleaning, command
   construction, and server lifecycle.

## Later work

- Persistent bridge for lower latency.
- WebSocket support.
- Response streaming for large assets.
- Optional `--open` browser integration.
- Route registry visible in `safeyolo status`.
- Admin API endpoints for listing and closing active previews.
- Optional mitmproxy/flow-store integration if preview traffic needs the same
  inspection UI as agent egress.

## Open questions

- Command name: `preview`, `serve`, `expose`, or `http`.
- Should the default token live only in memory, or should there be an optional
  reusable operator token?
- Should `GET`/`HEAD` be the MVP default, with `--allow-write-methods` for
  `POST`/`PUT`/`DELETE`?
- Should previews require an explicit TTL by default?
