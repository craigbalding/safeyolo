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
- Require an explicit one-time unlock flow so hostile web pages cannot abuse
  browser localhost probing, while keeping browser URLs safe for screenshots
  and demos.
- Log route open, request, response, error, and close events.
- Close the route when the command exits.

## Non-goals for the MVP

- No ambient stable listener on the configured SafeYolo proxy port.
- No raw TCP forwarding.
- No public LAN exposure.
- No attempt to make this traffic look like ordinary agent egress.
- No mitmproxy add-on dependency for host ingress.
- No HTTP/2, HTTP/3, WebTransport, WebRTC, or general protocol mirror.

`agent preview` is a browser-safe, operator-unlocked, localhost reverse proxy
for agent-local web apps. It supports HTTP/1.1 streaming and WebSockets. It is
not a general network tunnel and not a full HTTP/2, HTTP/3, WebTransport, or
WebRTC transport mirror.

## Proposed command

```bash
safeyolo agent preview <agent> <guest-port>
```

Default behavior:

- Picks an available host loopback port.
- Prints a clean URL and a separate one-time unlock code.
- Runs until interrupted.

Example:

```bash
$ safeyolo agent preview codey 8000
Preview open:
  http://127.0.0.1:54321/
Unlock code:
  4821-9037
Agent:
  codey -> 127.0.0.1:8000
```

Useful options:

```bash
safeyolo agent preview codey 8000 --host-port 54321
safeyolo agent preview codey 8000 --open
safeyolo agent preview codey 8000 --ttl 30m
safeyolo agent desktop web --open
safeyolo agent desktop web --browser https://example.com --open --ttl 15m
safeyolo agent desktop web --share tailnet --ttl 15m
safeyolo agent preview web 6080 --start-vnc
safeyolo agent preview web 6080 -b https://example.com
safeyolo agent preview web 6080 --start-vnc --vnc-size 1600x900
```

`agent desktop` is the first-class operator workflow. SafeYolo stages its own
launcher at `/safeyolo/guest-desktop`, checks the optional rootfs capability,
starts the guest stack on loopback, and opens the same token-gated preview.
The named agent must already be running; desktop access never starts its
configured coding-agent process implicitly. `--status` and `--stop` manage the
guest stack without opening a host preview.

The host-level `desktop.size` value in `~/.safeyolo/config.yaml` provides the
persistent default (`auto` or `WIDTHxHEIGHT`). SafeYolo stages the same value at
`/safeyolo/desktop-size`, so trusted agent-side browser orchestrators invoke the
core launcher with the same preference. An explicit `--size` wins for one host
command; `--remember-size` also saves that explicit size as the host default.

`preview --start-vnc` and `preview --browser` remain compatibility spellings,
but call the same core launcher. With automatic sizing, the CLI detects the
host display and starts the guest noVNC desktop at a size that fits the
operator's browser. Managed noVNC previews use
`/vnc.html#autoconnect=true&resize=remote`, so the client connects when the
page opens. Rootfs images supply Xvfb, x11vnc, websockify/noVNC assets, a
window manager, and optionally Chromium; SafeYolo never installs those
packages at runtime.
Ordinary HTTP preview sessions do not start guest services.

### Optional Tailscale transport

`--share tailnet` wraps the same loopback-only preview gateway in a foreground
Tailscale Serve HTTPS mapping. It does not bind the gateway or guest service to
a LAN/tailnet interface and never enables Funnel. The unlock code, session
cookie, agent binding, audit events, and TTL remain enforced by SafeYolo.

SafeYolo reserves a stable HTTPS port per configured agent in `policy.toml`,
starting at 8443, so several agent previews can coexist on one host. An
explicit `--tailnet-port` replaces that agent's reservation after checking it
is not assigned to another SafeYolo agent. Before starting Serve, the CLI also
refuses to replace an existing node-level Tailscale mapping on that port.

The Tailscale process runs in foreground mode and is owned by the preview
command. Ctrl-C, TTL shutdown, setup failure, and normal exit terminate that
process; SafeYolo never calls `tailscale serve reset`. Requests arriving from
the loopback reverse proxy may use Tailscale's forwarded HTTPS host/protocol
for same-origin unlock validation and a Secure cookie. Tailscale identity and
forwarding headers are removed before the request crosses into the guest.

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
- Linux: gVisor's native `runsc port-forward --stream` connected-FD donation.
  SafeYolo creates a short-lived operator-owned UDS for each request; no host
  TCP listener or guest process is created.

The session has two layers:

- **Host HTTP gate:** public loopback listener shown to the operator. It
  validates an in-memory session cookie issued after one-time unlock,
  strips SafeYolo preview cookies/headers, logs/audits, and enforces HTTP
  policy.
- **Private platform bridge:** command-owned transport from the host gate to
  the agent-local service. For each authenticated browser request, Linux
  donates one connected UDS stream into gVisor; macOS uses its existing
  shell-bridge subprocess and guest `socat`.

The host gate parses only enough HTTP to authenticate the browser request,
reserve SafeYolo control paths, strip SafeYolo cookies/headers, and attach
preview attribution headers to the response. Response bodies are streamed
without buffering, so chunked responses, large assets, SSE-style streams, and
WebSocket upgrades can flow over HTTP/1.1.

The host HTTP gate must remain in front of the bridge. A raw `ssh -L` style
listener exposed directly to the browser would bypass token checks and recreate
the localhost probing problem.

The browser-facing URL should not contain the preview secret. The CLI prints a
clean localhost URL plus a one-time unlock code in the terminal. The first
browser visit shows a local unlock form; a successful unlock invalidates the
code, sets an `HttpOnly; SameSite=Strict` session cookie, and redirects back to
`/`. The cookie name includes the browser-facing port, allowing one operator to
keep multiple local or Tailnet previews open on the same hostname without one
preview overwriting another's session.

## Request handling

For each inbound host request:

1. Reject unless the request includes a valid preview session cookie.
2. Strip SafeYolo preview cookies/headers before forwarding.
3. Reject methods outside an MVP allowlist if needed.
4. Forward the cleaned HTTP/1.1 request over the private platform bridge to
   `127.0.0.1:<guest-port>` inside the agent. Non-upgrade requests force
   `Connection: close` upstream to avoid implementing a full keep-alive proxy.
   Keep the relay write side open until the response is consumed: gVisor may
   translate an early host write EOF into closure of the whole guest stream.
5. Stream response headers and body back to the host client. For
   `101 Switching Protocols`, relay bytes bidirectionally until either side
   closes.
6. Log request and response metadata.

Requests under `/_safeyolo_preview/*` are reserved for the host gate and are
never forwarded to the guest app. The MVP uses
`/_safeyolo_preview/unlock` for the local unlock form.

Hop-by-hop headers are stripped. The host-facing proxy should also set response
headers such as:

```text
X-SafeYolo-Agent: <agent>
X-SafeYolo-Preview-Port: <guest-port>
```

## Safeguards

- **Explicit route creation:** the agent cannot open this bridge itself.
- **Loopback-only host bind:** the listener is not reachable from the LAN.
- **One-time unlock + session cookie:** protects against hostile web pages
  probing `127.0.0.1` without putting secrets in the URL bar, browser
  history, copied links, or screenshots.
- **Agent and port scope:** one command grants one guest port on one agent.
- **Reserved port denylist:** guest ports used by SafeYolo plumbing are
  rejected.
- **Lifecycle bound:** route closes on Ctrl-C, process exit, TTL expiry, or
  agent stop.
- **No credential forwarding by default:** the SafeYolo preview session cookie
  and headers are never sent to the guest app.
- **Unlock hardening:** unlock is `POST`-only, rate-limited/locked after
  repeated failures, short-lived, origin-aware where browser headers allow, and
  invalidated after first successful use.

## Audit events

Emit structured events into SafeYolo's existing audit log:

- `agent.preview_open`
- `agent.preview_unlock`
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
3. Start the host-local preview listener.
4. Start a `ThreadingHTTPServer` bound to `127.0.0.1`.
5. Generate a high-entropy session token with `secrets.token_urlsafe` plus a
   short one-time unlock code.
6. For each cookie-authenticated guest request, open a binary platform relay:
   native gVisor stream donation on Linux and the shell/socat bridge on macOS.
7. Stream HTTP/1.1 responses and WebSocket upgrade traffic through that bridge.
8. Log audit events.
9. Add focused unit tests for unlock enforcement, clean URL printing, command
   construction, and server lifecycle.

## Later work

- Persistent/multiplexed bridge if native per-request stream donation later
  proves too costly for very high request counts.
- Optional HTTPS/local-cert mode for secure-context browser APIs.
- Optional `--open` browser integration.
- Route registry visible in `safeyolo status`.
- Admin API endpoints for listing and closing active previews.
- Optional mitmproxy/flow-store integration if preview traffic needs the same
  inspection UI as agent egress.

## Open questions

- Command name: `preview`, `serve`, `expose`, or `http`.
- Should the unlock code TTL be configurable?
- Should `GET`/`HEAD` be the MVP default, with `--allow-write-methods` for
  `POST`/`PUT`/`DELETE`?
- Should previews require an explicit TTL by default?
