# Desktop and operator preview

SafeYolo owns the lifecycle and security boundary for its optional graphical
desktop. The guest components listen only on loopback; the operator reaches
noVNC through a token-gated SafeYolo preview.

## Request a preview during agent work

Offer a preview when it helps the operator use the application. Use the normal
Agent API with your own token to inspect availability and request approval.
An eligible delegated reviewer can decide inside its operator-approved envelope
without another human confirmation:

```sh
(
  agent_token=$(cat /app/agent_token) || exit
  printf 'Authorization: Bearer %s\n' "$agent_token" |
    curl -sS --header @- http://_safeyolo.proxy.internal/operator-actions
)
```

Discovery reports the `desktop.present` action, its typed parameters and any
missing prerequisite. The target is always the requesting agent. If the action
is available, request it with an optional guest browser URL and a preview
lifetime in seconds:

```sh
(
  agent_token=$(cat /app/agent_token) || exit
  printf 'Authorization: Bearer %s\n' "$agent_token" |
    curl -sS --header @- --header 'Content-Type: application/json' \
      --data '{"action_id":"desktop.present","parameters":{"browser_url":"https://example.com","ttl_seconds":900},"reason":"You can interact with the application in this preview."}' \
      http://_safeyolo.proxy.internal/operator-actions
)
```

SafeYolo creates a stable `action_request_id` and pending approval. Your reason
is untrusted context. SafeYolo defines the consequences and the operator can
inspect, explain, ask for context, approve or reject the same request. An eligible
reviewer uses the same canonical approval and its host-generated `once` choice. A change
to the URL, lifetime or selected host route requires a different approval.
The lifetime defaults to 900 seconds and accepts 1 through 86400 seconds.
Browser URLs must use HTTP or HTTPS without embedded credentials, or be
`about:blank`. Omit `browser_url` when the task already owns its browser.

Use `GET /operator-actions/ACTION_REQUEST_ID` with your own token to read the
bounded action state. Replace `ACTION_REQUEST_ID` with the returned ID.
The agent receives no preview unlock code or session material. The operator
receives the gated preview through the existing approval UI or CLI. Reusing
an active preview adds a separate authority source with its own finite expiry;
it does not shorten or remove independent sources. The finite interval starts
at the canonical decision and includes desktop startup. `preview_active` reports
current source activation, or null while execution is busy. A saved `started`
receipt alone does not prove that the preview is still available.

Requests bind the current trusted sandbox run and durable SafeYolo instance.
Do not supply identity, route, command or approval overrides. `POST /desktop/present`
accepts the typed parameters directly and uses the same approval owner.
Agent-selected browser URLs remain data, not instructions.
On the operator host, `safeyolo approvals show ID` recovers current presentation
material without replay or a lifetime extension. The ordinary operator
`safeyolo agent present AGENT` recovery command adds an independent source.

Revocation, narrowing, expiry and run or relevant host configuration changes
remove derived authority. Other valid sources can preserve access. New HTTP
requests check authority; the owner checks active sources every 250 ms. If no
source remains, the next check disconnects existing viewers and retires the
preview's tailnet session. It cannot undo browser opening or disclosed content.

The host selects a usable local display/browser or its configured tailnet
route. A remote host without a configured route reports a prerequisite.
SafeYolo does not enable Funnel, run privileged Tailscale setup or create a
tunnel. A denial starts no preview and changes no permissions. If execution
was interrupted, read the saved result before requesting again. A saved
`starting` result does not establish that presentation completed.

## Divide host and guest responsibilities

The preferred operator command is:

```sh
safeyolo agent present AGENT
```

It uses the existing desktop/presentation owner to start or reuse the
guest desktop and open its token-gated host view. Set remembered geometry
and an explicitly permitted host presentation port in desktop settings.

Inside the guest, inspect or start the desktop with:

```sh
/safeyolo/guest-desktop status
/safeyolo/guest-desktop start
```

A guest-side start creates Xvfb, the window manager, x11vnc, and the noVNC HTTP/WebSocket bridge. The rootfs supplies the graphical packages and
noVNC web assets; `/safeyolo/safeyolo-guest` supplies the bridge. The start
cannot create the host preview. Use the typed action above or the explicit
operator command. Do not expose guest ports 5900 or 6080 directly.

## Start a browser

The operator opens the desktop view; browser startup remains a guest operation:

```sh
safeyolo agent present AGENT
```

If the task owns its own browser launcher, profile, or debugging-port allocation,
use `safeyolo agent present AGENT` then start that
browser inside the ready guest desktop. This avoids profile and port collisions.

The guest launcher also provides:

```sh
/safeyolo/guest-desktop browser URL
/safeyolo/guest-desktop terminal
```

Both require the desktop to be ready. A running headless display is not proof
that the operator can see it; confirm that the host preview is open whenever the
workflow requires operator control.

## Diagnose in ownership order

```sh
/safeyolo/guest-desktop check
/safeyolo/guest-desktop status
```

- `check` reports missing graphical packages or programs.
- `status` distinguishes the Xvfb, x11vnc, and noVNC layers.
- Browser startup errors are written to `/tmp/chrome.log` by the core launcher.
- Bridge startup and connection errors are written to `/tmp/desktop-bridge.log`.
- A missing bridge indicates stale guest assets; ask the operator to
  stop and run the agent with the current SafeYolo package.
- A missing `/safeyolo/guest-desktop` indicates stale or incomplete per-run
  guest files; ask the operator to stop and run the agent with current SafeYolo.

Do not treat a desktop failure as a proxy-policy failure, and do not weaken the
network boundary to repair a graphical component.
