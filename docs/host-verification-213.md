# Host-side verification for issue #213 PR B

The sandbox this branch was developed in cannot spin up a real
`mitmproxy` master with a live `UnixInstance` listener. The blackbox
suite that would normally exercise the full lifecycle needs `runsc`
and a dedicated test VM (see `tests/blackbox/conftest.py`).

Per the reviewer's explicit ask, this file documents the concrete
host-side commands to run against a live SafeYolo proxy on
`agent/issue-213-doctor-probe-dag-consumers` before sign-off. These
verifications must pass on the host — the in-sandbox tests
(`tests/test_probe_lifecycle.py`, `tests/test_transport_guard.py`,
`cli/tests/test_doctor_traced_probe.py`) reconstruct the hook order
and interactions deterministically but cannot prove the real proxy
lifecycle behaves as designed.

## Two-layer defense being verified

Per the seventh-pass review architecture:

- **Layer 1 — `transport_guard.request()`** — client-correlatable
  request-hook failsafe. Runs AFTER `probe_sink`. If the sink is
  missing/inert, synthesises a 502 with `X-SafeYolo-Request-Id` and
  records `transport-guard/error/probe_sink_failed`. **The wire
  response IS delivered** because mitmproxy honours `flow.response`
  set from a request hook.
- **Layer 2 — `transport_guard.server_connect()`** — audit-only
  structural backstop. Fires only when BOTH `probe_sink` and layer 1
  are absent (catastrophic chain failure). Refuses the connection
  and writes `security.probe_reached_upstream` at CRITICAL.
  **Client sees mitmproxy's generic protocol error** —
  `handle_protocol_error()` in mitmproxy 12.2.2 does not honour
  `flow.response` set from the `error(flow)` hook.

V3a exercises Layer 1 (the normal missing-sink case). V3b exercises
Layer 2 (both absent).

## Preconditions

- Branch `agent/issue-213-doctor-probe-dag-consumers` checked out on
  the host.
- `safeyolo start` completed cleanly; at least one agent registered
  and reachable via its per-agent UDS.
- `safeyolo doctor` baseline runs without errors on `master` first
  (to isolate any regressions).

## Shared setup (used by V3a/V3b/V4)

These commands work on both Linux and macOS. Run from the host, NOT
from inside the SafeYolo sandbox. The agent token, Agent API address,
and mitmproxy log path differ from container assumptions — use the
paths below.

```sh
# Host-side agent token (get_agent_token_path()). NOT /app/agent_token
# which is the container path.
TOKEN_FILE="$HOME/.safeyolo/data/agent_token"

# mitmproxy log lives under XDG_STATE_HOME by default
# (get_logs_dir() in cli/src/safeyolo/config.py). Honour override.
LOG_DIR="${SAFEYOLO_LOGS_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/safeyolo}"
MITM_LOG="$LOG_DIR/mitmproxy.log"
# Structured audit JSONL — same directory (proxy.py sets
# SAFEYOLO_LOG_PATH = "$LOG_DIR/safeyolo.jsonl").
AUDIT_JSONL="$LOG_DIR/safeyolo.jsonl"

# First registered agent socket. Real layout is <ip>_<agent>/proxy.sock.
AGENT_SOCK=$(ls "$HOME/.safeyolo/data/sockets/"*/proxy.sock 2>/dev/null | head -1)
AGENT_NAME=$(basename "$(dirname "$AGENT_SOCK")" | cut -d_ -f2-)
test -n "$AGENT_SOCK" || { echo "no agent socket found"; exit 1; }
test -f "$MITM_LOG" || { echo "mitmproxy log not found at $MITM_LOG"; exit 1; }
test -f "$AUDIT_JSONL" || { echo "audit log not found at $AUDIT_JSONL"; exit 1; }

# Session-scoped log-diff helpers (issue #213 tenth-pass review).
# Both mitmproxy.log and safeyolo.jsonl are append/rotating — a
# whole-file grep can find hits from earlier sessions and let V3b
# "pass" on a historical event or make V1 "fail" on stale evidence.
# Baseline the byte offset before each phase, inspect only new bytes.
mark_offsets() {
  MITM_OFFSET=$(wc -c < "$MITM_LOG")
  AUDIT_OFFSET=$(wc -c < "$AUDIT_JSONL")
}
new_mitm() {
  tail -c +$((MITM_OFFSET + 1)) "$MITM_LOG"
}
new_audit() {
  tail -c +$((AUDIT_OFFSET + 1)) "$AUDIT_JSONL"
}

# curl the Agent API via the UDS. `_safeyolo.proxy.internal` is a
# mitmproxy virtual host, NOT a real DNS name — resolve it via the
# Host header while connecting to the UDS.
sy_api() (
  path="$1"
  agent_token=$(cat "$TOKEN_FILE") || exit
  printf 'Authorization: Bearer %s\n' "$agent_token" |
    curl -sS --unix-socket "$AGENT_SOCK" \
      -H "Host: _safeyolo.proxy.internal" --header @- \
      "http://_safeyolo.proxy.internal$path"
)

# Send the raw HTTP/1.0 origin-form probe (exactly what doctor does).
# printf with explicit \r\n keeps CRLF line endings — heredocs give LF
# and mitmproxy's HTTP/1.0 parser is strict about it.
send_probe() {
  local ctx_run="$1"
  printf 'GET /__pipeline_probe HTTP/1.0\r\nHost: _safeyolo.probe.internal\r\nX-SafeYolo-Trace: 1\r\nX-SafeYolo-Test-Context: run=%s;agent=%s;test=host-verification\r\nConnection: close\r\n\r\n' \
    "$ctx_run" "$AGENT_NAME" \
    | socat - "UNIX-CONNECT:$AGENT_SOCK"
}
```

## V1 — Normal probe reaches probe_sink and returns 200

```sh
mark_offsets  # baseline log positions for session-scoped assertions
safeyolo doctor
```

**Expect** in the output:

- `Pipeline probe` (existing virtual-host check) — `pass`.
- `Pipeline probe (traced)` — `pass` for every registered agent.
  - Each per-agent line shows the real agent name (NOT `proxy` — that
    would indicate the B5 socket-parse regression is back).
  - The `findings` block includes `probe HTTP 200` as the first entry.
  - Every `EXPECTED_ADDONS` member is accounted for. Any of these
    states is a healthy PASS for a given addon:
    - `state=evaluated` with any addon-specific outcome
    - `state=bypassed, reason=addon_disabled` (loaded but option off —
      legitimate for e.g. service-gateway on a default install)
    - `state=bypassed, reason=policy_disabled` (PDP scoped it out for
      the probe host)
  - **No** `state=error`, `not_loaded`, or `missing_from_trace` for
    any expected addon.
  - `probe-sink` step present with `outcome=probe_terminated`.
- No `transport-guard` step appears in any per-agent trace.
- **Session-scoped** — no NEW `security.probe_reached_upstream`
  event added since `mark_offsets` (must be zero for THIS session,
  not zero across all history):
  ```sh
  new_audit | grep -c '"event": *"security.probe_reached_upstream"'
  # → 0
  ```

## V2 — No egress to the probe host (architectural proof)

The strongest proof is architectural, not syscall-tracing:
`connect()` traces show sockaddrs (IPs), not hostnames, and DNS
payload greps don't reliably match `probe.internal`; `lsof` is a
point-in-time snapshot and misses transient attempts. Neither is
hostname-level proof.

Instead, the two-layer architecture itself provides deterministic
evidence:

- **V1** (already run above): the normal probe returns through
  `probe_sink` — no `server_connect` for the probe host is invoked
  and no `security.probe_reached_upstream` audit event is emitted.
- **V3a** (below): the request-hook failsafe catches a missing sink
  BEFORE transport is attempted. Still no `probe_reached_upstream`
  audit event.
- **V3b** (below): with both request-side terminators disabled, the
  `server_connect` structural boundary fires and refuses the
  reserved host BEFORE the connection is opened.

Together these three prove:

- Normal path never reaches `server_connect` for the probe host;
- Failsafe path never reaches `server_connect` for the probe host;
- The `server_connect` guard, when actually exercised, refuses the
  connection locally.

**V2 checklist requirement**: confirm the audit-event evidence
described in V1/V3a/V3b holds. Doctor's `Pipeline probe (traced)`
result plus `safeyolo logs --event security` grepping for
`probe_reached_upstream` is the authoritative signal.

### Optional supplementary syscall observation (not required)

If you want a syscall-level cross-check, these can be useful as
additional signal but do NOT replace the architectural proof above.
None of them provides hostname-level certainty on their own:

**Linux:**
```sh
MITM_PID=$(cat "$HOME/.safeyolo/data/proxy.pid")
sudo strace -f -e trace=connect,sendto -p "$MITM_PID" 2>&1 \
  | grep -iE 'probe\.internal|_safeyolo\.probe'
```

**macOS:**
```sh
MITM_PID=$(cat "$HOME/.safeyolo/data/proxy.pid")
sudo dtruss -p "$MITM_PID" -t connect 2>&1 \
  | grep -iE 'probe\.internal|_safeyolo\.probe'
```

**Cross-platform snapshot:**
```sh
lsof -p "$MITM_PID" -i | grep -i probe.internal
```

Missing hits are consistent with V1/V3a/V3b's authoritative proof
but do not by themselves guarantee it.

## V3a — Missing sink triggers the request-hook failsafe (Layer 1)

Force `probe_sink` to be inert without touching security addons.
Temporarily comment out the two hook methods in `probe_sink.py`:

```python
class ProbeSink:
    name = "probe-sink"
    # def requestheaders(self, flow): pass
    # def request(self, flow): pass
```

Leave `transport_guard.py` untouched — the failsafe should catch it.

Restart the proxy: `safeyolo stop && safeyolo start`.

Run the raw probe (uses `send_probe` from Shared setup):

```sh
mark_offsets  # baseline for session-scoped assertions below
send_probe v3a > /tmp/v3a.raw
cat /tmp/v3a.raw
```

**Expect (all mandatory)**:

- Response status is **502** (not a raw connection error). This proves
  Layer 1 synthesised the response.
- **`X-SafeYolo-Request-Id` header IS present.** Capture:
  ```sh
  RID=$(awk '
    tolower($1) ~ /^x-safeyolo-request-id:$/ { print $2 }
  ' /tmp/v3a.raw | tr -d '\r')
  echo "$RID"
  ```
- Response body is JSON with `reason_code: "probe_sink_failed"` and
  `host: "_safeyolo.probe.internal"`.
- Fetch `/trace` via the Agent API helper from Shared setup:
  ```sh
  sy_api "/trace?request_id=$RID" | python -m json.tool
  ```
  Expect a `transport-guard` step with
  `state=error, reason=probe_sink_failed`.
- **NO** NEW `PROBE REACHED UPSTREAM` line in mitmproxy.log
  since `mark_offsets` (session-scoped, ignores history):
  ```sh
  new_mitm | grep -c "PROBE REACHED UPSTREAM"
  # → 0
  ```
- **NO** NEW `security.probe_reached_upstream` audit event since
  `mark_offsets`:
  ```sh
  new_audit | grep -c '"event": *"security.probe_reached_upstream"'
  # → 0
  ```

Also confirm doctor picks this up:

```sh
safeyolo doctor
```

**Expect** `Pipeline probe (traced)` status is `fail` for each agent,
with findings mentioning `transport-guard (non-manifest): error
(probe_sink_failed)`.

## V3b — Both sink AND failsafe absent triggers server_connect backstop (Layer 2)

Now temporarily disable `transport_guard.request()` too — keeping the
`probe_sink.py` edit from V3a in place:

```python
class TransportGuard:
    # ...
    # def request(self, flow): pass  # disabled for V3b
    def server_connect(self, data): ...  # left in place
```

Restart: `safeyolo stop && safeyolo start`.

Repeat the raw probe:

```sh
mark_offsets  # fresh baseline for this phase
send_probe v3b > /tmp/v3b.raw
cat /tmp/v3b.raw
```

**Expect**:

- The client-side response is **not** a clean 502 with correlation —
  it's mitmproxy's generic protocol error (whatever
  `handle_protocol_error()` produces). No `X-SafeYolo-Request-Id`
  header — this is the intentional cost of reaching Layer 2, and
  matches the reviewer's stated posture: audit-only.
- **New** `PROBE REACHED UPSTREAM` line in mitmproxy.log for THIS
  phase (session-scoped, proves the boundary fired for THIS
  invocation and not a historical one):
  ```sh
  new_mitm | grep "PROBE REACHED UPSTREAM" | tail -1
  ```
- **New** `security.probe_reached_upstream` audit event for THIS
  phase, at CRITICAL severity with
  `details.reason_code = probe_reached_upstream`:
  ```sh
  new_audit | grep '"event": *"security.probe_reached_upstream"' | tail -1 | python -m json.tool
  ```

The operator can still correlate the failure via the audit log even
without a client-side request-id header.

## V4 — Restore everything, verify healthy state + no circuit damage

```sh
git checkout -- cli/src/safeyolo/mitm_addons/probe_sink.py cli/src/safeyolo/mitm_addons/transport_guard.py
safeyolo stop && safeyolo start
safeyolo doctor
```

**Expect** `Pipeline probe (traced)` back to `pass` for every agent
and no new `PROBE REACHED UPSTREAM` or `probe_sink_failed` events.

Also verify circuit-breaker did NOT open on the probe host during
V3a/V3b (issue #213 eighth-pass review — probe host is built-in
excluded so repeated diagnostic failures cannot open a persistent
diagnostic-host circuit):

```sh
sy_api /circuits | python -m json.tool | grep -A2 probe.internal
```

**Expect** no circuit-breaker state entry for `_safeyolo.probe.internal`.

## Sign-off checklist

- [ ] V1: `safeyolo doctor` shows `Pipeline probe (traced) pass` per agent
- [ ] V1: real agent names in DiagResult labels (no `proxy` leak)
- [ ] V1: every EXPECTED_ADDONS member accounted for in trace (evaluated
      OR bypassed with addon_disabled/policy_disabled reason); no
      `error`, `not_loaded`, or `missing_from_trace`
- [ ] V1: `probe-sink/evaluated/probe_terminated` step present
- [ ] V1: no NEW `PROBE REACHED UPSTREAM` / `probe_sink_failed`
      events since `mark_offsets` (session-scoped via `new_mitm` /
      `new_audit`)
- [ ] V2 (architectural proof): NEW `security.probe_reached_upstream`
      events for THIS session are **zero during V1**, **zero during
      V3a**, and **at least 1 during V3b** — the triple proves the
      `server_connect` boundary is exercised only when both request-
      side terminators are absent (whole-file `grep -c` is not the
      proof — historical events would poison the assertion)
- [ ] V3a: sink-only-disabled — 502 with `X-SafeYolo-Request-Id`,
      body `reason_code=probe_sink_failed`, `/trace` shows
      `transport-guard/error/probe_sink_failed`, NO audit event,
      `safeyolo doctor` FAILS with `probe_sink_failed` findings
- [ ] V3b: sink AND failsafe disabled — mitmproxy generic protocol
      error to client (no correlation), `PROBE REACHED UPSTREAM` in
      mitmproxy.log, `security.probe_reached_upstream` audit event
      at CRITICAL with `details.reason_code=probe_reached_upstream`
- [ ] V4: everything green again after revert
- [ ] V4: no circuit-breaker entry for the probe host after V3a/V3b
      (built-in exclusion holding)

Post the checklist result as a comment on
[PR #322](https://github.com/craigbalding/safeyolo/pull/322) before
merge.
