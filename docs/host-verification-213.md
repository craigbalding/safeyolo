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

## V1 — Normal probe reaches probe_sink and returns 200

```sh
safeyolo doctor
```

**Expect** in the output:

- `Pipeline probe` (existing virtual-host check) — `pass`.
- `Pipeline probe (traced)` — `pass` for every registered agent.
  - Each per-agent line shows the real agent name (NOT `proxy` — that
    would indicate the B5 socket-parse regression is back).
  - The `findings` block includes `probe HTTP 200` as the first entry.
  - Every `EXPECTED_ADDONS` member appears with `state=evaluated`.
- No `transport-guard` step appears in any per-agent trace.
- No `security.probe_reached_upstream` audit event in
  `safeyolo logs --event security --tail 20`.

## V2 — No DNS lookup or upstream socket attempt for the probe host

While `safeyolo doctor` is running (or immediately after), on the
host:

```sh
# On Linux: watch DNS traffic on the sandbox network for probe host.
# `sudo strace -f -e trace=connect,sendto -p <mitmdump-pid> 2>&1 | grep -i probe.internal`

# Simpler observable: check no /etc/hosts or resolver hit was made:
grep -i "probe.internal" /var/log/system.log  /var/log/syslog 2>/dev/null
```

**Expect** no DNS resolution attempts for `_safeyolo.probe.internal`
and no `connect()` syscalls to any address labelled as the probe host.
probe_sink terminates the flow before mitmproxy reaches `server_connect`
for this destination.

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

Run the traced probe manually (simulating what doctor does):

```sh
AGENT_SOCK=$(ls ~/.safeyolo/data/sockets/*/proxy.sock | head -1)
socat - UNIX-CONNECT:$AGENT_SOCK <<'EOF' > /tmp/v3a.raw
GET /__pipeline_probe HTTP/1.0
Host: _safeyolo.probe.internal
X-SafeYolo-Trace: 1
X-Test-Context: run=v3a;agent=$(basename $(dirname $AGENT_SOCK) | cut -d_ -f2);test=missing-sink
Connection: close

EOF
cat /tmp/v3a.raw
```

**Expect (all mandatory)**:

- Response status is **502** (not a raw connection error). This proves
  Layer 1 synthesised the response.
- **`X-SafeYolo-Request-Id` header IS present.** Capture:
  `RID=$(grep -i x-safeyolo-request-id /tmp/v3a.raw | awk '{print $2}' | tr -d '\r')`.
- Response body is JSON with `reason_code: "probe_sink_failed"` and
  `host: "_safeyolo.probe.internal"`.
- Fetch `/trace`:
  ```sh
  curl -sS -H "Authorization: Bearer $(cat /app/agent_token)" \
    "http://_safeyolo.proxy.internal/trace?request_id=$RID" | python -m json.tool
  ```
  Expect a `transport-guard` step with
  `state=error, reason=probe_sink_failed`.
- **NO** `PROBE REACHED UPSTREAM` line in `mitmproxy.log`.
- **NO** `security.probe_reached_upstream` audit event in
  `safeyolo logs --event security --tail 10`.

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

Repeat the socat probe from V3a. This time:

**Expect**:

- The client-side response is not a clean 502 with correlation — it's
  mitmproxy's generic protocol error (whatever `handle_protocol_error()`
  produces). No `X-SafeYolo-Request-Id` — this is the intentional cost
  of reaching Layer 2, and matches the reviewer's stated posture:
  "audit event can remain operator-only".
- `mitmproxy.log` contains `PROBE REACHED UPSTREAM`.
- `safeyolo logs --event security --tail 5` shows
  `security.probe_reached_upstream` at CRITICAL severity with
  `details.reason_code = probe_reached_upstream`.

The operator can still correlate the failure via the audit log even
without a client-side request-id header.

## V4 — Restore everything, verify healthy state

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
curl -sS -H "Authorization: Bearer $(cat /app/agent_token)" \
  http://_safeyolo.proxy.internal/circuits | python -m json.tool | grep -A2 probe
```

**Expect** no circuit-breaker state entry for `_safeyolo.probe.internal`.

## Sign-off checklist

- [ ] V1: `safeyolo doctor` shows `Pipeline probe (traced) pass` per agent
- [ ] V1: real agent names in DiagResult labels (no `proxy` leak)
- [ ] V1: no `PROBE REACHED UPSTREAM` events; no `probe_sink_failed` trace steps
- [ ] V2: no DNS / `connect()` attempts for `_safeyolo.probe.internal`
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
