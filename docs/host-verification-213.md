# Host-side verification for issue #213 PR B

The sandbox this branch was developed in cannot spin up a real
`mitmproxy` master with a live `UnixInstance` listener. The blackbox
suite that would normally exercise the full lifecycle needs `runsc`
and a dedicated test VM (see `tests/blackbox/conftest.py`).

Per the [reviewer's explicit ask](https://github.com/craigbalding/safeyolo/pull/322#issuecomment-XXX)
this file documents the concrete host-side commands to run against a
live SafeYolo proxy on `agent/issue-213-doctor-probe-dag-consumers`
before sign-off. These verifications must pass on the host — the
in-sandbox tests (`tests/test_probe_lifecycle.py`,
`tests/test_transport_guard.py`, `cli/tests/test_doctor_traced_probe.py`)
reconstruct the hook order and interactions deterministically but
cannot prove the real proxy lifecycle behaves as designed.

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

**Also grep** `mitmproxy.log`:

```sh
grep -i "PROBE REACHED UPSTREAM" /path/to/mitmproxy.log
```

**Expect** no matches from this session.

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
The transport guard's `server_connect` refusal must never actually be
needed — probe_sink terminates the flow before mitmproxy reaches
`server_connect` for this destination.

## V3 — Sink-disabled case triggers transport_guard

Force the sink to be inert without touching security addons. Temporarily
comment out the two hook methods in `probe_sink.py`:

```python
class ProbeSink:
    name = "probe-sink"
    # def requestheaders(self, flow): pass
    # def request(self, flow): pass
```

Restart the proxy: `safeyolo stop && safeyolo start`.

Run the traced probe manually (simulating what doctor does):

```sh
AGENT_SOCK=$(ls ~/.safeyolo/data/sockets/*/proxy.sock | head -1)
socat - UNIX-CONNECT:$AGENT_SOCK <<'EOF'
GET /__pipeline_probe HTTP/1.0
Host: _safeyolo.probe.internal
X-SafeYolo-Trace: 1
Connection: close

EOF
```

**Expect**:

- The socat request receives an error response (5xx or connection
  aborted, not 200).
- `mitmproxy.log` contains a `PROBE REACHED UPSTREAM` line.
- `safeyolo logs --event security --tail 5` shows
  `security.probe_reached_upstream` at CRITICAL severity with
  `details.reason_code = probe_reached_upstream` (lower-case, shared
  constant).
- If a request_id was captured in the response headers, calling
  `/trace?request_id=req-...` on the agent API returns a payload with
  a `transport-guard` step of `state=error, reason=probe_reached_upstream`.

## V4 — Sink restored, everything green again

Revert the `probe_sink.py` edit and restart:

```sh
git checkout -- cli/src/safeyolo/mitm_addons/probe_sink.py
safeyolo stop && safeyolo start
safeyolo doctor
```

**Expect** `Pipeline probe (traced)` back to `pass` for every agent
and no more `PROBE REACHED UPSTREAM` events fired by this session.

## Sign-off checklist

- [ ] V1: `safeyolo doctor` shows `Pipeline probe (traced) pass` per agent
- [ ] V1: real agent names in DiagResult labels (no `proxy` leak)
- [ ] V1: no `PROBE REACHED UPSTREAM` events
- [ ] V2: no DNS/`connect()` for `_safeyolo.probe.internal`
- [ ] V3: sink-disabled produces `probe_reached_upstream` audit event AND trace step
- [ ] V4: everything green again after revert

Post the checklist result as a comment on
[PR #322](https://github.com/craigbalding/safeyolo/pull/322) before
merge.
