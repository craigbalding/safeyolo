# SafeYolo Tests

## Blackbox Tests (`blackbox/`)

End-to-end security verification — SafeYolo's trust anchor. Runs the real
proxy, real firewall, real microVM. Split across two execution domains:

- **Host pytest** (`blackbox/host/`) — proxy functional tests (credential guard, network guard)
- **VM pytest** (`blackbox/isolation/`) — isolation tests run inside a real microVM (network escape, privilege escalation, key isolation)

See [`blackbox/README.md`](blackbox/README.md) for architecture and running instructions.

## Addon Unit Tests

Unit and integration tests for native mitmproxy addons.

## Test Areas

The suite covers addon enforcement, policy evaluation and mutation, agent and
admin APIs, host CLI lifecycle, flow evidence, process startup, and blackbox
isolation. The files and collected test count change frequently; use pytest as
the source of truth:

```bash
uv run pytest --collect-only -q tests/ cli/tests/
```

## Assurance Boundaries

All tests use real objects, concrete fakes, or signature-checked collaborators.
The CI assurance check rejects direct generic mocks and mock-producing patches
without `autospec=True`. Security-sensitive suites enrolled in `assurance.toml`
also declare their real subjects, which may not be patched.

### Factory acceptance

The `factory_acceptance` entries in `assurance.toml` name the small set of
operator-visible factory behaviors that must not disappear silently. Each
entry binds a stable behavior ID to one pytest function and its SHA-256 digest.

Run the named set with this command:

```bash
uv run pytest $(python3 scripts/check_test_assurance.py \
  --list-factory-acceptance-nodes) -v --tb=short
```

Some named tests start a real local NATS server. Stop a live nested factory
before the command if that factory uses ports 4222 or 8222. The factory state
files and retained Coord history remain available for the next factory run.

An edited named test makes the assurance check fail. Review the behavior, then
refresh only the recorded digests:

```bash
uv run python scripts/check_test_assurance.py --update-factory-acceptance
```

The digest update is not an approval. Its manifest diff and the GitHub Actions
notice show which acceptance behaviors changed.

## Running Tests

Use `uv` (the same tool the CLI ships with):

```bash
uv sync --group dev
uv run pytest tests/ -v
```

Requires a C compiler (for aioquic crypto) and, on Linux, Rust +
bpf-linker if you build mitmproxy's eBPF extras from source. `uv sync`
handles the rest.

## Mock Audit Closure

| Finding | Enforced resolution |
|---|---|
| Unspecced mocks hide signature drift | Repository-wide AST check in CI; real AdminAPI contracts cover grants and denials |
| Network Guard patches its subject | Real addon, flows, decisions, policy paths, bypass, and fail-closed tests |
| Real policy client underused | Real policy covers ordinary outcomes; autospec is reserved for unavailable/error boundaries |
| Headers represented as dictionaries | Contract tests use mitmproxy `Headers` and exercise case-insensitive removal |
| Real-process tests fail without evidence | Ten-second startup contract retained; failures capture process, console, logs, and timing data |
| Mock-only assertions overcorrected | Interaction assertions remain where calls are the behavior, with signature-checked collaborators |
| Blackbox suite is opt-in only | GitHub systrap nightly; trusted manual/on-demand KVM and VZ acceptance |

## Adding Tests

Tests use mitmproxy's test utilities:
- `mitmproxy.test.tflow` - Create test HTTP flows
- `mitmproxy.test.taddons` - Test addon context

Example:
```python
def test_blocks_credential(credential_guard, make_flow):
    flow = make_flow(
        method="POST",
        url="https://evil.com/api",
        content='{"key": "sk-abc123xyz456def789ghijklmno"}',
        headers={"Content-Type": "application/json"},
    )

    credential_guard.request(flow)

    assert flow.response.status_code == 403
    assert flow.metadata["blocked_by"] == "credential-guard"
```
