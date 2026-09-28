"""Generated host edits through the public CLI and the live Rust proxy."""

from __future__ import annotations

import json
import os
import shlex
import signal
import sys
import tempfile
import time
import tomllib
import uuid
from pathlib import Path

from hypothesis import HealthCheck, Phase, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from safeyolo.cli import app
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_native_network_policy import policy_proxy

PROPERTY_SETTINGS = settings(
    max_examples=40, deadline=None, phases=(Phase.generate,),
    suppress_health_check=(HealthCheck.too_slow,),
)
SEQUENCE_SETTINGS = settings(
    max_examples=8, deadline=None, phases=(Phase.generate,),
    suppress_health_check=(HealthCheck.too_slow,),
)
# Keep the historical bounded host-label grammar without importing its retired
# Python policy engine through experiments.policy_assurance.strategies.
_HOST_LABEL = st.builds(
    lambda first, rest: first + rest,
    st.sampled_from(tuple("abcdefghijklmnopqrstuvwxyz")),
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", max_size=4),
)
ROOTS = st.one_of(
    st.just("scope.invalid"),
    st.just("bücher.scope.invalid"),
    _HOST_LABEL.map(lambda label: f"{label}.scope.invalid"),
)
CLI = CliRunner()


def _wire_host(host: str) -> str:
    return host.encode("idna").decode("ascii")


def _canonical_host(host: str) -> str:
    """Use the DNS spelling named by an operation, independent of policy output."""
    labels = []
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            labels.append(label.encode("ascii").decode("idna").casefold())
        else:
            labels.append(label.casefold())
    return ".".join(labels)


def _host_matches(host: str, pattern: str) -> bool:
    host, pattern = _canonical_host(host), _canonical_host(pattern)
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return host == pattern


class HostIntent:
    """Only the explicit host effects exercised by this bounded family."""

    def __init__(self, root: str):
        self.rules = {
            (None, "*"): {"egress": "prompt"},
            (None, f"*.{root}"): {"egress": "deny"},
            (None, f"otherleaf.{root}"): {"egress": "allow"},
            (None, f"bypass.{root}"): {"egress": "deny"},
            (None, "unrelated.invalid"): {"egress": "allow"},
            ("bob", f"bobonly.{root}"): {"egress": "allow"},
        }

    def apply(self, operation: dict) -> None:
        action = operation["action"]
        if action == "reload":
            return
        key = (operation.get("agent"), operation["host"])
        if action == "remove":
            del self.rules[key]
            return
        entry = self.rules.setdefault(key, {})
        if action in {"allow", "unrated", "rate"}:
            entry["egress"] = "allow"
        elif action == "deny":
            entry["egress"] = "deny"
        elif action == "bypass":
            entry["bypass"] = True
        else:
            raise ValueError(f"Unknown host operation: {action}")

    def status(self, agent: str, host: str) -> int:
        # A host bypass is proxy-wide. The fixture leaves network_guard optional
        # so the supported CLI bypass has a visible request effect.
        if any(
            scope is None and entry.get("bypass") and _host_matches(host, pattern)
            for (scope, pattern), entry in self.rules.items()
        ):
            return 200
        for scope in (agent, None):
            matches = [
                (pattern, entry) for (owner, pattern), entry in self.rules.items()
                if owner == scope and pattern != "*" and _host_matches(host, pattern)
            ]
            exact = [(pattern, entry) for pattern, entry in matches if not pattern.startswith("*.")]
            selected = exact or sorted(matches, key=lambda item: len(item[0]), reverse=True)
            if selected:
                return {"allow": 200, "deny": 403, "prompt": 428}[selected[0][1]["egress"]]
        return {"allow": 200, "deny": 403, "prompt": 428}[self.rules[(None, "*")]["egress"]]


def _initial_policy(root: str, wildcard: str) -> str:
    # This is only fixture setup. Every later edit goes through the public CLI.
    return f'''# operator note: retain this unrelated content
version = "2.0"
description = "host history fixture"
budget = 12000
required = []

[hosts]
"*" = {{ egress = "prompt" }}
"{wildcard}" = {{ egress = "deny" }}
"otherleaf.{root}" = {{ egress = "allow" }}
"bypass.{root}" = {{ egress = "deny" }}
"unrelated.invalid" = {{ egress = "allow" }}

[agents.bob.hosts]
"bobonly.{root}" = {{ egress = "allow" }}
'''


def _probes(trace: dict) -> tuple[tuple[str, str], ...]:
    root = trace["root"]
    target = f"leaf.{root}"
    return (
        ("alice", target), ("bob", target),
        ("alice", f"deep.{target}"),
        ("alice", f"otherleaf.{root}"), ("bob", f"otherleaf.{root}"),
        ("alice", f"evil{root}"), ("alice", root),
        ("alice", f"bypass.{root}"), ("bob", f"bypass.{root}"),
        ("bob", f"bobonly.{root}"),
        ("alice", f"unrated.{root}"), ("alice", "unrelated.invalid"),
    )


def _observe(proxy, origin, intent: HostIntent, probes, step: int) -> dict:
    observed = {}
    for index, (agent, host) in enumerate(probes):
        before = origin.accepts, len(origin.requests)
        url = f"http://{_wire_host(host)}:8123/chaos-{step}-{index}"
        status, _, body = send_request(proxy.paths[agent], url)
        expected = intent.status(agent, host)
        assert status == expected, (step, agent, host, expected, status, body)
        allowed = int(expected == 200)
        assert (origin.accepts, len(origin.requests)) == (before[0] + allowed, before[1] + allowed), (
            step, agent, host, "origin effect", before, origin.accepts, origin.requests[-1:]
        )
        if allowed:
            assert body == b"hello"
            assert origin.requests[-1] == {"method": "GET", "target": url}
        observed[(agent, host)] = status
    return observed


def _assert_unrelated(policy: Path, original: dict, root: str) -> None:
    source = policy.read_text()
    document = tomllib.loads(source)
    assert "# operator note: retain this unrelated content" in source
    assert document["description"] == original["description"]
    assert document["hosts"]["unrelated.invalid"] == original["hosts"]["unrelated.invalid"]
    assert document["hosts"][f"otherleaf.{root}"] == original["hosts"][f"otherleaf.{root}"]
    assert document["agents"]["bob"]["hosts"][f"bobonly.{root}"] == (
        original["agents"]["bob"]["hosts"][f"bobonly.{root}"]
    )
    assert not list(policy.parent.glob(".policy-*.toml"))


def _converge(proxy, previous_marker) -> None:
    proxy.process.send_signal(signal.SIGHUP)
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        assert proxy.process.poll() is None, "Native proxy exited during host mutation"
        try:
            marker = proxy.readiness_file.stat()
        except FileNotFoundError:
            time.sleep(0.02)
            continue
        if (marker.st_ino, marker.st_mtime_ns) != previous_marker:
            return
        time.sleep(0.02)
    raise AssertionError("Native proxy did not publish the completed host mutation")


def _write_host(directory: Path, operation: dict) -> str:
    action, host = operation["action"], operation.get("host")
    if action == "reload":
        return "reload"
    command = ["policy", "host"]
    if action in {"allow", "unrated", "rate"}:
        command += ["add", host]
        if action == "rate" or operation.get("rated"):
            command += ["--rate", str(operation.get("rate_value", 600))]
    elif action == "deny":
        command += ["deny", host, "--expires", "2070-01-01T00:00:00+00:00"]
    elif action == "bypass":
        command += ["bypass", host, "network_guard"]
    elif action == "remove":
        command += ["remove", host]
    else:
        raise ValueError(f"Unknown host operation: {action}")
    if operation.get("agent"):
        command += ["--agent", operation["agent"]]
    result = CLI.invoke(app, command, env={"SAFEYOLO_CONFIG_DIR": str(directory)})
    assert result.exit_code == 0, (command, result.exit_code, result.output, result.exception)
    return result.output.strip()


def execute_trace(directory: Path, trace: dict) -> dict:
    """Run a saved host history at the same real writer and proxy boundaries."""
    operations = trace.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= 8:
        raise ValueError("Host trace requires one to eight operations")
    if trace.get("family") == "budget":
        return _execute_budget(directory, trace)
    if trace.get("family") == "rate":
        return _execute_rate(directory, trace)
    if trace.get("family") not in {"properties", "history", "wildcard"}:
        raise ValueError("Trace must name a supported host family")
    root = trace["root"]
    wildcard = trace.get("initial_wildcard", f"*.{root}")
    directory.mkdir(parents=True, exist_ok=True)
    policy = directory / "policy.toml"
    policy.write_text(_initial_policy(root, wildcard))
    original = tomllib.loads(policy.read_text())
    intent = HostIntent(root)
    if wildcard != f"*.{root}":
        intent.rules[(None, wildcard)] = intent.rules.pop((None, f"*.{root}"))
    probes = _probes(trace)
    steps = []
    with origin_server() as origin:
        parent = f"http://127.0.0.1:{origin.server_address[1]}"
        with policy_proxy("rust", directory, None, parent_proxy=parent) as proxy:
            before = _observe(proxy, origin, intent, probes, 0)
            for index, operation in enumerate(trace["operations"], 1):
                marker = proxy.readiness_file.stat()
                previous = marker.st_ino, marker.st_mtime_ns
                removed = intent.rules.get((operation.get("agent"), operation.get("host")))
                result = _write_host(directory, operation)
                intent.apply(operation)
                _converge(proxy, previous)
                after = _observe(proxy, origin, intent, probes, index)
                if operation.get("agent"):
                    assert all(
                        before[probe] == after[probe] for probe in probes
                        if probe[0] != operation["agent"]
                    ), (operation, "other agent changed", before, after)
                revokes_allow = operation["action"] == "remove" and removed is not None and (
                    removed.get("egress") == "allow" or removed.get("bypass")
                )
                if operation["action"] == "deny" or revokes_allow:
                    assert not any(before[probe] != 200 and after[probe] == 200 for probe in probes), (
                        operation, "denial or revocation broadened access", before, after
                    )
                if trace["family"] in {"properties", "wildcard"} and index == 1:
                    assert after[("alice", f"leaf.{root}")] == 200
                    assert after[("alice", f"evil{root}")] == 428
                _assert_unrelated(policy, original, root)
                steps.append({"operation": operation, "result": result, "statuses": {
                    f"{agent}:{host}": status for (agent, host), status in after.items()
                }})
                before = after
        final = policy.read_bytes()
        with policy_proxy("rust", directory, None, parent_proxy=parent) as fresh:
            assert policy.read_bytes() == final
            _observe(fresh, origin, intent, probes, len(steps) + 1)
        assert policy.read_bytes() == final
    return {"operations": len(steps), "steps": steps, "fresh_matches": True}


def _generated_run(trace: dict) -> None:
    try:
        with tempfile.TemporaryDirectory(prefix="sy-host-chaos-", dir=Path.home()) as temporary:
            execute_trace(Path(temporary) / "host-chaos", trace)
    except Exception:
        trace_dir = Path(os.environ.get(
            "SAFEYOLO_CHAOS_TRACE_DIR", str(Path.home() / ".local/state/safeyolo/host-chaos-traces")
        ))
        trace_dir.mkdir(parents=True, exist_ok=True)
        trace_file = trace_dir / f"failing-host-{uuid.uuid4().hex}.json"
        trace_file.write_text(json.dumps(trace, ensure_ascii=False, indent=2) + "\n")
        binary = Path(os.environ.get(
            "SAFEYOLO_RUST_PROXY", "proxy/target/debug/safeyolo-proxy"
        )).resolve()
        print(f"Replay: {shlex.quote(sys.executable)} -m tools.policy_chaos replay "
              f"{shlex.quote(str(trace_file))} --binary {shlex.quote(str(binary))}")
        raise


@PROPERTY_SETTINGS
@given(root=ROOTS, wildcard_case=st.booleans(), rated=st.booleans())
def test_host_permission_properties(root: str, wildcard_case: bool, rated: bool) -> None:
    """Saved wildcard and scoped edits preserve their intended permission delta."""
    wildcard = f"*.{root}".upper() if wildcard_case and root.isascii() else f"*.{root}"
    target = f"leaf.{root}"
    operations = [
        {"action": "allow", "host": wildcard, "rated": rated},
        {"action": "deny", "host": target, "agent": "alice"},
        {"action": "allow", "host": target, "agent": "alice", "rated": rated},
        {"action": "reload"},
    ]
    _generated_run({
        "family": "properties", "root": root, "initial_wildcard": wildcard,
        "operations": operations,
    })


@SEQUENCE_SETTINGS
@given(root=ROOTS, order=st.permutations(("deny", "rate", "bypass", "unrated", "reload")),
       agent=st.sampled_from((None, "alice")), wildcard=st.booleans())
def test_host_mutation_histories(root: str, order, agent, wildcard: bool) -> None:
    """Eight real host operations compose without losing the active or fresh state."""
    target = f"*.{root}" if wildcard else f"leaf.{root}"
    operations = [{"action": "allow", "host": target, "agent": agent}]
    for action in order:
        operation = {"action": action}
        if action in {"deny", "rate"}:
            operation.update(host=target, agent=agent)
        elif action == "bypass":
            operation["host"] = f"bypass.{root}"
        elif action == "unrated":
            operation["host"] = f"unrated.{root}"
        operations.append(operation)
    operations += [
        {"action": "remove", "host": target, "agent": agent},
        {"action": "remove", "host": f"bypass.{root}"},
    ]
    _generated_run({"family": "history", "root": root, "operations": operations})


def test_written_wildcard_has_dns_label_boundary() -> None:
    """The supported writer's *.scope.invalid rule reaches a child, not its sibling."""
    _generated_run({
        "family": "wildcard", "root": "scope.invalid",
        "operations": [{"action": "allow", "host": "*.scope.invalid"}],
    })


def _execute_budget(directory: Path, trace: dict) -> dict:
    directory.mkdir(parents=True)
    policy = directory / "policy.toml"
    policy.write_text('budget = 1\n[hosts]\n"*" = { egress = "prompt" }\n')
    for operation in trace["operations"]:
        _write_host(directory, operation)
    # The public rate writer uses 600 in generated histories; this bounded
    # budget control uses an explicit rate of one through the same CLI.
    source = tomllib.loads(policy.read_text())
    assert source["hosts"]["unrated.invalid"] == {"egress": "allow"}
    with origin_server() as origin:
        parent = f"http://127.0.0.1:{origin.server_address[1]}"
        for first, second in (("unrated.invalid", "rated.invalid"),
                              ("rated.invalid", "unrated.invalid")):
            with policy_proxy("rust", directory, None, parent_proxy=parent) as proxy:
                before = origin.accepts
                assert send_request(proxy.paths["alice"], f"http://{first}:8123/first")[0] == 200
                assert send_request(proxy.paths["bob"], f"http://{second}:8123/second")[0] == 200
                assert send_request(proxy.paths["alice"], f"http://{first}:8123/third")[0] == 429
                assert origin.accepts == before + 2
    assert tomllib.loads(policy.read_text())["hosts"]["unrated.invalid"] == {"egress": "allow"}
    return {"operations": len(trace["operations"]), "fresh_matches": True}


def _execute_rate(directory: Path, trace: dict) -> dict:
    directory.mkdir(parents=True)
    policy = directory / "policy.toml"
    policy.write_text('budget = 12000\n[hosts]\n"*" = { egress = "prompt" }\n')
    first, second = trace["operations"]
    _write_host(directory, first)
    with origin_server() as origin:
        parent = f"http://127.0.0.1:{origin.server_address[1]}"
        with policy_proxy("rust", directory, None, parent_proxy=parent) as proxy:
            url = "http://changed.invalid:8123/rate"
            assert send_request(proxy.paths["alice"], url)[0] == 200
            marker = proxy.readiness_file.stat()
            _write_host(directory, second)
            _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
            before = origin.accepts
            for expected in (200, 200, 429):
                assert send_request(proxy.paths["alice"], url)[0] == expected
            assert origin.accepts == before + 2
        final = policy.read_bytes()
        assert tomllib.loads(final.decode())["hosts"]["changed.invalid"] == {
            "egress": "allow", "rate": 1,
        }
        with policy_proxy("rust", directory, None, parent_proxy=parent) as fresh:
            assert policy.read_bytes() == final
            before = origin.accepts
            for expected in (200, 200, 429):
                assert send_request(fresh.paths["alice"], url)[0] == expected
            assert origin.accepts == before + 2
    return {"operations": len(trace["operations"]), "fresh_matches": True}


def test_unrated_allow_stays_under_aggregate_budget() -> None:
    """An unrated allowance survives a second edit and still charges global budget."""
    _generated_run({
        "family": "budget",
        "operations": [
            {"action": "unrated", "host": "unrated.invalid"},
            {"action": "rate", "host": "rated.invalid", "rate_value": 1},
        ],
    })


def test_rate_change_limits_live_and_fresh_requests() -> None:
    """A CLI rate change has a real request effect after reload and restart."""
    _generated_run({
        "family": "rate",
        "operations": [
            {"action": "unrated", "host": "changed.invalid"},
            {"action": "rate", "host": "changed.invalid", "rate_value": 1},
        ],
    })
