"""The installed P3 launcher must not require context on its ordinary guest calls."""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from tests.blackbox.isolation import p3_guest_journeys as guest

ROOT = Path(__file__).resolve().parents[2]
REQUEST_ID = "req-" + "a" * 32
MARKER = "p3-" + "b" * 32


def test_p3_launcher_targets_match_selected_guest_requests(tmp_path, monkeypatch):
    """Run the launcher's final addon rewrite and capture the guest's calls."""
    source = tmp_path / "source-instance"
    instance = tmp_path / "test-instance"
    environment = os.environ.copy()
    environment.update(
        SAFEYOLO_CONFIG_DIR=str(source),
        SAFEYOLO_TEST_CONFIG_DIR=str(instance),
        PATH=f"{Path(sys.executable).parent}:{environment['PATH']}",
        PYTHONPATH=f"{ROOT / 'cli/src'}:{ROOT}",
    )
    command = [
        str(ROOT / "tests/blackbox/run-tests.sh"),
        "--expect-platform",
        "systrap",
        "--proxy-impl",
        "rust",
        "--p3-config-only",
    ]
    prepared = subprocess.run(command, env=environment, cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert prepared.returncode == 0, prepared.stdout[-1000:] + prepared.stderr[-1000:]
    assert "no proxy or guest started" in prepared.stdout
    targets = yaml.safe_load((instance / "addons.yaml").read_text())["addons"]["test_context"]["target_hosts"]
    policy = tomllib.loads((instance / "policy.toml").read_text())
    assert policy["hosts"][guest.BASIC_HOST]["service"] == "p3_basic"
    assert policy["hosts"][guest.CONTRACT_HOST]["service"] == "p3_contract"
    assert policy["hosts"]["failing.test"]["egress"] == "allow"

    calls: list[tuple[str, str, bool]] = []

    def exchange(method, target, *, headers=None, **_kwargs):
        calls.append((method, urlsplit(target).hostname, bool(headers and "X-SafeYolo-Test-Context" in headers)))
        status = 428 if method == "POST" else 200
        return status, {"x-safeyolo-request-id": REQUEST_ID}, b'{"received":true}'

    declared = None

    def api(method, path, *, payload=None):
        nonlocal declared
        if method == "POST" and path == "/api/test-context/current":
            declared = {"run": "installed-p3", "agent": "bbtest", "test": MARKER}
            return 200, {}, {"context": declared}
        if method == "GET" and path == "/api/test-context/current":
            return 200, {}, {"context": declared}
        if method == "GET" and path.startswith("/trace?"):
            return 200, {}, {"agent_id": "bbtest"}
        if method == "POST" and path == "/api/flows/search":
            return 200, {}, {"flows": [{"id": "owned-flow", "request_id": REQUEST_ID, "agent_id": "bbtest"}]}
        if method == "GET" and path == "/api/flows/owned-flow":
            return 200, {}, {"request_id": REQUEST_ID}
        if method == "DELETE" and path == "/api/test-context/current":
            declared = None
            return 200, {}, {"status": "cleared"}
        raise AssertionError((method, path, payload))

    monkeypatch.setattr(guest, "service_token", lambda _service: "sgw_fixture")
    monkeypatch.setattr(guest, "exchange", exchange)
    monkeypatch.setattr(guest, "api", api)
    guest.basic_read(MARKER)
    guest.contract_prompt()
    guest.context_and_evidence("bbtest", MARKER)

    assert calls == [
        ("GET", guest.BASIC_HOST, False),
        ("POST", guest.CONTRACT_HOST, False),
        ("GET", guest.BASIC_HOST, True),
    ]
    assert targets == ["failing.test"], (
        "P3 needs an owned activation target without mandatory context on ordinary hosts"
    )
    assert all(host not in targets or has_context for _, host, has_context in calls)
    assert guest.BASIC_HOST not in targets, "the explicit header must exercise a non-target host"

    # The operator's execution-970 configuration would block both ordinary calls.
    old_targets = ["httpbin.org", "failing.test", "legitimate-api.com", "httpbin.org"]
    assert [host for _, host, has_context in calls if host in old_targets and not has_context] == [
        guest.BASIC_HOST,
        guest.CONTRACT_HOST,
    ]
