"""Controls for interpreting the nested Docker fixture's outbound results.

These exercise the observer's refusal handling. They do not establish the
installed sandbox's network enforcement.
"""

import io
import json
import runpy
from copy import deepcopy
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import create_autospec
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from urllib.response import addinfourl

import pytest

from tests.blackbox.installed_docker_preflight import gateway_management, run, verify_outbound, verify_provider_origin

PROBE = Path(__file__).parent / "blackbox/fixtures/nested-docker/network_probe.py"


@pytest.mark.parametrize("linked", [False, True])
def test_gateway_binary_selection_restores_the_retained_entry_after_staging_failure(tmp_path, monkeypatch, linked):
    prepared = tmp_path / "prepared"
    for part in ("bin", "assets/guest", "share/rootfs-tree"):
        (prepared / part).mkdir(parents=True, exist_ok=True)
    for name in ("bin/safeyolo", "bin/safeyolo-proxy", "assets/guest/safeyolo-guest"):
        (prepared / name).write_text("synthetic source identity\n")
    root = tmp_path / "instance"
    root.mkdir()
    workspace = root / "workspace"
    workspace.mkdir()
    retained = root / "retained-binaries" if linked else root / "bin"
    retained.mkdir()
    (retained / "sentinel").write_text("original binary bytes\n")
    if linked:
        (root / "bin").symlink_to(retained, target_is_directory=True)
    (root / "config.toml").write_text("")
    (root / "policy.toml").write_text(f'[agents.notes]\nnested_docker = true\nfolder = "{workspace}"\n')

    def checked(command, **_):
        if command[-1] == "--version":
            return "synthetic commit=revision"
        return '{"runtime_state":"stopped"}' if "status" in command else ""

    def failed_copy(*_):
        assert (root / "bin").resolve() == prepared / "bin"
        raise RuntimeError("staging interrupted")

    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.checked", checked)
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.shutil.copy2", failed_copy)
    args = SimpleNamespace(prepared_config=prepared, root=root, output=tmp_path / "output", revision="revision",
                           proxy_revision=None, guest_revision=None, reuse_root=True, gateway=True,
                           journey=False, nested_docker=True)
    with pytest.raises(RuntimeError, match="staging interrupted"):
        run(args)
    assert (root / "bin").is_symlink() is linked
    assert (root / "bin/sentinel").read_text() == "original binary bytes\n"
    assert not list(root.glob("bin-docker-gateway-*"))


@pytest.mark.parametrize("interruption", ["gateway-create", "gateway-exec"])
def test_gateway_observer_preserves_uncertain_mutations_and_restores_the_fixture(tmp_path, monkeypatch, interruption):
    caller = tmp_path / "docker-caller"
    caller.mkdir()
    service = tmp_path / "services/notes.yaml"
    service.parent.mkdir()
    service.write_text("retained application service\n")
    policy = tmp_path / "policy.toml"
    provider = tmp_path / "provider"
    provider.mkdir()
    (provider / "docker-gateway-client").write_text("synthetic client, never executed\n")
    policy.write_text('[hosts."notes.safeyolo.internal"]\nservice = "notes"\n'
                      + f'[agents.notes]\nfolder = "{provider}"\n')
    originals = {path: path.read_bytes() for path in (service, policy)}
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.running_guest", lambda *_: {"agent_id": "ag-caller"})
    steps = []

    def native(*arguments):
        return '{"runtime_state":"stopped"}' if arguments[:2] == ("agent", "status") else ""

    def guest(command, label, **_):
        steps.append(label)
        if label == interruption:
            raise RuntimeError("response interrupted after dispatch")
        return {"gateway-unapproved": "\x1b[2K403", "gateway-inspect": "\x1b[2Ktrue"}.get(label, "")

    def background(*_):
        return (SimpleNamespace(poll=lambda: None),)

    report = {}
    with pytest.raises(RuntimeError, match="response interrupted"):
        gateway_management(SimpleNamespace(docker_data="/home/agent/retained/data"), tmp_path, output,
                           native, guest, background, report)
    assert steps.count("gateway-create") == 1
    assert "gateway-remove" not in steps
    assert report["gateway_container"].startswith("sygateway")
    for path, original in originals.items():
        assert path.read_bytes() == original
        backup = output / f"original-{path.name}"
        assert backup.read_bytes() == original
        assert backup.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("refusal", ["policy", "missing-attribution", "approval", "reachable", "transport"])
def test_network_probe_requires_an_explicit_policy_denial(monkeypatch, capsys, refusal):
    headers = Message()
    headers["X-SafeYolo-Request-Id"] = "req-allowed"
    allowed = addinfourl(io.BytesIO(b"allowed"), headers, "https://example.com", 200)
    denied_headers = Message()
    denied_headers["X-SafeYolo-Request-Id"] = "req-denied"
    if refusal != "missing-attribution":
        denied_headers["X-Blocked-By"] = "network-guard"
    if refusal == "reachable":
        denied = addinfourl(io.BytesIO(b"unexpected origin"), Message(), "http://denied.invalid", 200)
    elif refusal == "transport":
        denied = URLError("proxy transport failed")
    else:
        status = 428 if refusal == "approval" else 403
        denied = HTTPError("http://denied.invalid", status, "refused", denied_headers, io.BytesIO(b"refused"))
    boundary = create_autospec(urlopen, spec_set=True, side_effect=[allowed, denied])
    monkeypatch.setattr("urllib.request.urlopen", boundary)
    monkeypatch.setenv("PROBE_PHASE", "build")
    if refusal == "policy":
        runpy.run_path(str(PROBE))
        rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        assert [(row["status"], row["request_id"]) for row in rows] == [(200, "req-allowed"), (403, "req-denied")]
    else:
        with pytest.raises(URLError if refusal == "transport" else AssertionError):
            runpy.run_path(str(PROBE))
    assert [call.args[0].full_url for call in boundary.call_args_list] == [
        "https://example.com", "http://denied.invalid"]


@pytest.fixture
def outbound_journey():
    report = {"runtime": {"agent_id": "ag-host", "run_id": "current"},
              "recovery": {"after": {"run_id": "recovered"}},
              "network_probes": [
                  {"request_id": "req-allowed", "destination": "example.com", "status": 200},
                  {"request_id": "req-denied", "destination": "denied.invalid", "status": 403}]}
    events = []
    # Current http.rs binds the run only on the evaluated guard. The logger
    # response and HTTP terminal producer both carry attribution and status.
    for probe in report["network_probes"]:
        allowed = probe["status"] == 200
        decision = "allow" if allowed else "deny"
        for event in ("security.network_guard.evaluated", "traffic.request_outcome", "traffic.response",
                      *(() if allowed else ("security.network_guard",))):
            details = {"attribution": {"attribution_status": "resolved", "trusted_transport_identity": "notes",
                       "attribution_provenance": {"transport_source": "uds", "uds_agent": "notes"}}}
            row = {"event": event, "request_id": probe["request_id"], "agent": "notes",
                   "host": probe["destination"], "details": details}
            if event == "security.network_guard.evaluated":
                details.update(outcome="allowed" if allowed else "blocked", sandbox_run={
                    "agent": "notes", "agent_id": "ag-host", "run_id": "current"})
            elif event == "traffic.request_outcome":
                row["decision"] = decision
                details.update(decision=decision, status=probe["status"])
            elif event == "traffic.response":
                details["status"] = probe["status"]
            else:
                row["decision"] = decision
            events.append(row)
    return events, report


def test_outbound_joins_current_producers_with_a_retained_stopped_run(outbound_journey):
    events, report = outbound_journey
    stopped = deepcopy(events[0])
    stopped["details"]["sandbox_run"]["run_id"] = "stopped"
    verify_outbound([stopped, *events], report, reused_image=True)
    assert len(report["outbound"]) == len(events)
    assert all(row["details"]["sandbox_run"]["run_id"] == "current" for row in report["outbound"]
               if row["event"] == "security.network_guard.evaluated")
    assert all("sandbox_run" not in row["details"] for row in report["outbound"]
               if row["event"].startswith("traffic."))


@pytest.mark.parametrize(("event", "path", "value"), [
    ("security.network_guard.evaluated", ("details", "sandbox_run", "agent_id"), "ag-foreign"),
    ("security.network_guard.evaluated", ("details", "sandbox_run", "agent"), "foreign"),
    ("security.network_guard.evaluated", ("details", "sandbox_run", "run_id"), "stopped"),
    ("security.network_guard.evaluated", ("details", "sandbox_run", "run_id"), "recovered"),
    ("security.network_guard.evaluated", ("details", "outcome"), "allowed"),
    ("traffic.request_outcome", ("decision",), "allow"),
    ("traffic.request_outcome", ("details", "decision"), "allow"),
    ("traffic.request_outcome", ("details", "status"), 428),
    ("traffic.response", ("details", "status"), 428),
    ("security.network_guard", ("decision",), "allow"),
] + [(event, path, value) for event in (
    "security.network_guard.evaluated", "traffic.request_outcome", "traffic.response", "security.network_guard")
    for path, value in [
        (("request_id",), "req-unrelated"), (("host",), "other.invalid"), (("agent",), "foreign"),
        (("details", "attribution", "attribution_status"), "unresolved"),
        (("details", "attribution", "trusted_transport_identity"), "foreign"),
        (("details", "attribution", "attribution_provenance", "transport_source"), "tcp"),
        (("details", "attribution", "attribution_provenance", "uds_agent"), "foreign"),
    ]])
def test_outbound_requires_identity_run_host_status_and_decision_join(outbound_journey, event, path, value):
    events, report = outbound_journey
    stopped = deepcopy(next(row for row in events if row["event"] == "security.network_guard.evaluated" and
                            row["request_id"] == "req-denied"))
    stopped["details"]["sandbox_run"]["run_id"] = "stopped"
    events.append(stopped)
    row = next(row for row in events if row["event"] == event and row["request_id"] == "req-denied")
    for key in path[:-1]:
        row = row[key]
    row[path[-1]] = value
    with pytest.raises(AssertionError, match="hosting-principal"):
        verify_outbound(events, report, reused_image=True)


def test_fresh_image_pull_needs_its_own_successful_join(outbound_journey):
    events, report = outbound_journey
    with pytest.raises(AssertionError, match="image pull"):
        verify_outbound(events, report, reused_image=False)
    registry = deepcopy(events[:3])
    for row in registry:
        row.update(request_id="req-registry", host="registry-1.docker.io")
    verify_outbound([*events, *registry], report, reused_image=False)


@pytest.mark.parametrize("prefix", ["", "\x1b[2K"])
@pytest.mark.parametrize("failure", [None, "extra", "extra-anonymous", "identity", "name", "authorization", "legacy", "route"])
def test_provider_origin_handles_compose_prefix_without_weakening_checks(prefix, failure):
    local = {"role": "api", "method": "GET", "path": "/api/v1/notes", "caller_ids": [], "caller_names": [],
             "authorization_count": 0, "legacy_identity_count": 0}
    allowed = {**local, "caller_ids": ["ag-caller"], "caller_names": ["dockercaller"]}
    rows = [local, allowed, deepcopy(allowed)]
    if failure == "extra":
        rows.append(allowed)
    elif failure == "extra-anonymous":
        rows.append(local)
    elif failure:
        key, value = {"identity": ("caller_ids", ["ag-caller", "forged"]), "name": ("caller_names", ["forged"]),
                      "authorization": ("authorization_count", 1), "legacy": ("legacy_identity_count", 1),
                      "route": ("path", "/outside")}[failure]
        rows[2][key] = value
    logs = "compose output\n" + "\n".join(prefix + json.dumps(row) for row in rows)
    if failure:
        with pytest.raises(AssertionError):
            verify_provider_origin(logs, "ag-caller")
    else:
        assert verify_provider_origin(logs, "ag-caller") == rows
