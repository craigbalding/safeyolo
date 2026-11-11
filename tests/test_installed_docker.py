"""Controls for interpreting the nested Docker fixture's outbound results.

These exercise the observer's refusal handling. They do not establish the
installed sandbox's network enforcement.
"""

import hashlib
import http.client
import io
import json
import os
import runpy
import shlex
import shutil
import subprocess
import sys
import threading
from copy import deepcopy
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import create_autospec
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from urllib.response import addinfourl

import pytest

from tests.blackbox.installed_docker_preflight import (
    gateway_client_failure,
    gateway_compose_journey,
    gateway_management,
    run,
    verify_gateway_client_failure,
    verify_outbound,
    verify_provider_origin,
)
from tests.blackbox.installed_provider import wait_file
from tests.blackbox.registry_fixture import distribution_registry

PROBE = Path(__file__).parent / "blackbox/fixtures/nested-docker/network_probe.py"


@pytest.mark.parametrize("disk_backed", [False, True])
def test_owned_registry_handles_docker_chunked_layers_and_schema2_readback(tmp_path, disk_backed):
    log = tmp_path / "events.jsonl"
    directory = tmp_path / "blobs" if disk_backed else None
    layer = b"docker-layer" * 10000
    digest = "sha256:" + hashlib.sha256(layer + b"tail").hexdigest()
    with distribution_registry(directory, log) as (repository, blobs, _, _, _, _):
        connection = http.client.HTTPConnection(repository.split("/")[0], timeout=5)

        def request(method, path, body=None, **kwargs):
            connection.request(method, path, body=body, **kwargs)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()

        assert request("GET", "/v2/")[0] == 200
        assert request("HEAD", "/v2/guest/blobs/" + digest)[0] == 404
        status, headers, _ = request("POST", "/v2/guest/blobs/uploads/")
        assert status == 202
        location = headers["Location"]
        status, headers, _ = request("PATCH", location, iter([layer[:3], layer[3:]]), encode_chunked=True)
        assert status == 202 and headers["Range"] == f"0-{len(layer) - 1}"
        status, headers, _ = request("PATCH", location, b"tail")
        assert status == 202 and headers["Range"] == f"0-{len(layer) + 3}"
        assert request("PUT", location + "?digest=sha256:" + "0" * 64)[0] == 400
        assert request("GET", "/v2/guest/blobs/" + digest)[0] == 404
        assert request("PUT", location + "?digest=" + digest)[0] == 201
        if disk_backed:
            assert isinstance(blobs[digest], Path)
        status, headers, body = request("GET", "/v2/guest/blobs/" + digest)
        assert status == 200 and body == layer + b"tail"
        assert headers["Docker-Content-Digest"] == digest
        status, headers, body = request("HEAD", "/v2/guest/blobs/" + digest)
        assert status == 200 and int(headers["Content-Length"]) == len(layer) + 4 and body == b""
        manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                               "config": {}, "layers": [{"digest": digest, "size": len(layer) + 4}]}).encode()
        manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
        assert request("PUT", "/v2/guest/manifests/qualification", manifest)[0] == 201
        for reference in ("qualification", manifest_digest):
            status, headers, body = request("GET", "/v2/guest/manifests/" + reference)
            assert status == 200 and body == manifest and headers["Docker-Content-Digest"] == manifest_digest
        assert request("GET", "/v2/guest/manifests/missing")[0] == 404
        connection.close()
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert any(row["method"] == "PATCH" and row["status"] == 202 for row in events)
    assert events[-1]["status"] == 404


def test_owned_registry_standalone_guest_script_stops_its_listener(tmp_path):
    ready = tmp_path / "ready.json"
    script = Path(__file__).parent / "blackbox/registry_fixture.py"
    with subprocess.Popen([sys.executable, "-I", str(script), "--directory", str(tmp_path / "blobs"),
                           "--ready-file", str(ready), "--events-file", str(tmp_path / "events.jsonl")]) as child:
        try:
            wait_file(ready, child)
            state = json.loads(ready.read_text())
            assert state["pid"] == child.pid and state["repository"].startswith("127.0.0.1:")
            connection = http.client.HTTPConnection(state["repository"].split("/")[0], timeout=5)
            connection.request("GET", "/v2/")
            response = connection.getresponse()
            assert response.status == 200 and response.read() == b"{}"
            connection.close()
        finally:
            child.terminate()
            assert child.wait(timeout=5) == 0
    with pytest.raises(ConnectionRefusedError):
        http.client.HTTPConnection(state["repository"].split("/")[0], timeout=5).connect()


def registry_guest(_command, label, **_):
    if label == "gateway-registry-create":
        return "c" * 64
    if label == "gateway-registry-ready":
        return json.dumps({"repository": "127.0.0.1:44444/guest", "pid": 123})
    if label == "gateway-registry-pull-requests":
        return json.dumps({"method": "GET", "path": "/v2/guest/manifests/qualification", "status": 200})
    return ""


def registry_background(*_):
    return (SimpleNamespace(poll=lambda: None, wait=lambda **_: 0),)


def test_gateway_registry_uses_image_python_and_removes_its_container_before_build(tmp_path):
    """Execute the produced shell arguments and their actual registry helper."""
    binaries = tmp_path / "bin"
    binaries.mkdir()
    captured = tmp_path / "docker-arguments"
    container_id = "c" * 64
    image_id = "sha256:" + "a" * 64
    # Record Docker arguments through Bash without needing a local daemon.
    for executable, script in {
        "sudo": '#!/bin/sh\n[ "$1" = -n ] || exit 1\nshift\nexec "$@"\n',
        "docker": '#!/bin/sh\nprintf "%s\\0" "$@" > "$CAPTURE"\nprintf "%s\\n" "$CONTAINER_ID"\n',
    }.items():
        path = binaries / executable
        path.write_text(script)
        path.chmod(0o755)
    env = os.environ | {"PATH": str(binaries) + ":" + os.environ["PATH"],
                        "CAPTURE": str(captured), "CONTAINER_ID": container_id}
    directory = tmp_path / "provider-state"
    calls = []
    container_command = []
    report = {}
    child = None

    def docker_arguments(command, label):
        output = subprocess.check_output(["bash", "-c", command], env=env, text=True)
        arguments = captured.read_bytes().decode().split("\0")[:-1]
        calls.append((label, arguments))
        assert arguments.pop(0) == "--host=unix:///run/safeyolo-nested-docker/docker.sock"
        return output, arguments

    def guest(command, label, **_):
        if label == "gateway-registry-state":
            directory.mkdir()
        if label == "gateway-registry-create":
            output, arguments = docker_arguments(command, label)
            assert arguments[:2] == ["create", "--pull=never"]
            assert arguments[arguments.index("--name") + 1] == report["gateway_lifecycle"]["project"] + "-registry"
            assert "--network=host" in arguments
            assert arguments[arguments.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
            entrypoint = arguments.index("--entrypoint")
            assert arguments[entrypoint + 1:entrypoint + 3] == ["python3", image_id]
            container_command.extend([sys.executable, *arguments[entrypoint + 3:]])
            for index, value in enumerate(arguments):
                if value != "--mount":
                    continue
                mount = dict(part.split("=", 1) if "=" in part else (part, True)
                             for part in arguments[index + 1].split(","))
                assert mount["type"] == "bind"
                if mount["source"] == "/workspace/registry_fixture.py":
                    assert mount["readonly"]
                    source = Path(__file__).parent / "blackbox/registry_fixture.py"
                else:
                    assert mount["source"] == "/home/agent/" + report["gateway_lifecycle"]["project"]
                    assert "readonly" not in mount
                    source = directory
                container_command[:] = [arg.replace(mount["target"], str(source)) for arg in container_command]
            return output
        if label == "gateway-registry-ready":
            state = "/home/agent/" + report["gateway_lifecycle"]["project"]
            return subprocess.check_output(["bash", "-c", command.replace(state, str(directory))], text=True)
        if label == "gateway-registry-seed":
            registry_request("PUT", "/v2/guest/manifests/qualification", json.dumps({"mediaType": "application/test"}))
        if label in {"gateway-registry-seed-requests", "gateway-registry-pull-requests"}:
            return (directory / "registry-events.jsonl").read_text()
        if label == "gateway-registry-stop":
            _, arguments = docker_arguments(command, label)
            assert arguments == ["stop", "--time", "20", container_id]
            child.terminate()
            assert child.wait(timeout=5) == 0
        if label == "gateway-registry-remove":
            _, arguments = docker_arguments(command, label)
            assert arguments == ["rm", container_id] and child.poll() == 0
        if label == "gateway-registry-blobs-remove":
            shutil.rmtree(directory / "registry")
        return ""

    def background(_agent, command, label):
        nonlocal child
        _, arguments = docker_arguments(command, label)
        assert arguments == ["start", "--attach", container_id]
        child = subprocess.Popen(container_command)
        return (child,)

    def registry_request(method, path, body=None):
        repository = json.loads((directory / "registry.json").read_text())["repository"]
        connection = http.client.HTTPConnection(repository.split("/")[0], timeout=5)
        connection.request(method, path, body)
        response = connection.getresponse()
        response.read()
        connection.close()
        assert response.status in {200, 201}

    def client(_command, label, **_):
        if label in {"gateway-base-image", "gateway-pulled-image"}:
            return json.dumps([{"Id": image_id}])
        if label == "gateway-image-pull":
            registry_request("GET", "/v2/guest/manifests/qualification")
        if label == "gateway-compose-build":
            assert report["gateway_lifecycle"]["registry_cleanup"] == "removed" and child.poll() == 0
            assert not (directory / "registry").exists()
            repository = json.loads((directory / "registry.json").read_text())["repository"]
            with pytest.raises(ConnectionRefusedError):
                http.client.HTTPConnection(repository.split("/")[0], timeout=5).connect()
            raise RuntimeError("build boundary reached")
        return ""

    try:
        with pytest.raises(RuntimeError, match="build boundary reached"):
            gateway_compose_journey(tmp_path, client, guest, background, report)
        assert [label for label, _ in calls] == ["gateway-registry-create", "gateway-registry",
                                                "gateway-registry-stop", "gateway-registry-remove"]
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            child.wait(timeout=5)


@pytest.mark.parametrize("interruption", ["gateway-registry-create", "gateway-registry-seed", "gateway-image-pull",
                                         "gateway-registry-stop", "gateway-registry-remove", "gateway-compose-up"])
def test_gateway_lifecycle_preserves_failed_effects_without_repeating_mutations(tmp_path, interruption):
    caller = tmp_path / "caller"
    caller.mkdir()
    report = {}
    steps = []

    def guest(command, label, **kwargs):
        steps.append(label)
        if label == interruption:
            raise RuntimeError("response interrupted after dispatch")
        return registry_guest(command, label, **kwargs)

    def client(command, label, **_):
        steps.append(label)
        if label == interruption:
            raise RuntimeError("response interrupted after dispatch")
        if label in {"gateway-base-image", "gateway-pulled-image"}:
            return json.dumps([{"Id": "sha256:" + "a" * 64}])
        return ""

    with pytest.raises(RuntimeError, match="response interrupted after dispatch"):
        gateway_compose_journey(caller, client, guest, registry_background, report)
    observation = report["gateway_lifecycle"]
    assert observation["state"] == "incomplete"
    assert observation["volume"] == observation["project"] + "_notes"
    assert observation["image"] == observation["project"] + ":qualification"
    if interruption != "gateway-registry-create":
        assert observation["registry_image"].endswith(":" + observation["project"])
    assert steps.count(interruption) == 1
    assert not any("teardown" in step or step in {"gateway-image-remove", "gateway-registry-remove",
                                                 "gateway-registry-blobs-remove"}
                   for step in steps[steps.index(interruption) + 1:])


@pytest.mark.parametrize("failure", ["no-manifest-get", "different-image"])
def test_gateway_lifecycle_requires_registry_pull_and_matching_image_before_build(tmp_path, failure):
    report = {}
    steps = []

    def guest(command, label, **kwargs):
        steps.append(label)
        if failure == "no-manifest-get" and label == "gateway-registry-pull-requests":
            return ""
        return registry_guest(command, label, **kwargs)

    def client(_command, label, **_):
        steps.append(label)
        if label in {"gateway-base-image", "gateway-pulled-image"}:
            character = "b" if failure == "different-image" and label == "gateway-pulled-image" else "a"
            return json.dumps([{"Id": "sha256:" + character * 64}])
        return ""

    with pytest.raises(AssertionError, match="pull did not fetch|pulled image differs"):
        gateway_compose_journey(tmp_path, client, guest, registry_background, report)
    assert report["gateway_lifecycle"]["state"] == "incomplete"
    assert steps.count("gateway-image-pull") == 1 and "gateway-compose-build" not in steps
    assert "gateway-registry-stop" not in steps and "gateway-registry-remove" not in steps


@pytest.mark.parametrize("failure", [None, "lost-write-response", "lost-data"])
def test_gateway_lifecycle_application_observer_checks_persistence_without_replaying_writes(tmp_path, failure):
    caller = tmp_path / "caller"
    caller.mkdir()
    report = {}
    requests = []
    saved = []
    recovered = False
    steps = []

    class Application(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append("GET")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps([] if recovered and failure == "lost-data" else saved).encode())

        def do_POST(self):
            requests.append("POST")
            saved.append(json.loads(self.rfile.read(int(self.headers["Content-Length"])))["text"])
            if failure == "lost-write-response":
                self.close_connection = True
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(saved).encode())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Application)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()

    def client(command, label, **_):
        nonlocal recovered
        steps.append(label)
        if label in {"gateway-compose-containers", "gateway-compose-recreated"}:
            return "new-api\nnew-store\n" if recovered else "api\nstore\n"
        if label == "gateway-base-image":
            return json.dumps([{"Id": "sha256:" + "a" * 64}])
        if label == "gateway-pulled-image":
            return json.dumps([{"Id": "sha256:" + "a" * 64}])
        if label == "gateway-compose-inspect":
            return json.dumps([{"Id": name, "State": {"Running": True}, "HostConfig": {"NetworkMode": "host"},
                                "Config": {"Labels": {"com.docker.compose.service": name}}} for name in ("api", "store")])
        if label.startswith("gateway-notes-"):
            program = shlex.split(command)[-1].replace('"127.0.0.1", 8088', f'"127.0.0.1", {server.server_port}')
            return subprocess.check_output(["python3", "-c", program], text=True, stderr=subprocess.PIPE)
        if label == "gateway-compose-exec":
            return "gateway-exec"
        if label == "gateway-compose-logs":
            return '"role": "api"\n"role": "store"'
        if label == "gateway-lifecycle-attach":
            return "attach:gateway-attach"
        if label in {"gateway-volume-before", "gateway-volume-after"}:
            return '[{"CreatedAt":"same-creation"}]'
        if label == "gateway-compose-recreate":
            recovered = True
        return ""

    try:
        if failure:
            with pytest.raises(subprocess.CalledProcessError):
                gateway_compose_journey(caller, client, registry_guest, registry_background, report)
            assert report["gateway_lifecycle"]["state"] == "incomplete"
            assert "gateway-compose-teardown" not in steps
        else:
            gateway_compose_journey(caller, client, registry_guest, registry_background, report)
            assert report["gateway_lifecycle"]["state"] == "passed"
            assert "gateway-compose-teardown" in steps
        assert requests.count("POST") == 1
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.mark.parametrize("exit_code,diagnostic,valid", [
    (1, "Error response from daemon: Proxy request failed\n", True),
    (1, "Error response from daemon: GATEWAY_PROVIDER_UNAVAILABLE\n", True),
    (1, "Cannot connect to the Docker daemon\n", True),
    (0, "Error response from daemon: Proxy request failed\n", False),
    (1, "", False),
    (1, " \n", False),
    (1, "Error response from daemon: \n\n", False),
    (1, "docker: Error response from daemon: \n", False),
    (1, "Error:\n", False),
    (1, "502\n", False),
])
def test_gateway_failure_requires_the_actual_client_exit_and_useful_text(exit_code, diagnostic, valid):
    observation = {"exit": exit_code, "stderr": diagnostic}
    if valid:
        verify_gateway_client_failure(observation)
    else:
        with pytest.raises(AssertionError):
            verify_gateway_client_failure(observation)


def test_gateway_failure_capture_keeps_client_exit_separate_from_raw_http(tmp_path):
    client = tmp_path / "docker-client"
    client.write_text("#!/bin/sh\nprintf 'client version on stdout\\n'\nprintf 'Error response from daemon: Proxy request failed\\n' >&2\nexit 23\n")
    client.chmod(0o700)
    directory = tmp_path / "client"
    directory.mkdir()
    (directory / "config.json").write_text(json.dumps({"HttpHeaders": {
        "X-SafeYolo-Docker-Service": "notes", "Authorization": "Bearer synthetic-scoped-token"}}))
    requests = []

    class Reply(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers["X-SafeYolo-Docker-Service"], self.headers["Authorization"]))
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b'{"error":"unavailable","message":"Docker endpoint unavailable"}')

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Reply)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        def execute(command, _label):
            command = command.replace("/workspace/docker-client", shlex.quote(str(client)))
            command = command.replace("/home/agent/docker-gateway-client", str(directory))
            return subprocess.check_output(["bash", "-euc", command], text=True,
                                           env=os.environ | {"HTTP_PROXY": f"http://127.0.0.1:{server.server_port}", "BASH_ENV": ""})

        observation = gateway_client_failure(execute, "daemon-failed")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert observation["exit"] == 23
    assert observation["stderr"] == "Error response from daemon: Proxy request failed\n"
    assert observation["http"]["status"] == 503
    assert json.loads(observation["http"]["body"])["message"] == "Docker endpoint unavailable"
    assert json.loads((directory / "daemon-failed.http.json").read_text()) == observation["http"]
    assert (directory / "daemon-failed.stdout").read_text() == "client version on stdout\n"
    assert requests == [("/v1.45/version", "notes", "Bearer synthetic-scoped-token")]
    verify_gateway_client_failure(observation)


@pytest.mark.parametrize("blank", [False, True])
def test_gateway_failure_only_retains_diagnostics_without_replaying_mutations(tmp_path, monkeypatch, blank):
    (tmp_path / "docker-caller").mkdir()
    provider = tmp_path / "provider"
    provider.mkdir()
    (provider / "docker-gateway-client").write_text("synthetic client, never executed\n")
    service = tmp_path / "services/notes.yaml"
    service.parent.mkdir()
    service.write_text("retained application service\n")
    policy = tmp_path / "policy.toml"
    policy.write_text('[hosts."notes.safeyolo.internal"]\nservice = "notes"\n'
                      + f'[agents.notes]\nfolder = "{provider}"\n')
    originals = {path: path.read_bytes() for path in (service, policy)}
    output = tmp_path / "output"
    output.mkdir()
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.running_guest", lambda *_: {})
    steps = []

    def native(*arguments):
        return '{"runtime_state":"stopped"}' if arguments[:2] == ("agent", "status") else ""

    def guest(command, label, **_):
        steps.append(label)
        return "403" if label == "gateway-unapproved" else ""

    def background(*_):
        return (SimpleNamespace(poll=lambda: None, wait=lambda **_: 0),)

    observation = {"exit": 1, "stderr": "Error response from daemon: " + ("" if blank else "Proxy request failed"),
                   "http": {"status": 502, "body": '{"error":"Proxy request failed"}'}}
    captures = []

    def failure(_client, label):
        captures.append(label)
        return observation

    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.gateway_client_failure", failure)
    args = SimpleNamespace(docker_data="/home/agent/retained/data", gateway_failures_only=True)
    report = {}
    if blank:
        with pytest.raises(AssertionError, match="no useful failure diagnostic"):
            gateway_management(args, tmp_path, output, native, guest, background, report)
    else:
        gateway_management(args, tmp_path, output, native, guest, background, report)
    assert captures == (["gateway-daemon-failed"] if blank else
                        ["gateway-daemon-failed", "gateway-closed", "gateway-stopped"])
    assert not {"gateway-create", "gateway-container-start", "gateway-inspect", "gateway-exec",
                "gateway-attach", "gateway-remove"}.intersection(steps)
    assert report["gateway_failures"]["gateway-daemon-failed"] == observation
    assert json.loads((output / "gateway-daemon-failed.json").read_text()) == observation
    for path, original in originals.items():
        assert path.read_bytes() == original


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
