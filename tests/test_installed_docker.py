"""Controls for interpreting the nested Docker fixture's outbound results.

These exercise the observer's refusal handling. They do not establish the
installed sandbox's network enforcement.
"""

import base64
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
from contextlib import contextmanager
from copy import deepcopy
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import ThreadingUnixStreamServer
from types import SimpleNamespace
from unittest.mock import create_autospec
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from urllib.response import addinfourl

import pytest
import tomlkit

from tests.blackbox.installed_docker_preflight import (
    GuestStepFailed,
    application_resume_input,
    compose_journey,
    gateway_client_failure,
    gateway_compose_journey,
    gateway_compose_resume,
    gateway_management,
    gateway_notes_command,
    gateway_recovery_receipt,
    main,
    provider_controls,
    public_pull_token,
    pull_public_image,
    run,
    verify_gateway_client_failure,
    verify_outbound,
    verify_provider_origin,
)
from tests.blackbox.installed_host_smoke import _process_start_token
from tests.blackbox.installed_provider import capture_guest_command, wait_file
from tests.blackbox.registry_fixture import distribution_registry

PROBE = Path(__file__).parent / "blackbox/fixtures/nested-docker/network_probe.py"


@pytest.mark.parametrize("defect", [None, "reuse-root", "journey", "recurring", "gateway"])
def test_application_resume_cli_selects_owned_receivers_without_recurring_gateway_replay(tmp_path, monkeypatch, defect):
    arguments = ["--prepared-config", str(tmp_path / "prepared"), "--root", str(tmp_path / "retained"),
                 "--output", str(tmp_path / "output"), "--revision", "product", "--nested-docker",
                 "--docker-data", "/home/agent/docker-image-data", "--reuse-root", "--journey",
                 "--application-resume", str(tmp_path / "previous/result.json")]
    if defect in {"reuse-root", "journey"}:
        arguments.remove("--" + defect)
    elif defect:
        arguments.append("--" + defect)
    calls = []

    def observed(args, receipt):
        calls.append((args, receipt))
        return {"status": "application-resume-passed", "cleanup": "stopped"}

    monkeypatch.setattr(sys, "argv", ["installed_docker_preflight.py", *arguments])
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.recurring_journey", observed)
    if defect:
        with pytest.raises(SystemExit) as result:
            main()
        assert result.value.code == 2 and not calls
    else:
        assert main() == 0 and len(calls) == 1
        args, receipt = calls[0]
        assert receipt is None and not args.recurring and not args.gateway
        assert args.application_resume == tmp_path / "previous/result.json"


@pytest.mark.parametrize("defect", [None, "root", "step", "cleanup", "marker"])
def test_application_resume_reads_original_result_without_assigning_old_probes_to_new_run(tmp_path, defect):
    root = tmp_path / "root"
    previous = {"root": str(root), "status": "incomplete", "step": "privileged-network",
                "cleanup": "stopped", "cleanup_failures": [], "runtime": {"agent_id": "notes", "run_id": "old"},
                "containers": [{"Id": "api"}, {"Id": "store"}], "network_probes": [{"request_id": "old-request"}]}
    if defect == "root":
        previous["root"] += "-other"
    elif defect == "step":
        previous["step"] = "compose-build"
    elif defect == "cleanup":
        previous["cleanup_failures"] = ["owned process survived"]
    path = tmp_path / "result.json"
    path.write_text(json.dumps(previous))
    path.with_name("notes-written.log").write_text(json.dumps([] if defect == "marker" else ["saved-note"]))
    if defect:
        with pytest.raises(AssertionError):
            application_resume_input(path, root)
    else:
        result = application_resume_input(path, root)
        assert result["runtime"] == previous["runtime"] and result["marker"] == "saved-note"
        assert result["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert "network_probes" not in result


@pytest.mark.parametrize("defect", [None, "run", "image", "binding", "selection", "volume", "marker", "privileged"])
def test_application_resume_runs_remaining_checks_without_pull_build_or_rewriting_data(tmp_path, monkeypatch, defect):
    workspace, output, root = (tmp_path / name for name in ("workspace", "output", "root"))
    (workspace / "nested-docker").mkdir(parents=True)
    output.mkdir()
    guest_input = root / "agents/notes/config-share/safeyolo-guest"
    guest_input.parent.mkdir(parents=True)
    guest_input.write_text("guest bytes")
    mount = {"Type": "volume", "Name": "nested-notes_notes", "Source": "/data/notes", "Destination": "/data"}
    containers = [{"Id": name, "Image": "sha256:retained", "Name": name,
                   "Mounts": [mount] if name == "store" else [],
                   "State": {"Running": True, "Pid": 10}, "HostConfig": {"NetworkMode": "host"}}
                  for name in ("api", "store")]
    previous = {"runtime": {"agent_id": "ag-notes", "run_id": "old"},
                "containers": deepcopy(containers), "marker": "saved-note"}
    report = {"resumed_application": previous,
              "runtime": {"agent_id": "ag-notes", "run_id": "old" if defect == "run" else "new",
                          "backend_pid": 1, "backend_token": "birth"},
              "inputs": {"guest": {"sha256": hashlib.sha256(guest_input.read_bytes()).hexdigest()}}}
    commands, native_calls, provider = [], [], []

    def native(*arguments):
        native_calls.append(arguments)
        return "{}"

    def guest(command, label, **_):
        commands.append((label, command))
        assert " build " not in command and " pull " not in command and "--data " not in command
        assert label not in {"context", "compose-create", "notes-empty", "notes-write", "fresh-ca-reader"}
        if label == "retained-image":
            return json.dumps([{"Id": "other" if defect == "image" else "sha256:retained"}])
        if label in {"retained-containers", "compose-inspect"}:
            actual = deepcopy(containers)
            if defect == "binding":
                actual[1]["Mounts"] = []
            return json.dumps(actual)
        if label in {"retained-compose-containers", "compose-ps"}:
            return "api other" if defect == "selection" else "api store"
        if label == "retained-volume":
            return json.dumps([{"Name": "nested-notes_notes", "Mountpoint": "/other" if defect == "volume" else "/data/notes"}])
        if label in {"retained-notes", "after-container-restart", "after-recreation", "after-sandbox-restart"}:
            return json.dumps([] if defect == "marker" else ["saved-note"])
        if label == "after-data-deletion":
            return "[]"
        if label == "docker-info":
            return '{"Driver":"vfs"}'
        if label in {"application-network", "privileged-network"}:
            if label == "privileged-network":
                assert "--privileged" in command and "--pull=never" in command
                if defect == "privileged":
                    raise RuntimeError("interrupted privileged command")
            phase = label.removesuffix("-network")
            return "\n".join(json.dumps({"phase": phase, "status": status, "request_id": f"new-{phase}-{status}"})
                             for status in (200, 403))
        return ""

    child = SimpleNamespace(poll=lambda: None, wait=lambda **_: 0)
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.running_guest",
                        lambda *_: {"agent_id": "ag-notes", "run_id": "recovered"})
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.surviving_processes", lambda *_: [])
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.provider_controls", lambda *_: provider.append(True))
    args = SimpleNamespace(docker_data="/home/agent/docker-image-data", host_address="127.0.0.1", host_port=12345,
                           owned_origins={"PROBE_ALLOWED": "http://allowed", "PROBE_DENIED": "http://denied"})
    if defect:
        with pytest.raises((AssertionError, RuntimeError)):
            compose_journey(args, root, output, workspace, native, guest, lambda *_: (child,), report)
        assert not provider and not any(label == "explicit-data-deletion" for label, _ in commands)
        if defect != "privileged":
            assert not any(label == "privileged-network" for label, _ in commands)
    else:
        compose_journey(args, root, output, workspace, native, guest, lambda *_: (child,), report)
        labels = [label for label, _ in commands]
        for label in ("retained-image", "retained-containers", "retained-compose-containers", "retained-volume"):
            assert labels.index(label) < labels.index("retained-start")
        assert labels.index("retained-notes") < labels.index("privileged-network") < labels.index("explicit-data-deletion")
        assert {row["request_id"] for row in report["network_probes"]} == {
            f"new-{phase}-{status}" for phase in ("application", "privileged") for status in (200, 403)}
        assert report["resumed_application"]["runtime"]["run_id"] == "old"
        assert report["recovery"]["before"]["run_id"] == "new" and report["recovery"]["after"]["run_id"] == "recovered"
        assert provider == [True] and native_calls == [
            ("agent", "stop", "notes"), ("agent", "start", "notes", "--sandbox-only"), ("agent", "status", "notes")]


@pytest.mark.parametrize("failed_command", ["", "apt-get update", "apt-get install", "python3"])
def test_build_installs_and_probes_in_final_dockerfile_step(tmp_path, failed_command):
    instructions = [line for line in (PROBE.parent / "Dockerfile").read_text().replace("\\\n", "").splitlines()
                    if line and not line.startswith("#")]
    # All source and metadata preparation precedes the single populated layer.
    [command] = [line.removeprefix("RUN ") for line in instructions if line.startswith("RUN ")]
    assert instructions[-1] == "RUN " + command
    assert "COPY network_probe.py notes.py /app/" in instructions
    assert 'CMD ["python3", "-u", "/app/notes.py"]' in instructions
    tools, calls, config, lists = (tmp_path / name for name in ("bin", "calls", "proxy.conf", "lists"))
    tools.mkdir()
    lists.mkdir()
    (lists / "package-index").touch()
    for name in ("apt-get", "python3"):
        tool = tools / name
        tool.write_text('#!/bin/sh\n'
                        f'printf "%s\\n" "{name} $*" >> "$BUILD_CALLS"\n'
                        f'case "{name} $*" in "$FAILED_COMMAND"*) exit 17;; esac\n')
        tool.chmod(0o755)
    # Execute the actual RUN chain with only package/network tools substituted.
    # Redirect its two absolute write paths into this disposable fixture.
    command = command.replace("/etc/apt/apt.conf.d/80-safeyolo-proxy", shlex.quote(str(config)))
    command = command.replace("/var/lib/apt/lists/*", shlex.quote(str(lists)) + "/*")
    env = os.environ | {"PATH": str(tools) + os.pathsep + os.environ["PATH"], "BUILD_CALLS": str(calls),
                        "FAILED_COMMAND": failed_command or "unused-command", "HTTP_PROXY": "http://proxy:3128",
                        "HTTPS_PROXY": "http://proxy:3128", "SSL_CERT_FILE": "/fixture/ca.crt"}
    result = subprocess.run(["/bin/sh", "-c", command], env=env, capture_output=True, text=True, timeout=5)
    expected = ["apt-get update", "apt-get install -y --no-install-recommends python3", "python3 /app/network_probe.py"]
    if failed_command:
        expected = expected[:next(index for index, call in enumerate(expected) if call.startswith(failed_command)) + 1]
    assert result.returncode == (17 if failed_command else 0), result.stderr
    assert calls.read_text().splitlines() == expected
    assert config.read_text() == ('Acquire::http::Proxy "http://proxy:3128";\n'
                                  'Acquire::https::Proxy "http://proxy:3128";\n'
                                  'Acquire::https::CaInfo "/fixture/ca.crt";\n')
    assert (lists / "package-index").exists() == failed_command.startswith("apt-get")


@pytest.mark.parametrize("completed_exit", [None, 7])
def test_guest_failure_keeps_capture_until_owned_stop(tmp_path, monkeypatch, completed_exit):
    prepared, root, release = (tmp_path / name for name in ("prepared", "fresh", "stop"))
    for name in ("bin", "assets/guest", "share/rootfs-tree"):
        (prepared / name).mkdir(parents=True)
    for name in ("bin/safeyolo", "bin/safeyolo-proxy", "assets/guest/safeyolo-guest"):
        (prepared / name).write_text("selected bytes")
    (prepared / "config.toml").write_text("[linux]\n")
    captures, stops = [], []

    def prepare(_base, destination):
        (destination / "data").mkdir(parents=True)
        (destination / "services").mkdir()
        (destination / "config.toml").write_text("[linux]\n")

    def checked(command, **_):
        if command[-1] == "--version":
            return "commit=revision"
        arguments = command[3:]
        home = root / "agents/notes"
        if arguments[:2] == ["agent", "create"]:
            (home / "config-share").mkdir(parents=True)
            (home / "config-share/safeyolo-guest").write_text("selected bytes")
            (home / "config.json").write_text("{}")
        if arguments == ["agent", "stop", "notes"]:
            child, reader, finished = captures[0]
            stops.append({"running": child.poll() is None, "capturing": reader.is_alive(), "finished": finished.is_set()})
            release.touch()
        return "{}"

    def capture(*arguments):
        result = capture_guest_command(*arguments)
        captures.append(result)
        return result

    def journey(_args, _root, _output, _workspace, _native, guest, *_):
        guest("build", "compose-build", timeout=0.2)

    program = ('import pathlib, time\nprint("build-started", flush=True)\n'
               f'while not pathlib.Path({str(release)!r}).exists(): time.sleep(0.01)\n'
               'print("drained-during-stop", flush=True)\n')
    if completed_exit is not None:
        program = f'import sys\nprint("command-failed", flush=True)\nsys.exit({completed_exit})\n'
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.prepare_native_instance", prepare)
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.copy_prepared_nats", lambda *_: None)
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.checked", checked)
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.running_guest", lambda *_: {})
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.owned_processes", lambda *_: [])
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight._agent_listeners",
                        lambda *_: [{"agent_id": "notes", "path": str(tmp_path)}])
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.runsc_identity", lambda *_, **__: {})
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight._native_config", lambda *_: {})
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight._runtime_observation", lambda *_, **__: {})
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.guest_command_args",
                        lambda *_, **__: [sys.executable, "-u", "-c", program])
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.capture_guest_command", capture)
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.compose_journey", journey)
    args = SimpleNamespace(prepared_config=prepared, root=root, output=tmp_path / "output", revision="revision",
                           proxy_revision=None, guest_revision=None, reuse_root=False, gateway=False,
                           journey=True, nested_docker=True, docker_data=None, admin_port=12345)
    try:
        with pytest.raises(subprocess.TimeoutExpired if completed_exit is None else GuestStepFailed) as raised:
            run(args)
    finally:
        release.touch()
        for child, reader, finished in captures:
            child.wait(timeout=5)
            finished.set()
            reader.join(timeout=5)
    if completed_exit is None:
        assert stops == [{"running": True, "capturing": True, "finished": False}]
        assert (args.output / "compose-build.log").read_text() == "build-started\ndrained-during-stop\n"
    else:
        assert raised.value.label == "compose-build" and raised.value.exit_code == completed_exit
        assert stops == [{"running": False, "capturing": False, "finished": True}]
        assert (args.output / "compose-build.log").read_text() == "command-failed\n"
    report = json.loads((args.output / "result.json").read_text())
    assert report["status"] == "incomplete" and report["cleanup"] == "stopped"
    assert report["cleanup_failures"] == [] and report["commands"] == [{"step": "compose-build", "exit": completed_exit or 0}]


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
            original = report["gateway_lifecycle"].get("recovery_probe", {}).get("command", command)
            program = shlex.split(original)[-1].replace('"127.0.0.1", 8088', f'"127.0.0.1", {server.server_port}')
            if label == "gateway-notes-recovered":
                command = command.replace(original, shlex.join([sys.executable, "-c", program]))
                command = command.replace("/workspace/" + report["gateway_lifecycle"]["project"],
                                          str(caller / report["gateway_lifecycle"]["project"]))
                return subprocess.check_output(["bash", "-c", "set -eu; " + command], text=True, stderr=subprocess.PIPE)
            return subprocess.check_output(["python3", "-c", program], text=True, stderr=subprocess.PIPE)
        if label == "gateway-compose-exec":
            return "gateway-exec"
        if label == "gateway-compose-logs":
            return '"role": "api"\n"role": "store"'
        if label == "gateway-lifecycle-attach":
            return "attach:gateway-attach"
        if label in {"gateway-volume-before", "gateway-volume-after"}:
            return '[{"Name":"original-volume","Mountpoint":"/original/data","CreatedAt":"same-creation"}]'
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


@pytest.mark.parametrize("failure", [None, "container-changed", "volume-changed", "mount-changed",
                                     "start-unknown", "client-126", "native-126", "capture-lost"])
def test_gateway_continuation_reconciles_existing_targets_and_preserves_command_receipts(tmp_path, failure):
    name = "sycompose" + "a" * 12
    context = tmp_path / name
    context.mkdir()
    (context / "compose.yaml").write_text("retained caller context\n")
    volume = {"Name": name + "_notes", "Mountpoint": "/retained/volume/_data", "CreatedAt": "original-creation"}
    observation = {"project": name, "image": name + ":qualification", "volume": volume["Name"],
                   "registry_image": "127.0.0.1:12345/guest:" + name, "volume_before": [volume],
                   "containers": ["old-api", "old-store"], "recreated_containers": ["new-api", "new-store"],
                   "written": '["persist-original"]\n', "state": "incomplete"}
    inspected = [{"Id": "new-" + service, "State": {"Running": False}, "HostConfig": {"NetworkMode": "host"},
                  "Config": {"Image": observation["image"], "Labels": {"com.docker.compose.project": name,
                             "com.docker.compose.service": service}},
                  "Mounts": [{"Type": "volume", "Name": volume["Name"], "Source": volume["Mountpoint"],
                              "Destination": "/data"}] if service == "store" else []} for service in ("api", "store")]
    steps = []

    def client(command, label):
        steps.append(label)
        if label == "gateway-resume-containers":
            return "different-api\nnew-store\n" if failure == "container-changed" else "new-api\nnew-store\n"
        if label == "gateway-resume-inspect":
            if failure == "mount-changed":
                inspected[1]["Mounts"][0]["Source"] = "/different/data"
            return json.dumps(inspected)
        if label in {"gateway-resume-volume", "gateway-volume-after"}:
            return json.dumps([volume | {"CreatedAt": "different"}] if failure == "volume-changed" else [volume])
        if label == "gateway-resume-start-store" and failure == "start-unknown":
            raise RuntimeError("unknown start result after dispatch")
        if label == "gateway-notes-recovered":
            if failure == "native-126":
                raise RuntimeError("native shell exited 126 before command capture")
            original = observation["recovery_probe"]["command"]
            assert shlex.split(original)[-5:-1] == ["-T", "api", "python3", "-c"]
            assert "\nif False:\n" in shlex.split(original)[-1], "recovery must not write another note"
            replacement = "(exit 126)" if failure == "client-126" else "printf '%s\\n' '[\"persist-original\"]'"
            command = command.replace(original, replacement).replace("/workspace/" + name, str(context))
            output = subprocess.check_output(["bash", "-c", "set -eu; " + command], text=True, stderr=subprocess.PIPE)
            if failure == "capture-lost":
                raise RuntimeError("native output unavailable after command completed")
            return output
        return ""

    if failure:
        with pytest.raises((AssertionError, RuntimeError, subprocess.CalledProcessError)):
            gateway_compose_resume(tmp_path, observation, client)
        assert observation["state"] == "incomplete" and "gateway-compose-teardown" not in steps
        if failure in {"container-changed", "volume-changed", "mount-changed"}:
            assert not any("start-" in step or step == "gateway-notes-recovered" for step in steps)
        if failure == "start-unknown":
            assert steps.count("gateway-resume-start-store") == 1 and "gateway-resume-start-api" not in steps
        if failure in {"client-126", "native-126", "capture-lost"}:
            probe = observation["recovery_probe"]
            assert probe["exit"] == {"client-126": "126\n", "native-126": None, "capture-lost": "0\n"}[failure]
            assert probe["stdout"] == {"client-126": "", "native-126": None,
                                       "capture-lost": '["persist-original"]\n'}[failure]
    else:
        gateway_compose_resume(tmp_path, observation, client)
        assert observation["state"] == "passed" and observation["volume_after"] == [volume]
        assert steps.index("gateway-resume-volume") < steps.index("gateway-resume-start-store") < steps.index("gateway-resume-start-api")
        assert "gateway-compose-teardown" in steps and observation["recovery_probe"]["exit"] == "0\n"
    assert not {"gateway-image-pull", "gateway-compose-build", "gateway-compose-up", "gateway-compose-recreate"}.intersection(steps)
    assert steps.count("gateway-notes-recovered") <= 1


@pytest.mark.parametrize("failure", [None, "source", "project", "command", "started", "exit", "stdout", "stderr",
                                     "container-changed", "mount-changed", "volume-changed", "volume-after-changed",
                                     "teardown-unknown", "remaining-pull-image"])
def test_gateway_saved_client_recovery_continues_only_volume_and_owned_teardown(tmp_path, failure):
    name = "sycompose" + "b" * 12
    volume = {"Name": name + "_notes", "Mountpoint": "/retained/volume/_data", "CreatedAt": "original-creation"}
    observation = {"project": name, "image": name + ":qualification", "volume": volume["Name"],
                   "volume_before": [volume], "containers": ["old-api", "old-store"],
                   "recreated_containers": ["new-api", "new-store"], "written": '["persist-original"]\n', "state": "incomplete"}
    previous = {"lifecycle": observation, "gateway_route": {"provider": "notes", "caller": "dockercaller"}}
    compose = f"/workspace/docker-client compose -p {name} --project-directory /home/agent/{name}/context"
    probe = {"command": gateway_notes_command(compose, "persist-original", ["persist-original"]),
             "started": "started\n", "stdout": observation["written"], "stderr": "", "exit": "0\n"}
    receipt = {field: deepcopy(observation[field]) for field in
               ("project", "image", "volume", "recreated_containers", "written", "volume_before")}
    receipt.update(original_containers=observation["containers"], gateway_route=previous["gateway_route"],
                   prior_receipt_sha256="original-receipt-hash", cleanup="stopped", restoration="complete", survivors=[],
                   reached_step="gateway-notes-recovered", native_command_exit=1, recovery_probe=probe)
    if failure == "source":
        receipt["prior_receipt_sha256"] = "different"
    elif failure == "project":
        receipt["project"] = "different"
    elif failure in {"command", "started", "exit", "stdout", "stderr"}:
        receipt["recovery_probe"][failure] = {"command": "different", "started": None, "exit": "126\n",
                                               "stdout": '["different"]\n', "stderr": "failed"}[failure]
    path = tmp_path / "recovery.json"
    path.write_text(json.dumps(receipt))
    report = {}
    if failure in {"source", "project", "command", "started", "exit", "stdout", "stderr"}:
        with pytest.raises(AssertionError):
            gateway_recovery_receipt(path, previous, "original-receipt-hash", report)
        assert report["gateway_recovery_source"]["receipt"] == receipt
        return
    retained = gateway_recovery_receipt(path, previous, "original-receipt-hash", report)
    observation["registry_image"] = "127.0.0.1:12345/guest:" + name
    context = tmp_path / name
    context.mkdir()
    (context / "compose.yaml").write_text("retained context\n")
    inspected = [{"Id": "new-" + service, "State": {"Running": False}, "HostConfig": {"NetworkMode": "host"},
                  "Config": {"Image": observation["image"], "Labels": {"com.docker.compose.project": name,
                             "com.docker.compose.service": service}},
                  "Mounts": [{"Type": "volume", "Name": volume["Name"], "Source": volume["Mountpoint"],
                              "Destination": "/data"}] if service == "store" else []} for service in ("api", "store")]
    steps = []

    def client(command, label):
        steps.append(label)
        if label == "gateway-resume-containers":
            return "different-api\nnew-store\n" if failure == "container-changed" else "new-api\nnew-store\n"
        if label == "gateway-resume-inspect":
            if failure == "mount-changed":
                inspected[1]["Mounts"][0]["Source"] = "/different/data"
            return json.dumps(inspected)
        if label in {"gateway-resume-volume", "gateway-volume-after"}:
            changed = failure == "volume-changed" or (label == "gateway-volume-after" and failure == "volume-after-changed")
            return json.dumps([volume | {"CreatedAt": "different"}] if changed else [volume])
        if label == "gateway-compose-teardown" and failure == "teardown-unknown":
            raise RuntimeError("teardown reply lost after dispatch")
        if label == "gateway-teardown-pull-image" and failure == "remaining-pull-image":
            return "remaining-image\n"
        return ""

    if failure:
        with pytest.raises((AssertionError, RuntimeError)):
            gateway_compose_resume(tmp_path, observation, client, recovery_receipt=retained)
        assert observation["state"] == "incomplete"
        if failure in {"container-changed", "mount-changed", "volume-changed", "volume-after-changed"}:
            assert "gateway-compose-teardown" not in steps
        if failure == "teardown-unknown":
            assert steps.count("gateway-compose-teardown") == 1 and "gateway-image-remove" not in steps
        if failure == "volume-after-changed":
            assert observation["volume_after"][0]["CreatedAt"] == "different"
        if failure == "remaining-pull-image":
            assert observation["teardown_absence"]["pull-image"] == "remaining-image\n"
    else:
        gateway_compose_resume(tmp_path, observation, client, recovery_receipt=retained)
        assert observation["state"] == "passed" and observation["volume_after"] == [volume]
        assert observation["recovery_probe"] == probe and observation["recovered"] == probe["stdout"]
        assert steps[-4:] == ["gateway-teardown-" + label for label in ("containers", "volumes", "images", "pull-image")]
    assert report["gateway_recovery_source"]["receipt"]["native_command_exit"] == 1
    assert not any("start-" in step or "notes-" in step or "build" in step or "pull" == step for step in steps)
    assert path.read_text() == json.dumps(receipt)


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


@pytest.mark.parametrize("mode", ["ordinary", "failures", "lifecycle", "resume"])
@pytest.mark.parametrize("python_state", ["absent", "installed", "update-failed", "install-failed"])
def test_gateway_prepares_caller_python_before_configuration(tmp_path, monkeypatch, mode, python_state):
    """Run the real caller shell with controlled package and Agent API replies."""
    caller = tmp_path / "docker-caller"
    caller.mkdir()
    provider = tmp_path / "provider"
    provider.mkdir()
    for name in ("docker-gateway-client", "docker-gateway-compose"):
        (provider / name).write_text("synthetic client, never executed\n")
    service = tmp_path / "services/notes.yaml"
    service.parent.mkdir()
    service.write_text("retained application service\n")
    policy = tmp_path / "policy.toml"
    policy.write_text('[hosts."notes.safeyolo.internal"]\nservice = "notes"\n'
                      + f'[agents.notes]\nfolder = "{provider}"\n')
    originals = {path: path.read_bytes() for path in (service, policy)}
    output = tmp_path / "output"
    output.mkdir()
    tools = tmp_path / "tools"
    tools.mkdir()
    for name in ("cat", "mkdir"):
        (tools / name).symlink_to(shutil.which(name))
    if python_state == "installed":
        (tools / "python3").symlink_to(sys.executable)
    installer = tools / "sudo"
    installer.write_text('#!/bin/bash\n'
                         'printf "%s\\n" "$*" >> "$CALLER_PACKAGE_LOG"\n'
                         'if [[ "$CALLER_PYTHON_STATE" == "$3-failed" ]]; then exit 73; fi\n'
                         'if [[ "$3" == install ]]; then /bin/ln -s -- "$CALLER_PYTHON" "$CALLER_TOOLS/python3"; fi\n')
    installer.chmod(0o700)
    curl = tools / "curl"
    curl.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"authorized":{"notes":{"token":"synthetic-scoped-token"}}}\'\n')
    curl.chmod(0o700)
    token = tmp_path / "synthetic-token"
    token.write_text("synthetic-agent-token\n")
    config = caller / "client-config"
    package_log = tmp_path / "package.log"
    environment = os.environ | {"PATH": str(tools), "BASH_ENV": "", "CALLER_PACKAGE_LOG": str(package_log),
                                 "CALLER_PYTHON_STATE": python_state, "CALLER_PYTHON": sys.executable,
                                 "CALLER_TOOLS": str(tools)}
    args = SimpleNamespace(docker_data="/home/agent/retained/data", gateway_failures_only=mode == "failures",
                           gateway_lifecycle=mode == "lifecycle")
    if mode == "resume":
        args.gateway_lifecycle_resume = tmp_path / "previous.json"
        args.gateway_lifecycle_resume.write_text(json.dumps({
            "cleanup": "stopped", "registry": {"registry_cleanup": "removed"},
            "reached_step": "gateway-notes-recovered", "lifecycle": {"state": "incomplete"},
            "source_driver": "retained-driver", "driver_sha256": "a" * 64}))
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.running_guest", lambda *_: {})
    steps = []
    native_calls = []

    def native(*arguments):
        native_calls.append(arguments)
        return '{"runtime_state":"stopped"}' if arguments[:2] == ("agent", "status") else ""

    def guest(command, label, **kwargs):
        steps.append(label)
        if label in {"gateway-caller-tools", "gateway-client-config"}:
            assert kwargs["agent"] == "dockercaller"
            command = command.replace("/app/agent_token", shlex.quote(str(token)))
            command = command.replace("/home/agent/docker-gateway-client", str(config))
            return subprocess.check_output(["/bin/bash", "-c", command], env=environment, text=True, stderr=subprocess.PIPE)
        if label == "gateway-version":
            assert json.loads((config / "config.json").read_text()) == {"HttpHeaders": {
                "X-SafeYolo-Docker-Service": "notes", "Authorization": "Bearer synthetic-scoped-token"}}
            assert (config / "config.json").stat().st_mode & 0o777 == 0o600
            raise RuntimeError("caller configured before Engine effects")
        return "403" if label == "gateway-unapproved" else ""

    def background(_agent, _command, label):
        steps.append(label)
        return (SimpleNamespace(poll=lambda: None),)

    failed = python_state.endswith("-failed")
    if failed:
        with pytest.raises(subprocess.CalledProcessError) as error:
            gateway_management(args, tmp_path, output, native, guest, background, {})
        assert error.value.returncode == 73
        assert "gateway-daemon" not in steps and "gateway-client-config" not in steps
        assert not any(call[0] == "services" for call in native_calls)
    else:
        with pytest.raises(RuntimeError, match="caller configured before Engine effects"):
            gateway_management(args, tmp_path, output, native, guest, background, {})
        if python_state == "absent":
            assert steps.index("gateway-caller-tools") < steps.index("gateway-daemon") < steps.index("gateway-client-config")
    packages = package_log.read_text().splitlines() if package_log.exists() else []
    assert packages == ([] if python_state == "installed" else ["-n apt-get update"] +
                        ([] if python_state == "update-failed" else ["-n apt-get install -y --no-install-recommends python3"]))
    assert native_calls[-1] == ("stop",)
    for path, original in originals.items():
        assert path.read_bytes() == original


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
@pytest.mark.parametrize("gateway", [False, True, "application"])
@pytest.mark.parametrize("interruption", ["selection", "staging", "start", "live-owner"])
def test_docker_product_selection_preserves_the_stopped_donor(tmp_path, monkeypatch, linked, gateway, interruption):
    application_resume, gateway = gateway == "application", gateway is True
    prepared = tmp_path / "prepared"
    for part in ("bin", "assets/guest", "share/rootfs-tree", "libexec", "host"):
        (prepared / part).mkdir(parents=True, exist_ok=True)
    for name in ("bin/safeyolo", "bin/safeyolo-proxy", "assets/guest/safeyolo-guest"):
        (prepared / name).write_text("#!/bin/sh\nprintf 'selected commit=revision\\n'\n")
        (prepared / name).chmod(0o755)
    (prepared / "package-info").write_text("selected package\n")
    root = tmp_path / "instance"
    root.mkdir()
    workspace = root / "workspace"
    workspace.mkdir()
    originals = {}
    for name in ("bin", "assets", "share", "host"):
        path = root / name
        retained = root / ("retained-" + name) if linked else path
        retained.mkdir()
        (retained / "sentinel").write_text("original " + name)
        if linked:
            path.symlink_to(retained, target_is_directory=True)
        originals[name] = path.readlink() if linked else None
    pair = root / "versions/retained"
    if linked:
        pair.mkdir(parents=True)
        (pair / "host").symlink_to(root / "retained-host")
        (pair / "share").symlink_to(root / "retained-share")
        (root / "current").symlink_to("versions/retained")
    home = root / "agents/notes/home"
    home.mkdir(parents=True)
    data = home / "docker-data"
    data.write_bytes(b"retained image bytes")
    home_inode, data_inode = home.stat().st_ino, data.stat().st_ino
    (root / "config.toml").write_text("")
    (root / "policy.toml").write_text(f'[agents.notes]\nnested_docker = true\nfolder = "{workspace}"\n')
    original_policy = (root / "policy.toml").read_bytes()
    previous_path = tmp_path / "previous/result.json"
    if application_resume:
        previous_path.parent.mkdir()
        previous_path.write_text(json.dumps({"root": str(root), "status": "incomplete", "step": "privileged-network",
                                            "cleanup": "stopped", "cleanup_failures": [],
                                            "containers": [{"Id": "api"}, {"Id": "store"}], "runtime": {"run_id": "old"}}))
        previous_path.with_name("notes-written.log").write_text('["saved-note"]')
    (root / "services").mkdir()
    calls = []

    def selected_inputs():
        assert (root / "current").resolve().parent == root / "versions"
        assert (root / "current/host").resolve() == prepared
        assert (root / "current/share/rootfs-tree").resolve() == prepared / "share/rootfs-tree"
        for path in (root / "bin/safeyolo-proxy", root / "assets/guest/safeyolo-guest",
                     root / "current/host/assets/guest/safeyolo-guest"):
            assert subprocess.check_output([str(path), "--version"], text=True) == "selected commit=revision\n"
        assert data.read_bytes() == b"retained image bytes" and data.stat().st_ino == data_inode

    def checked(command, **_):
        if command[-1] == "--version":
            return subprocess.check_output(command, text=True)
        calls.append(command[3:])
        if command[3:] == ["start"]:
            selected_inputs()
            if application_resume:
                selected_policy = tomlkit.parse((root / "policy.toml").read_text())
                assert selected_policy["hosts"]["127.0.0.1:12401"]["egress"] == "allow"
                assert selected_policy["hosts"]["127.0.0.1:12402"]["egress"] == "deny"
            raise RuntimeError("start interrupted")
        return '{"runtime_state":"stopped"}' if "status" in command else ""

    def failed_copy(*_):
        selected_inputs()
        if interruption == "staging":
            raise RuntimeError("staging interrupted")

    original_link = Path.symlink_to

    def symlink(path, *arguments, **options):
        if interruption == "selection" and path == root / "assets":
            raise OSError("selection interrupted")
        return original_link(path, *arguments, **options)

    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.checked", checked)
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.shutil.copy2", failed_copy)
    monkeypatch.setattr(Path, "symlink_to", symlink)
    args = SimpleNamespace(prepared_config=prepared, root=root, output=tmp_path / "output", revision="revision",
                           proxy_revision=None, guest_revision=None, reuse_root=True, gateway=gateway,
                           journey=not gateway, nested_docker=True, docker_data="/home/agent/docker-data",
                           application_resume=previous_path if application_resume else None,
                           owned_origins={"PROBE_ALLOWED": "http://127.0.0.1:12401/allowed",
                                          "PROBE_DENIED": "http://127.0.0.1:12402/denied"})
    with subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]) as owner:
        try:
            if interruption == "live-owner":
                (root / "agents/notes/container.pid").write_text(str(owner.pid))
            with pytest.raises((OSError, RuntimeError, AssertionError),
                               match="stop the retained fixture" if interruption == "live-owner" else interruption + " interrupted"):
                run(args)
            assert owner.poll() is None
        finally:
            owner.terminate()
            owner.wait(timeout=5)
    for name, target in originals.items():
        assert (root / name).is_symlink() is linked
        if linked:
            assert (root / name).readlink() == target
        assert (root / name / "sentinel").read_text() == "original " + name
    if linked:
        assert (root / "current").readlink() == Path("versions/retained")
    else:
        assert not (root / "current").exists()
    assert not (root / "libexec").exists() and not (root / "package-info").exists()
    assert not list(root.glob("*-docker-proof-*"))
    assert list((root / "versions").glob("*")) == ([pair] if linked else [])
    assert home.stat().st_ino == home_inode and data.stat().st_ino == data_inode
    assert data.read_bytes() == b"retained image bytes"
    if application_resume:
        assert (root / "policy.toml").read_bytes() == original_policy
    assert ["agent", "stop", "notes"] in calls if interruption == "start" else not any("stop" in call for call in calls)
    result = json.loads((args.output / "result.json").read_text())
    assert result["status"] == "incomplete"
    assert result["cleanup"] == ("stopped" if interruption == "start" else "not-started")


@pytest.mark.parametrize("copy_failure", [False, True])
def test_fresh_image_input_copies_image_directories_before_start(tmp_path, monkeypatch, copy_failure):
    prepared, root, source = (tmp_path / name for name in ("prepared", "fresh", "images"))
    for name in ("bin", "assets/guest", "share/rootfs-tree"):
        (prepared / name).mkdir(parents=True)
    for name in ("bin/safeyolo", "bin/safeyolo-proxy", "assets/guest/safeyolo-guest"):
        (prepared / name).write_text("selected bytes")
    (prepared / "config.toml").write_text("[linux]\n")
    for name in ("image/vfs", "vfs/dir/layer"):
        (source / name).mkdir(parents=True)
        (source / name / "sentinel").write_text(name)
    (source / "vfs/dir/layer/guest-link").symlink_to("/missing-guest-path")
    os.link(source / "vfs/dir/layer/sentinel", source / "vfs/dir/layer/hard-link")
    # These are never part of a qualified image input or selected for copying.
    for name in ("containers", "volumes", "network"):
        (source / name).mkdir()
        (source / name / "excluded").write_text("unrelated state")
    (source / "key.pem").write_text("excluded daemon credential")
    calls = []

    def prepare(_base, destination):
        (destination / "data").mkdir(parents=True)
        (destination / "services").mkdir()
        (destination / "config.toml").write_text("[linux]\n")

    def checked(command, **_):
        if command[0] == "sudo":
            assert command[:6] == ["sudo", "-n", "rsync", "-aHAX", "--numeric-ids", "--"]
            if copy_failure:
                subprocess.run(["rsync", "-aHAX", "--numeric-ids", "--", str(source / "image"), command[-1]], check=True)
                raise OSError("copy interrupted")
            subprocess.run(command[2:], check=True)
            return ""
        if command[-1] == "--version":
            return "commit=revision"
        arguments = command[3:]
        calls.append(arguments)
        if arguments == ["start"]:
            target = root / "agents/notes/home/docker-image-data"
            assert (target / "image/vfs/sentinel").read_text() == "image/vfs"
            assert (target / "vfs/dir/layer/guest-link").readlink() == Path("/missing-guest-path")
            assert (target / "vfs/dir/layer/sentinel").stat().st_ino == (target / "vfs/dir/layer/hard-link").stat().st_ino
            assert set(target.iterdir()) == {target / "image", target / "vfs"}
            raise RuntimeError("start interrupted")
        return ""

    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.prepare_native_instance", prepare)
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.copy_prepared_nats", lambda *_: None)
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.checked", checked)
    args = SimpleNamespace(prepared_config=prepared, root=root, output=tmp_path / "output", revision="revision",
                           proxy_revision=None, guest_revision=None, reuse_root=False, gateway=False,
                           journey=True, nested_docker=True, docker_data=None, docker_image_data=source, admin_port=12345)
    with pytest.raises((OSError, RuntimeError), match="copy interrupted" if copy_failure else "start interrupted"):
        run(args)
    assert (source / "vfs/dir/layer/sentinel").read_text() == "vfs/dir/layer"
    assert (source / "vfs/dir/layer/guest-link").is_symlink()
    assert (source / "containers/excluded").read_text() == "unrelated state"
    result = json.loads((args.output / "result.json").read_text())
    assert result["initial_reused_image"] is True and result["image_data_source"] == str(source)
    assert result["status"] == "incomplete"
    if copy_failure:
        assert ["start"] not in calls and not any("stop" in call for call in calls)
        assert result["cleanup"] == "not-started"
    else:
        assert args.docker_data == "/home/agent/docker-image-data"
        assert ["agent", "stop", "notes"] in calls and result["cleanup"] == "stopped"


@pytest.mark.parametrize("prepared_image,reused_root", [(False, False), (True, False), (False, True)])
def test_compose_journey_inspects_the_pin_after_optional_public_pull(tmp_path, monkeypatch, prepared_image, reused_root):
    workspace, output = tmp_path / "workspace", tmp_path / "output"
    workspace.mkdir()
    output.mkdir()
    steps = []
    pin = (PROBE.parent / "Dockerfile").read_text().splitlines()[0].split()[1]

    # The token carrier has its own file/command controls below. This caller
    # check observes which input path selects it without performing networking.
    @contextmanager
    def token_input(actual_workspace, *_):
        assert actual_workspace == workspace and not prepared_image and not reused_root
        steps.append("private-token")
        yield

    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.public_pull_token", token_input)

    def native(*arguments, instance=None):
        if arguments[:2] == ("approvals", "list"):
            assert not reused_root
            return '{"approvals":[]}'
        assert arguments == ("init",)
        for name, mode in {"certs/mitmproxy-ca-cert.pem": 0o644, "certs/mitmproxy-ca.pem": 0o600,
                           "data/admin_token": 0o600, "data/agent_token": 0o600}.items():
            path = instance / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture bytes")
            path.chmod(mode)

    def guest(command, label, **_):
        steps.append(label)
        if label == "fresh-ca-reader":
            return hashlib.sha256(b"fixture bytes").hexdigest()
        if label == "image-pull":
            assert command.startswith("sudo -n env DOCKER_BUILDKIT=0 DOCKER_CONFIG=/home/agent/docker-journey/client "
                                      "docker --host=unix:///run/safeyolo-nested-docker/docker.sock pull ")
            assert command.endswith(" pull " + pin)
        if label == "image-identity":
            assert command.endswith(" image inspect " + pin)
            return '[{"Id":"qualified-image"}]'
        if label == "image-denied":
            raise RuntimeError("end of setup control")
        return ""

    args = SimpleNamespace(docker_data="/home/agent/docker-image-data" if prepared_image else None, reuse_root=reused_root)
    report = {}
    with pytest.raises(RuntimeError, match="end of setup control"):
        compose_journey(args, tmp_path / "root", output, workspace, native, guest, registry_background, report)
    assert ("image-pull" in steps) is not prepared_image
    assert ("private-token" in steps) is (not prepared_image and not reused_root)
    assert report["base_image"] == [{"Id": "qualified-image"}]
    assert report["reused_image_data"] == args.docker_data


@pytest.mark.parametrize("failure", [None, "challenge", "issuer", "scope", "token", "fetch", "install", "pull"])
def test_public_pull_token_is_private_stable_and_removed(tmp_path, failure):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    installed = tmp_path / "guest-client/config.json"
    token = "private-anonymous-read-token"
    report, calls, pulled = {}, [], []
    pin = (PROBE.parent / "Dockerfile").read_text().splitlines()[0].split()[1]

    def guest(command, label):
        calls.append((label, command))
        assert token not in command
        private = next(workspace.glob(".docker-pull-*"))
        assert private.stat().st_mode & 0o777 == 0o700
        shared = "/workspace/" + private.name
        if label == "registry-token-challenge":
            assert "/v2/library/debian/manifests/" + pin.split("@")[1] in command
            assert f"--dump-header {shared}/challenge --output /dev/null" in command
            realm = "https://other.invalid/token" if failure == "issuer" else "https://auth.docker.io/token"
            scope = "repository:library/debian:pull,push" if failure == "scope" else "repository:library/debian:pull"
            (private / "challenge").write_text('HTTP/1.1 200 Connection established\n\nHTTP/2 401\n'
                                               f'WWW-Authenticate: Bearer realm="{realm}",'
                                               f'service="registry.docker.io",scope="{scope}"\n\n')
            return "403" if failure == "challenge" else "401"
        if label == "registry-token-fetch":
            assert "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fdebian%3Apull" in command
            assert f"--output {shared}/response.json" in command and "--fail" in command
            if failure == "fetch":
                raise GuestStepFailed(label, 22)
            (private / "response.json").write_text(json.dumps({"token": None if failure == "token" else token}))
        elif label == "registry-token-install":
            source = private / "config.json"
            assert source.stat().st_mode & 0o777 == 0o600
            assert not (private / "response.json").exists()
            assert f"install -m 0600 {shared}/config.json /home/agent/docker-journey/client/config.json" in command
            if failure == "install":
                raise GuestStepFailed(label, 1)
            installed.parent.mkdir(mode=0o700)
            shutil.copy2(source, installed)
        else:
            assert label == "registry-token-remove"
            assert command == "sudo -n rm -f -- /home/agent/docker-journey/client/config.json"
            installed.unlink(missing_ok=True)
        return ""

    def docker(command, label):
        assert command.endswith(" version --format '{{json .}}'") and label == "registry-token-version"
        return '{"Client":{"Version":"26.1.5+dfsg1"},"Server":{"Version":"26.1.5+dfsg1"}}'

    def consume():
        with public_pull_token(workspace, guest, docker, report, pin):
            assert not list(workspace.glob(".docker-pull-*/config.json"))
            for _ in range(2):
                pulled.append(json.loads(installed.read_text())["auths"]["https://index.docker.io/v1/"]["registrytoken"])
                if failure == "pull":
                    raise GuestStepFailed("image-pull-authorized", 1)

    if failure is None:
        consume()
        assert pulled == [token, token]
    else:
        with pytest.raises((AssertionError, GuestStepFailed)):
            consume()
    assert not installed.exists() and not list(workspace.iterdir())
    assert report["public_pull_token"]["removed"] is True
    assert token not in json.dumps(report) and token not in str(calls)
    assert len([label for label, _ in calls if label == "registry-token-fetch"]) == (
        0 if failure in {"challenge", "issuer", "scope"} else 1)


def test_public_pull_token_reaches_docker_cli_carrier(tmp_path):
    """A real Docker CLI must forward the file's same bearer on both pulls."""
    if not shutil.which("docker"):
        pytest.skip("Docker CLI is required for the RegistryToken consumer control")
    workspace, state = tmp_path / "workspace", tmp_path / "state"
    workspace.mkdir()
    received = []
    token = "private-fixture-registry-token"

    class Engine(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Do not record the Docker API's authorization headers.

        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Api-Version", "1.45")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            body = b'{"ApiVersion":"1.45","Version":"26.1.5","Os":"linux","Arch":"arm64"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            assert self.path.startswith("/v1.45/images/create?")
            received.append(json.loads(base64.urlsafe_b64decode(self.headers["X-Registry-Auth"])))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "0")
            self.end_headers()

    socket = tmp_path / "docker.sock"
    server = ThreadingUnixStreamServer(str(socket), Engine)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def guest(command, label):
        private = next(workspace.glob(".docker-pull-*"))
        if label == "registry-token-challenge":
            (private / "challenge").write_text('WWW-Authenticate: Bearer realm="https://auth.docker.io/token",'
                                               'service="registry.docker.io",scope="repository:library/debian:pull"\n')
            return "401"
        if label == "registry-token-fetch":
            (private / "response.json").write_text(json.dumps({"token": token}))
            return ""
        # Execute the actual install/remove commands with paths mapped to this
        # owned host fixture. Guest sudo itself is outside this consumer check.
        command = command.replace("/workspace", str(workspace)).replace("/home/agent/docker-journey", str(state))
        return subprocess.check_output(["bash", "-ec", command.replace("sudo -n ", "")], text=True)

    def docker(command, _label):
        command = command.replace("unix:///run/safeyolo-nested-docker/docker.sock", "unix://" + str(socket))
        env = {**os.environ, "DOCKER_CONFIG": str(state / "client"), "DOCKER_BUILDKIT": "0"}
        return subprocess.check_output(shlex.split(command), env=env, text=True)

    report = {}
    pin = (PROBE.parent / "Dockerfile").read_text().splitlines()[0].split()[1]
    try:
        with public_pull_token(workspace, guest, docker, report, pin):
            for _ in range(2):
                docker(f"docker --host=unix://{socket} pull {pin}", "pull")
        assert len(received) == 2 and all(row["registrytoken"] == token for row in received)
        assert report["public_pull_token"]["docker_version"]["Client"]["Version"]
        assert not (state / "client/config.json").exists() and not list(workspace.iterdir())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("failure", [None, "success", "transport", "non-428", "no-event", "old-event", "two-events",
                                     "network", "registry", "agent", "run", "fingerprints", "unavailable", "not-pending",
                                     "method", "port", "changed-event", "changed-run", "lost-decision", "inactive",
                                     "wrong-grant", "baseline", "retry-refused"])
def test_public_pull_consumes_only_one_current_run_approval(tmp_path, failure):
    root, output = tmp_path / "root", tmp_path / "output"
    (root / "agents/notes").mkdir(parents=True)
    output.mkdir()
    policy = root / "policy.toml"
    policy.write_text('[credential]\nunknown = "prompt"\n')
    run = {"agent": "notes", "agent_id": "ag-owned", "run_id": "current-run"}
    runtime = {"name": "notes", "agent_id": run["agent_id"], "run_id": run["run_id"],
               "backend_pid": os.getpid(), "backend_token": _process_start_token(os.getpid())}
    (root / "agents/notes/runtime.json").write_text(json.dumps(runtime))
    status = {**runtime, "runtime_state": "running"}
    action = {"kind": "credential_allow", "agent": "notes", "agent_id": run["agent_id"], "run": run,
              "host": "registry-1.docker.io", "credentials": ["hmac:actual-event"]}
    if failure in {"network", "registry", "agent", "run", "fingerprints"}:
        key, value = {"network": ("kind", "network_allow"), "registry": ("host", "other.invalid"),
                      "agent": ("agent_id", "ag-peer"), "run": ("run", {**run, "run_id": "stopped-run"}),
                      "fingerprints": ("credentials", [])}[failure]
        action[key] = value
    canonical = {"approval_id": "apr-owned", "request_id": "req-pull", "status": "pending", "action": action,
                 "authority": {"action": action, "scheme": "https", "port": 443, "method": "GET"},
                 "options": [{"id": "persistent", "status": "available"}, {"id": "run", "status": "available"}]}
    if failure == "unavailable":
        canonical["options"][1]["status"] = "superseded"
    if failure == "not-pending":
        canonical["status"] = "rejected"
    if failure == "method":
        canonical["authority"]["method"] = "POST"
    if failure == "port":
        canonical["authority"]["port"] = 80
    granted = {**deepcopy(canonical), "status": "approved", "option": "run", "grant_active": True,
               "result": {"lifetime": "worker_run", "issued_access": {
                   "approval_id": "apr-owned", "beneficiary": run, "action": action, "option": "run"}}}
    calls, attempts = [], []
    report = {"runtime": runtime}
    pin = (PROBE.parent / "Dockerfile").read_text().splitlines()[0].split()[1]

    def native(*arguments):
        calls.append(arguments)
        if arguments[:2] == ("approvals", "list"):
            assert arguments == ("approvals", "list", "--agent", "notes", "--json")
            first = len([call for call in calls if call[:2] == ("approvals", "list")]) == 1
            rows = [] if first or failure == "no-event" else [canonical]
            if failure == "old-event":
                rows = [canonical]
            if not first and failure == "two-events":
                rows = [canonical, {**canonical, "approval_id": "apr-another"}]
            return json.dumps({"approvals": rows})
        if arguments == ("agent", "status", "notes"):
            if failure == "changed-run" and any(call[:2] == ("approvals", "approve") for call in calls):
                status["run_id"] = "replacement-run"
                (root / "agents/notes/runtime.json").write_text(json.dumps({**runtime, "run_id": status["run_id"]}))
            return json.dumps(status)
        if arguments[:2] == ("approvals", "approve"):
            assert arguments == ("approvals", "approve", "apr-owned", "--option", "run", "--agent", "notes", "--json")
            if failure == "baseline":
                policy.write_text('[credential]\nunknown = "allow"\n')
            if failure == "lost-decision":
                raise RuntimeError("decision reply lost")
            return json.dumps(granted)
        assert arguments == ("approvals", "show", "apr-owned", "--agent", "notes", "--json")
        decided = any(call[:2] == ("approvals", "approve") for call in calls)
        view = deepcopy(granted if decided else canonical)
        if failure == "changed-event" and not decided:
            view["request_id"] = "req-different"
        if decided and failure == "inactive":
            view["grant_active"] = False
        if decided and failure == "wrong-grant":
            view["result"]["issued_access"]["action"]["credentials"] = ["hmac:uninspected"]
        return json.dumps(view)

    def docker(command, label, *, timeout):
        attempts.append(label)
        assert command == f"docker --host=unix:///run/safeyolo-nested-docker/docker.sock pull {pin}" and timeout == 180
        if failure == "transport":
            raise subprocess.TimeoutExpired(command, timeout)
        if label == "image-pull" and failure != "success":
            (output / "image-pull.log").write_text("ordinary failure" if failure == "non-428" else "unexpected status: 428")
            raise GuestStepFailed(label, 1)
        if failure == "retry-refused":
            raise GuestStepFailed(label, 1)
        return "image pulled"

    if failure in {None, "success"}:
        pull_public_image(root, output, native, docker, report, pin)
    else:
        with pytest.raises((AssertionError, RuntimeError, subprocess.TimeoutExpired)):
            pull_public_image(root, output, native, docker, report, pin)
    observed = json.loads((output / "result.json").read_text())["public_pull"]
    approvals = [call for call in calls if call[:2] == ("approvals", "approve")]
    decision_cases = {None, "lost-decision", "inactive", "wrong-grant", "baseline", "changed-run", "retry-refused"}
    assert len(approvals) == (1 if failure in decision_cases else 0)
    assert attempts == (["image-pull", "image-pull-authorized"] if failure in {None, "retry-refused"} else ["image-pull"])
    if failure in decision_cases:
        assert observed["pending"]["approval_id"] == "apr-owned" and observed["initial_exit"] == 1
        assert observed["effective"]["status"] == "approved"
    if failure == "lost-decision":
        assert "decision" not in observed and "effective" in observed
    if failure is None:
        assert observed["authorized_exit"] == 0 and policy.read_text() == '[credential]\nunknown = "prompt"\n'
    if failure == "success":
        assert observed["initial_exit"] == 0 and "pending" not in observed


@pytest.mark.parametrize("failure", [None, "caller-stop", "caller-running", "caller-status", "worker"])
def test_provider_completion_stops_caller_before_gateway_configuration(tmp_path, monkeypatch, failure):
    output = tmp_path / "output"
    output.mkdir()
    config = tmp_path / "config.toml"
    config.write_text('parent_proxy = "http://retained-proxy"\n')
    original = config.read_bytes()
    service = tmp_path / "services/notes.yaml"
    service.parent.mkdir()
    service.write_text("retained application service\n")
    (tmp_path / "policy.toml").write_text("")
    calls, report = [], {}
    caller_state, provider_finished = "running", False

    def native(*arguments):
        nonlocal caller_state
        calls.append(arguments)
        if arguments == ("agent", "stop", "dockercaller"):
            if failure == "caller-stop":
                raise RuntimeError("caller stop failed")
            if failure != "caller-running":
                caller_state = "stopped"
        if arguments == ("agent", "status", "dockercaller"):
            if provider_finished and failure == "caller-status":
                raise RuntimeError("caller status failed")
            return json.dumps({"runtime_state": caller_state})
        if provider_finished and arguments == ("stop",):
            raise RuntimeError("gateway configuration reached")
        return ""

    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.running_guest", lambda *_: {"agent_id": "caller"})
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.wait_file", lambda *_: None)
    clients = {name: {"status": status, "body_sha256": "same-body"}
               for name, status in [("method", 403), ("path", 403), ("destination", 403), ("port", 403),
                                    ("allowed", 200), ("revoked", 403), ("recovered", 200), ("closed", 502), ("stopped", 502)]}
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.client_observation", lambda *_: clients)
    requests = [{"role": "api", "method": "GET", "path": "/api/v1/notes", "caller_ids": ids,
                 "caller_names": ["dockercaller"] if ids else [], "authorization_count": 0, "legacy_identity_count": 0}
                for ids in ([], ["caller"], ["caller"])]
    worker = SimpleNamespace(wait=lambda **_: 1 if failure == "worker" else 0)

    def provider():
        provider_controls(tmp_path, output, native, lambda *_args, **_kwargs: "403",
                          lambda *_: (worker,), lambda *_: "\n".join(map(json.dumps, requests)), report)

    if failure in {"caller-stop", "worker"}:
        with pytest.raises(RuntimeError if failure == "caller-stop" else AssertionError):
            provider()
        assert config.read_bytes() == original
        assert (("agent", "stop", "dockercaller") in calls) == (failure == "caller-stop")
        return
    provider()
    provider_finished = True
    assert config.read_bytes() == original and report["parent_fallback_accepts"] == 0 and report["parent_control_accepts"] == 1
    native("agent", "start", "notes", "--sandbox-only")
    gateway_start = len(calls)
    with pytest.raises(AssertionError if failure == "caller-running" else RuntimeError,
                       match={None: "gateway configuration reached", "caller-running": "stop dockercaller",
                              "caller-status": "caller status failed"}[failure]):
        gateway_management(SimpleNamespace(docker_data="/home/agent/retained/data"), tmp_path, output,
                           native, lambda *_: pytest.fail("unexpected gateway guest command"), None, report)
    assert calls.index(("agent", "stop", "dockercaller")) < calls.index(("agent", "start", "notes", "--sandbox-only"))
    if failure == "caller-status":
        assert "gateway_caller_status" not in report
    else:
        assert json.loads((output / "result.json").read_text())["gateway_caller_status"] == {"runtime_state": caller_state}
    if failure:
        assert calls[gateway_start:] == [("agent", "status", "dockercaller")]
    assert service.read_text() == "retained application service\n"


@pytest.mark.parametrize("with_receipt", [False, True])
@pytest.mark.parametrize("failure", [None, "reader-positive", "adjacent-effect", "revoked-http", "revoked-effect",
                                    "blank-diagnostic", "refresh", "stopped-403"])
def test_gateway_management_checks_scoped_effects_without_a_recurring_receipt(tmp_path, monkeypatch, with_receipt, failure):
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
    steps, native_calls, checkpoints = [], [], []
    report = {}
    token_generation, client_token_generation = 0, None

    def native(*arguments):
        nonlocal token_generation
        native_calls.append(arguments)
        if arguments == ("agent", "stop", "notes"):
            # Native stop removes the listener through a full proxy reload.
            token_generation += 1
        return '{"runtime_state":"stopped"}' if arguments[:2] == ("agent", "status") else ""

    def guest(command, label, **kwargs):
        nonlocal client_token_generation
        steps.append(label)
        if "http://_safeyolo.proxy.internal/gateway/services" in command:
            assert kwargs.get("agent") == "dockercaller"
            if token_generation and failure == "refresh":
                raise RuntimeError("gateway token refresh failed")
            client_token_generation = token_generation
        if label in {"gateway-adjacent-host-inspect", "gateway-revoked-host-inspect", "gateway-removed-host-inspect"}:
            assert kwargs.get("agent", "notes") == "notes", "effect read must bypass the scoped caller"
        if label == "gateway-adjacent-host-inspect":
            return json.dumps([] if failure == "adjacent-effect" else [{"Id": "owned-id", "Name": "/" + report["gateway_container"]}])
        if label == "gateway-revoked-host-inspect":
            return json.dumps([{"Id": "changed" if failure == "revoked-effect" else "owned-id"}])
        if label in {"gateway-adjacent-delete", "gateway-revoked-delete", "gateway-daemon-failed", "gateway-closed", "gateway-stopped"}:
            status = {"gateway-adjacent-delete": 200, "gateway-revoked-delete": 403}.get(label, 503)
            if label == "gateway-stopped" and (client_token_generation != token_generation or failure == "stopped-403"):
                return json.dumps({"exit": 1, "stderr": "Error response from daemon: INVALID_TOKEN\n",
                                   "http": {"status": 403, "body": '{"error":"INVALID_TOKEN"}'}})
            if failure == "reader-positive" and label == "gateway-adjacent-delete":
                status = 403
            if failure == "revoked-http" and label == "gateway-revoked-delete":
                status = 200
            if label == "gateway-revoked-delete":
                assert native_calls[-1] == ("services", "revoke", "dockercaller", "notes")
                assert "gateway-engine-client-config" not in steps
            return json.dumps({"exit": 1, "stderr": "" if failure == "blank-diagnostic" else "scope refused or provider unavailable",
                               "http": {"status": status, "body": "controlled reply"}})
        return {"gateway-unapproved": "403", "gateway-inspect": "true", "gateway-exec": "exec-half-close\n",
                "gateway-attach": "internal:attach-half-close\n"}.get(label, "")

    def background(*_):
        return (SimpleNamespace(poll=lambda: None, wait=lambda **_: 0),)

    receipt = SimpleNamespace(checkpoint=lambda name, **_: checkpoints.append(name)) if with_receipt else None
    args = SimpleNamespace(docker_data="/home/agent/retained/data")
    if failure:
        with pytest.raises(RuntimeError if failure == "refresh" else AssertionError):
            gateway_management(args, tmp_path, output, native, guest, background, report, receipt)
        assert "gateway_result" not in report
        assert ("gateway-remove" in steps) is (failure in {"refresh", "stopped-403"})
        if failure == "refresh":
            assert "gateway-stopped" not in steps
        if failure == "stopped-403":
            assert json.loads((output / "gateway-stopped.json").read_text())["http"]["status"] == 403
    else:
        gateway_management(args, tmp_path, output, native, guest, background, report, receipt)
        assert report["gateway_adjacent"]["container_id"] == report["gateway_revoked"]["container_id"] == "owned-id"
        assert report["gateway_revoked"]["client"]["http"]["status"] == 403
        assert steps.index("gateway-adjacent-host-inspect") < steps.index("gateway-revoked-delete")
        assert steps.index("gateway-revoked-host-inspect") < steps.index("gateway-engine-client-config") < steps.index("gateway-remove")
        assert list(report["gateway_failures"]) == ["gateway-daemon-failed", "gateway-closed", "gateway-stopped"]
        assert checkpoints == (["gateway-effects", "gateway-revocation", "gateway-failures"] if with_receipt else [])
    assert steps.count("gateway-create") == steps.count("gateway-exec") == steps.count("gateway-attach") == 1
    assert native_calls[-1] == ("stop",)
    for path, original in originals.items():
        assert path.read_bytes() == original


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
    old_events = deepcopy(events)
    for row in old_events:
        row["request_id"] = "old-" + row["request_id"]
        if row["event"] == "security.network_guard.evaluated":
            row["details"]["sandbox_run"]["run_id"] = "stopped"
    report["resumed_application"] = {"runtime": {"agent_id": "ag-host", "run_id": "stopped"}}
    verify_outbound([stopped, *old_events, *events], report, reused_image=True)
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
