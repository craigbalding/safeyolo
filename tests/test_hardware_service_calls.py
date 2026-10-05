"""Service-boundary controls with local HTTP and subprocess fixtures."""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tests.blackbox.hardware import attempt_results, service_calls


@pytest.fixture
def rundeck_fixture(tmp_path):
    state = {"calls": [], "execution": 17, "completed": True, "status": "SUCCEEDED", "pages": {}}

    class Response(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # Local fixture requests are checked below; do not print authentication headers.

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["calls"].append((self.path, self.command, body))
            assert self.headers["X-Rundeck-Auth-Token"] == "fixture-principal"
            assert "fixture-principal" not in json.dumps(body)
            self.reply({"execution": {"id": state["execution"]}})

        def do_GET(self):
            state["calls"].append((self.path, self.command, None))
            assert self.headers["X-Rundeck-Auth-Token"] == "fixture-principal"
            if self.path.endswith("/state"):
                self.reply({"executionId": state["execution"], "completed": state["completed"], "executionState": state["status"]})
            elif self.path.endswith("/abort"):
                self.reply({"execution": {"id": state["execution"]}, "abort": {"status": "pending"}})
            else:
                offset = int(self.path.split("offset=", 1)[1].split("&")[0])
                self.reply(state["pages"][offset])

        def reply(self, data):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Response)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    principal = tmp_path / "rundeck-principal"
    principal.write_text("fixture-principal")
    client = service_calls.Rundeck(f"http://127.0.0.1:{server.server_port}", principal)
    try:
        yield client, state
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_actual_script_api_records_identity_and_status_without_product_acceptance(rundeck_fixture, tmp_path):
    client, state = rundeck_fixture
    invocation = client.submit("bash /var/lib/rundeck/harness/jobs/list_guests.sh\n")
    assert invocation == 17
    assert state["calls"][0] == ("/api/59/project/acceptance/run/script", "POST", {
        "project": "acceptance", "scriptInterpreter": "/bin/bash", "script": "bash /var/lib/rundeck/harness/jobs/list_guests.sh\n",
    })
    assert client.wait(invocation, 2) == {"executionId": 17, "completed": True, "executionState": "SUCCEEDED"}
    attempt = attempt_results.HardwareAttempt(tmp_path / "attempts", "a" * 40, "overnight")
    attempt.finish()
    assert attempt.execution_succeeded() is False, "a successful API script is not a paired hardware result"
    state["execution"] = 18
    with pytest.raises(ValueError):
        client.state(17)


def test_pending_abort_and_lost_execution_do_not_establish_cleanup(rundeck_fixture):
    client, state = rundeck_fixture
    state.update(completed=False, status="RUNNING")
    with pytest.raises(TimeoutError):
        client.wait(17, 1)
    assert client.abort(17) == "pending"
    assert client.state(17)["completed"] is False
    state.update(completed=True, status="RUNNING")
    with pytest.raises(ValueError):
        client.wait(17, 1)


def test_bounded_private_output_requires_complete_matching_pages(rundeck_fixture, tmp_path):
    client, state = rundeck_fixture
    state["pages"] = {
        0: {"id": 17, "completed": False, "execCompleted": True, "offset": 80, "entries": [{"log": "private line one"}]},
        80: {"id": 17, "completed": True, "execCompleted": True, "offset": 100, "entries": [{"log": "private line two"}]},
    }
    target = tmp_path / "private-output"
    client.output(17, target)
    assert target.read_text() == "private line one\nprivate line two\n"
    with pytest.raises(FileExistsError):
        client.output(17, target)
    state["pages"][0].update(offset=0, execCompleted=False)
    with pytest.raises(ValueError):
        client.output(17, tmp_path / "unfinished")
    state["pages"][0].update(id=99)
    with pytest.raises(ValueError):
        client.output(17, tmp_path / "mismatched")


def test_tart_uses_existing_client_and_reads_its_canonical_response(tmp_path):
    mailbox = tmp_path / "operator-mailbox"
    responses = mailbox / "responses"
    responses.mkdir(parents=True)
    job = "c" * 32
    canonical = {"exit_code": 7, "timed_out": False, "stdout": "failed selected build", "stderr": "private build diagnostic"}
    (responses / f"{job}.json").write_text(json.dumps(canonical))
    client = tmp_path / "existing-tart-client"
    client.write_text(f"#!{sys.executable}\nimport sys\n"
                      "assert sys.argv[1:3] == ['--timeout', '10']\n"
                      f"print('tart job={job}')\nprint('tart exit=0; apparent success')\n")
    client.chmod(0o755)
    script = tmp_path / "build-command"
    script.write_text("selected command fixture")
    response = service_calls.tart_command(client, mailbox, script, 10)
    assert response == {"job_id": job, **canonical}
    (responses / f"{job}.json").write_text(json.dumps(dict(canonical, timed_out="false")))
    with pytest.raises(ValueError):
        service_calls.tart_command(client, mailbox, script, 10)


def test_bristol_uses_stdin_and_preserves_failed_transport(tmp_path, monkeypatch):
    executable = tmp_path / "ssh"
    executable.write_text(f"#!{sys.executable}\nimport sys\n"
                          "assert sys.argv[1] == '-F'\n"
                          "assert sys.argv[3:6] == ['-o', 'BatchMode=yes', 'seatbelt-mac']\n"
                          "assert sys.stdin.buffer.read() == b'verified transfer fixture'\n"
                          "raise SystemExit(7)\n")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    payload = tmp_path / "payload"
    payload.write_bytes(b"verified transfer fixture")
    with payload.open("rb") as source, (tmp_path / "private-output").open("wb") as output:
        assert service_calls.bristol_command(Path("/operator/ssh-config"), "trusted stdin receiver", source, output, 5) == 7
    with pytest.raises(ValueError):
        service_calls.bristol_command(Path("/operator/ssh-config"), "trusted stdin receiver", None, None, 0)


def test_initial_publication_failure_prevents_candidate_and_preserves_attempt(tmp_path):
    from tests.blackbox.hardware import publish_results

    class UnavailableGitHub(publish_results.GitHubResults):
        def api(self, endpoint, method="GET", body=None):
            raise subprocess.CalledProcessError(7, ["gh", "api"])

    github = UnavailableGitHub()
    with pytest.raises(subprocess.CalledProcessError):
        with publish_results.managed_attempt(tmp_path / "attempts", "a" * 40, "overnight", github):
            pytest.fail("publication admission failure must prevent candidate work")
    records = list((tmp_path / "attempts").glob("*/attempt.json"))
    assert len(records) == 1
    recorded = attempt_results.read_json(records[0])
    assert recorded["finished_at"] and recorded["publication"]["verified"] is False
    assert {"stage": "publication", "lane": None} in recorded["failures"]
