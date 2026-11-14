"""Exercise blackbox GitHub request spelling through an executable gh stand-in."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

import pytest

from scripts import claude_blackbox_events as events
from scripts import select_blackbox_artifacts as selector
from tools.assurance import notify_blackbox as notices


@pytest.fixture
def gh_command(tmp_path, monkeypatch):
    command = tmp_path / "gh"
    command.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''\
        import json, os, pathlib, sys
        pathlib.Path(os.environ["BLACKBOX_GH_REQUEST"]).write_text(json.dumps({
            "args": sys.argv[1:],
            "input": sys.stdin.read() if "--input" in sys.argv else None,
        }))
        sys.stdout.buffer.write(bytes.fromhex(os.environ["BLACKBOX_GH_RESPONSE"]))
        if os.environ.get("BLACKBOX_GH_FAILURE"):
            sys.stderr.write("controlled gh failure\\n")
            sys.exit(23)
    '''))
    command.chmod(0o700)
    request = tmp_path / "request.json"
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    monkeypatch.setenv("BLACKBOX_GH_REQUEST", str(request))
    monkeypatch.setenv("BLACKBOX_GH_RESPONSE", b'{"default_branch":"master"}'.hex())
    return request


@pytest.mark.parametrize(("endpoint", "path"), [
    ("", "repos/craigbalding/safeyolo"),
    ("actions/runs/42", "repos/craigbalding/safeyolo/actions/runs/42"),
    ("actions/runs?status=completed&branch=master", "repos/craigbalding/safeyolo/actions/runs?status=completed&branch=master"),
])
def test_event_api_repository_and_resource_requests(gh_command, endpoint, path):
    assert events.GitHub(None).api(endpoint) == {"default_branch": "master"}
    assert json.loads(gh_command.read_bytes()) == {"args": ["api", path], "input": None}


def test_event_api_post_keeps_json_stdin_and_empty_response(gh_command, monkeypatch):
    monkeypatch.setenv("BLACKBOX_GH_RESPONSE", "")
    payload = {"ref": "master", "inputs": {"packages_only": "true"}}
    assert events.GitHub(None).api("actions/workflows/proxy-rust.yml/dispatches", payload) is None
    request = json.loads(gh_command.read_bytes())
    assert request["args"] == ["api", "repos/craigbalding/safeyolo/actions/workflows/proxy-rust.yml/dispatches",
                               "--method", "POST", "--input", "-"]
    assert json.loads(request["input"]) == payload


def test_event_api_raw_response_keeps_original_bytes(gh_command, monkeypatch):
    data = b"PK\x00\xff\n"
    monkeypatch.setenv("BLACKBOX_GH_RESPONSE", data.hex())
    assert events.GitHub(None).api("actions/artifacts/99/zip", raw=True) == data
    assert json.loads(gh_command.read_bytes()) == {
        "args": ["api", "repos/craigbalding/safeyolo/actions/artifacts/99/zip"], "input": None,
    }


@pytest.mark.parametrize("paginated", [False, True])
@pytest.mark.parametrize(("endpoint", "path"), [
    ("", "repos/craigbalding/safeyolo"),
    ("actions/runs/42/jobs", "repos/craigbalding/safeyolo/actions/runs/42/jobs"),
    ("actions/runs?status=completed&branch=master", "repos/craigbalding/safeyolo/actions/runs?status=completed&branch=master"),
])
def test_selector_repository_and_resource_requests(gh_command, monkeypatch, paginated, endpoint, path):
    if paginated:
        monkeypatch.setenv("BLACKBOX_GH_RESPONSE", b'[{"jobs":[{"id":1}]},{"jobs":[{"id":2}]}]'.hex())
        assert selector.pages(endpoint, "jobs") == [{"id": 1}, {"id": 2}]
        expected = ["api", "--paginate", "--slurp", path]
    else:
        assert selector.gh(endpoint) == {"default_branch": "master"}
        expected = ["api", path]
    assert json.loads(gh_command.read_bytes()) == {"args": expected, "input": None}


@pytest.mark.parametrize("caller", ["event", "selector", "selector-pages"])
def test_github_command_failure_propagates(gh_command, monkeypatch, caller, tmp_path):
    monkeypatch.setenv("BLACKBOX_GH_FAILURE", "1")
    with (tmp_path / "private.log").open("wb") as log:
        with pytest.raises(subprocess.CalledProcessError) as failure:
            if caller == "event":
                events.GitHub(log).api("")
            elif caller == "selector":
                selector.gh("")
            else:
                selector.pages("", "jobs")
    assert failure.value.returncode == 23
    assert gh_command.is_file()
    if caller == "event":
        assert (tmp_path / "private.log").read_text() == "controlled gh failure\n"


@pytest.mark.parametrize("payload", [None, {"body": "one notice"}])
def test_notice_api_reads_included_headers_without_changing_json_input(gh_command, monkeypatch, payload):
    response = 'HTTP/2.0 201 Created\r\nX-Github-Request-Id: A:B:123\r\n\r\n{"id":42}\n'
    monkeypatch.setenv("BLACKBOX_GH_RESPONSE", response.encode().hex())
    assert notices.api("issues/123/comments", payload) == {"id": 42}
    command = ["api", "--include", "repos/craigbalding/safeyolo/issues/123/comments"]
    if payload is not None:
        command.extend(["--method", "POST", "--input", "-"])
    request = json.loads(gh_command.read_bytes())
    assert request["args"] == command
    assert (json.loads(request["input"]) if payload is not None else request["input"]) == payload


def test_notice_main_retains_only_bounded_api_failure_fields(gh_command, monkeypatch, tmp_path, capsys):
    token = "fixture-private-token"
    message = "Resource not accessible by integration\n" + token + " another-private-token " + "x" * 1000
    response = ('HTTP/2.0 403 Forbidden\r\nX-Github-Request-Id: A:B:123\r\n'
                'X-Private-Header: must-not-publish\r\n\r\n' + json.dumps({
                    "message": message, "request_body": "private notice body", "errors": ["private detail"],
                }))
    monkeypatch.setenv("GH_TOKEN", token)
    monkeypatch.setenv("GITHUB_TOKEN", "another-private-token")
    monkeypatch.setenv("BLACKBOX_GH_RESPONSE", response.encode().hex())
    monkeypatch.setenv("BLACKBOX_GH_FAILURE", "1")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    event, report, result = (tmp_path / name for name in ("event.json", "report.json", "result.json"))
    event.write_text("{}")
    report.write_text("{}")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request_target")
    monkeypatch.setattr(sys, "argv", ["notify_blackbox.py", "--report", str(report), "--result", str(result)])
    calls = []

    def publish(*args):
        calls.append(args)
        return notices.api("issues/123/comments", {"body": "private notice body"})

    monkeypatch.setattr(notices, "publish", publish)
    assert notices.main() == 1
    receipt = json.loads(result.read_text())
    assert receipt["status"] == "failed"
    assert "POST issues/123/comments failed" in receipt["error"]
    assert "HTTP 403; request ID A:B:123; message: Resource not accessible by integration [redacted] [redacted]" in receipt["error"]
    assert len(receipt["error"]) < 500
    assert json.loads(capsys.readouterr().out) == receipt
    assert len(calls) == 1
    for private in (token, "another-private-token", "must-not-publish", "private notice body", "private detail", "controlled gh failure"):
        assert private not in result.read_text()


@pytest.mark.parametrize("response", [
    "", "private transport text", "HTTP/2.0 502 Bad Gateway\n\nprivate HTML response",
    'HTTP/2.0 500 Internal Server Error\n\n["private non-object response"]',
    'HTTP/2.0 500 Internal Server Error\n\n{"message":{"private":"not a string"}}',
])
def test_notice_api_failure_without_structured_message_stays_explicit(gh_command, monkeypatch, response):
    monkeypatch.setenv("BLACKBOX_GH_RESPONSE", response.encode().hex())
    monkeypatch.setenv("BLACKBOX_GH_FAILURE", "1")
    with pytest.raises(ValueError, match="request ID unavailable; message: unavailable") as failure:
        notices.api("issues/123/comments", {"body": "private notice body"})
    assert "gh exit 23" in str(failure.value)
    assert "private" not in str(failure.value)
