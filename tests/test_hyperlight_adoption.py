"""The installed witness must not accept tampered input or retry an uncertain write."""

import base64
import hashlib
import importlib.util
import json
import socket
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("adoption", REPO / "tests/blackbox/host/hyperlight_adoption.py")
adoption = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adoption)


@pytest.mark.parametrize("change", [None, "digest", "number", "author", "pull_request"])
def test_checked_snapshot_is_consumed_only_for_its_exact_subject(change):
    issue = json.loads((REPO / "proxy/tests/fixtures/policy-check-github-issue.json").read_bytes())
    witness = adoption.Witness.__new__(adoption.Witness)
    witness.args = SimpleNamespace(issue=issue["number"], author_id=str(issue["user"]["id"]),
                                   repository="craigbalding/safeyolo")
    if change == "number":
        issue["number"] += 1
    if change == "author":
        issue["user"]["id"] = 0
    if change == "pull_request":
        issue["pull_request"] = {}
    raw = json.dumps(issue).encode()
    capture = {"content_base64": base64.b64encode(raw).decode(), "sha256": hashlib.sha256(raw).hexdigest()}
    if change == "digest":
        capture["sha256"] = "0" * 64
    work = {"automatic": [{"binding": {"boundary": "admit_issue"}, "state": "satisfied",
                           "evidence": {"execution": {"checked_input": capture}}}]}
    if change is None:
        assert witness.checked_issue(work) == (capture, issue)
    else:
        with pytest.raises(AssertionError):
            witness.checked_issue(work)


def test_uncertain_unix_request_retains_original_operation_without_retry(tmp_path):
    root = tmp_path / "installed"
    (root / "data").mkdir(parents=True)
    token = "synthetic-private-instance-token"
    (root / "data/agent_token").write_text(token)
    args = SimpleNamespace(root=root, scratch=tmp_path / "private", room="selected", run_id="one-attempt", phase="admit")
    witness = adoption.Witness(args)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    path = tmp_path / "proxy.sock"
    listener.bind(str(path))
    listener.listen(1)
    requests = []

    def disconnect_after_request():
        with listener, listener.accept()[0] as stream:
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                header.extend(stream.recv(1))
            length = next(int(line.split(b":", 1)[1]) for line in header.split(b"\r\n")
                          if line.lower().startswith(b"content-length:"))
            body = bytearray()
            while len(body) < length:
                body.extend(stream.recv(length - len(body)))
            requests.append(json.loads(body))
            # The write may have happened. Deliberately supply no response.

    server = threading.Thread(target=disconnect_after_request)
    server.start()
    try:
        with pytest.raises(adoption.http.client.RemoteDisconnected):
            witness.call(path, {"action": "create", "title": "uncertain fixture"})
    finally:
        server.join(timeout=5)
    assert not server.is_alive()
    retained = json.loads((args.scratch / "1-request.json").read_bytes())
    assert requests == [retained]
    assert retained["operation_id"] == "one-attempt-admit-1"
    assert token not in (args.scratch / "1-request.json").read_text()
    assert args.scratch.stat().st_mode & 0o777 == 0o700
