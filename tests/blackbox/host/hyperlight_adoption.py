"""Exercise installed native admission and output bindings in a selected test factory.

Sylab supplies the disposable installed root, adopted policy, approved factory,
room and existing creator/owner Unix listeners. This script creates only its
fixture Work, consumes its checked snapshot, and publishes retained fixture
artifacts. It never installs, changes policy, answers independent checks or
accepts an output. Keep the supplied scratch directory private and disk-backed.
Each invocation is one attempt. After a lost reply, inspect the saved original
operation and canonical Work before running another mutation.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import socket
import subprocess
import urllib.parse
from pathlib import Path


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


class Witness:
    def __init__(self, args):
        self.args = args
        self.index = 0
        args.scratch.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.token = (args.root / "data/agent_token").read_text().strip()
        room = urllib.parse.quote(args.room, safe="")
        self.endpoint = f"http://_safeyolo.proxy.internal/api/coord/rooms/{room}/work"

    def call(self, listener, value=None, *, work_id=None, status=200):
        self.index += 1
        method = "GET" if value is None else "POST"
        url = self.endpoint
        if work_id is not None:
            url += "?" + urllib.parse.urlencode({"work_id": work_id})
        body = None
        if value is not None:
            value = {**value, "operation_id": f"{self.args.run_id}-{self.args.phase}-{self.index}"}
            save(self.args.scratch / f"{self.index}-request.json", value)
            body = json.dumps(value)
        connection = http.client.HTTPConnection("_safeyolo.proxy.internal", timeout=120)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(120)
        connection.sock.connect(str(listener))
        try:
            connection.request(method, url, body, {"Authorization": "Bearer " + self.token,
                                                 "Content-Type": "application/json"})
            response = connection.getresponse()
            observed, result = response.status, json.load(response)
        finally:
            connection.close()
        save(self.args.scratch / f"{self.index}-response.json", {"status": observed, "body": result})
        if observed != status:
            raise RuntimeError(f"Request {self.index}: expected HTTP {status}, observed {observed}; inspect private scratch")
        return result

    def read(self, work_id):
        result = self.call(self.args.owner_socket, work_id=work_id)
        return result.get("work", result)

    @staticmethod
    def mutation(work, action):
        return {"action": action, "work_id": work["work_id"], "expected_version": work["version"],
                "expected_generation": work["claim_generation"]}

    def checked_issue(self, work):
        records = [item for item in work["automatic"] if item["binding"]["boundary"] == "admit_issue"]
        assert len(records) == 1 and records[0]["state"] == "satisfied"
        capture = records[0]["evidence"]["execution"]["checked_input"]
        raw = base64.b64decode(capture["content_base64"], validate=True)
        assert hashlib.sha256(raw).hexdigest() == capture["sha256"]
        issue = json.loads(raw)
        assert issue["number"] == self.args.issue
        assert issue["user"]["id"] == int(self.args.author_id)
        assert issue["url"] == f"https://api.github.com/repos/{self.args.repository}/issues/{self.args.issue}"
        assert "pull_request" not in issue
        return capture, issue

    def admit(self):
        create = {"action": "create", "title": "Installed Hyperlight checked-input witness",
                  "external_ref": f"https://github.com/{self.args.repository}/issues/{self.args.issue}",
                  "assignee": {"kind": "agent", "id": self.args.owner_id}}
        if self.args.expect_denied:
            refusal = self.call(self.args.creator_socket, create, status=409)
            assert "automatic requirement" in refusal["error"]
            print(json.dumps({"phase": "admission held under the selected revoked authority"}))
            return
        # The proxy must select the applicable factory without a caller selector.
        receipt = self.call(self.args.creator_socket, create)
        work = self.read(receipt["work"]["work_id"])
        assert work["created_by"] == {"kind": "agent", "id": self.args.creator_id}
        assert work["factory"]["reference"] == {"name": self.args.factory, "snapshot_id": self.args.snapshot}
        capture, _ = self.checked_issue(work)
        for extra in ({"evidence": {"positive": True}}, {"expected_author_id": "0"}):
            self.call(self.args.creator_socket, {**create, **extra}, status=400)
        refusal = self.call(self.args.creator_socket, {**create, "factory": {
            "name": self.args.factory, "snapshot_id": "0" * 64}}, status=409)
        assert "configured approved factory" in refusal["error"]
        # A selected existing PR or author mismatch must remain refused through an API alias.
        rejected = {**create, "external_ref": f"https://api.github.com/repos/{self.args.repository}/issues/{self.args.rejected_issue}"}
        refusal = self.call(self.args.creator_socket, rejected, status=409)
        assert "automatic requirement" in refusal["error"]
        print(json.dumps({"work_id": work["work_id"], "checked_input_sha256": capture["sha256"],
                          "factory": work["factory"]["reference"], "phase": "admission observed"}))

    def publish(self):
        work = self.read(self.args.work_id)
        capture, issue = self.checked_issue(work)
        if work["state"] == "open":
            self.call(self.args.owner_socket, self.mutation(work, "claim"))
            work = self.read(self.args.work_id)
        assert work["claim_agent_id"] == self.args.owner_id
        assert work["state"] in {"claimed", "done"}
        # The fixture worker consumes title and body from the checked bytes only.
        artifact = {"status": self.args.artifact_status, "checked_input_sha256": capture["sha256"],
                    "title": issue["title"],
                    "body_sha256": hashlib.sha256((issue.get("body") or "").encode()).hexdigest()}
        path = self.args.scratch / "result.json"
        save(path, artifact)
        helper = self.args.root / "assets/skills/job-authoring/scripts/publication.py"
        fields = json.loads(subprocess.check_output(["python3", str(helper), str(path)]))
        request = {**self.mutation(work, "publish_output"), **fields,
                   "expected_target_generation": work["target_generation"], "execution_outcome": "succeeded",
                   "summary": "Controlled installed witness artifact from the canonical checked issue snapshot"}
        # Bytes and reference must agree; the refused attempt cannot advance the output.
        self.call(self.args.owner_socket, {**request, "artifact_base64": base64.b64encode(b"substitution").decode()}, status=400)
        self.call(self.args.owner_socket, request)
        current = self.read(self.args.work_id)
        assert current["target_generation"] == work["target_generation"] + 1
        self.call(self.args.owner_socket, request, status=409)
        records = [item for item in current["automatic"] if item["binding"]["boundary"] == "verify_output"
                   and item["target_generation"] == current["target_generation"]]
        assert len(records) == 1
        assert (records[0]["state"] == "satisfied") == (self.args.artifact_status == "ready")
        assert current["acceptance_status"]["state"] != "accepted"
        if current["state"] == "claimed":
            self.call(self.args.owner_socket, {**self.mutation(current, "complete"),
                                             "short_result": "Installed fixture output retained for independent review"})
            current = self.read(self.args.work_id)
        print(json.dumps({"work_id": current["work_id"], "target_generation": current["target_generation"],
                          "automatic_state": records[0]["state"], "acceptance_status": current["acceptance_status"],
                          "required_checks": current["factory"]["current_checks"],
                          "phase": "published; independent review remains required"}))

    def inspect(self):
        work = self.read(self.args.work_id)
        capture, _ = self.checked_issue(work)
        if self.args.expect_accepted:
            assert work["acceptance_status"]["state"] == "accepted"
        if self.args.prior_input_sha256:
            assert capture["sha256"] != self.args.prior_input_sha256, "The relevant issue bytes did not change; changed-input proof is pending"
        print(json.dumps({"work_id": work["work_id"], "version": work["version"],
                          "claim_generation": work["claim_generation"], "target_generation": work["target_generation"],
                          "checked_input_sha256": capture["sha256"], "acceptance_status": work["acceptance_status"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["admit", "publish", "inspect"])
    for name in ("root", "scratch", "creator-socket", "owner-socket"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("room", "factory", "snapshot", "creator-id", "owner-id", "repository", "author-id", "run-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--issue", required=True, type=int)
    parser.add_argument("--rejected-issue", type=int)
    parser.add_argument("--work-id")
    parser.add_argument("--artifact-status", choices=["ready", "draft"], default="ready")
    parser.add_argument("--expect-accepted", action="store_true")
    parser.add_argument("--expect-denied", action="store_true")
    parser.add_argument("--prior-input-sha256")
    args = parser.parse_args()
    if args.phase == "admit" and not args.expect_denied and args.rejected_issue is None:
        parser.error("admit requires --rejected-issue from the selected repository")
    if args.phase != "admit" and not args.work_id:
        parser.error("publish and inspect require --work-id from canonical admission")
    os.umask(0o077)
    witness = Witness(args)
    getattr(witness, args.phase)()


if __name__ == "__main__":
    main()
