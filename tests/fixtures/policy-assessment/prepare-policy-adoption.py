"""Host preparation for the connected installed snapshot/assessment/adoption journey.

Use an owned isolated fixture with the native assessment-fixture support grant.
The guest runs installed native commands only. Keep this output private.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path

import tomlkit

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("phase", choices=["request", "compose", "narrow", "submit", "verify"])
parser.add_argument("output", type=Path)
parser.add_argument("--snapshot-id")
parser.add_argument("--operation-id")
parser.add_argument("--policy-file", type=Path)
args = parser.parse_args()
os.umask(0o077)
args.output.mkdir(parents=True, exist_ok=True)


def read(name):
    return json.loads((args.output / name).read_text())


def write(name, value):
    (args.output / name).write_text(json.dumps(value))


if args.phase == "request":
    if not args.snapshot_id or not args.operation_id or args.snapshot_id == args.operation_id:
        parser.error("choose distinct snapshot and submission req- IDs before sending")
    write("snapshot-request.json", {"operation_id": args.snapshot_id})
    write("snapshot-read.json", {"request_id": args.snapshot_id})
    write("submission-read.json", {"request_id": args.operation_id})
elif args.phase == "compose":
    snapshot = read("approved-snapshot.json")
    assert snapshot["status"] == "approved"
    document = tomlkit.parse(snapshot["snapshot"]["source"])
    assert "assessment-fixture" in document["support_grants"]
    document["budget"] = int(document["budget"]) + 1
    logging = document.setdefault("logging", tomlkit.table())
    quiet = logging.setdefault("quiet_hosts", tomlkit.table())
    quiet.setdefault("hosts", tomlkit.array()).append("adoption-fixture.invalid")
    request = {
        "snapshot_request_id": read("snapshot-read.json")["request_id"],
        "source": document.as_string(),
        "definition_version": read("capabilities.json")["definition_version"],
    }
    write("broad-request.json", request)
elif args.phase == "narrow":
    broad = read("broad-assessment.json")
    assert broad["valid"] is True and broad["operator_notified"] is False
    alternative = next(item for item in broad["alternatives"] if item["path"] == ["support_grants", "assessment-fixture"])
    document = tomlkit.parse(read("broad-request.json")["source"])
    document["support_grants"]["assessment-fixture"] = alternative["value"]
    request = read("broad-request.json")
    request["source"] = document.as_string()
    write("narrow-request.json", request)
    print("Scope removed:", alternative["removes"])
    print("Tradeoff:", alternative["tradeoff"])
elif args.phase == "submit":
    narrow = read("narrow-assessment.json")
    assert narrow == read("narrow-assessment-repeated.json")
    assert narrow["valid"] is True and narrow["operator_notified"] is False
    assert narrow["authority"]["removed"]
    write("submission.json", {
        "operation_id": read("submission-read.json")["request_id"],
        "candidate": read("narrow-request.json"),
    })
else:
    if args.policy_file is None:
        parser.error("verify requires the owning host's --policy-file")
    # Retain reached bytes before checking the observer's expectations.
    source = args.policy_file.read_bytes()
    (args.output / "host-saved-after.toml").write_bytes(source)
    result = read("adoption-result.json")
    assert result["status"] == "approved", result["status"]
    outcome = result["result"]
    revision = hashlib.sha256(source).hexdigest()
    assert outcome["status"] == "active" and outcome["activation_required"] is False
    assert outcome["saved_source_revision"] == revision == outcome["active_source_revision"]
    assert outcome == read("adoption-result-repeated.json")["result"]
    document = tomlkit.parse(source.decode())
    assert json.loads(document["support_grants"]["assessment-fixture"])["guest_admin"] is False
    assert "adoption-fixture.invalid" in document["logging"]["quiet_hosts"]["hosts"]
    print("PASS: installed exact adoption, saved/active receipt and readback", revision)
