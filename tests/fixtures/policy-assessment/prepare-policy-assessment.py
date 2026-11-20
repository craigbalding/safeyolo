"""Host-only fixture preparation using the repository's locked tomlkit.

Stage generated JSON in the ordinary guest's private output directory. The
guest runs only its installed native client, in the same disclosure run.

Run this file on the owning host with the repository's frozen Python environment:
    .venv/bin/python prepare-policy-assessment.py PHASE ORIGINAL_REQ_ID OUTPUT
Prepare a synthetic assessment-fixture support grant through its native owner.
Create the owned agent home before staging. Interleave host/guest phases:
host request -> guest request -> owning operator's exact snapshot approval ->
guest read -> host broad -> guest broad -> host narrow -> guest narrow ->
host verify. Transfer inputs/results privately between those phases. No
support command, guest log read or candidate adoption is part of this fixture.
"""

import argparse
import json
from pathlib import Path

import tomlkit

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("phase", choices=["request", "broad", "narrow", "verify"])
parser.add_argument("request_id", help="the original req- identifier")
parser.add_argument("output", type=Path)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
grant_name = "assessment-fixture"


def read(name):
    return json.loads((args.output / name).read_text())


def write(name, value):
    (args.output / name).write_text(json.dumps(value))


if args.phase == "request":
    write("snapshot-request.json", {"operation_id": args.request_id})
    write("snapshot-read.json", {"request_id": args.request_id})
elif args.phase == "broad":
    snapshot = read("approved-snapshot.json")
    assert snapshot["status"] == "approved", snapshot["status"]
    source = snapshot["snapshot"]["source"]
    assert grant_name in tomlkit.parse(source)["support_grants"]
    (args.output / "base.toml").write_text(source)
    write(
        "broad-request.json",
        {
            "snapshot_request_id": args.request_id,
            "source": source,
            "definition_version": read("capabilities.json")["definition_version"],
        },
    )
elif args.phase == "narrow":
    broad = read("broad-assessment.json")
    assert broad["valid"] is True
    assert broad["operator_notified"] is False and broad["activated"] is False
    alternative = next(item for item in broad["alternatives"] if item["path"] == ["support_grants", grant_name])
    assert alternative["kind"] == "inspection_only"
    document = tomlkit.parse((args.output / "base.toml").read_text())
    document["support_grants"][grant_name] = alternative["value"]
    source = document.as_string()
    # The native support owner writes an inline table. Parse the complete
    # edited source; never guess the serialization with a line replacement.
    grant = json.loads(tomlkit.parse(source)["support_grants"][grant_name])
    assert grant["guest_admin"] is False and not grant["guest_logs"]
    request = read("broad-request.json")
    request["source"] = source
    write("narrow-request.json", request)
    (args.output / "candidate.toml").write_text(source)
    print("Scope removed:", alternative["removes"])
    print("Tradeoff:", alternative["tradeoff"])
else:
    broad = read("broad-assessment.json")
    narrow = read("narrow-assessment.json")
    assert narrow == read("narrow-assessment-repeated.json")
    assert narrow["valid"] is True and narrow["operator_notified"] is False
    assert narrow["permission_changed"] is False and narrow["activated"] is False
    assert narrow["assessment_id"] != broad["assessment_id"]
    assert narrow["authority"]["removed"]
    print("PASS: private assessment, supported narrower choice and identical repeat.")
    print("assessment_id:", narrow["assessment_id"])
