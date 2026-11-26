#!/usr/bin/env python3
"""Controlled job-helper outputs for native host admission, with no VM/model."""

import json
import sys
from pathlib import Path

invocation = json.loads(Path(sys.argv[1]).read_text())
request = json.loads((Path(invocation["input"]) / "request.json").read_text())
subject = json.loads(request["subject"]["value"])
mode = Path(invocation["argv"][0]).read_text()
with Path(invocation["argv"][1]).open("a") as capture:
    capture.write(json.dumps({"subject": subject, "request": request}) + "\n")

concern = mode == "concern" or (
    mode == "adaptive" and subject["trusted"]["action"]["invocation"]["arguments"]["wait"] == 6
)
result = {
    "finding": {
        "kind": "task_action",
        "assessment": {
            "relevance": "irrelevant" if concern else "relevant",
            "proportionality": "excessive" if concern else "proportionate",
            "evidence_refs": ["task", "action"],
            "clarification": "Choose the narrower action" if concern else None,
            "uncertainty": ["Controlled fixture; no model judgment"],
        },
    },
}
if mode == "expired":
    result["valid_until_ms"] = 1
print("malformed" if mode == "malformed" else json.dumps(result))
Path(sys.argv[2]).write_text(
    json.dumps({"completion": {"kind": "guest_call_completed", "reported_status": 0}, "error": None})
)
