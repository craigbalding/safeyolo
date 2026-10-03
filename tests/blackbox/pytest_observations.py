"""Retain bounded pytest outcomes without tracebacks, captures or parameter data."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

MAX_CASES = 4096


def case_name(nodeid: str) -> str:
    """Keep the source test name; omit parameter values and absolute paths."""
    parts = nodeid.split("[", 1)[0].split("::")
    parts[0] = Path(parts[0]).name
    name = "::".join(parts)
    return name if re.fullmatch(r"[A-Za-z0-9_.:-]{1,300}", name) else "unidentified_test"


class PytestObservations:
    """Record collection, actual outcomes, skips and unexecuted cases."""

    def __init__(self, path: Path):
        self.path = path
        self.started_at = datetime.now(UTC).isoformat()
        self.cases: dict[str, dict] = {}
        self.deselected = 0
        self.collection_errors = 0
        self.collected = 0

    def pytest_deselected(self, items):
        self.deselected += len(items)

    def pytest_collection_finish(self, session):
        self.collected = len(session.items)
        for item in session.items:
            self.cases[item.nodeid] = {"test": case_name(item.nodeid),
                                      "case_sha256": hashlib.sha256(item.nodeid.encode()).hexdigest(),
                                      "outcome": "unexecuted", "phase": None}

    def pytest_collectreport(self, report):
        if report.failed:
            self.collection_errors += 1

    def pytest_runtest_logreport(self, report):
        case = self.cases.get(report.nodeid)
        if case is None:
            return
        if report.failed or (report.skipped and case["outcome"] != "failed"):
            case.update(outcome=report.outcome, phase=report.when)
        elif report.when == "call" and case["outcome"] == "unexecuted":
            case.update(outcome="passed", phase="call")

    def pytest_sessionfinish(self, session, exitstatus):
        document = {
            "schema_version": 1, "run_id": os.environ["SAFEYOLO_BLACKBOX_RUN_ID"],
            "source_revision": os.environ["SAFEYOLO_BLACKBOX_INSTALL_REVISION"],
            "suite": os.environ["SAFEYOLO_BLACKBOX_PYTEST_SUITE"],
            "started_at": self.started_at, "finished_at": datetime.now(UTC).isoformat(),
            "exit": int(exitstatus), "collected": self.collected, "deselected": self.deselected,
            "collection_errors": self.collection_errors,
            "counts": dict(Counter(case["outcome"] for case in self.cases.values())),
            "cases": list(self.cases.values())[:MAX_CASES],
            "omitted_cases": max(0, len(self.cases) - MAX_CASES),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(document, indent=2) + "\n")


def pytest_configure(config):
    """Enable observation only for a runner-owned, attributed pytest call."""
    if config.pluginmanager.hasplugin("safeyolo-blackbox-observations"):
        return
    directory = os.environ.get("SAFEYOLO_BLACKBOX_OBSERVATIONS_DIR")
    path = os.environ.get("SAFEYOLO_BLACKBOX_OBSERVATIONS_PATH")
    suite = os.environ.get("SAFEYOLO_BLACKBOX_PYTEST_SUITE")
    if not (path or directory):
        return
    if (not suite or not re.fullmatch(r"[a-z-]+", suite)
            or not re.fullmatch(r"[0-9a-f]{32}", os.environ.get("SAFEYOLO_BLACKBOX_RUN_ID", ""))
            or not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("SAFEYOLO_BLACKBOX_INSTALL_REVISION", ""))):
        raise ValueError("pytest observations require a runner ID, selected commit and suite")
    output = Path(path) if path else Path(directory) / f"pytest-{suite}.json"
    config.pluginmanager.register(PytestObservations(output), "safeyolo-blackbox-observations")
