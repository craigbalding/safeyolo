"""Normative two-revision acceptance test for coord store upgrades."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from safeyolo.coord import api, nats_client, store
from safeyolo.coord import nats_runtime as nr

# The exact master revision whose unversioned coord store Stage 0 supersedes.
LEGACY_BASE_SHA = "c1bb9c2083f30f33c35ed86aadc6366994a3e8a6"

_BASELINE_SETUP = r"""
import asyncio
import inspect
import json
import os
import sqlite3

from safeyolo.coord import nats_runtime as nr

# The historical revision predates the internal dynamic-port test contract.
# Point its real nats-py client at the candidate-owned server before importing
# the historical API module. Production defaults in both revisions stay intact.
nr.NATS_CLIENT_PORT = int(os.environ["SAFEYOLO_NATS_TEST_CLIENT_PORT"])
nr.NATS_MONITOR_PORT = int(os.environ["SAFEYOLO_NATS_TEST_MONITOR_PORT"])

from safeyolo.coord import api, store

async def main():
    instance_id = api.bootstrap()
    room_id = await api.create_room("upgrade-room")
    grant_supports_operations = "operation_id" in inspect.signature(api.grant).parameters
    grant_a_kwargs = {"operation_id": "op-baseline-grant-a"} if grant_supports_operations else {}
    grant_b_kwargs = {"operation_id": "op-baseline-grant-b"} if grant_supports_operations else {}
    api.grant("upgrade-room", "agent", "ag-upgrade-a", **grant_a_kwargs)
    api.grant("upgrade-room", "agent", "ag-upgrade-b", **grant_b_kwargs)
    sent = await api.send(
        "upgrade-room",
        "agent",
        "ag-upgrade-a",
        "retained across coord upgrade",
        sender_agent_name="upgrade-a",
    )
    with sqlite3.connect(store.db_path()) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    print(json.dumps({
        "instance_id": instance_id,
        "room_id": room_id,
        "sequence": sent["sequence"],
        "schema_version": version,
    }))

asyncio.run(main())
"""


def _run(coro):
    return asyncio.run(coro)


def _extract_revision(repo: Path, sha: str, destination: Path) -> None:
    archive = destination.parent / "baseline.tar"
    with archive.open("wb") as output:
        completed = subprocess.run(
            ["git", "archive", "--format=tar", sha],
            cwd=repo,
            stdout=output,
            stderr=subprocess.PIPE,
            check=False,
        )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    destination.mkdir()
    with tarfile.open(archive) as source:
        source.extractall(destination, filter="data")


@pytest.mark.timeout(90)
def test_current_master_state_upgrades_through_candidate(
    nats_env, tmp_path, monkeypatch
):
    if os.environ.get("SAFEYOLO_RUN_TWO_REVISION_ACCEPTANCE") != "1":
        pytest.skip("set SAFEYOLO_RUN_TWO_REVISION_ACCEPTANCE=1")

    repo = Path(__file__).resolve().parents[2]
    base_sha = os.environ.get("SAFEYOLO_COORD_ACCEPTANCE_BASE_SHA") or LEGACY_BASE_SHA
    candidate_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    baseline = tmp_path / "baseline-source"
    _extract_revision(repo, base_sha, baseline)

    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()
    environment = os.environ.copy()
    active = nr._read_pidfile()
    assert active is not None
    environment["SAFEYOLO_NATS_TEST_CLIENT_PORT"] = str(active["client_port"])
    environment["SAFEYOLO_NATS_TEST_MONITOR_PORT"] = str(
        active["monitor_port"]
    )
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(baseline / "cli" / "src"), str(baseline)]
    )
    completed = subprocess.run(
        [sys.executable, "-c", _BASELINE_SETUP],
        cwd=baseline,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    baseline_result = json.loads(completed.stdout.strip().splitlines()[-1])
    assert baseline_result["schema_version"] <= store.CURRENT_SCHEMA_VERSION

    # Prove JetStream persistence too: candidate code starts a new NATS process
    # against the exact same storage, not merely a new Python client.
    nr.stop_server()
    nats_client.reset_for_tests()
    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()

    assert api.bootstrap() == baseline_result["instance_id"]
    with store.connect() as conn:
        migrated_version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert migrated_version == store.CURRENT_SCHEMA_VERSION
    assert api.join_room("upgrade-room", "agent", "ag-upgrade-b")[
        "room_id"
    ] == baseline_result["room_id"]
    page = _run(api.read_room("upgrade-room", "agent", "ag-upgrade-b"))
    assert [message["sequence"] for message in page["messages"]] == [
        baseline_result["sequence"]
    ]
    assert page["messages"][0]["body"] == "retained across coord upgrade"

    api.grant(
        "upgrade-room",
        "agent",
        "ag-upgrade-c",
        operation_id="op-upgrade-grant",
    )
    api.grant(
        "upgrade-room",
        "agent",
        "ag-upgrade-c",
        operation_id="op-upgrade-grant",
    )
    assert api.revoke_grant(
        "upgrade-room",
        "agent",
        "ag-upgrade-c",
        operation_id="op-upgrade-revoke",
    ) is True
    assert api.revoke_grant(
        "upgrade-room",
        "agent",
        "ag-upgrade-c",
        operation_id="op-upgrade-revoke",
    ) is True

    # Candidate restart remains idempotent and the baseline message is intact.
    nr.stop_server()
    nats_client.reset_for_tests()
    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()
    assert api.bootstrap() == baseline_result["instance_id"]
    restarted_page = _run(
        api.read_room("upgrade-room", "agent", "ag-upgrade-b")
    )
    assert restarted_page["messages"][0]["sequence"] == baseline_result["sequence"]

    report = {
        "base_sha": base_sha,
        "candidate_sha": candidate_sha,
        "schema_before": baseline_result["schema_version"],
        "schema_after": migrated_version,
        "scenarios": {
            "baseline_state_created_via_base_api": True,
            "sqlite_migrated": True,
            "authorization_preserved": True,
            "jetstream_retention_preserved": True,
            "new_mutations_idempotent": True,
            "candidate_restart_idempotent": True,
        },
    }
    report_path = Path(
        os.environ.get(
            "SAFEYOLO_COORD_ACCEPTANCE_REPORT",
            tmp_path / "stage0-acceptance.json",
        )
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
