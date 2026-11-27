"""Doctor observes current decisions and retained storage without repairing it."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess

import pytest
import tomlkit

from tests.proxy_contracts.harness import request
from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_first_agent_launch import CREDENTIAL_RETRY_POLICY
from tests.proxy_contracts.test_native_coord_operator import terminal, wait_terminal_exit
from tests.proxy_contracts.test_native_policy_cli import native_inputs, native_instance


def checks(report):
    assert sum(report["counts"].values()) == len(report["checks"])
    assert report["exit_code"] == int(report["counts"]["fail"] + report["counts"]["unknown"] > 0)
    return {row["name"]: row for row in report["checks"]}


def test_doctor_names_missing_listeners_without_claiming_requests_were_probed(tmp_path):
    with native_instance(tmp_path, agent_addresses={}) as instance:
        result = instance.cli("doctor")
        report = json.loads(result.stdout)
        assert result.returncode == report["exit_code"]
        pipeline = checks(report)["Request pipeline and egress controls"]
        assert pipeline["status"] == "warn" and pipeline["details"]["agents"] == []
        assert "no requests were probed" in pipeline["message"]
        assert "agent launch" in pipeline["next_action"]
        with terminal(instance, ["doctor"]) as (process, master, until):
            output = until(b"Overall:")
            assert b"no requests were probed" in output and b"agent launch" in output
            assert b"Inspect failed pipeline findings" not in output
            assert wait_terminal_exit(process, master, bytearray(), timeout=5) in (0, 1)


def test_doctor_surfaces_current_pending_decisions_and_keeps_review_read_only(tmp_path):
    with origin_server() as origin, native_instance(tmp_path, source=CREDENTIAL_RETRY_POLICY) as instance:
        def report():
            result = instance.cli("doctor")
            value = json.loads(result.stdout)
            assert result.returncode == value["exit_code"]
            return checks(value)

        assert report()["Pending approvals"]["status"] == "pass"
        target = f"http://127.0.0.1:{origin.server_address[1]}/doctor"
        assert request(instance.paths["alice"], target,
                       headers={"Authorization": "Bearer first-launch-key"})[0] == 428
        pending = instance.admin("GET", "/admin/approvals")["approvals"]
        policy = instance.policy.read_bytes()
        approval = report()["Pending approvals"]
        assert approval["status"] == "warn" and approval["details"]["count"] == 1
        assert "watch" in approval["next_action"] and str(instance.root) in approval["next_action"]
        with terminal(instance, ["doctor"]) as (process, master, until):
            output = until(b"Overall:")
            assert b"WARN" in output and b"1 pending operator decisions" in output
            assert b"first-launch-key" not in output and b"request_id" not in output
            assert wait_terminal_exit(process, master, bytearray(), timeout=5) in (0, 1)
        assert instance.policy.read_bytes() == policy and origin.accepts == 0
        assert instance.admin("GET", "/admin/approvals")["approvals"] == pending


def test_doctor_inspects_selected_storage_without_creating_or_repairing_it(tmp_path):
    binary = native_inputs()[0] / "safeyolo"
    root = tmp_path / "instance with spaces"
    subprocess.run([str(binary), "--dangerously-allow-root", "--instance-dir", str(root), "init"],
                   capture_output=True, text=True, check=True, timeout=15)
    audit = tmp_path / "separate audit" / "current.jsonl"
    database = tmp_path / "separate flows" / "current.sqlite3"
    config = root / "config.toml"
    settings = tomlkit.parse(config.read_text())
    settings.update(audit_log_path=str(audit), flow_store_db_path=str(database), flow_store_enabled=False)
    config.write_text(tomlkit.dumps(settings))
    original = config.read_bytes(), (root / "policy.toml").read_bytes()

    def report():
        result = subprocess.run([str(binary), "--instance-dir", str(root), "doctor", "--json"],
                                capture_output=True, text=True, timeout=15)
        value = json.loads(result.stdout)
        assert result.returncode == value["exit_code"]
        return checks(value)

    absent = report()
    assert absent["Local logs"]["status"] == "pass"
    assert absent["Local logs"]["details"]["bytes"] is None
    assert absent["Retained flow store"]["details"]["exists"] is False
    assert not audit.parent.exists() and not database.parent.exists()
    audit.parent.mkdir()
    # Sparse input exercises the inherited 100 MB warning without allocating it.
    with audit.open("wb") as stream:
        stream.truncate(100_000_001)
    database.parent.mkdir()
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE flows(id INTEGER PRIMARY KEY)")
        connection.executemany("INSERT INTO flows VALUES (?)", [(1,), (2,)])
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    database.chmod(0o400)
    populated = report()
    assert populated["Local logs"]["status"] == "warn"
    assert populated["Local logs"]["details"]["path"] == str(audit)
    assert populated["Local logs"]["details"]["free_bytes"] > 0
    assert populated["Retained flow store"]["status"] == "pass"
    assert populated["Retained flow store"]["details"]["count"] == 2
    assert populated["Retained flow store"]["details"]["enabled"] is False
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before
    database.chmod(0o600)
    database.write_bytes(b"unreadable SQLite content")
    corrupt = report()["Retained flow store"]
    assert corrupt["status"] == "unknown" and str(database) in corrupt["message"]
    assert database.read_bytes() == b"unreadable SQLite content"
    database.chmod(0)
    try:
        assert report()["Retained flow store"]["status"] == "unknown"
    finally:
        database.chmod(0o600)
    assert (config.read_bytes(), (root / "policy.toml").read_bytes()) == original
    assert not (root / "data/proxy-process.json").exists()
    assert os.geteuid() != 0


@pytest.mark.parametrize("kind", ["fifo", "directory"])
@pytest.mark.parametrize("structured", [False, True])
def test_doctor_reports_non_regular_flow_path_without_waiting_or_changing_it(tmp_path, kind, structured):
    binary = native_inputs()[0] / "safeyolo"
    root = tmp_path / "selected instance"
    subprocess.run([str(binary), "--dangerously-allow-root", "--instance-dir", str(root), "init"],
                   capture_output=True, text=True, check=True, timeout=15)
    database = tmp_path / "unusable flows"
    if kind == "fifo":
        os.mkfifo(database, 0o600)
    else:
        database.mkdir()
    config = root / "config.toml"
    settings = tomlkit.parse(config.read_text())
    settings.update(flow_store_db_path=str(database), flow_store_enabled=False)
    config.write_text(tomlkit.dumps(settings))
    original = config.read_bytes(), (root / "policy.toml").read_bytes(), database.stat()
    result = subprocess.run(
        [str(binary), "--instance-dir", str(root), "doctor", *(["--json"] if structured else [])],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 1, result.stderr
    if structured:
        report = json.loads(result.stdout)
        rows = checks(report)
        flow = rows["Retained flow store"]
        assert flow["status"] == "unknown"
        assert report["counts"]["unknown"] > 0
        assert "Local logs" in rows
        message = flow["message"]
    else:
        assert "UNKNOWN Retained flow store" in result.stdout
        assert "Local logs" in result.stdout and "Overall:" in result.stdout
        message = result.stdout
    assert str(database) in message and "Not an ordinary flow database file" in message
    assert (config.read_bytes(), (root / "policy.toml").read_bytes(), database.stat()) == original
    assert not (root / "data/proxy-process.json").exists()
