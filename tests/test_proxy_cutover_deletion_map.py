"""Keep the #640 proxy deletion ledger path-level and rollback-safe."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LEDGER = REPO_ROOT / "docs" / "proxy-cutover-deletion-map.md"

# These are the current Python runtime owners that the parity inventory marks
# as deletion targets. Keeping the set here makes an accidental omission in
# the human-readable ledger fail close during review.
REQUIRED_PATHS = {
    "cli/src/safeyolo/proxy.py",
    "cli/src/safeyolo/traffic_master.py",
    "cli/src/safeyolo/traffic_session.py",
    "cli/src/safeyolo/proxy_modes/unix_listener.py",
    "cli/src/safeyolo/proxy_modes/__init__.py",
    "cli/src/safeyolo/core/base.py",
    "cli/src/safeyolo/core/audit_writer.py",
    "cli/src/safeyolo/core/flow_writer.py",
    "cli/src/safeyolo/mitm_addons/__init__.py",
    "cli/src/safeyolo/mitm_addons/pid_writer.py",
    "cli/src/safeyolo/mitm_addons/file_logging.py",
    "cli/src/safeyolo/mitm_addons/memory_monitor.py",
    "cli/src/safeyolo/mitm_addons/admin_shield.py",
    "cli/src/safeyolo/mitm_addons/agent_api.py",
    "cli/src/safeyolo/mitm_addons/agent_api_guard.py",
    "cli/src/safeyolo/mitm_addons/loop_guard.py",
    "cli/src/safeyolo/mitm_addons/request_id.py",
    "cli/src/safeyolo/mitm_addons/operator_provenance.py",
    "cli/src/safeyolo/mitm_addons/service_discovery.py",
    "cli/src/safeyolo/mitm_addons/sse_streaming.py",
    "cli/src/safeyolo/mitm_addons/policy_engine.py",
    "cli/src/safeyolo/mitm_addons/service_gateway.py",
    "cli/src/safeyolo/mitm_addons/network_guard.py",
    "cli/src/safeyolo/mitm_addons/circuit_breaker.py",
    "cli/src/safeyolo/mitm_addons/credential_guard.py",
    "cli/src/safeyolo/mitm_addons/pattern_scanner.py",
    "cli/src/safeyolo/mitm_addons/test_context.py",
    "cli/src/safeyolo/mitm_addons/flow_recorder.py",
    "cli/src/safeyolo/mitm_addons/request_logger.py",
    "cli/src/safeyolo/mitm_addons/ignored_host_logger.py",
    "cli/src/safeyolo/mitm_addons/metrics.py",
    "cli/src/safeyolo/mitm_addons/traffic_scope.py",
    "cli/src/safeyolo/mitm_addons/flow_pruner.py",
    "cli/src/safeyolo/mitm_addons/admin_api.py",
    "cli/src/safeyolo/mitm_addons/probe_sink.py",
    "cli/src/safeyolo/mitm_addons/transport_guard.py",
    "cli/src/safeyolo/websocket_console.py",
    "cli/src/safeyolo/websocket_body_filter.py",
    "pdp/",
    "pyproject.toml",
    "uv.lock",
}


def _table_rows() -> list[list[str]]:
    rows: list[list[str]] = []
    in_table = False
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        if line.startswith("| ID | Original path |"):
            in_table = True
            continue
        if not in_table:
            continue
        if line.startswith("|---|"):
            continue
        if not line.startswith("|"):
            break
        fields = [field.strip() for field in line.strip("|").split("|")]
        assert len(fields) == 6, line
        rows.append(fields)
    return rows


def _paths_from_checks(checks: str) -> list[tuple[str, bool]]:
    paths = []
    for item in checks.split("<br>"):
        item = item.strip()
        historical = item.startswith("historical: ")
        if historical:
            item = item.removeprefix("historical: ")
        assert item.startswith("`") and item.endswith("`")
        paths.append((item.strip("`"), historical))
    return paths


def test_ledger_covers_current_runtime_owners_and_existing_paths() -> None:
    rows = _table_rows()
    paths = {row[1].strip("`").rstrip("/") for row in rows}
    expected = {path.rstrip("/") for path in REQUIRED_PATHS}
    assert paths == expected

    ids = [row[0] for row in rows]
    assert len(ids) == len(set(ids))
    for row in rows:
        current_path = row[1].strip("`")
        path = REPO_ROOT / current_path.rstrip("/")
        state = row[5]
        if state.startswith("removed"):
            assert not path.exists(), current_path
        else:
            assert path.exists(), current_path
        assert state.startswith(("removed", "retained", "updated")), row
        assert row[3] and row[4], row
        for check, historical in _paths_from_checks(row[4]):
            exists = (REPO_ROOT / check).exists()
            assert exists != historical, (current_path, check)


def test_ledger_records_native_cutover_and_explicit_package_rollback() -> None:
    text = LEDGER.read_text(encoding="utf-8")
    assert "41 pre-cutover owners" in text
    assert "no Python backend selection or automatic fallback" in text
    assert "pinned prior Python checkout" in text
    assert "physical macOS/VZ" in text


def test_native_migration_lane_has_no_policy_adapter() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "proxy-rust.yml").read_text(encoding="utf-8")
    config = (REPO_ROOT / "proxy" / "src" / "config.rs").read_text(encoding="utf-8")
    assert "--proxy-backend rust" in workflow
    assert "temporary_policy_socket" not in config
    assert not (REPO_ROOT / "tools" / "proxy_migration" / "temporary_policy.py").exists()
    assert "SAFEYOLO_PYTHON_SOURCE" not in workflow
    assert "--proxy-backend python" not in workflow
