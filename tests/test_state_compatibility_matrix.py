"""Guard the complete #638 writer/reader inventory against omissions."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INVENTORY = REPO_ROOT / "docs" / "state-compatibility.md"

REQUIRED_FAMILIES = {
    "Baseline policy, host/agent settings, lists and task policy (durable)",
    "Approvals (durable policy mutation)",
    "Service definitions/catalog (durable files, watched)",
    "Service authorization, contracts, grants and bindings (durable policy records; session leases ephemeral)",
    "Encrypted vault and OAuth credential state (durable)",
    "Credential guard fingerprint key (durable `data_dir/hmac_secret`)",
    "Interception CA and key material (durable)",
    "Circuit cache and counters (durable when configured; worker/process lifetime)",
    "Flow evidence (durable SQLite)",
    "Audit, trace and metrics evidence (append-only files or process state)",
    "Coordination/collaboration state (external service boundary)",
    "Readiness, runtime identity, listener registry and task registry (ephemeral)",
}


def _rows() -> list[list[str]]:
    rows: list[list[str]] = []
    active = False
    for line in INVENTORY.read_text(encoding="utf-8").splitlines():
        if line.startswith("| State family and lifetime |"):
            active = True
            continue
        if not active:
            continue
        if line.startswith("| ---"):
            continue
        if not line.startswith("|"):
            break
        fields = [item.strip() for item in line.strip("|").split("|")]
        assert len(fields) == 5, line
        rows.append(fields)
    return rows


def test_writer_matrix_contains_every_durable_and_ephemeral_family() -> None:
    rows = _rows()
    families = {row[0] for row in rows}
    assert families == REQUIRED_FAMILIES
    assert len(rows) == len(REQUIRED_FAMILIES)
    for family, source, native, invariants, controls in rows:
        assert source and native and invariants and controls, family
        assert "proxy/" in native or "No proxy-owned replacement writer" in native, family


def test_writer_matrix_retains_explicit_rollback_and_unresolved_owners() -> None:
    text = " ".join(INVENTORY.read_text(encoding="utf-8").split())
    for required in (
        "OAuth refresh and alternate service catalogs",
        "installed-instance rollback",
        "Flow evidence (durable SQLite)",
        "Coordination/collaboration state (external service boundary)",
        "do not resurrect removed access or claim exactly-once across restart",
        "does not claim that the Python comparator, guest isolation, or a platform lane has passed",
    ):
        assert required in text
