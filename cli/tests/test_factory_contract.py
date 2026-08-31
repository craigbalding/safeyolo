"""Acceptance tests for declarative supervised factory contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from safeyolo.cli import app
from safeyolo.factory_contract import FactoryContractError, load_active_snapshot, load_factory_file


def _factory_file(tmp_path: Path, *, extra: str = "") -> Path:
    (tmp_path / "coordinator.md").write_text("# Coordinator\n\nDelegate exact tasks.\n")
    (tmp_path / "owner.md").write_text("# Owner\n\nOwn the issue.\n")
    (tmp_path / "reviewer.md").write_text("# Reviewer\n\nReview independently.\n")
    path = tmp_path / "backlog.toml"
    path.write_text(
        'schema = "safeyolo.factory/v1"\n'
        'name = "backlog"\n'
        'room = "backlog"\n\n'
        '[roles.coordinator]\nagent = "relay"\ncontract = "coordinator.md"\n\n'
        '[roles.owner]\nagent = "forge"\ncontract = "owner.md"\n\n'
        '[roles.reviewer]\nagent = "lens"\ncontract = "reviewer.md"\n\n'
        '[[handoffs]]\nrequest = "TASK"\nfrom = "coordinator"\nto = "owner"\n'
        'responses = ["DONE", "BLOCKED", "FAILED"]\n\n'
        '[[handoffs]]\nrequest = "REVIEW_READY"\nfrom = "owner"\nto = "reviewer"\n'
        'responses = ["READY", "CHANGES_REQUIRED", "BLOCKED"]\n' + extra
    )
    return path


def test_factory_check_resolves_roles_handoffs_and_contract_hashes(cli_runner, tmp_path):
    path = _factory_file(tmp_path)

    result = cli_runner.invoke(app, ["factory", "check", str(path)])

    assert result.exit_code == 0, result.output
    assert "factory=backlog schema=safeyolo.factory/v1 room=backlog" in result.output
    assert "role=owner agent=forge contract=owner.md" in result.output
    assert "sha256=" in result.output
    assert "handoff=REVIEW_READY from=owner to=reviewer" in result.output


def test_factory_apply_requires_approval_and_stores_immutable_snapshot(cli_runner, tmp_path, tmp_config_dir):
    path = _factory_file(tmp_path)

    denied = cli_runner.invoke(app, ["factory", "apply", str(path)], input="n\n")
    assert denied.exit_code == 1
    assert not (tmp_config_dir / "factories").exists()

    applied = cli_runner.invoke(app, ["factory", "apply", str(path), "--yes"])
    assert applied.exit_code == 0, applied.output
    identifier, snapshot_path, payload = load_active_snapshot("backlog")
    assert snapshot_path.name == f"{identifier}.json"
    assert snapshot_path.stat().st_mode & 0o777 == 0o600
    assert payload["roles"]["owner"]["contract_text"] == "# Owner\n\nOwn the issue.\n"
    first = snapshot_path.read_bytes()

    repeated = cli_runner.invoke(app, ["factory", "apply", str(path), "--yes"])
    assert repeated.exit_code == 0
    assert snapshot_path.read_bytes() == first


def test_factory_run_uses_only_the_active_verified_snapshot(cli_runner, tmp_path, tmp_config_dir, monkeypatch):
    path = _factory_file(tmp_path)
    applied = cli_runner.invoke(app, ["factory", "apply", str(path), "--yes"])
    assert applied.exit_code == 0
    calls = []
    monkeypatch.setattr(
        "safeyolo.commands.factory._run_snapshot",
        lambda snapshot_path, payload: calls.append((snapshot_path, payload)),
    )

    result = cli_runner.invoke(app, ["factory", "run", "backlog"])

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    assert calls[0][1]["name"] == "backlog"
    assert calls[0][1]["roles"]["reviewer"]["agent"] == "lens"


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda raw: raw.replace('name = "backlog"', 'name = "backlog"\nunknown = true'), "unknown"),
        (lambda raw: raw.replace('agent = "lens"', 'agent = "forge"'), "more than one role"),
        (lambda raw: raw.replace('request = "REVIEW_READY"', 'request = "review-ready"'), "uppercase"),
        (lambda raw: raw.replace('to = "reviewer"', 'to = "missing"'), "unknown role"),
    ],
)
def test_factory_contract_rejects_unknown_or_ambiguous_authority(tmp_path, mutation, message):
    path = _factory_file(tmp_path)
    path.write_text(mutation(path.read_text()))

    with pytest.raises(FactoryContractError, match=message):
        load_factory_file(path)


def test_active_snapshot_rejects_tampering(tmp_path, tmp_config_dir):
    from safeyolo.factory_contract import store_snapshot

    identifier, snapshot_path = store_snapshot(load_factory_file(_factory_file(tmp_path)))
    payload = json.loads(snapshot_path.read_text())
    payload["room"] = "other"
    snapshot_path.write_text(json.dumps(payload))

    with pytest.raises(FactoryContractError, match="content hash"):
        load_active_snapshot("backlog")
    assert identifier in snapshot_path.name
