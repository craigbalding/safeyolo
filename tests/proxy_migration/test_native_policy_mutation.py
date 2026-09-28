"""Native policy mutation and fresh-process observations from existing state."""

from __future__ import annotations

import shutil
import tomllib
from pathlib import Path

import pytest
import tomlkit

from safeyolo.operator_approvals import approve
from tests.proxy_migration.harness import ReadinessError, launch_proxy
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_native_network_policy import policy_proxy
from tests.proxy_migration.test_operator_consumer_approval import (
    _admin_client,
    _audit_rows,
    _compiled_permission,
    _pending,
    _wait_for_native_state,
)

STOCK = Path(__file__).resolve().parents[2] / "cli/src/safeyolo/templates"


def _stock_policy(directory: Path) -> Path:
    """Preserve the stock external lists while selecting a bounded prompt target."""
    directory.mkdir()
    shutil.copytree(STOCK / "lists", directory / "lists")
    document = tomlkit.parse((STOCK / "policy.toml").read_text())
    document["hosts"]["*"]["egress"] = "prompt"
    document["hosts"]["localhost"] = {"egress": "allow"}
    path = directory / "policy.toml"
    path.write_text(tomlkit.dumps(document))
    return path


def _assert_permissions(proxy, target, other, expected):
    """Check the policy decision and the controlled-origin effect together."""
    cases = (
        ("selected", "alice", "127.0.0.1", target),
        ("other_agent", "bob", "127.0.0.1", target),
        ("other_port", "alice", "127.0.0.1", other),
        ("other_host", "alice", "127.0.0.2", None),
        ("permitted_control", "alice", "localhost", other),
    )
    for name, agent, host, origin in cases:
        port = target.server_address[1] if origin is None else origin.server_address[1]
        accepts = origin.accepts if origin is not None else None
        requests = len(origin.requests) if origin is not None else None
        status, _, body = send_request(proxy.paths[agent], f"http://{host}:{port}/{name}")
        assert status == expected[name], (name, status, body)
        if origin is not None:
            allowed = status == 200
            assert origin.accepts == accepts + allowed, name
            assert len(origin.requests) == requests + allowed, name
            if allowed:
                assert body == b"hello"
                assert origin.requests[-1]["target"] == f"/{name}"


def test_native_approval_preserves_stock_lists_and_survives_fresh_process(tmp_path):
    directory = tmp_path / "existing"
    policy = _stock_policy(directory)
    original = policy.read_bytes()
    list_files = {path.name: path.read_bytes() for path in (directory / "lists").iterdir()}
    token_file = directory / "operator-token"
    token_file.write_text("native-chaos-operator\n")
    before = {
        "selected": 428,
        "other_agent": 428,
        "other_port": 428,
        "other_host": 428,
        "permitted_control": 200,
    }
    after = {**before, "selected": 200}

    with origin_server() as target, origin_server() as other:
        port = target.server_address[1]
        with policy_proxy(
            "rust", directory, None, admin_port=0, admin_api_token_file=token_file
        ) as proxy:
            assert policy.read_bytes() == original
            hmac_file = directory / "data/hmac_secret"
            assert hmac_file.is_file()
            hmac_secret = hmac_file.read_bytes()
            _assert_permissions(proxy, target, other, before)

            api = _admin_client(proxy, token_file)
            event = next(
                row for row in _pending(api)
                if row.get("agent") == "alice"
                and row.get("approval", {}).get("target") == f"127.0.0.1:{port}"
            )
            assert event["approval"]["approval_type"] == "network_egress"
            assert approve(event, api) == "added"
            _wait_for_native_state(
                api, event["request_id"],
                lambda document: _compiled_permission(
                    document, action="network:request", resource="127.0.0.1/*",
                    effect="budget", budget=600, agent="alice", port=port,
                ),
            )
            _assert_permissions(proxy, target, other, after)
            assert any(
                row.get("event") == "admin.host_allowed"
                and row.get("details", {}).get("agent") == "alice"
                and row["details"].get("port") == port
                for row in _audit_rows(directory)
            )

        final = policy.read_bytes()
        assert final != original
        original_document = tomllib.loads(original.decode())
        final_document = tomllib.loads(final.decode())
        agents = final_document.pop("agents")
        assert agents == {"alice": {"hosts": {f"127.0.0.1:{port}": {
            "egress": "allow", "rate": 600,
        }}}}
        assert final_document == original_document
        assert b"# SafeYolo baseline policy" in final
        assert {path.name: path.read_bytes() for path in (directory / "lists").iterdir()} == list_files
        assert not list(directory.glob(".policy-*.toml"))
        assert hmac_file.read_bytes() == hmac_secret

        with policy_proxy(
            "rust", directory, None, admin_port=0, admin_api_token_file=token_file
        ) as fresh:
            assert policy.read_bytes() == final
            assert hmac_file.read_bytes() == hmac_secret
            _assert_permissions(fresh, target, other, after)
        assert policy.read_bytes() == final


def test_existing_policy_start_requires_external_list(tmp_path):
    directory = tmp_path / "missing-list"
    policy = _stock_policy(directory)
    original = policy.read_bytes()
    (directory / "lists/package-registries.txt").unlink()

    with pytest.raises(ReadinessError, match="package-registries.txt"):
        with launch_proxy("rust", directory, None, native_policy=True):
            pytest.fail("Rust accepted a policy with a missing external list")
    assert policy.read_bytes() == original


def test_existing_policy_start_requires_policy_file(tmp_path):
    with pytest.raises(FileNotFoundError, match="Existing fixture policy is missing"):
        with launch_proxy("rust", tmp_path, None, native_policy=True):
            pytest.fail("The fixture invented a replacement policy")
