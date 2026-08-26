"""Focused regressions promoted from the policy assurance experiment lab."""

from unittest.mock import patch

import pytest
import tomlkit

POLICY = """\
budget = 1000000

[hosts]
"blocked.example" = { egress = "deny" }
"*" = { egress = "deny", unknown_creds = "prompt" }

[agents.atlas]
egress = "deny"
"""


def test_bypass_reload_rejection_rolls_back_without_success_audit(tmp_path):
    from safeyolo.policy.engine import PolicyEngine

    path = tmp_path / "policy.toml"
    path.write_text(POLICY)
    engine = PolicyEngine(baseline_path=path)
    original = path.read_bytes()
    real_reload = engine._loader.reload
    calls = 0

    def reject_once():
        nonlocal calls
        calls += 1
        return False if calls == 1 else real_reload()

    with (
        patch.object(engine._loader, "reload", side_effect=reject_once, autospec=True),
        patch("safeyolo.policy.engine.write_event", autospec=True) as audit,
        pytest.raises(RuntimeError, match="reload rejected"),
    ):
        engine.add_host_bypass("blocked.example", "pattern-scanner")

    assert path.read_bytes() == original
    audit.assert_not_called()


def test_disjoint_gateway_instances_merge_contract_bindings(tmp_path):
    from safeyolo.mitm_addons.service_gateway import ServiceGateway

    path = tmp_path / "policy.toml"
    path.write_text(POLICY)
    gateways = (ServiceGateway(), ServiceGateway())
    for gateway in gateways:
        gateway._get_policy_path = lambda: path

    gateways[0].add_contract_binding(
        "atlas", "mail", "read", "tenant={tenant}", {"tenant": "one"}, ["GET /"]
    )
    gateways[1].add_contract_binding(
        "atlas", "calendar", "read", "tenant={tenant}", {"tenant": "two"}, ["GET /"]
    )

    bindings = tomlkit.parse(path.read_text()).unwrap()["agents"]["atlas"][
        "contract_bindings"
    ]
    assert {binding["service"] for binding in bindings} == {"mail", "calendar"}
    assert tomlkit.parse(path.read_text()).unwrap()["hosts"]["blocked.example"][
        "egress"
    ] == "deny"


def test_gateway_persistence_failure_does_not_change_live_binding_state(tmp_path):
    from safeyolo.mitm_addons.service_gateway import ServiceGateway

    path = tmp_path / "policy.toml"
    path.write_text(POLICY)
    gateway = ServiceGateway()
    gateway._get_policy_path = lambda: path

    with patch(
        "safeyolo.policy.toml_roundtrip.save_roundtrip",
        autospec=True,
        side_effect=OSError("disk full"),
    ):
        with pytest.raises(OSError, match="disk full"):
            gateway.add_contract_binding(
                "atlas", "mail", "read", "tenant={tenant}", {}, ["GET /"]
            )

    assert gateway.get_contract_binding("atlas", "mail", "read") is None


def test_policy_host_lock_is_shared_with_other_writers(tmp_path, monkeypatch):
    from safeyolo.commands.policy_host import host_add
    from safeyolo.policy.toml_roundtrip import locked_policy_mutate, update_host_field

    path = tmp_path / "policy.toml"
    path.write_text(POLICY)
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))

    locked_policy_mutate(
        path,
        lambda document: update_host_field(
            document, "first.example", "rate", 100000
        ),
    )
    host_add("second.example", rate=100000, agent=None, expires=None)

    hosts = tomlkit.parse(path.read_text()).unwrap()["hosts"]
    assert {"first.example", "second.example"} <= hosts.keys()
    assert hosts["blocked.example"]["egress"] == "deny"
