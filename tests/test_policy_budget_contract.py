"""Focused regressions for the aggregate and per-host request budget contract."""

from pathlib import Path

import pytest


def _engine(tmp_path: Path, policy: str):
    from safeyolo.policy.engine import PolicyEngine

    path = tmp_path / "policy.toml"
    path.write_text(policy)
    return PolicyEngine(baseline_path=path), path


def test_rate_less_allowance_uses_shared_global_budget(tmp_path):
    engine, _path = _engine(
        tmp_path,
        'budget = 10\n[hosts]\n"*" = { egress = "deny" }\n',
    )
    engine.add_host_allowance("one.example")
    engine.add_host_allowance("two.example")

    decisions = [
        engine.evaluate_request("one.example" if index % 2 else "two.example").effect
        for index in range(20)
    ]

    assert decisions[0] == "allow"
    assert "budget_exceeded" in decisions
    assert "network:request:__global__" in engine._budget_tracker.get_stats()["keys"]
    assert not any(key.endswith("one.example") for key in engine._budget_tracker.get_stats()["keys"])


def test_host_rate_adds_a_second_atomic_ceiling(tmp_path):
    engine, _path = _engine(
        tmp_path,
        'budget = 100\n[hosts]\n"limited.example" = { rate = 10 }\n',
    )

    assert engine.evaluate_request("limited.example").effect == "allow"
    keys = set(engine._budget_tracker.get_stats()["keys"])
    assert keys == {
        "network:request:limited.example",
        "network:request:__global__",
    }


def test_multi_budget_rejection_does_not_partially_consume(monkeypatch):
    from safeyolo.policy.budget_tracker import GCRABudgetTracker

    monkeypatch.setattr("safeyolo.policy.budget_tracker.time.time", lambda: 1000.0)
    tracker = GCRABudgetTracker()
    assert tracker.check_and_consume("host", 1)[0]
    assert tracker.check_and_consume("host", 1)[0]
    before = tracker._budgets["host"].tat

    allowed, remaining = tracker.check_and_consume_many(
        [("global", 100, 1), ("host", 1, 1)]
    )

    assert not allowed
    assert remaining["host"] == 0
    assert tracker._budgets["host"].tat == before
    assert "global" not in tracker._budgets


@pytest.mark.parametrize("rate", (12001, 50000))
def test_compile_rejects_rate_above_global_budget(rate):
    from safeyolo.policy.compiler import compile_policy

    with pytest.raises(ValueError, match="exceeds global budget 12000"):
        compile_policy(
            {
                "global_budget": 12000,
                "hosts": {"too-fast.example": {"rate_limit": rate}},
            }
        )


def test_compile_allows_rate_equal_to_global_budget():
    from safeyolo.policy.compiler import compile_policy

    result = compile_policy(
        {
            "global_budget": 12000,
            "hosts": {"equal.example": {"rate_limit": 12000}},
        }
    )
    assert result["permissions"][0]["budget"] == 12000


def test_rate_less_api_rejects_policy_without_global_budget(tmp_path):
    engine, path = _engine(tmp_path, '[hosts]\n"*" = { egress = "deny" }\n')
    original = path.read_bytes()

    with pytest.raises(ValueError, match="no global network budget"):
        engine.add_host_allowance("uncapped.example")

    assert path.read_bytes() == original


def test_persistence_failure_preserves_live_and_durable_policy(tmp_path, monkeypatch):
    engine, path = _engine(
        tmp_path,
        'budget = 12000\n[hosts]\n"*" = { egress = "deny" }\n',
    )
    original = path.read_bytes()

    def fail_save(_path, _document):
        raise OSError("disk full")

    monkeypatch.setattr("safeyolo.policy.toml_roundtrip.save_roundtrip", fail_save)
    with pytest.raises(OSError, match="disk full"):
        engine.add_host_allowance("failed.example")

    assert path.read_bytes() == original
    assert engine.evaluate_request("failed.example").effect == "deny"


def test_reload_rejection_rolls_back_saved_allowance(tmp_path, monkeypatch):
    engine, path = _engine(
        tmp_path,
        'budget = 12000\n[hosts]\n"*" = { egress = "deny" }\n',
    )
    original = path.read_bytes()
    calls = 0
    real_reload = engine._loader.reload

    def reject_once():
        nonlocal calls
        calls += 1
        return False if calls == 1 else real_reload()

    monkeypatch.setattr(engine._loader, "reload", reject_once)
    with pytest.raises(RuntimeError, match="reload rejected"):
        engine.add_host_allowance("rejected.example")

    assert path.read_bytes() == original
    assert engine.evaluate_request("rejected.example").effect == "deny"
