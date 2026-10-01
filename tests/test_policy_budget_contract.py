"""Retained policy compiler budget hierarchy regressions."""

import pytest


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
