"""Tests for the shared X-SafeYolo-Test-Context parser and formatter contract."""

import os
from unittest.mock import patch

import pytest

import safeyolo.test_context_contract as context_contract
from safeyolo.test_context_contract import (
    CANONICAL_KEYS,
    MAX_CONTEXT_PAIRS,
    REQUIRED_KEYS,
    TEST_CONTEXT_HEADER,
    atomic_write_test_context,
    format_test_context,
    format_test_context_header,
    parse_test_context,
)

ALL_CANONICAL_FIELDS = {
    "run": "sec3",
    "agent": "logic",
    "role": "guest",
    "suite": "payment",
    "subject": "CTRL-PAY-011",
    "step": "4",
    "test": "PAY-011-return",
    "intent": "forge-return",
    "expect": "blocked",
}


def test_contract_constants_are_complete_and_ordered():
    assert TEST_CONTEXT_HEADER == "X-SafeYolo-Test-Context"
    assert REQUIRED_KEYS == ("run", "agent")
    assert CANONICAL_KEYS == tuple(ALL_CANONICAL_FIELDS)


def test_every_canonical_dimension_formats_in_contract_order():
    reverse_input = dict(reversed(ALL_CANONICAL_FIELDS.items()))
    value = format_test_context(reverse_input)

    assert value == (
        "run=sec3;agent=logic;role=guest;suite=payment;subject=CTRL-PAY-011;"
        "step=4;test=PAY-011-return;intent=forge-return;expect=blocked"
    )
    assert parse_test_context(value) == ALL_CANONICAL_FIELDS


def test_additional_fields_sort_after_canonical_fields():
    value = format_test_context(
        [
            ("zeta", "last"),
            ("agent", "logic"),
            ("alpha", "first"),
            ("run", "sec3"),
        ]
    )
    assert value == "run=sec3;agent=logic;alpha=first;zeta=last"


def test_complete_header_uses_canonical_value():
    assert format_test_context_header({"agent": "logic", "run": "sec3"}) == ("X-SafeYolo-Test-Context: run=sec3;agent=logic")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "run=sec3",
        "agent=logic",
        "run=sec 3;agent=logic",
        "run=sec3;agent=logic tool",
        "run=sec3;agent=logic;bad key=value",
        "run=sec3;agent=logic;empty=",
        "run-sec3;agent=logic",
        "run=first;agent=logic;run=second",
    ],
)
def test_parser_rejects_invalid_or_ambiguous_values(value):
    with pytest.raises(context_contract.TestContextError):
        parse_test_context(value)


def test_parser_rejects_more_than_max_pairs_instead_of_truncating():
    pairs = [("run", "sec3"), ("agent", "logic")]
    pairs.extend((f"key{index}", f"value{index}") for index in range(MAX_CONTEXT_PAIRS - 1))
    with pytest.raises(context_contract.TestContextError, match="more than"):
        parse_test_context(";".join(f"{key}={value}" for key, value in pairs))


def test_parser_preserves_safe_values_without_slugging():
    parsed = parse_test_context("run=Sec3;agent=Logic_Tool;intent=Forge.Return")
    assert parsed["run"] == "Sec3"
    assert parsed["agent"] == "Logic_Tool"
    assert parsed["intent"] == "Forge.Return"


def test_formatter_rejects_duplicate_pairs():
    with pytest.raises(context_contract.TestContextError, match="duplicate context key: run"):
        format_test_context([("run", "first"), ("agent", "logic"), ("run", "second")])


def test_atomic_writer_replaces_file_with_no_newline(tmp_path):
    target = tmp_path / "watch" / "context"
    target.parent.mkdir()
    target.write_text("run=old;agent=old")
    value = "run=sec3;agent=logic;test=PAY-011-return"

    with patch("safeyolo.test_context_contract.os.replace", wraps=os.replace) as replace:
        atomic_write_test_context(target, value)

    assert target.read_text() == value
    assert replace.call_count == 1
    assert not list(target.parent.glob(f".{target.name}.*.tmp"))


def test_atomic_writer_preserves_old_file_and_cleans_temp_on_failure(tmp_path):
    target = tmp_path / "context"
    target.write_text("run=old;agent=old")

    with (
        patch(
            "safeyolo.test_context_contract.os.replace",
            side_effect=OSError("replace failed"),
        ),
        pytest.raises(OSError, match="replace failed"),
    ):
        atomic_write_test_context(target, "run=sec3;agent=logic")

    assert target.read_text() == "run=old;agent=old"
    assert not list(tmp_path.glob(f".{target.name}.*.tmp"))
