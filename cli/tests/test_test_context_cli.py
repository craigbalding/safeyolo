"""Tests for the first-party X-Test-Context command."""

from safeyolo.cli import app


def test_default_output_contains_every_canonical_dimension(cli_runner):
    result = cli_runner.invoke(
        app,
        [
            "test-context",
            "--run",
            "sec3",
            "--agent",
            "logic",
            "--role",
            "guest",
            "--suite",
            "payment",
            "--subject",
            "CTRL-PAY-011",
            "--step",
            "4",
            "--test",
            "PAY-011-return",
            "--intent",
            "forge-return",
            "--expect",
            "blocked",
        ],
    )

    assert result.exit_code == 0
    assert result.output.strip() == (
        "run=sec3;agent=logic;role=guest;suite=payment;subject=CTRL-PAY-011;"
        "step=4;test=PAY-011-return;intent=forge-return;expect=blocked"
    )


def test_header_output_and_sorted_additional_fields(cli_runner):
    result = cli_runner.invoke(
        app,
        [
            "test-context",
            "--agent",
            "logic",
            "--run",
            "sec3",
            "--field",
            "zeta=last",
            "--field",
            "alpha=first",
            "--header",
        ],
    )

    assert result.exit_code == 0
    assert result.output.strip() == ("X-Test-Context: run=sec3;agent=logic;alpha=first;zeta=last")


def test_write_atomically_replaces_watched_file_and_still_prints_value(cli_runner, tmp_path):
    target = tmp_path / "watched" / "context"
    result = cli_runner.invoke(
        app,
        [
            "test-context",
            "--run",
            "sec3",
            "--agent",
            "logic",
            "--test",
            "PAY-011-return",
            "--write",
            str(target),
        ],
    )

    expected = "run=sec3;agent=logic;test=PAY-011-return"
    assert result.exit_code == 0
    assert result.output.strip() == expected
    assert target.read_text() == expected
    assert not list(target.parent.glob(f".{target.name}.*.tmp"))


def test_missing_required_field_is_rejected(cli_runner):
    result = cli_runner.invoke(app, ["test-context", "--run", "sec3"])
    assert result.exit_code == 2
    assert "missing required context field(s): agent" in result.output


def test_invalid_value_is_rejected_without_slugging(cli_runner):
    result = cli_runner.invoke(
        app,
        ["test-context", "--run", "sec3", "--agent", "logic", "--intent", "forge return"],
    )
    assert result.exit_code == 2
    assert "outside [A-Za-z0-9_.:-]" in result.output


def test_duplicate_named_option_is_rejected(cli_runner):
    result = cli_runner.invoke(
        app,
        [
            "test-context",
            "--run",
            "first",
            "--run",
            "second",
            "--agent",
            "logic",
        ],
    )
    assert result.exit_code == 2
    assert "duplicate helper field: run" in result.output


def test_duplicate_additional_field_is_rejected(cli_runner):
    result = cli_runner.invoke(
        app,
        [
            "test-context",
            "--run",
            "sec3",
            "--agent",
            "logic",
            "--field",
            "trace=one",
            "--field",
            "trace=two",
        ],
    )
    assert result.exit_code == 2
    assert "duplicate helper field: trace" in result.output


def test_canonical_field_escape_hatch_is_rejected(cli_runner):
    result = cli_runner.invoke(
        app,
        [
            "test-context",
            "--run",
            "sec3",
            "--agent",
            "logic",
            "--field",
            "role=guest",
        ],
    )
    assert result.exit_code == 2
    assert "must use --role" in result.output
