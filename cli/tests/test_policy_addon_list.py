"""Tests for locked, comment-preserving addons.yaml list mutations."""

import yaml
from typer.testing import CliRunner

from safeyolo.cli import app

runner = CliRunner()


ADDONS = """\
# SafeYolo addon configuration
addons:
  # Circuit-breaker documentation must survive mutations.
  circuit_breaker:
    enabled: true
    excluded_domains:
      - localhost

  # Test-context documentation must survive mutations.
  test_context:
    target_hosts: []

  pattern_scanner:
    builtin_sets:
      - secrets
"""


def _write_addons(config_dir, content=ADDONS):
    path = config_dir / "addons.yaml"
    path.write_text(content)
    return path


def test_add_value_preserves_comments_and_unrelated_data(tmp_config_dir):
    path = _write_addons(tmp_config_dir)

    result = runner.invoke(
        app,
        ["policy", "addon-list", "add", "test_context", "target_hosts", "target.example.com"],
    )

    assert result.exit_code == 0, result.output
    assert "Added addon list value" in result.output
    text = path.read_text()
    assert "# Circuit-breaker documentation must survive mutations." in text
    assert "# Test-context documentation must survive mutations." in text
    data = yaml.safe_load(text)
    assert data["addons"]["test_context"]["target_hosts"] == ["target.example.com"]
    assert data["addons"]["circuit_breaker"]["excluded_domains"] == ["localhost"]
    assert data["addons"]["pattern_scanner"]["builtin_sets"] == ["secrets"]


def test_add_value_is_idempotent(tmp_config_dir):
    path = _write_addons(tmp_config_dir)
    args = ["policy", "addon-list", "add", "test_context", "target_hosts", "target.example.com"]
    first = runner.invoke(app, args)
    assert first.exit_code == 0
    after_first = path.read_text()

    second = runner.invoke(app, args)

    assert second.exit_code == 0
    assert "Unchanged addon list value" in second.output
    assert path.read_text() == after_first


def test_add_value_appends_to_existing_block_list(tmp_config_dir):
    path = _write_addons(tmp_config_dir)

    result = runner.invoke(
        app,
        ["policy", "addon-list", "add", "circuit_breaker", "excluded_domains", "dev.example.com"],
    )

    assert result.exit_code == 0, result.output
    values = yaml.safe_load(path.read_text())["addons"]["circuit_breaker"]["excluded_domains"]
    assert values == ["localhost", "dev.example.com"]


def test_remove_value_and_missing_remove_are_idempotent(tmp_config_dir):
    path = _write_addons(tmp_config_dir)

    removed = runner.invoke(
        app,
        ["policy", "addon-list", "remove", "circuit_breaker", "excluded_domains", "localhost"],
    )
    missing = runner.invoke(
        app,
        ["policy", "addon-list", "remove", "circuit_breaker", "excluded_domains", "localhost"],
    )

    assert removed.exit_code == 0, removed.output
    assert missing.exit_code == 0, missing.output
    assert "Unchanged addon list value" in missing.output
    assert yaml.safe_load(path.read_text())["addons"]["circuit_breaker"]["excluded_domains"] == []


def test_add_creates_missing_addon_and_setting(tmp_config_dir):
    path = _write_addons(tmp_config_dir, "# heading\naddons:\n  existing:\n    enabled: true\n")

    result = runner.invoke(
        app,
        ["policy", "addon-list", "add", "test_context", "target_hosts", "target.example.com"],
    )

    assert result.exit_code == 0, result.output
    text = path.read_text()
    assert "# heading" in text
    data = yaml.safe_load(text)
    assert data["addons"]["existing"]["enabled"] is True
    assert data["addons"]["test_context"]["target_hosts"] == ["target.example.com"]


def test_add_handles_unterminated_mapping_header(tmp_config_dir):
    path = _write_addons(tmp_config_dir, "addons:")

    result = runner.invoke(
        app,
        ["policy", "addon-list", "add", "test_context", "target_hosts", "target.example.com"],
    )

    assert result.exit_code == 0, result.output
    assert yaml.safe_load(path.read_text()) == {
        "addons": {
            "test_context": {"target_hosts": ["target.example.com"]},
        },
    }


def test_add_handles_unterminated_addon_header(tmp_config_dir):
    path = _write_addons(tmp_config_dir, "addons:\n  test_context:")

    result = runner.invoke(
        app,
        ["policy", "addon-list", "add", "test_context", "target_hosts", "target.example.com"],
    )

    assert result.exit_code == 0, result.output
    assert yaml.safe_load(path.read_text()) == {
        "addons": {
            "test_context": {"target_hosts": ["target.example.com"]},
        },
    }


def test_non_list_setting_is_rejected_without_modifying_file(tmp_config_dir):
    path = _write_addons(
        tmp_config_dir,
        "addons:\n  test_context:\n    target_hosts: target.example.com\n",
    )
    original = path.read_text()

    result = runner.invoke(
        app,
        ["policy", "addon-list", "add", "test_context", "target_hosts", "other.example.com"],
    )

    assert result.exit_code == 1
    assert "must be a list of strings" in result.output
    assert path.read_text() == original


def test_missing_addons_file_is_rejected(tmp_config_dir):
    result = runner.invoke(
        app,
        ["policy", "addon-list", "add", "test_context", "target_hosts", "target.example.com"],
    )

    assert result.exit_code == 1
    assert "run 'safeyolo init'" in result.output


def test_rejects_ambiguous_inline_addons_mapping(tmp_config_dir):
    path = _write_addons(tmp_config_dir, "addons: {}\n")
    original = path.read_text()

    result = runner.invoke(
        app,
        ["policy", "addon-list", "add", "test_context", "target_hosts", "target.example.com"],
    )

    assert result.exit_code == 1
    assert "inline value" in result.output
    assert path.read_text() == original
