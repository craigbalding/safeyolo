"""Tests for scripts/check_doc_cli_flags.py — the CLI-flag drift detector."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_doc_cli_flags.py"


def _load_module():
    # The script imports check_skill_markers via sys.path munging; make sure
    # our load respects that.
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("check_doc_cli_flags", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load_module()


# ---------------------------------------------------------------------------
# _extract_safeyolo_invocations
# ---------------------------------------------------------------------------

class TestExtractInvocations:
    def test_ignores_inline_prose_backticks(self, tmp_path: Path):
        doc = tmp_path / "d.md"
        doc.write_text(
            "Run `safeyolo start` to boot the proxy.\n"
            "```bash\nsafeyolo start\n```\n",
        )
        invocations = mod._extract_safeyolo_invocations(doc)
        assert invocations == [(3, "safeyolo start")]

    def test_captures_multiple_fenced_invocations(self, tmp_path: Path):
        doc = tmp_path / "d.md"
        doc.write_text(
            "```\nsafeyolo doctor\nsafeyolo agent list\n```\n",
        )
        invocations = mod._extract_safeyolo_invocations(doc)
        assert invocations == [(2, "safeyolo doctor"), (3, "safeyolo agent list")]

    def test_strips_shell_continuations(self, tmp_path: Path):
        doc = tmp_path / "d.md"
        doc.write_text("```\nsafeyolo start --dev \\\n```\n")
        invocations = mod._extract_safeyolo_invocations(doc)
        assert invocations == [(2, "safeyolo start --dev")]

    def test_skips_non_safeyolo_lines(self, tmp_path: Path):
        doc = tmp_path / "d.md"
        doc.write_text("```\nls -la\necho safeyolo\nsafeyolo status\n```\n")
        invocations = mod._extract_safeyolo_invocations(doc)
        assert invocations == [(4, "safeyolo status")]


# ---------------------------------------------------------------------------
# _validate_line
# ---------------------------------------------------------------------------

# Minimal fake CLI surface used by validation tests.
FAKE_SURFACE = {
    "": {"--version"},
    "start": {"--dev", "--test", "--wait", "--no-wait"},
    "stop": {"--all"},
    "agent": set(),
    "agent add": {"--host-script", "--force", "-f"},
    "agent run": {"--yolo", "--no-yolo"},
    "proxy": set(),
    "proxy web": set(),
    "proxy web share": {"--tailnet", "--port"},
}


class TestValidateLine:
    def test_valid_flag_passes(self):
        assert mod._validate_line("safeyolo start --dev", FAKE_SURFACE) is None

    def test_valid_subcommand_flag_passes(self):
        assert (
            mod._validate_line(
                "safeyolo agent add myproject ~/code --host-script setup.sh",
                FAKE_SURFACE,
            )
            is None
        )

    def test_unknown_flag_on_known_command_fails(self):
        err = mod._validate_line("safeyolo start --build", FAKE_SURFACE)
        assert err is not None
        assert "--build" in err
        assert "start" in err

    def test_unknown_command_fails(self):
        err = mod._validate_line("safeyolo token create --ttl 1h", FAKE_SURFACE)
        assert err is not None
        # "token" is unknown; resolver stops at "" root, then --ttl fails
        assert "unknown flag" in err or "unknown command" in err

    def test_positional_placeholder_ignored(self):
        assert (
            mod._validate_line("safeyolo agent add NAME PATH", FAKE_SURFACE) is None
        )

    def test_double_dash_ends_option_parsing(self):
        assert (
            mod._validate_line(
                "safeyolo agent run myproject -- bash -l", FAKE_SURFACE,
            )
            is None
        )

    def test_short_flag_valid(self):
        assert (
            mod._validate_line("safeyolo agent add x y -f", FAKE_SURFACE) is None
        )

    def test_shell_operator_ends_parsing(self):
        # `| grep` after the safeyolo command must not tank validation
        assert (
            mod._validate_line("safeyolo start | grep --line-buffered X", FAKE_SURFACE)
            is None
        )

    def test_valued_flag_with_equals(self):
        # --flag=value form must strip the value before lookup
        assert (
            mod._validate_line("safeyolo start --dev=false", FAKE_SURFACE) is None
        )

    def test_greedy_command_resolution(self):
        # `proxy web share` should be recognized as a 3-token command
        assert (
            mod._validate_line("safeyolo proxy web share --tailnet", FAKE_SURFACE)
            is None
        )
        err = mod._validate_line(
            "safeyolo proxy web share --nonsense", FAKE_SURFACE,
        )
        assert err is not None
        assert "proxy web share" in err
