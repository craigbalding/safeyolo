#!/usr/bin/env python3
"""Fail when a user-facing doc mentions a `safeyolo` command or flag that
does not exist in the current CLI surface.

Complements ``check_skill_markers.py``: markers guard against changes to
code without doc updates; this check guards against docs referencing
things the code no longer provides (or never provided).

How it works
------------

1. Introspect the Typer ``app`` and walk its Click command tree.
   Build ``{"agent add": {"--host-script", "--force", "-f", ...},
            "start":     {"--dev", "--test", ...}, ...}``.
2. Walk every fenced code block in the user-facing doc allowlist.
3. For each line starting with ``safeyolo ``, parse the command path
   greedily (longest match against the surface), then classify remaining
   tokens as flags. Every ``--foo`` or short ``-f`` must be in the
   allowed-flag set for the resolved command.
4. Placeholder tokens (``$VAR``, ``<PATH>``, ``NAME``, ``PATH/TO/X``)
   and shell operators (``|``, ``&&``, ``\\``) are skipped.

Exit codes
----------

    0  -- every safeyolo invocation in the docs resolves to a real command
          and uses only real flags.
    1  -- at least one invocation is invalid.
    2  -- environment problem (cannot import the CLI, etc.).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI_SRC = REPO_ROOT / "cli" / "src"

# Load the shared user-facing docs allowlist. Drift-detection scope is
# defined once in scripts/doc_allowlist.toml.
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from _doc_config import USER_FACING_DOCS  # noqa: E402


FENCE_RE = re.compile(r"^\s*```")
SAFEYOLO_LINE_RE = re.compile(r"^\s*safeyolo(?:\s|$)")

# Tokens that look like flags but are placeholders in prose. If we hit one,
# stop parsing the rest of the line (typical: `safeyolo agent add NAME <PATH>`
# where NAME and <PATH> are positional placeholders).
_PLACEHOLDER_RE = re.compile(r"^(?:[A-Z_][A-Z0-9_]*|<[^>]+>|\$\w+|\{[^}]+\})$")


def _load_cli_surface() -> dict[str, set[str]]:
    """Return {command_path: allowed_flag_set} for the full Typer surface.

    ``command_path`` uses space-separated tokens as they'd be typed on the
    CLI, e.g. ``"agent add"`` or ``"policy host add"``. The empty string is
    the top-level app itself (only holds global flags).

    Duck-types Group/Option because Typer's TyperGroup/TyperOption do not
    subclass their Click counterparts in current versions.
    """
    sys.path.insert(0, str(CLI_SRC))
    import typer

    from safeyolo.cli import app

    surface: dict[str, set[str]] = {}

    def walk(cmd, path: list[str]) -> None:
        key = " ".join(path)
        flags: set[str] = set()
        for p in getattr(cmd, "params", []):
            opts = list(getattr(p, "opts", []) or [])
            secondary = list(getattr(p, "secondary_opts", []) or [])
            # An option is a param with at least one dash-prefixed opt string;
            # arguments have bare names like `"name"`.
            option_opts = [o for o in opts if o.startswith("-")]
            option_secondary = [o for o in secondary if o.startswith("-")]
            flags.update(option_opts)
            flags.update(option_secondary)
        surface[key] = flags
        # Group check: presence of `.commands` mapping is the reliable signal.
        subcommands = getattr(cmd, "commands", None)
        if isinstance(subcommands, dict):
            for sub_name in subcommands:
                walk(subcommands[sub_name], path + [sub_name])

    walk(typer.main.get_command(app), [])
    return surface


def _extract_safeyolo_invocations(doc_path: Path) -> list[tuple[int, str]]:
    """Return [(line_number, invocation), ...] for every safeyolo line inside
    a fenced code block (only fenced blocks — inline `code` is prose)."""
    invocations: list[tuple[int, str]] = []
    in_fence = False
    for i, raw in enumerate(doc_path.read_text().splitlines(), start=1):
        if FENCE_RE.match(raw):
            in_fence = not in_fence
            continue
        if not in_fence:
            continue
        if SAFEYOLO_LINE_RE.match(raw):
            # Strip trailing `#` comments and shell continuations
            line = raw.split("#", 1)[0].rstrip(" \\").strip()
            invocations.append((i, line))
    return invocations


def _validate_line(
    line: str, surface: dict[str, set[str]],
) -> str | None:
    """Return an error message if the invocation is invalid, else None.

    Command resolution is greedy: keep extending the command path as long
    as the next token is a known subcommand. Then treat remaining tokens as
    flags (with values interleaved) or positional placeholders.
    """
    tokens = line.split()
    if not tokens or tokens[0] != "safeyolo":
        return None  # not a safeyolo invocation; defensive

    # Greedy resolve command path
    path: list[str] = []
    i = 1
    while i < len(tokens):
        candidate = " ".join(path + [tokens[i]])
        if candidate in surface and surface[candidate] is not None:
            # Only extend if this is a group (has sub-commands) or exact match
            path.append(tokens[i])
            i += 1
            # Peek: is (path + next_token) also a valid command? if not, stop
            if i < len(tokens):
                deeper = " ".join(path + [tokens[i]])
                if deeper not in surface:
                    break
        else:
            break

    key = " ".join(path)
    if key not in surface and key != "":
        return f"unknown command: `safeyolo {key}` — no such command"

    allowed = surface.get(key, set()) | surface.get("", set())  # inherit global opts

    # Walk remaining tokens; validate flags
    for tok in tokens[i:]:
        if tok in ("|", "&&", "||", "\\", ";", ">", ">>", "<", "2>&1"):
            break  # shell operator; stop scanning
        if tok == "--":
            break  # POSIX end-of-options; everything after is positional
        if _PLACEHOLDER_RE.match(tok):
            continue  # positional placeholder
        if tok.startswith("--"):
            flag = tok.split("=", 1)[0]
            if flag not in allowed:
                return f"unknown flag `{flag}` for `safeyolo {key}`"
        elif tok.startswith("-") and len(tok) > 1 and not tok[1].isdigit():
            # short options: could be -f or -fVALUE
            if tok not in allowed and tok[:2] not in allowed:
                return f"unknown flag `{tok[:2]}` for `safeyolo {key}`"
        # Otherwise it's a value or positional; not our concern.
    return None


def main() -> int:
    try:
        surface = _load_cli_surface()
    except Exception as exc:  # noqa: BLE001
        print(f"check-doc-cli-flags: cannot introspect CLI: {exc}", file=sys.stderr)
        return 2

    problems: list[tuple[Path, int, str, str]] = []
    for doc_rel in sorted(USER_FACING_DOCS):
        doc_path = REPO_ROOT / doc_rel
        if not doc_path.exists():
            continue
        for lineno, line in _extract_safeyolo_invocations(doc_path):
            err = _validate_line(line, surface)
            if err:
                problems.append((Path(doc_rel), lineno, line, err))

    if problems:
        print(
            "check-doc-cli-flags: user-facing docs reference CLI surface that "
            "does not exist:",
            file=sys.stderr,
        )
        for doc, lineno, line, err in problems:
            print(f"  {doc}:{lineno}: {err}", file=sys.stderr)
            print(f"    → {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
