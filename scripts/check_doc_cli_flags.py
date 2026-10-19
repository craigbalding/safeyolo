#!/usr/bin/env python3
"""Fail when a user-facing doc mentions a `safeyolo` command or flag that
does not exist in the current CLI surface.

Complements ``check_skill_markers.py``: markers guard against changes to
code without doc updates; this check guards against docs referencing
things the code no longer provides (or never provided).

How it works
------------

1. Read the native CLI's authoritative usage strings. Build a command/flag
   map without importing the retired Python CLI or building Rust.
2. Walk every fenced code block and inline code span in the user-facing doc
   allowlist.
3. For each invocation starting with ``safeyolo ``, parse the command path
   greedily (longest match against the surface), then classify remaining
   tokens as flags. Every ``--foo`` or short ``-f`` must be in the
   allowed-flag set for the resolved command.
4. Placeholder tokens (``$VAR``, ``<PATH>``, ``NAME``, ``PATH/TO/X``)
   and shell operators (``|``, ``&&``, ``\\``) are skipped.
5. Guard the README's two-command public entry, supported launch options and
   150-word required-prose budget. Human review checks the complete reader
   path, including prerequisites and decisions outside that section.

Exit codes
----------

    0  -- documented safeyolo commands/flags and the README quick start match.
    1  -- a documented invocation or the README quick start has drifted.
    2  -- environment problem (cannot read native usage strings, etc.).
"""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Load the shared shipped-docs allowlist (user-facing docs plus
# agent-facing skill files). Both tiers can contain `safeyolo` invocations
# that must resolve against the current native surface. Defined once in
# scripts/doc_allowlist.toml.
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from _doc_config import ALL_SHIPPED_DOCS  # noqa: E402

FENCE_RE = re.compile(r"^\s*```")
SAFEYOLO_LINE_RE = re.compile(r"^\s*safeyolo(?:\s|$)")
INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")

# Tokens that look like flags but are placeholders in prose. If we hit one,
# stop parsing the rest of the line (typical: `safeyolo agent add NAME <PATH>`
# where NAME and <PATH> are positional placeholders).
_PLACEHOLDER_RE = re.compile(r"^(?:[A-Z_][A-Z0-9_]*|<[^>]+>|\$\w+|\{[^}]+\})$")

QUICK_START_INSTALLER_URL = (
    "https://github.com/craigbalding/safeyolo/releases/latest/download/install-safeyolo.sh"
)


def _check_quick_start_commands(commands: list[str], surface: dict[str, set[str]]) -> list[str]:
    """Check the public interface, not qualification fixture identities."""
    if len(commands) != 2:
        return ["#1053: Quick start needs two setup commands; review added setup"]
    try:
        download, launch = [shlex.split(line) for line in commands]
    except ValueError as exc:
        return [f"#1053: invalid quick-start shell quoting: {exc}"]
    problems = []
    if re.search(r"[;&|`<>]|\$\(", "\n".join(commands)):
        problems.append("#1053: Quick start commands must run individually, without shell control flow")
    # Accept grouped/individual short options and their long spellings.
    curl_options = set()
    for option in download[1:-1]:
        option = {"--fail": "f", "--location": "L", "--remote-name": "O"}.get(option, option)
        if option.startswith("-"):
            curl_options.update(option[1:])
        else:
            curl_options.add(option)
    if (
        download[:1] != ["curl"]
        or download[-1:] != [QUICK_START_INSTALLER_URL]
        or curl_options != {"f", "L", "O"}
    ):
        problems.append("#1053: download the official public installer with curl's fail, location and remote-name options")
    if launch[:3] != ["bash", "install-safeyolo.sh", "--launch"]:
        problems.append("#1053: run the downloaded installer with --launch")
    else:
        error = _validate_line("safeyolo agent launch " + shlex.join(launch[3:]), surface)
        if error:
            problems.append(f"#1053: installer launch arguments: {error}")
    return problems


def _check_readme_quick_start(surface: dict[str, set[str]]) -> list[str]:
    """Catch command/prose drift; this does not prove a runtime journey."""
    readme = (REPO_ROOT / "README.md").read_text()
    match = re.search(r"^## Quick start\n(.*?)(?=^## |\Z)", readme, re.M | re.S)
    if match is None:
        return ["#1053: README Quick start section is missing"]
    commands: list[str] = []
    prose: list[str] = []
    in_fence = False
    for line in match.group(0).splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
        elif in_fence:
            if line.strip():
                commands.append(line.strip())
        elif not line.startswith(">"):
            prose.append(line)
    problems = _check_quick_start_commands(commands, surface)
    # Task/expected-output blockquotes are excluded. Count all other context,
    # headings and instructions, with Markdown links rendered as their labels.
    rendered = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", "\n".join(prose))
    words = len(rendered.replace("#", "").replace("`", "").split())
    if words > 150:
        problems.append(f"#1053: Quick start required prose has {words} words (limit 150)")
    return problems


def _native_cli_surface() -> dict[str, set[str]]:
    """Read commands/flags from the native CLI's authoritative usage strings.

    This keeps the existing source-only doc check usable before a Rust build.
    Native help and its parser are also checked by native_host_cli tests.
    """
    surface: dict[str, set[str]] = {"": set()}
    for relative in (
        "proxy/src/bin/safeyolo.rs", "proxy/src/host_commands.rs", "proxy/src/host_launch.rs", "proxy/src/demo.rs", "proxy/src/lab.rs", "proxy/src/factory.rs",
        "proxy/src/bin/safeyolo/credential_commands.rs",
        "proxy/src/coord_rooms.rs", "proxy/src/coord_operator.rs", "proxy/src/mattermost.rs",
        "proxy/src/dispatch.rs", "proxy/src/dispatch/request.rs",
        "proxy/src/factory_proposals/commands.rs", "proxy/src/operator_commands.rs",
        "proxy/src/ssh_proxy.rs", "proxy/src/guest_acquisition.rs", "proxy/src/linux_host.rs",
        "proxy/src/guest_acquisition/components.rs",
    ):
        source = (REPO_ROOT / relative).read_text()
        for literal in re.findall(r'"(safeyolo (?:[^"\\]|\\.)*)"', source):
            for usage in json.loads('"' + literal.replace("\n", r"\n") + '"').splitlines():
                if not usage.startswith("safeyolo "):
                    continue
                rest = usage.removeprefix("safeyolo ")
                while rest.startswith("["):
                    global_options, rest = rest.split("]", 1)
                    surface[""].update(re.findall(r"--?[a-z][a-z0-9-]*", global_options))
                    rest = rest.strip()
                flags = set(re.findall(r"(?<![\w-])--?[a-z][a-z0-9-]*", rest))
                paths = [""]
                for token in rest.split():
                    if not re.fullmatch(r"[a-z][a-z-]*(?:\|[a-z][a-z-]*)*", token):
                        break
                    paths = [" ".join((path, word)).strip() for path in paths for word in token.split("|")]
                    for path in paths:
                        surface.setdefault(path, set())
                for path in paths:
                    surface[path].update(flags)
    return surface


def _load_cli_surface() -> dict[str, set[str]]:
    """Return the native commands and flags used by shipped guidance."""
    return _native_cli_surface()


def _extract_safeyolo_invocations(doc_path: Path) -> list[tuple[int, str]]:
    """Return each fenced or inline-code SafeYolo invocation."""  # DOC: docs/technical-writing.md
    invocations: list[tuple[int, str]] = []
    in_fence = False
    for i, raw in enumerate(doc_path.read_text().splitlines(), start=1):
        if FENCE_RE.match(raw):
            in_fence = not in_fence
            continue
        if not in_fence:
            for match in INLINE_CODE_RE.finditer(raw):
                inline = match.group(1).strip()
                if inline.startswith("safeyolo "):
                    invocations.append((i, inline))
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
    try:
        tokens = shlex.split(line)
    except ValueError as exc:
        return f"invalid shell quoting: {exc}"
    if not tokens or tokens[0] != "safeyolo":
        return None  # not a safeyolo invocation; defensive

    # Resolve the longest known command path. A known group followed by an
    # unknown bare token is an invalid subcommand, not a positional argument.
    path: list[str] = []
    i = 1
    # Native instance selection precedes the command. Resolve the command
    # after its path value so its own flags still receive the normal check.
    if i < len(tokens) and tokens[i] in {"--root", "--config"}:
        if tokens[i] not in surface.get("", set()) or i + 1 >= len(tokens):
            return f"unknown global flag or missing path: `{tokens[i]}`"
        i += 2
    while i < len(tokens):
        candidate = " ".join(path + [tokens[i]])
        if candidate in surface:
            path.append(tokens[i])
            i += 1
        else:
            break

    key = " ".join(path)
    group_prefix = f"{key} " if key else ""
    is_group = any(
        command != key and command.startswith(group_prefix)
        for command in surface
    )
    if is_group and i < len(tokens):
        token = tokens[i]
        if (
            not token.startswith("-")
            and not _PLACEHOLDER_RE.match(token)
            and token not in ("|", "&&", "||", "\\", ";", ">", ">>", "<")
        ):
            attempted = " ".join(path + [token])
            return f"unknown command: `safeyolo {attempted}` — no such command"

    # Native entries provide --help through their existing command dispatch.
    allowed = surface.get(key, set()) | surface.get("", set()) | {"--help"}

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
    for doc_rel in sorted(ALL_SHIPPED_DOCS):
        doc_path = REPO_ROOT / doc_rel
        if not doc_path.exists():
            continue
        for lineno, line in _extract_safeyolo_invocations(doc_path):
            err = _validate_line(line, surface)
            if err:
                problems.append((Path(doc_rel), lineno, line, err))

    for err in _check_readme_quick_start(surface):
        problems.append((Path("README.md"), 1, "## Quick start", err))

    if problems:
        print(
            "check-doc-cli-flags: documented commands or the README quick start "
            "have drifted:",
            file=sys.stderr,
        )
        for doc, lineno, line, err in problems:
            print(f"  {doc}:{lineno}: {err}", file=sys.stderr)
            print(f"    → {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
