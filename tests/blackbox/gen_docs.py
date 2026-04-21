#!/usr/bin/env python3
"""Generate docs/blackbox-coverage.md from test docstrings.

Walks tests/blackbox/ via AST, extracts each test class's Title+Why and
each test function's Title+What+Why, and renders a grouped markdown doc.

The goal is an operator-facing answer to "what does SafeYolo's blackbox
suite actually verify?" — no drift, because the docstrings are the
source of truth and the lint (tests/blackbox/_docstring_lint.py)
rejects missing structure at test-collection time.

Run manually or via pre-commit when blackbox tests change.
"""
from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BB_DIR = REPO_ROOT / "tests" / "blackbox"
OUT_PATH = REPO_ROOT / "docs" / "blackbox-coverage.md"

# Suites we walk and how to label them in the doc.
SUITES = [
    ("Host-side", BB_DIR / "host"),
    ("In-sandbox (isolation)", BB_DIR / "isolation"),
]


@dataclass
class TestFunc:
    name: str
    title: str
    what: str
    why: str


@dataclass
class TestClass:
    name: str
    title: str
    why: str
    funcs: list[TestFunc] = field(default_factory=list)


def _split_docstring(doc: str) -> tuple[str, dict[str, str]]:
    """Return (title, sections) from a docstring.

    Sections is a dict keyed by 'what' | 'why' | etc., values are the
    text after the marker (may span multiple lines, whitespace-trimmed).
    """
    if not doc:
        return "", {}
    text = doc.strip()
    lines = text.splitlines()
    title = lines[0].strip()
    # Split the rest on "Word:" markers at start of line.
    rest = "\n".join(lines[1:])
    sections: dict[str, str] = {}
    current_key: str | None = None
    buf: list[str] = []
    for raw in rest.splitlines():
        m = re.match(r"\s*([A-Z][a-zA-Z]*):\s*(.*)", raw)
        if m:
            if current_key is not None:
                sections[current_key] = "\n".join(buf).strip()
            current_key = m.group(1).lower()
            buf = [m.group(2)] if m.group(2) else []
        elif current_key is not None:
            buf.append(raw)
    if current_key is not None:
        sections[current_key] = "\n".join(buf).strip()
    return title, sections


def _parse_file(path: Path) -> list[TestClass]:
    """Extract test classes + test functions from a file."""
    tree = ast.parse(path.read_text())
    classes: list[TestClass] = []
    for node in tree.body:
        if not (isinstance(node, ast.ClassDef) and node.name.startswith("Test")):
            continue
        cls_doc = ast.get_docstring(node)
        title, sections = _split_docstring(cls_doc or "")
        tc = TestClass(
            name=node.name,
            title=title,
            why=sections.get("why", ""),
        )
        for item in node.body:
            if not (isinstance(item, ast.FunctionDef) and item.name.startswith("test_")):
                continue
            fn_doc = ast.get_docstring(item)
            ftitle, fsections = _split_docstring(fn_doc or "")
            tc.funcs.append(
                TestFunc(
                    name=item.name,
                    title=ftitle,
                    what=fsections.get("what", ""),
                    why=fsections.get("why", ""),
                )
            )
        classes.append(tc)
    return classes


def _render(suites: list[tuple[str, list[tuple[Path, list[TestClass]]]]]) -> str:
    """Render the collected classes as markdown."""
    out: list[str] = []
    out.append("# SafeYolo Blackbox Test Coverage")
    out.append("")
    out.append(
        "Generated from test docstrings in `tests/blackbox/`. "
        "Do not edit by hand — run `python3 tests/blackbox/gen_docs.py`."
    )
    out.append("")
    out.append(
        "Each entry states the security property the test asserts and the "
        "threat it defends against. The probe (What) describes the specific "
        "observation used to confirm the property."
    )
    out.append("")

    total_classes = sum(len(files) for _, files in suites for files in files)  # noqa: B035
    total_tests = sum(
        len(cls.funcs)
        for _, files in suites
        for _, classes in files
        for cls in classes
    )
    total_classes = sum(
        len(classes)
        for _, files in suites
        for _, classes in files
    )
    out.append(f"**{total_tests} tests across {total_classes} threat categories.**")
    out.append("")

    for suite_label, files in suites:
        out.append(f"## {suite_label}")
        out.append("")
        for path, classes in files:
            if not classes:
                continue
            rel = path.relative_to(REPO_ROOT)
            out.append(f"### `{rel}`")
            out.append("")
            for cls in classes:
                out.append(f"#### {cls.name} — {cls.title}")
                out.append("")
                if cls.why:
                    out.append(f"**Threat:** {cls.why}")
                    out.append("")
                for fn in cls.funcs:
                    out.append(f"- **`{fn.name}`** — {fn.title}")
                    if fn.what:
                        out.append(f"  - *Probe:* {fn.what}")
                    if fn.why:
                        out.append(f"  - *Consequence if unasserted:* {fn.why}")
                out.append("")
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    suites: list[tuple[str, list[tuple[Path, list[TestClass]]]]] = []
    for label, root in SUITES:
        files: list[tuple[Path, list[TestClass]]] = []
        # rglob so phase subdirectories (host/proxy/, host/security/, ...)
        # are walked. A flat glob here was the reason silently-dropped
        # test files went unnoticed in the coverage doc too.
        for path in sorted(root.rglob("test_*.py")):
            classes = _parse_file(path)
            if classes:
                files.append((path, classes))
        suites.append((label, files))

    rendered = _render(suites)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # --check mode: fail if the on-disk doc is stale.
    if "--check" in sys.argv:
        current = OUT_PATH.read_text() if OUT_PATH.exists() else ""
        if current != rendered:
            print(
                f"{OUT_PATH} is out of date. "
                f"Run: python3 tests/blackbox/gen_docs.py",
                file=sys.stderr,
            )
            return 1
        return 0

    OUT_PATH.write_text(rendered)
    print(f"Wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
