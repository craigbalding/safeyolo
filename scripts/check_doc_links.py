#!/usr/bin/env python3
"""Fail when a user-facing doc references a repo-relative path that no
longer exists on disk.

Scope: **repo-relative links only**. External URLs (http:, https:, mailto:)
are skipped — they flake, hit rate limits, and require network in CI.
This check catches the drift class that actually matters here: files
being renamed or moved while docs still reference the old path.

Recognized reference forms in a Markdown doc:

- ``[text](relative/path)`` — standard markdown link
- ``[text](relative/path#anchor)`` — link with fragment
- ``[text](relative/path "title")`` — link with title
- Reference-style definitions: ``[label]: relative/path``

Anchors are advisory (not validated — mapping heading→anchor is fragile).

Exit codes
----------

    0  -- every repo-relative link resolves
    1  -- one or more broken links
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from _doc_config import ALL_SHIPPED_DOCS  # noqa: E402

# Inline links: [text](target) or [text](target "title"). Target ends at
# whitespace or closing paren.
INLINE_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
# Reference-style link definitions: [label]: target
REF_DEF_RE = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)")
# Inline code spans — content inside single backticks is literal illustration,
# not a link. Stripped before regex matching to avoid false positives when
# documenting the link syntax itself (`[text](path)`).
INLINE_CODE_RE = re.compile(r"`[^`\n]*`")


def _is_external(target: str) -> bool:
    return target.startswith(("http://", "https://", "mailto:", "ftp://", "#"))


def _extract_targets(doc_path: Path) -> list[tuple[int, str]]:
    """Return [(line_number, target), ...] for every repo-relative link target.

    Content inside inline code spans (backticks) is stripped first, so
    illustrative syntax like `` `[text](path)` `` in prose is not
    mistaken for a real link.
    """
    targets: list[tuple[int, str]] = []
    for i, line in enumerate(doc_path.read_text().splitlines(), start=1):
        stripped = INLINE_CODE_RE.sub("", line)
        for m in INLINE_LINK_RE.finditer(stripped):
            targets.append((i, m.group(1)))
        m_ref = REF_DEF_RE.match(stripped)
        if m_ref:
            targets.append((i, m_ref.group(1)))
    return [(ln, t) for ln, t in targets if not _is_external(t)]


def _resolve(target: str, doc_path: Path) -> Path:
    """Resolve a link target to an absolute filesystem path.

    Absolute (leading ``/``) targets are resolved from REPO_ROOT.
    Relative targets are resolved from the doc's directory.
    Fragments (``#anchor``) are stripped before resolution.
    """
    bare = target.split("#", 1)[0]
    if not bare:  # pure fragment; already skipped by _is_external but defensive
        return doc_path
    if bare.startswith("/"):
        return (REPO_ROOT / bare.lstrip("/")).resolve()
    return (doc_path.parent / bare).resolve()


def main() -> int:
    problems: list[tuple[Path, int, str, str]] = []
    for doc_rel in sorted(ALL_SHIPPED_DOCS):
        doc_path = REPO_ROOT / doc_rel
        if not doc_path.exists():
            continue
        for lineno, target in _extract_targets(doc_path):
            resolved = _resolve(target, doc_path)
            if not resolved.exists():
                try:
                    rel = resolved.relative_to(REPO_ROOT)
                    display = str(rel)
                except ValueError:
                    display = str(resolved)
                problems.append(
                    (Path(doc_rel), lineno, target, f"resolves to missing: {display}"),
                )

    if problems:
        print(
            "check-doc-links: user-facing docs reference paths that do not exist:",
            file=sys.stderr,
        )
        for doc, lineno, target, why in problems:
            print(f"  {doc}:{lineno}: {target} -- {why}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
