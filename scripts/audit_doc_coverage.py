#!/usr/bin/env python3
"""Report drift-detection coverage across user-facing docs.

Soft check — always exits 0. Its purpose is *visibility*: which docs
carry how many bindings, which security keywords lack any binding, and
where the biggest gaps are.

Coverage is measured across the four active mechanisms:

- ``# DOC: <doc>`` markers in .py/.sh source (co-change contract)
- ``[[assertion]]`` entries in scripts/doc_constants.toml (pinned values)
- ``[[rule]]`` entries in scripts/doc_forbidden.toml (prose blacklist)
- Automatic: check_doc_cli_flags introspects every doc's ``safeyolo``
  invocations against the Typer surface (not counted here since it's
  auto-applied to every listed doc)

Usage
-----

    scripts/audit_doc_coverage.py           # full report
    scripts/audit_doc_coverage.py --brief   # per-doc counts only
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from _doc_config import USER_FACING_DOCS  # noqa: E402

CONSTANTS_PATH = REPO_ROOT / "scripts" / "doc_constants.toml"
FORBIDDEN_PATH = REPO_ROOT / "scripts" / "doc_forbidden.toml"

DOC_MARKER_RE = re.compile(r"#\s*DOC:\s*([\w./#, -]+?)(?:\s*(?:#(?!\w).*)?)?$")
SOURCE_SUFFIXES = {".py", ".sh"}
EXCLUDED_PATH_PREFIXES = ("tests/", ".git/", "cli/src/safeyolo.egg-info/")

# Security-relevant keyword set. If any doc mentions one of these, the
# security-invariant probably deserves a binding. This is deliberately
# curated (not derived) so the audit stays stable and reader-legible.
SECURITY_KEYWORDS: dict[str, str] = {
    "no external network interface": "network isolation",
    "loopback-only":                  "network isolation",
    "unshare -Un":                    "rootless userns",
    "no CAP_SYS_ADMIN":               "capability boundary",
    "uid 100000":                     "subuid mapping",
    "100000":                         "subuid mapping",
    "127.0.0.1":                      "admin API bind",
    "loopback only":                  "admin API bind",
    "bearer token":                   "admin API auth",
    "compare_digest":                 "admin API auth",
    "HMAC":                           "credential fingerprinting",
    "SHA-256":                        "credential fingerprinting",
    "SHA256":                         "credential fingerprinting",
    "homoglyph":                      "domain spoofing detection",
    "GCRA":                           "rate limiting",
    "path trick":                     "canonicalisation",
    "credential injection":           "credential vault",
    "sgw_":                           "gateway token",
    "capability contract":            "gateway capability",
    "wait_for_approval":              "approval workflow",
    "HTTP 428":                       "block-response code",
    "block mode":                     "startup fail-closed",
    "PROXY protocol v2":              "STALE claim (see forbidden)",
    "Docker socket":                  "STALE claim (see forbidden)",
}


# ---------------------------------------------------------------------------
# Coverage sources
# ---------------------------------------------------------------------------

def _all_source_files() -> list[Path]:
    """Every .py / .sh file in the repo, excluding tests/ and generated dirs."""
    files: list[Path] = []
    for suffix in SOURCE_SUFFIXES:
        for path in REPO_ROOT.rglob(f"*{suffix}"):
            rel = path.relative_to(REPO_ROOT)
            rel_str = str(rel)
            if any(rel_str.startswith(p) for p in EXCLUDED_PATH_PREFIXES):
                continue
            files.append(path)
    return files


def _marker_bindings() -> dict[str, list[tuple[Path, int]]]:
    """{doc_ref: [(source_file, line_no), ...]} for every # DOC: marker."""
    bindings: dict[str, list[tuple[Path, int]]] = defaultdict(list)
    for src in _all_source_files():
        try:
            for i, line in enumerate(src.read_text().splitlines(), start=1):
                m = DOC_MARKER_RE.search(line)
                if not m:
                    continue
                for ref in m.group(1).split(","):
                    ref = ref.strip().split("#", 1)[0]
                    if ref:
                        bindings[ref].append((src.relative_to(REPO_ROOT), i))
        except (OSError, UnicodeDecodeError):
            continue
    return bindings


def _constants_bindings() -> dict[str, list[str]]:
    """{doc_ref: [assertion_name, ...]} for every doc_constants.toml entry."""
    bindings: dict[str, list[str]] = defaultdict(list)
    if not CONSTANTS_PATH.exists():
        return bindings
    with CONSTANTS_PATH.open("rb") as f:
        cfg = tomllib.load(f)
    for a in cfg.get("assertion", []):
        name = a.get("name", "<unnamed>")
        for doc in a.get("docs", []):
            bindings[doc].append(name)
    return bindings


def _forbidden_bindings() -> dict[str, list[str]]:
    """{doc_ref: [rule_name, ...]} for every doc_forbidden.toml rule."""
    bindings: dict[str, list[str]] = defaultdict(list)
    if not FORBIDDEN_PATH.exists():
        return bindings
    with FORBIDDEN_PATH.open("rb") as f:
        cfg = tomllib.load(f)
    for r in cfg.get("rule", []):
        name = r.get("name", "<unnamed>")
        for doc in r.get("docs", []):
            bindings[doc].append(name)
    return bindings


# ---------------------------------------------------------------------------
# Keyword coverage
# ---------------------------------------------------------------------------

def _keyword_hits(doc_path: Path) -> dict[str, list[int]]:
    """{keyword: [line_no, ...]} for every SECURITY_KEYWORDS phrase in doc."""
    hits: dict[str, list[int]] = defaultdict(list)
    try:
        text = doc_path.read_text()
    except (OSError, UnicodeDecodeError):
        return hits
    for i, line in enumerate(text.splitlines(), start=1):
        for kw in SECURITY_KEYWORDS:
            if kw in line:
                hits[kw].append(i)
    return hits


def _keyword_has_binding(
    doc_rel: str,
    kw: str,
    marker_b: dict[str, list],
    const_b: dict[str, list],
    forbid_b: dict[str, list],
) -> bool:
    """Does the (doc, keyword) pair have ANY binding pointing at doc?

    This is a coarse heuristic — it does not verify the binding actually
    defends the specific keyword, only that the doc is under active
    drift-detection for SOMETHING. A doc with zero bindings but 10
    security keywords is a real gap.
    """
    return (
        bool(marker_b.get(doc_rel))
        or bool(const_b.get(doc_rel))
        or bool(forbid_b.get(doc_rel))
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _print_per_doc_counts(
    marker_b, const_b, forbid_b, out=sys.stdout,
) -> None:
    print("=== DOC BINDING COUNTS ===\n", file=out)
    print(f"{'Doc':44}  {'Markers':>8}  {'Consts':>7}  {'Forbid':>7}  {'Total':>6}", file=out)
    print("-" * 80, file=out)
    for doc in sorted(USER_FACING_DOCS):
        m = len(marker_b.get(doc, []))
        c = len(const_b.get(doc, []))
        f = len(forbid_b.get(doc, []))
        tot = m + c + f
        marker = " " if tot else "!"
        print(f"{marker} {doc:42}  {m:>8}  {c:>7}  {f:>7}  {tot:>6}", file=out)
    # Totals are per (doc, binding) counts across the allowlist only. Refs
    # pointing outside the allowlist show up in _print_orphan_markers.
    total_m = sum(len(marker_b.get(d, [])) for d in USER_FACING_DOCS)
    total_c = sum(len(const_b.get(d, [])) for d in USER_FACING_DOCS)
    total_f = sum(len(forbid_b.get(d, [])) for d in USER_FACING_DOCS)
    print("-" * 80, file=out)
    print(f"  {'TOTAL':42}  {total_m:>8}  {total_c:>7}  {total_f:>7}  {total_m + total_c + total_f:>6}", file=out)
    print(file=out)


def _print_keyword_coverage(
    marker_b, const_b, forbid_b, out=sys.stdout,
) -> None:
    print("=== SECURITY KEYWORD COVERAGE ===\n", file=out)
    print(
        "Keywords found in each user-facing doc, and whether that doc has any\n"
        "active binding at all. Docs with keywords but no bindings are the\n"
        "highest-value gaps to close next.\n",
        file=out,
    )
    for doc_rel in sorted(USER_FACING_DOCS):
        doc_path = REPO_ROOT / doc_rel
        if not doc_path.exists():
            continue
        hits = _keyword_hits(doc_path)
        if not hits:
            continue
        has_binding = _keyword_has_binding(
            doc_rel, "", marker_b, const_b, forbid_b,
        )
        gap = "" if has_binding else "  << NO BINDINGS ANYWHERE"
        print(f"{doc_rel}{gap}", file=out)
        for kw, lines in sorted(hits.items()):
            line_summary = ",".join(str(ln) for ln in lines[:4])
            more = f"...+{len(lines)-4}" if len(lines) > 4 else ""
            category = SECURITY_KEYWORDS[kw]
            print(f"    L{line_summary}{more}: '{kw}' [{category}]", file=out)
        print(file=out)


def _print_orphan_markers(
    marker_b, const_b, forbid_b, out=sys.stdout,
) -> None:
    """DOC refs that point at unknown / not-in-allowlist docs."""
    all_refs = set(marker_b) | set(const_b) | set(forbid_b)
    unknown = sorted(r for r in all_refs if r not in USER_FACING_DOCS)
    if not unknown:
        return
    print("=== BINDINGS POINTING OUTSIDE THE ALLOWLIST ===\n", file=out)
    for r in unknown:
        print(f"  {r}   (should be added to scripts/doc_allowlist.toml, or removed)", file=out)
    print(file=out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--brief", action="store_true", help="Per-doc counts only")
    args = parser.parse_args()

    marker_b = _marker_bindings()
    const_b = _constants_bindings()
    forbid_b = _forbidden_bindings()

    _print_per_doc_counts(marker_b, const_b, forbid_b)
    if not args.brief:
        _print_keyword_coverage(marker_b, const_b, forbid_b)
        _print_orphan_markers(marker_b, const_b, forbid_b)
    return 0


if __name__ == "__main__":
    sys.exit(main())
