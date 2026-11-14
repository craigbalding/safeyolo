#!/usr/bin/env python3
"""Generate the BB control catalogue and maintained test descriptions.

Authored metadata supplies control meaning, conformance and remaining work.
Source discovery supplies exact identities, source links and runner selection.
Execution receipts remain separate from this source inventory.
"""
from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

if __package__:
    from .catalogue import render as render_catalogue
    from .selections import PYTEST_PHASES, SECTIONS
else:
    from catalogue import render as render_catalogue
    from selections import PYTEST_PHASES, SECTIONS

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BB_DIR = REPO_ROOT / "tests" / "blackbox"
OUT_PATH = REPO_ROOT / "docs" / "blackbox-coverage.md"

# Suites we walk and how to label them in the doc.
SUITES = [
    ("Installed native ingress", BB_DIR / "host/native"),
    ("Host process security", BB_DIR / "host/security"),
    ("Installed agent identity", BB_DIR / "host/identity"),
    ("Installed agent persistence and restart", BB_DIR / "host/lifecycle"),
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
    out.append("Generated from authored control metadata, maintained Python/Rust witnesses and installed runner selections. Do not edit this document by hand.")
    out.append("")
    out.append("## Regenerate and check")
    out.append("")
    out.append("From the repository root with the frozen development environment, run:")
    out.append("")
    out.append("```sh\nuv run --frozen python tests/blackbox/gen_docs.py\nuv run --frozen python tests/blackbox/gen_docs.py --check\nuv run --frozen python tests/blackbox/_docstring_lint.py\nuv run --frozen python scripts/check_blackbox_cadence.py\n```")
    out.append("")
    out.append("The checks reject unresolved identities, unclassified assurance tests, unwired selectors and stale output. "
               "Installed runs retain `pytest-PHASE.json` and `procedure.json` beside section reports. "
               "Each pytest report records the collected and selected parameter cases, numeric UID/GID, observed guest/backend lifetime, run identity and setup/call/teardown outcomes. "
               "The section and hardware readers recompute completeness against the maintained selections. "
               "Missing reports, missing or deselected required cases, required skips, failed preparation, partial procedures and failed cleanup remain incomplete. "
               "Named platform exclusions retain their reasons. Existing opt-in checks retain their explicit selection; a selected opt-in check must pass. Arbitrary skips are not exclusions. "
               "Product source, controller source and selected guest artifact identity remain separate. "
               "A source inventory does not establish deployed cadence or a passing installed run. "
               "[#1559](https://github.com/craigbalding/safeyolo/issues/1559) owns material assertion-change notification; "
               "[#889](https://github.com/craigbalding/safeyolo/issues/889) owns hardware deployment; "
               "[#838](https://github.com/craigbalding/safeyolo/issues/838) owns protected acceptance.")
    out.append("")
    out.append(render_catalogue(REPO_ROOT))
    out.append("")
    out.append("## Maintained guest and host pytest descriptions")
    out.append("")
    out.append(
        "Each entry states the security property the test asserts and the "
        "threat it defends against. The probe (What) describes the specific "
        "observation used to confirm the property."
    )
    out.append("")

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
    out.append(f"**{total_tests} distinct pytest methods across {total_classes} threat categories.**")
    out.append("")
    out.append(
        "This is a source inventory, not a passing execution receipt. The ordinary "
        "guest selection excludes root containment; the root selection runs root "
        "containment and private-key isolation. Private-key scans run under both "
        "identities; public-cert checks run as the ordinary user. "
        "Parameterization and platform/fixture skips affect executed nodes. "
        "The retired host/proxy selection is excluded."
    )
    out.append("")
    out.append("## Installed procedural selections")
    out.append("")
    out.append("`run-installed.sh` prepares once and runs these independent sections:")
    out.append("")
    out.append("| Actual lane | Selected sections |")
    out.append("|---|---|")
    for lane, sections in SECTIONS.items():
        out.append(f"| `{lane}` | {', '.join(sections)} |")
    out.append("")
    for section in sorted({s for sections in SECTIONS.values() for s in sections} - {"isolation"}):
        path = BB_DIR / ("installed_state_transition.py" if section == "continuity" else f"installed_{section}.py")
        doc = ast.get_docstring(ast.parse(path.read_text()))
        assert doc, f"selected procedure lacks a description: {path}"
        out.append(f"### `{path.relative_to(REPO_ROOT)}`")
        out.append("")
        out.append(doc)
        out.append("")
    out.append("### Installed host package")
    out.append("")
    out.append("""`run-installed-package.sh` can install a checksum-verified host archive through
the archive's own installer. The archive path does not build or install product
files from the test checkout. The default installation acquires the compatible
guest through the native OCI client. `--platform-assets` selects prepared offline
inputs; `--no-guest-download` selects a proxy-only witness.

On a disposable supported Linux host, start from this test checkout with its
Python test environment prepared. Python and uv are test-driver dependencies,
not packaged-product dependencies. The host must have the runtime prerequisites
in [installation prerequisites](installation.md#guest-prerequisites). Obtain the host archive and its SHA-256
digest from the selected release. Replace both values below with those actual
inputs. The command creates owned installation and section state under `HOME`,
downloads the default guest, and starts and stops the test runtime.

```sh
./tests/blackbox/run-installed-package.sh --package /path/to/host.tar.gz --sha256 FULL_RELEASE_SHA256 --lane systrap
```

The output names the host archive digest, package source/profile and selected
guest identities separately. The existing reports record the running installed
executables and owned cleanup. Install-to-agent-ready timing includes artifact
verification, installation and test fixture preparation. A staged input is not
a published-artifact result.

`--lane systrap` and `--lane vz` run the maintained isolation and lifecycle
sections against that installation. `--lane kvm` runs isolation and ingress;
guest restart/persistence proof for KVM remains separate. Physical Apple Silicon
VZ needs the approved host route and assigned fixture ports. The fixed-port
lifecycle and continuity probes cover TLS on that route. The same installation
can be reused with `run-installed.sh LANE --prepared-config INSTALLATION_ROOT`; an
explicit `--install-commit` must match the package's source identity.

Without `--lane`, `installed_host_smoke.py` observes the native installed
launcher, authenticated runtime identity, owned HTTP allow/deny authorities and
verified stop. That host-only result boots no guest and proves no guest isolation.
Without `--package`, the wrapper retains the existing source-based proxy witness.""")
    for selected in PYTEST_PHASES["package-tls"][1]:
        out.append("")
        out.append(f"The host witness also selects `{selected}` against its packaged executable. "
                   "Those ephemeral-port controls run on Linux and the hosted Mac; physical VZ uses the fixed-port probes described above.")
    out.append("")
    out.append(
        "The complete native process/protocol family is separately maintained in "
        "`tests/proxy_contracts/`, run once per supported host platform overnight. "
        "installed_state_transition.py checks installed durable state "
        "through four native process lifetimes on Linux and the hosted Mac. "
        "Historical cross-backend receipts remain in the accepted issues. "
        "Runner selection describes intended execution, not a passing receipt."
    )
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

    try:
        rendered = _render(suites)
    except (OSError, ValueError) as exc:
        print(f"blackbox catalogue: {exc}", file=sys.stderr)
        return 1
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
