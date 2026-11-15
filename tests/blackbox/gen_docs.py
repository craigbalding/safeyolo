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
    out.append("## Focused policy, job and installation controls")
    out.append("")
    out.append("From a Linux or macOS test checkout, prepare the frozen development environment and the pinned Rust toolchain. "
               "Use an ordinary account and a new disk-backed result directory. "
               "Set `SAFEYOLO_BLACKBOX_ARTIFACTS_DIR` to that directory. "
               "Native selections build through the existing Cargo space guard with one job. "
               "Set its reserve and target directory for the actual host; `--cargo-profile release` selects optimized tests. "
               "These commands create owned process fixtures and retain reports/build logs; they do not qualify an installed guest.")
    out.append("")
    out.append("```sh\n./tests/blackbox/run-controls.sh named-checks\n./tests/blackbox/run-controls.sh managed-feeds\n./tests/blackbox/run-controls.sh before-after\n./tests/blackbox/run-controls.sh mediated-services\n```")
    out.append("")
    out.append("Each native report records the selected and observed exact Cargo test names, executable digest, command, controller revision, "
               "working-tree state, profile, host architecture and numeric identity. "
               "A failed build, absent test, ignored case or failed observer leaves the phase incomplete. "
               "The named-checks selection includes the accepted prepared-job case. "
               "Without its explicitly supplied `SAFEYOLO_POLICY_CHECK_PREPARED` instance and `--include-ignored`, that phase remains incomplete. "
               "Use the existing authorized host execution route for that case; do not substitute a mock or acquire privilege through the runner.")
    out.append("")
    out.append("With the matching native CLI/proxy/Coord binaries and existing fixture inputs prepared, "
               "`./tests/blackbox/run-controls.sh policy-recipe` selects deterministic preview/composition/redirect cases. "
               "It defaults to the accepted installed layout. `SAFEYOLO_AUTHORING_LAYOUT=source` explicitly selects source-layout proof, "
               "which proves neither package integrity nor installer behavior. "
               "`./tests/blackbox/run-controls.sh sudo-disclosure` selects the existing disclosure/consent/cleanup cases. "
               "That Linux fixture needs its documented guest sudo, ACL and archive tools; authentication modes are controlled. "
               "Its tiny metadata stages need the [native guest filesystem](../tests/test_linux_host.py); "
               "a nested 9p workspace cannot supply ACLs. Keep bulk inputs, pytest scratch and reports on disk. "
               "Use `SAFEYOLO_NATIVE_ARTIFACTS`, `SAFEYOLO_BUILD_PROFILE` and `SAFEYOLO_NATIVE_CLI` as their fixtures require. "
               "Both selections reuse named pytest receipts; required skips and teardown failures remain incomplete.")
    out.append("")
    out.append("For BB-31's real engine boundary, use `./tests/blackbox/run-controls.sh hyperlight-services --help` "
               "and the existing [two-engine driver](../tests/blackbox/host/hyperlight_services.py). "
               "It requires a matching protocol-3 artifact bundle, accessible Linux KVM or entitled Apple-silicon HVF, "
               "a new owned instance, empty private disk-backed scratch, authorized ports and a privately supplied scoped GitHub read credential. "
               "Its `procedure.json` records permitted/scope/lifetime cases per engine, host-observed invocation/artifact/authority identities and cleanup. "
               "A lifetimes-only run cannot complete the two-engine receipt. "
               "The mediated-services native phase uses controlled adapters and does not prove that either engine ran. "
               "These focused selectors are manual. Existing workflow selectors below retain their actual conditions; "
               "no recurring real-engine deployment is inferred. "
               "Accepted product evidence and its platform limits remain linked in the catalogue; a complete phase does not establish whole-control acceptance.")
    out.append("")
    out.append("For BB-33, #1553 feasibility and all seven #1554 product criteria have independent acceptance at "
               "[607d8488](https://github.com/craigbalding/safeyolo/issues/1554#issuecomment-6899892091). "
               "Maintained blackbox integration and control acceptance remain with #1563. "
               "The read-only `rootless-preparation` selector checks the retained native Linux storage receipt. "
               "Obtain its sanitized report, SHA-256 and exact candidate revision from the execution owner's canonical result. "
               "Keep the report private and choose a separate disk-backed output path. "
               "From this checkout, inspect the options before supplying those inputs:")
    out.append("")
    out.append("```sh\n./tests/blackbox/run-controls.sh rootless-preparation --help\n```")
    out.append("")
    out.append("Supply `--source-report`, `--source-sha256`, `--install-commit` and `--output`. "
               "The selector uses the existing bounded report reader and checks the digest before interpreting the report. "
               "It recomputes the named storage actions, cache/upgrade operands, persistence, reported host-sudo result and cleanup. "
               "Its output retains the original candidate, platform, prerequisites, execution identity, commands, setup failures and limits. "
               "A missing field, failed action, changed selection/inode, observer error or cleanup failure produces exit 2 and `complete=false`. "
               "Exit 0 means only that this selected retained witness is complete; `control_complete` remains false. "
               "The selector does not execute recorded commands, authenticate an arbitrary report author or independently accept the product. "
               "Installation/repeat/upgrade invocation remains attributed to the execution owner, outside the 32 storage actions. "
               "This selected receipt does not establish changed guest bytes, distinct mappings, extended/special metadata, "
               "failure/cancellation, existing-install preservation, macOS production or deployed recurring cadence. "
               "To collect new storage evidence on an authorized prepared Linux host, use the storage driver from the matching product revision. "
               "The [accepted #1554 driver](https://github.com/craigbalding/safeyolo/blob/607d8488a7fdc5c0c6ada605077ca99b4cb21682/tests/blackbox/installed_storage.py) "
               "carries the prepared instance's namespace authorization through acquisition. "
               "This checkout includes that driver interface; retained receipts keep their original candidate identity. "
               "Do not replay a completed operation for report formatting.")
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
