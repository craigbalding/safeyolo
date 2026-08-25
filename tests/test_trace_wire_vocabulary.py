"""Drift check: shipped wire-vocabulary doc must match source constants (#213 B7).

The skill DAGs (`triage-request-failing.yaml`,
`triage-credential-guard.yaml`) branch on literal strings for `state`,
`reason`, and per-addon `outcome`. Those literals are documented in
`agent_context/skills/safeyolo/references/agent-api.md` under
"Trace wire vocabulary" so the sandbox can branch without introspecting
Python source.

This test enforces that the doc's tables list exactly the constants
defined in:

- `safeyolo.core.trace` — `STATE_*`, `REASON_*` module-level constants
- each trace-participating addon module — `OUTCOME_*` constants

If a new outcome ships in an addon or a state/reason is added, this
test fails until the doc catches up. Same in reverse: if the doc lists
an outcome the addon no longer defines, this test fails.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

DOC_PATH = (
    Path(__file__).resolve().parents[1]
    / "cli/src/safeyolo/agent_context/skills/safeyolo/references/agent-api.md"
)


# Trace-participating addon modules and the human-readable section name
# used to label them in the doc. Any addon that publishes OUTCOME_*
# constants and is expected to appear in /trace goes here.
ADDON_MODULES_AND_SECTIONS = [
    ("credential_guard", "credential-guard"),
    ("pattern_scanner", "pattern-scanner"),
    ("network_guard", "network-guard"),
    ("circuit_breaker", "circuit-breaker"),
    ("test_context", "test-context"),
    ("service_gateway", "service-gateway"),
    ("probe_sink", "probe-sink"),
]


def _outcome_constants(module) -> set[str]:
    """Return the set of OUTCOME_* string values defined at module top."""
    return {
        getattr(module, name)
        for name in dir(module)
        if name.startswith("OUTCOME_") and isinstance(getattr(module, name), str)
    }


def _table_literals_after(doc: str, header: str) -> set[str]:
    """Extract the literal values from the leftmost column of the FIRST
    markdown table appearing after `header` in `doc`.

    Stops at the next `###` / `##` / `**` header or an obvious paragraph
    break so tables further down the doc don't leak in.
    """
    idx = doc.find(header)
    if idx == -1:
        raise AssertionError(f"doc missing header: {header!r}")

    tail = doc[idx + len(header):]
    # Cut off at the next top-level structural boundary: ### or ## header,
    # or a bold-emphasis section marker (**name**) used for per-addon
    # subsections in the doc.
    boundary = re.search(r"\n(###?[ \t]|\*\*[A-Za-z])", tail)
    section = tail[: boundary.start()] if boundary else tail

    # Rows of the form: | `literal` | anything |
    rows = re.findall(r"^\|\s*`([^`|]+)`\s*\|[^|]+\|", section, re.MULTILINE)
    if not rows:
        raise AssertionError(f"no table literals found after header {header!r}")
    return set(rows)


class TestStatesAreDocumented:
    def test_all_STATE_constants_appear(self):
        from safeyolo.core import trace as trace_mod

        source_states = {
            getattr(trace_mod, name)
            for name in dir(trace_mod)
            if name.startswith("STATE_") and isinstance(getattr(trace_mod, name), str)
        }
        doc = DOC_PATH.read_text()
        doc_states = _table_literals_after(doc, "### Trace states")

        missing = source_states - doc_states
        extra = doc_states - source_states
        assert not missing, f"agent-api.md missing STATE literals: {missing}"
        assert not extra, f"agent-api.md lists STATE literals not in source: {extra}"


class TestReasonsAreDocumented:
    def test_all_REASON_constants_appear(self):
        from safeyolo.core import trace as trace_mod

        source_reasons = {
            getattr(trace_mod, name)
            for name in dir(trace_mod)
            if name.startswith("REASON_") and isinstance(getattr(trace_mod, name), str)
        }
        doc = DOC_PATH.read_text()
        doc_reasons = _table_literals_after(doc, "### Bypass / error reasons")

        missing = source_reasons - doc_reasons
        extra = doc_reasons - source_reasons
        assert not missing, f"agent-api.md missing REASON literals: {missing}"
        assert not extra, f"agent-api.md lists REASON literals not in source: {extra}"


class TestPerAddonOutcomesAreDocumented:
    @pytest.mark.parametrize(
        "module_name,section_name",
        ADDON_MODULES_AND_SECTIONS,
        ids=[section for _, section in ADDON_MODULES_AND_SECTIONS],
    )
    def test_addon_outcomes_match_doc(self, module_name, section_name):
        """Every OUTCOME_* constant in the addon module must appear in
        the corresponding doc section, and vice versa. The DAG YAMLs
        branch on these literals — drift breaks skill correctness.
        """
        module = importlib.import_module(module_name)
        source_outcomes = _outcome_constants(module)
        assert source_outcomes, (
            f"{module_name} declares no OUTCOME_* constants — either add "
            "some or remove it from ADDON_MODULES_AND_SECTIONS."
        )

        # The section header format is "**<name>** (`OUTCOME_*` in `mitm_addons/<file>.py`):"
        doc = DOC_PATH.read_text()
        header = f"**{section_name}**"
        doc_outcomes = _table_literals_after(doc, header)

        missing = source_outcomes - doc_outcomes
        extra = doc_outcomes - source_outcomes
        assert not missing, (
            f"agent-api.md **{section_name}** section missing OUTCOME literals: {missing}"
        )
        assert not extra, (
            f"agent-api.md **{section_name}** section lists OUTCOME literals "
            f"not in {module_name}: {extra}"
        )


class TestDocSectionsExistForAllTraceAddons:
    def test_every_module_has_a_doc_section(self):
        """Sanity check that the parametrised addon list matches the
        canonical trace-participating set. If EXPECTED_ADDONS gains an
        entry not covered above, this test fails and forces the doc + this
        list to catch up.
        """
        from safeyolo.core.trace import EXPECTED_ADDONS

        # probe-sink isn't in EXPECTED_ADDONS (it's the terminator, not a
        # security pipeline participant) but does publish outcomes and
        # appears in /trace, so it's covered separately.
        expected_sections = set(EXPECTED_ADDONS)
        covered_sections = {section for _, section in ADDON_MODULES_AND_SECTIONS}
        missing = expected_sections - covered_sections
        assert not missing, (
            f"EXPECTED_ADDONS entries lack a doc-drift check: {missing}. "
            "Add them to ADDON_MODULES_AND_SECTIONS in this test AND to "
            "agent-api.md's trace wire vocabulary."
        )
