"""Contract tests for implemented versus documented blackbox cadence."""

from scripts.check_blackbox_cadence import (
    CADENCE_DOCS,
    WORKFLOW_PATH,
    cadence_table_from_doc,
    contract_problems,
    scheduled_lanes_from_workflow,
)


def test_only_systrap_is_scheduled_and_publishes_an_artifact() -> None:
    """The workflow, not aspirational hardware docs, defines automation."""
    assert scheduled_lanes_from_workflow() == {"systrap": True}


def test_cadence_tables_match_the_workflow() -> None:
    """No table may turn a manual hardware lane into a claimed nightly."""
    expected = {"systrap": True, "kvm": False, "vz": False}
    for doc_path in CADENCE_DOCS:
        assert cadence_table_from_doc(doc_path) == expected
    assert contract_problems(WORKFLOW_PATH, CADENCE_DOCS) == []
