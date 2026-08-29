"""Contract tests for implemented versus documented blackbox cadence."""

from pathlib import Path

import pytest
import yaml

from scripts.check_blackbox_cadence import (
    CADENCE_DOCS,
    WORKFLOW_PATH,
    cadence_table_from_doc,
    contract_problems,
    scheduled_lanes_from_workflow,
)


def _write_workflow(
    path: Path,
    *,
    job_condition: str | None = None,
    run_condition: str | None = None,
    upload_condition: str | None = "always()",
) -> Path:
    run_step = {"run": "./tests/blackbox/run-lane.sh systrap --verbose"}
    if run_condition is not None:
        run_step["if"] = run_condition
    upload_step = {
        "uses": "actions/upload-artifact@example",
        "with": {
            "name": "blackbox-systrap-example",
            "path": "tests/blackbox/artifacts/",
        },
    }
    if upload_condition is not None:
        upload_step["if"] = upload_condition
    job = {"runs-on": "ubuntu", "steps": [run_step, upload_step]}
    if job_condition is not None:
        job["if"] = job_condition
    path.write_text(
        yaml.safe_dump(
            {
                "name": "fixture",
                "on": {"schedule": [{"cron": "17 3 * * *"}]},
                "jobs": {"systrap": job},
            },
            sort_keys=False,
        )
    )
    return path


def test_only_systrap_is_scheduled_and_publishes_an_artifact() -> None:
    """The workflow, not aspirational hardware docs, defines automation."""
    assert scheduled_lanes_from_workflow() == {"systrap": True}


def test_cadence_tables_match_the_workflow() -> None:
    """No table may turn a manual hardware lane into a claimed nightly."""
    expected = {"systrap": True, "kvm": False, "vz": False}
    for doc_path in CADENCE_DOCS:
        assert cadence_table_from_doc(doc_path) == expected
    assert contract_problems(WORKFLOW_PATH, CADENCE_DOCS) == []


def test_manual_only_job_cannot_count_as_scheduled(tmp_path: Path) -> None:
    workflow = _write_workflow(
        tmp_path / "manual-job.yml",
        job_condition="github.event_name == 'workflow_dispatch'",
    )
    with pytest.raises(ValueError, match="job-level if condition"):
        scheduled_lanes_from_workflow(workflow)


def test_conditional_lane_step_cannot_count_as_scheduled(tmp_path: Path) -> None:
    workflow = _write_workflow(
        tmp_path / "manual-step.yml",
        run_condition="github.event_name == 'workflow_dispatch'",
    )
    with pytest.raises(ValueError, match="step-level if condition"):
        scheduled_lanes_from_workflow(workflow)


@pytest.mark.parametrize(
    "condition",
    [None, "github.event_name == 'workflow_dispatch'", "failure()"],
)
def test_conditional_upload_is_not_pass_and_fail_evidence(
    tmp_path: Path, condition: str | None
) -> None:
    workflow = _write_workflow(
        tmp_path / "conditional-upload.yml",
        upload_condition=condition,
    )
    assert scheduled_lanes_from_workflow(workflow) == {"systrap": False}
    problems = contract_problems(workflow, CADENCE_DOCS)
    assert problems == [
        "scheduled full lanes lack actions/upload-artifact evidence: ['systrap']"
    ]


def test_wrapped_always_expression_publishes_pass_and_fail_evidence(
    tmp_path: Path,
) -> None:
    workflow = _write_workflow(
        tmp_path / "always-upload.yml",
        upload_condition="${{ always() }}",
    )
    assert scheduled_lanes_from_workflow(workflow) == {"systrap": True}
