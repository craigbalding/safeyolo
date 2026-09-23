"""Keep the Rust proxy's focused and final GitHub Actions events distinct."""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "proxy-rust.yml"


def rust_workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_relevant_pr_updates_and_integration_pushes_trigger_the_workflow() -> None:
    workflow = rust_workflow()
    # PyYAML's YAML 1.1 loader parses the Actions key `on` as boolean True.
    events = workflow[True]
    assert set(events) == {"pull_request", "push"}
    assert set(events["pull_request"]["types"]) == {
        "opened",
        "reopened",
        "synchronize",
        "converted_to_draft",
        "ready_for_review",
    }
    assert set(events["push"]["branches"]) == {"master", "main", "feat/rust-proxy-620"}
    assert "paths" not in events["push"]
    paths = events["pull_request"]["paths"]
    for path in (
        "cli/src/safeyolo/mitm_addons/credential_guard.py",
        "proxy/**",
        "tests/test_credential_guard.py",
        "tests/test_proxy_rust_ci_events.py",
        "tests/test_proxy_rust_coord_fixture.py",
        ".github/workflows/proxy-rust.yml",
        "scripts/cargo_with_space.sh",
    ):
        assert path in paths


def test_focused_pr_job_covers_fast_positive_and_negative_boundaries() -> None:
    job = rust_workflow()["jobs"]["focused-pr"]
    assert job["if"] == "github.event_name == 'pull_request'"
    assert job["runs-on"] == "ubuntu-latest"
    assert job["env"]["CARGO_BUILD_JOBS"] == "1"
    checkout = job["steps"][0]
    assert checkout["with"]["ref"] == "${{ github.event.pull_request.head.sha }}"
    assert "git rev-parse HEAD" in job["steps"][1]["run"]
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    for required in (
        "cargo_with_space.sh fmt --all -- --check",
        "cargo_with_space.sh clippy --locked --all-targets -- -D warnings",
        "tests/test_credential_guard.py",
        "tests/test_check_doc_cli_flags.py",
        "tests/test_proxy_rust_coord_fixture.py",
        "tests/test_rust_temporary_policy.py",
        "tests/test_proxy_cutover_deletion_map.py",
        "cargo_with_space.sh test --locked --test agent_api_audit",
        "cargo_with_space.sh test --locked --test gateway_workflow",
    ):
        assert required in runs
    assert "cargo_with_space.sh test --locked --lib" not in runs
    assert not any("tests/proxy_migration --proxy-backend rust" in step.get("run", "") for step in job["steps"])


def test_full_matrix_requires_ready_transition_or_branch_push_at_exact_head() -> None:
    job = rust_workflow()["jobs"]["http-slice"]
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'push' || "
        "(github.event_name == 'pull_request' && "
        "github.event.action == 'ready_for_review' && "
        "github.event.pull_request.draft == false)"
    )
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "macos-latest"]
    checkout = job["steps"][0]
    expected_head = "${{ github.event.pull_request.head.sha || github.sha }}"
    assert checkout["with"]["ref"] == expected_head
    assert job["steps"][1]["env"]["EXPECTED_HEAD"] == expected_head
    assert "git rev-parse HEAD" in job["steps"][1]["run"]
    steps = {step.get("name"): step for step in job["steps"]}
    assert steps["Test and build the Rust proxy"]["timeout-minutes"] == 10
    assert steps["Stop the Python-owned Coord fixture"]["if"] == "always() && matrix.os == 'ubuntu-latest'"
    assert (
        "--proxy-backend python" in steps["Run shared HTTP contracts against the historical Python comparator"]["run"]
    )
    assert (
        "--proxy-backend rust"
        in steps["Run shared HTTP contracts against native Rust without the temporary adapter"]["run"]
    )
