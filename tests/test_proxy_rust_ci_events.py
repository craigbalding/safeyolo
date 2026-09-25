"""Keep the Rust proxy's focused and final GitHub Actions events distinct."""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "proxy-rust.yml"


def rust_workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_relevant_pr_updates_and_explicit_integration_checkpoints_trigger_the_workflow() -> None:
    workflow = rust_workflow()
    # PyYAML's YAML 1.1 loader parses the Actions key `on` as boolean True.
    events = workflow[True]
    assert set(events) == {"pull_request", "push"}
    assert set(events["pull_request"]["types"]) == {
        "opened",
        "reopened",
        "synchronize",
        "ready_for_review",
    }
    assert set(events["push"]["branches"]) == {"master", "main", "ci/proxy-rust-620"}
    assert "paths" not in events["push"]
    paths = events["pull_request"]["paths"]
    for path in (
        "proxy/**",
        "tests/blackbox/proxy_backend.py",
        "tests/blackbox/run-tests.sh",
        "tests/test_blackbox_harness.py",
        "tests/test_proxy_rust_ci_events.py",
        "tests/test_proxy_rust_coord_fixture.py",
        ".github/workflows/proxy-rust.yml",
        "scripts/cargo_with_space.sh",
    ):
        assert path in paths


def test_ready_transition_does_not_cancel_the_same_head_focused_run() -> None:
    workflow = rust_workflow()
    assert workflow["concurrency"]["group"] == "${{ github.workflow }}-${{ github.ref }}"
    assert workflow["concurrency"]["cancel-in-progress"] == "${{ github.event.action != 'ready_for_review' }}"
    assert "ready_for_review" in workflow[True]["pull_request"]["types"]
    assert "github.event.action != 'ready_for_review'" in workflow["jobs"]["focused-pr"]["if"]


def test_focused_pr_job_covers_fast_positive_and_negative_boundaries() -> None:
    job = rust_workflow()["jobs"]["focused-pr"]
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'pull_request' && "
        "github.base_ref != 'master' && github.base_ref != 'main' && "
        "github.event.action != 'ready_for_review'"
    )
    assert job["runs-on"] == "ubuntu-latest"
    assert job["env"]["CARGO_BUILD_JOBS"] == "1"
    checkout = job["steps"][0]
    assert checkout["with"]["ref"] == "${{ github.event.pull_request.head.sha }}"
    assert "git rev-parse HEAD" in job["steps"][1]["run"]
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    for required in (
        "cargo_with_space.sh fmt --all -- --check",
        "cargo_with_space.sh clippy --locked --all-targets -- -D warnings",
        "tests/test_proxy_rust_coord_fixture.py",
        "tests/test_rust_temporary_policy.py",
        "tests/test_proxy_cutover_deletion_map.py",
        "tests/test_blackbox_harness.py",
        "tests/proxy_migration/test_readiness.py",
        "cargo_with_space.sh test --locked --test agent_api_audit",
        "cargo_with_space.sh test --locked --test gateway_workflow oauth_refresh_reaches_origin_once_and_shared_flight_reuses_token -- --exact",
    ):
        assert required in runs
    assert "cargo_with_space.sh test --locked --lib" not in runs
    # The concurrent resource observation remains in the final full suite;
    # it does not turn each intermediate PR's focused check into a load probe.
    assert "repeated_service_oauth_activity_runs_concurrently" not in runs
    full_runs = "\n".join(step.get("run", "") for step in rust_workflow()["jobs"]["http-slice"]["steps"])
    assert "cargo_with_space.sh test --locked" in full_runs
    assert not any("tests/proxy_migration --proxy-backend rust" in step.get("run", "") for step in job["steps"])


def test_full_matrix_requires_checkpoint_or_default_branch_push_at_exact_head() -> None:
    job = rust_workflow()["jobs"]["http-slice"]
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'push' || "
        "(github.event_name == 'pull_request' && "
        "(github.base_ref == 'master' || github.base_ref == 'main') && "
        "github.event.pull_request.draft == false)"
    )
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "macos-latest"]
    checkout = job["steps"][0]
    expected_head = "${{ github.event.pull_request.head.sha || github.sha }}"
    assert checkout["with"]["ref"] == expected_head
    assert job["steps"][1]["env"]["EXPECTED_HEAD"] == expected_head
    assert "git rev-parse HEAD" in job["steps"][1]["run"]
    steps = {step.get("name"): step for step in job["steps"]}
    assert steps["Test and build the Rust proxy"]["timeout-minutes"] == (
        "${{ matrix.os == 'macos-latest' && 20 || 10 }}"
    )
    assert steps["Stop the Python-owned Coord fixture"]["if"] == "always()"
    peer = steps["Provide the macOS owned HTTP peer address"]
    assert peer["if"] == "matrix.os == 'macos-latest'"
    assert "ifconfig lo0 alias 127.0.0.2" in peer["run"]
    assert job["steps"].index(peer) < job["steps"].index(
        steps["Run shared HTTP contracts against the historical Python comparator"]
    )
    short_tmp = "${{ matrix.os == 'macos-latest' && '--basetemp=/tmp/sy-py' || '' }}"
    assert steps["Run shared HTTP contracts against the historical Python comparator"]["env"]["PYTEST_ADDOPTS"] == short_tmp
    assert steps["Run shared HTTP contracts against native Rust without the temporary adapter"]["env"][
        "PYTEST_ADDOPTS"
    ] == short_tmp.replace("sy-py", "sy-rs")
    assert (
        "--proxy-backend python" in steps["Run shared HTTP contracts against the historical Python comparator"]["run"]
    )
    assert (
        "--proxy-backend rust"
        in steps["Run shared HTTP contracts against native Rust without the temporary adapter"]["run"]
    )


def test_full_matrix_ignored_oracles_use_the_pinned_source_and_interpreter() -> None:
    steps = rust_workflow()["jobs"]["http-slice"]["steps"]
    named = {step.get("name"): step for step in steps}
    assert named["Install uv"]["with"]["version"] == "0.12.8"
    installation = named["Install the historical comparator and temporary policy adapter"]["run"]
    assert "uv python install 3.12.14" in installation
    assert "uv sync --frozen --group dev --python 3.12.14" in installation

    source = named["Prepare pinned Python oracle source"]
    comparator = "7e934a5470f1aa9b74052fea08c6bae9b5f32e8a"
    assert source["env"]["SAFEYOLO_COMPARATOR_COMMIT"] == comparator
    assert 'git fetch --no-tags --depth=1 origin "$SAFEYOLO_COMPARATOR_COMMIT"' in source["run"]
    assert "git worktree add --detach" in source["run"]
    assert 'cd "$SAFEYOLO_STATE_PYTHON_SOURCE"' in source["run"]
    assert "uv sync --frozen --group dev --python 3.12.14" in source["run"]
    assert steps.index(source) < steps.index(named["Compare native behavior with the historical implementation"])

    oracle = named["Compare native behavior with the historical implementation"]
    env = oracle["env"]
    assert env["SAFEYOLO_POLICY_PYTHON"] == "${{ runner.temp }}/safeyolo-comparator/.venv/bin/python"
    for key in ("SAFEYOLO_PYTHON", "SAFEYOLO_SOURCE_PYTHON"):
        assert env[key] == "${{ github.workspace }}/.venv/bin/python"
    assert env["SAFEYOLO_SOURCE_ROOT"] == "${{ github.workspace }}"
    assert env["SAFEYOLO_STATE_PYTHON_SOURCE"] == source["env"]["SAFEYOLO_STATE_PYTHON_SOURCE"]
    assert env["SAFEYOLO_STATE_EVIDENCE_DIR"] == "${{ runner.temp }}/safeyolo-state-oracle"
    assert f'"$comparator_head" != {comparator}' in oracle["run"]
    assert "status --porcelain" in oracle["run"]
    assert "platform.python_version(), unicodedata.unidata_version" in oracle["run"]
    assert "('3.12.14', '15.0.0')" in oracle["run"]
    assert "set -e -o pipefail" in oracle["run"]
    assert "cargo_with_space.sh test --locked -- --ignored --nocapture" in oracle["run"]


def test_full_matrix_ignored_oracle_summary_fails_closed() -> None:
    steps = rust_workflow()["jobs"]["http-slice"]["steps"]
    oracle = next(
        step for step in steps if step.get("name") == "Compare native behavior with the historical implementation"
    )
    assert (
        subprocess.run(["bash", "-n"], input=oracle["run"], text=True, capture_output=True, check=False).returncode == 0
    )
    assert "2>&1 | tee" in oracle["run"]
    awk_script = oracle["run"].split("awk '", 1)[1].rsplit("' \"$RUNNER_TEMP", 1)[0]

    def summary_exits_zero(summary: str) -> bool:
        return (
            subprocess.run(["awk", awk_script], input=summary, text=True, capture_output=True, check=False).returncode
            == 0
        )

    assert summary_exits_zero("test result: ok. 3 passed; 0 failed; 0 ignored; 5 filtered out\n")
    assert not summary_exits_zero("")
    assert not summary_exits_zero("test result: ok. 0 passed; 0 failed; 0 ignored; 8 filtered out\n")
    assert not summary_exits_zero("test result: ok. 3 passed; 0 failed; 1 ignored; 4 filtered out\n")
