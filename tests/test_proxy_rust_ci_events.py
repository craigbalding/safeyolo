"""Keep quick PR checks distinct from overnight supported-platform contracts."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "proxy-rust.yml"


def rust_workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_relevant_pr_updates_and_explicit_integration_checkpoints_trigger_the_workflow() -> None:
    workflow = rust_workflow()
    # PyYAML's YAML 1.1 loader parses the Actions key `on` as boolean True.
    events = workflow[True]
    assert set(events) == {"pull_request", "push", "schedule", "workflow_dispatch"}
    assert set(events["pull_request"]["types"]) == {
        "opened",
        "reopened",
        "synchronize",
        "ready_for_review",
    }
    assert set(events["push"]["branches"]) == {"master", "main"}
    assert "paths" not in events["push"]
    paths = events["pull_request"]["paths"]
    for path in (
        "cli/src/safeyolo/rust_proxy.py",
        "cli/tests/test_rust_proxy.py",
        "proxy/**",
        "tests/blackbox/proxy_backend.py",
        "tests/blackbox/run-tests.sh",
        "tests/test_blackbox_harness.py",
        "tests/test_proxy_rust_ci_events.py",
        "tests/test_proxy_rust_coord_fixture.py",
        "cli/src/safeyolo/desktop_presenter*.py",
        "cli/src/safeyolo/preview.py",
        "cli/tests/test_agent_preview.py",
        "cli/tests/test_desktop_presenter*.py",
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
        "github.event_name == 'push' || "
        "(github.event_name == 'pull_request' && github.event.action != 'ready_for_review')"
    )
    assert job["runs-on"] == "ubuntu-latest"
    assert job["env"]["CARGO_BUILD_JOBS"] == "1"
    checkout = job["steps"][0]
    assert checkout["with"]["ref"] == "${{ github.event.pull_request.head.sha || github.sha }}"
    assert "git rev-parse HEAD" in job["steps"][1]["run"]
    steps = {step["name"]: step for step in job["steps"] if "name" in step}
    assert "socat" in steps["Install preview test system dependency"]["run"]
    step_names = list(steps)
    assert step_names.index("Install preview test system dependency") < step_names.index(
        "Test desktop presentation and preview"
    )
    native = steps["Test focused native boundaries"]
    assert native["if"] == "steps.changes.outputs.rust == 'true'"
    assert steps["Check Rust formatting and lint"]["if"] == native["if"]
    assert steps["Install the pinned Rust toolchain"]["if"] == (
        "steps.changes.outputs.rust == 'true' || steps.changes.outputs.guest == 'true' || steps.changes.outputs.dispatch == 'true'"
    )
    cli_build = steps["Build the native CLI for recovery and Dispatch checks"]
    site_check = steps["Validate the Dispatch publication tree"]
    assert "--bin safeyolo" in cli_build["run"]
    assert step_names.index(cli_build["name"]) < step_names.index(site_check["name"])
    assert site_check["run"] == "proxy/target/debug/safeyolo dispatch check-site"
    assert "--ignored" not in native["run"]
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    for required in (
        "cargo_with_space.sh fmt --all -- --check",
        "cargo_with_space.sh clippy --locked --all-targets -- -D warnings",
        "cli/tests/test_rust_proxy.py",
        "cli/tests/test_sockets.py",
        "tests/test_proxy_rust_coord_fixture.py",
        "tests/test_proxy_cutover_deletion_map.py",
        "cli/tests/test_desktop_presenter.py",
        "cli/tests/test_agent_preview.py",
        "tests/test_blackbox_harness.py",
        "tests/proxy_contracts/test_readiness.py",
        "cargo_with_space.sh test --locked --test agent_api_audit",
        "cargo_with_space.sh test --locked --test gateway_workflow oauth_refresh_reaches_origin_once_and_shared_flight_reuses_token -- --exact",
        "cargo_with_space.sh test --locked --lib native_config::tests",
        "cargo_with_space.sh test --locked --lib policy::native::tests",
    ):
        assert required in runs
    assert "../scripts/cargo_with_space.sh test --locked --lib" not in native["run"].splitlines()
    # The concurrent resource observation remains in the final full suite;
    # it does not turn each intermediate PR's focused check into a load probe.
    assert "repeated_service_oauth_activity_runs_concurrently" not in runs
    full_runs = "\n".join(step.get("run", "") for step in rust_workflow()["jobs"]["contracts"]["steps"])
    assert "cargo_with_space.sh test --locked" in full_runs
    assert not any("tests/proxy_contracts --proxy-backend rust" in step.get("run", "") for step in job["steps"])


def test_full_matrix_is_overnight_or_explicit_and_uses_the_exact_head() -> None:
    job = rust_workflow()["jobs"]["contracts"]
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
    )
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "macos-latest"]
    checkout = job["steps"][0]
    expected_head = "${{ github.event.pull_request.head.sha || github.sha }}"
    assert checkout["with"]["ref"] == expected_head
    assert job["steps"][1]["env"]["EXPECTED_HEAD"] == expected_head
    assert "git rev-parse HEAD" in job["steps"][1]["run"]
    steps = {step.get("name"): step for step in job["steps"]}
    assert steps["Test and build the Rust proxy"]["timeout-minutes"] == (
        "${{ matrix.os == 'macos-latest' && 20 || 15 }}"
    )
    assert steps["Stop the Python-owned Coord fixture"]["if"] == "always()"
    peer = steps["Provide the macOS owned HTTP peer address"]
    assert peer["if"] == "matrix.os == 'macos-latest'"
    assert "ifconfig lo0 alias 127.0.0.2" in peer["run"]
    assert job["steps"].index(peer) < job["steps"].index(
        steps["Run native proxy component contracts"]
    )
    short_tmp = "${{ matrix.os == 'macos-latest' && '--basetemp=/tmp/sy-rs' || '' }}"
    assert steps["Run native proxy component contracts"]["env"][
        "PYTEST_ADDOPTS"
    ] == short_tmp
    assert (
        "--proxy-backend rust"
        in steps["Run native proxy component contracts"]["run"]
    )


def test_full_matrix_uses_only_the_native_proxy() -> None:
    steps = rust_workflow()["jobs"]["contracts"]["steps"]
    named = {step.get("name"): step for step in steps}
    assert named["Install uv"]["with"]["version"] == "0.12.8"
    installation = named["Install the native CLI test environment"]["run"]
    assert "uv python install 3.12.14" in installation
    assert "uv sync --frozen --group dev --python 3.12.14" in installation
    assert named["Test and build the Rust proxy"]["env"]["SAFEYOLO_PYTHON"] == (
        "${{ github.workspace }}/.venv/bin/python"
    )
    rendered = str(steps)
    assert "--proxy-backend python" not in rendered
    assert "-- --ignored" not in rendered
    assert "git fetch --no-tags --depth=1 origin" not in rendered
    assert "SAFEYOLO_PYTHON_SOURCE" not in rendered


def test_platform_changes_add_relevant_macos_checks_without_full_contract_matrix():
    jobs = rust_workflow()["jobs"]
    job = jobs["macos-pr"]
    assert job["needs"] == "focused-pr"
    assert job["if"] == "needs.focused-pr.outputs.macos == 'true'"
    assert job["runs-on"] == "macos-latest"
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    assert "test_vm_control.py" in runs
    assert "test_vm_identity.py" in runs
    assert "test_vm_diagnostics.py" in runs
    assert "--test native_runtime_dependency" in runs
    assert "tests/proxy_contracts --proxy-backend rust" not in runs
    assert "install.sh" not in runs and "bootstrap" not in runs


@pytest.mark.parametrize("path,expected,matcher", [
    ("cli/src/safeyolo/platform/linux.py", {"linux": "true"}, "available"),
    ("cli/src/safeyolo/platform/darwin.py", {"macos": "true"}, "available"),
    ("proxy/src/host_platform.rs", {"rust": "true", "linux": "true", "macos": "true"}, "available"),
    ("docs/DEVELOPERS.md", {}, "available"),
    ("site/index.md", {"dispatch": "true"}, "available"),
    (".github/workflows/pages.yml", {"dispatch": "true"}, "available"),
    ("proxy/src/host_platform.rs", {}, "missing"),
    ("proxy/src/host_platform.rs", {}, "failing"),
], ids=["linux-only", "mac-only", "shared-native", "docs-only", "dispatch-content", "dispatch-workflow", "missing-grep", "failing-grep"])
def test_pr_change_selection_runs_the_matching_platform_checks(tmp_path, path, expected, matcher):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path, text=True).strip()

    git("init", "-q")
    (tmp_path / "base").touch()
    git("add", "base")
    git("-c", "user.name=Runner test", "-c", "user.email=runner@example.invalid",
        "commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    changed = tmp_path / path
    changed.parent.mkdir(parents=True)
    changed.touch()
    git("add", path)
    git("-c", "user.name=Runner test", "-c", "user.email=runner@example.invalid",
        "commit", "-qm", "change")
    output = tmp_path / "outputs"
    commands = tmp_path / "commands"
    commands.mkdir()
    for name in ("bash", "git", "grep"):
        executable = shutil.which(name)
        assert executable is not None, f"required hosted-runner command is unavailable: {name}"
        (commands / name).symlink_to(executable)
    assert shutil.which("rg", path=str(commands)) is None
    if matcher != "available":
        (commands / "grep").unlink()
        if matcher == "failing":
            (commands / "grep").write_text("#!/bin/sh\nexit 2\n")
            (commands / "grep").chmod(0o755)
    step = next(step for step in rust_workflow()["jobs"]["focused-pr"]["steps"]
                if step.get("id") == "changes")
    result = subprocess.run([str(commands / "bash"), "-euo", "pipefail", "-c", step["run"]],
                            cwd=tmp_path, capture_output=True, text=True, check=False,
                            env=dict(os.environ, PATH=str(commands), BASE=base,
                                     RUNNER_TEMP=str(tmp_path), GITHUB_OUTPUT=str(output)))
    if matcher == "available":
        assert result.returncode == 0, result.stderr
        assert not result.stderr
    else:
        assert result.returncode == 2
        assert "changed-path matcher failed" in result.stderr
    actual = dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}
    assert actual == expected


def test_general_python_workflow_uses_quick_pr_and_full_overnight_selections():
    workflow = yaml.safe_load(WORKFLOW.with_name("ci.yml").read_text())
    for job_name, quick_name, all_name, matrix_key in (
        ("test-addons", "Quick runner and workflow checks", "All retained Python tests overnight", "python-version"),
        ("test-cli", "Quick CLI checks", "All retained CLI tests overnight", "os"),
    ):
        job = workflow["jobs"][job_name]
        steps = {step.get("name"): step for step in job["steps"]}
        assert steps[all_name]["if"] == "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
        assert steps[quick_name]["if"] == "github.event_name != 'schedule' && github.event_name != 'workflow_dispatch'"
        assert "schedule" in job["strategy"]["matrix"][matrix_key]
        assert "install.sh" not in steps[quick_name]["run"]
