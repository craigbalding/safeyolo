"""Keep quick PR checks distinct from overnight supported-platform contracts."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
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
        "tests/reference/safeyolo/rust_proxy.py",
        "cli/tests/test_rust_proxy.py",
        "proxy/**",
        "tests/blackbox/proxy_backend.py",
        "tests/blackbox/run-tests.sh",
        "tests/test_blackbox_harness.py",
        "tests/test_proxy_rust_ci_events.py",
        "tests/test_proxy_rust_coord_fixture.py",
        "tests/reference/safeyolo/platform/**",
        "cli/tests/test_vm_control.py",
        "cli/tests/test_vm_diagnostics.py",
        ".github/workflows/proxy-rust.yml",
        ".github/workflows/guest-test-inputs.yml",
        ".github/workflows/ci.yml",
        "scripts/cargo_with_space.sh",
        "scripts/rust_cache_command.sh",
    ):
        assert path in paths


def test_ready_transition_does_not_cancel_the_same_head_focused_run() -> None:
    workflow = rust_workflow()
    assert workflow["concurrency"]["group"] == (
        "${{ github.workflow }}-${{ github.ref }}-${{ github.event_name }}-"
        "${{ inputs.packages_only && inputs.package_architecture || '' }}"
    )
    assert workflow["concurrency"]["cancel-in-progress"] == "${{ github.event.action != 'ready_for_review' }}"
    assert "ready_for_review" in workflow[True]["pull_request"]["types"]
    assert "github.event.action != 'ready_for_review'" in workflow["jobs"]["focused-pr"]["if"]
    assert not cancels_run(workflow, "pull_request", "pull_request", "refs/pull/123/merge", "ready_for_review")
    assert cancels_run(workflow, "pull_request", "pull_request", "refs/pull/123/merge", "synchronize")


def cancels_run(workflow: dict, running_event: str, incoming_event: str,
                ref: str = "refs/heads/master", action: str = "",
                running_packages: str = "", incoming_packages: str = "") -> bool:
    concurrency = workflow["concurrency"]

    def group(event: str, packages: str) -> str:
        rendered = concurrency["group"]
        for key, value in (("workflow", workflow["name"]), ("ref", ref), ("event_name", event)):
            rendered = rendered.replace("${{ github." + key + " }}", value)
        rendered = rendered.replace("${{ inputs.packages_only && inputs.package_architecture || '' }}", packages)
        assert "${{" not in rendered, rendered
        return rendered

    cancel = concurrency["cancel-in-progress"]
    if isinstance(cancel, str):
        assert cancel == "${{ github.event.action != 'ready_for_review' }}"
        cancel = action != "ready_for_review"
    assert isinstance(cancel, bool)
    return cancel and group(running_event, running_packages) == group(incoming_event, incoming_packages)


def test_package_dispatch_does_not_cancel_contracts_or_another_package_group():
    workflow = rust_workflow()
    assert not cancels_run(workflow, "workflow_dispatch", "workflow_dispatch", incoming_packages="all")
    assert not cancels_run(workflow, "workflow_dispatch", "workflow_dispatch", running_packages="all")
    assert not cancels_run(workflow, "workflow_dispatch", "workflow_dispatch",
                           running_packages="amd64", incoming_packages="arm64")
    assert cancels_run(workflow, "workflow_dispatch", "workflow_dispatch",
                       running_packages="amd64", incoming_packages="amd64")


@pytest.mark.parametrize("workflow_name,full_event", [
    ("ci.yml", "schedule"),
    ("ci.yml", "workflow_dispatch"),
    ("proxy-rust.yml", "schedule"),
    ("proxy-rust.yml", "workflow_dispatch"),
    ("codeql.yml", "schedule"),
])
def test_full_admissions_and_quick_updates_do_not_cancel_each_other(workflow_name, full_event):
    workflow = yaml.safe_load(WORKFLOW.with_name(workflow_name).read_text())
    assert full_event in workflow[True]
    assert not cancels_run(workflow, full_event, "push")
    assert not cancels_run(workflow, "push", full_event)


@pytest.mark.parametrize("workflow_name", ["ci.yml", "proxy-rust.yml", "codeql.yml"])
@pytest.mark.parametrize("event,ref", [
    ("push", "refs/heads/master"),
    ("pull_request", "refs/pull/123/merge"),
])
def test_superseded_quick_runs_still_cancel(workflow_name, event, ref):
    workflow = yaml.safe_load(WORKFLOW.with_name(workflow_name).read_text())
    assert cancels_run(workflow, event, event, ref, "synchronize")


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
        "Test native desktop presentation and host entry"
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
    assert site_check["run"] == "proxy/target/release/safeyolo dispatch check-site"
    assert "--ignored" not in native["run"]
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    for required in (
        "cargo_with_space.sh fmt --all -- --check",
        "cargo_with_space.sh clippy --release --locked --all-targets -- -D warnings",
        "cli/tests/test_rust_proxy.py",
        "cli/tests/test_sockets.py",
        "tests/test_proxy_rust_coord_fixture.py",
        "tests/test_proxy_cutover_deletion_map.py",
        "--test desktop_native --test native_host_cli",
        "--test native_runtime_dependency",
        "tests/test_blackbox_harness.py",
        "tests/proxy_contracts/test_readiness.py",
        "tests/proxy_contracts/test_first_agent_launch.py",
        "cli/tests/test_host_setup_scripts.py::test_claude_host_state_choice_controls_auth_preferences_and_extensions",
        "cli/tests/test_host_setup_scripts.py::test_claude_setup_does_not_write_through_guest_created_host_links",
        "cargo_with_space.sh test --release --locked --test agent_api_audit",
        "cargo_with_space.sh test --release --locked --test gateway_workflow oauth_refresh_reaches_origin_once_and_shared_flight_reuses_token -- --exact",
        "cargo_with_space.sh test --release --locked --lib native_config::tests",
        "cargo_with_space.sh test --release --locked --lib policy::native::tests",
    ):
        assert required in runs
    assert "../scripts/cargo_with_space.sh test --release --locked --lib" not in native["run"].splitlines()
    # The concurrent resource observation remains in the final full suite;
    # it does not turn each intermediate PR's focused check into a load probe.
    assert "repeated_service_oauth_activity_runs_concurrently" not in runs
    full_runs = "\n".join(step.get("run", "") for step in rust_workflow()["jobs"]["contracts"]["steps"])
    assert "cargo_with_space.sh test --release --locked" in full_runs
    assert not any("tests/proxy_contracts --proxy-backend rust" in step.get("run", "") for step in job["steps"])


@pytest.mark.parametrize("rust,host,guest,cancelled,expected", [
    ("true", "success", "success", False, True),
    ("true", "failure", "success", False, False),
    ("true", "skipped", "success", False, False),
    ("true", "cancelled", "success", False, False),
    ("true", "success", "failure", False, False),
    ("true", "success", "skipped", False, False),
    ("true", "success", "cancelled", False, False),
    ("false", "success", "success", False, False),
    ("", "", "", False, False),
    ("true", "success", "success", True, False),
])
def test_linux_input_retention_requires_successful_producers_after_test_failure(rust, host, guest, cancelled, expected):
    job = rust_workflow()["jobs"]["focused-pr"]
    producers = {step.get("id"): step for step in job["steps"]}
    host_build = producers["linux_host_inputs"]
    guest_build = producers["linux_guest_inputs"]
    assert host_build["run"] == (
        "scripts/cargo_with_space.sh build --release --manifest-path proxy/Cargo.toml --locked "
        "--bin safeyolo --bin safeyolo-coord --bin safeyolo-proxy"
    )
    assert "pytest" not in host_build["run"]
    assert guest_build["run"] == "scripts/build_guest_command.sh"
    assert guest_build["env"]["SAFEYOLO_BUILD_PROFILE"] == "production"
    for artifact in ("linux-host-amd64-production", "linux-guest-amd64-production"):
        upload = next(step for step in job["steps"] if step.get("with", {}).get("name") == artifact)
        # An explicit Actions status function removes the implicit success()
        # check, so a later failed test does not suppress successful builds.
        condition = upload["if"].strip().removeprefix("${{").removesuffix("}}").strip()
        assert condition.startswith("!cancelled() && ")
        condition = condition.replace("!cancelled()", "'false' == 'true'" if cancelled else "'true' == 'true'")
        for name, value in (("steps.changes.outputs.rust", rust),
                            ("steps.linux_host_inputs.outcome", host),
                            ("steps.linux_guest_inputs.outcome", guest)):
            assert name in condition
            condition = condition.replace(name, shlex.quote(value))
        # These string equalities and conjunctions have the same truth table
        # in Bash. This checks admission, not a hosted artifact upload.
        result = subprocess.run(["bash", "-e", "-c", f"[[ {condition} ]]"], capture_output=True, text=True)
        assert result.returncode == (0 if expected else 1), result.stderr
        assert upload["with"]["retention-days"] == 7
        assert upload["with"]["if-no-files-found"] == "error"
        assert job["steps"].index(host_build) < job["steps"].index(upload)
        assert job["steps"].index(guest_build) < job["steps"].index(upload)
    assert not job.get("continue-on-error")


@pytest.mark.parametrize("failure", [None, "compiler", "missing", "ambiguous", "entry"])
def test_installed_share_test_staging_refuses_incomplete_compiler_output(tmp_path, failure):
    steps = rust_workflow()["jobs"]["focused-pr"]["steps"]
    stage = next(step for step in steps if step.get("id") == "linux_share_test")
    upload = next(step for step in steps
                  if step.get("with", {}).get("name") == "linux-share-test-amd64-production")
    assert upload["if"] == "${{ !cancelled() && steps.linux_share_test.outcome == 'success' }}"
    assert upload["with"]["path"] == "${{ runner.temp }}/linux-share-test/native-library-test"
    assert steps.index(stage) < steps.index(upload)
    focused = next(step for step in steps if step.get("name") == "Test focused native boundaries")
    for artifact in ("linux-host-amd64-production", "linux-guest-amd64-production", "linux-share-test-amd64-production"):
        retained = next(step for step in steps if step.get("with", {}).get("name") == artifact)
        producer = stage if artifact == "linux-share-test-amd64-production" else next(
            step for step in steps if step.get("id") == "linux_host_inputs"
        )
        assert steps.index(producer) < steps.index(retained) < steps.index(focused)
    for directory in ("scripts", ".venv/bin", "proxy/target", "runner temp", "commands"):
        (tmp_path / directory).mkdir(parents=True)
    (tmp_path / ".venv/bin/python").symlink_to(sys.executable)
    for name in ("rustc", "cargo"):
        compiler = tmp_path / "commands" / name
        compiler.write_text('#!/bin/sh\nprintf "fixture compiler\\n"\n')
        compiler.chmod(0o755)
    test_binary = tmp_path / "library test"
    entry = "other::test" if failure == "entry" else "linux_host::shares::tests::installed_share_operation"
    test_binary.write_text(f'#!/bin/sh\n[ "$1" = --list ] && [ "$2" = --exact ] || exit 31\nprintf "%s: test\\n" {shlex.quote(entry)}\n')
    test_binary.chmod(0o755)
    artifact = {"reason": "compiler-artifact", "target": {"name": "safeyolo_proxy"},
                "profile": {"test": True}, "executable": str(test_binary)}
    rows = [{**artifact, "target": {"name": "safeyolo"}}, {**artifact, "executable": None}]
    if failure != "missing":
        rows.append(artifact)
    if failure == "ambiguous":
        rows.append(artifact)
    output = tmp_path / "compiler-output.jsonl"
    output.write_text("".join(json.dumps(row) + "\n" for row in rows))
    cargo = tmp_path / "scripts/cargo_with_space.sh"
    cargo.write_text('#!/bin/sh\ncat "$FIXTURE_CARGO_OUTPUT"\nexit "$FIXTURE_CARGO_EXIT"\n')
    cargo.chmod(0o755)
    result = subprocess.run(
        ["bash", "-c", stage["run"]], cwd=tmp_path,
        env=dict(os.environ, BASH_ENV="", RUNNER_TEMP=str(tmp_path / "runner temp"),
                 PATH=f"{tmp_path / 'commands'}:{os.environ['PATH']}",
                 FIXTURE_CARGO_OUTPUT=str(output), FIXTURE_CARGO_EXIT="17" if failure == "compiler" else "0"),
        capture_output=True, text=True,
    )
    retained = tmp_path / "runner temp/linux-share-test/native-library-test"
    if failure is None:
        assert result.returncode == 0, result.stderr
        assert retained.read_bytes() == test_binary.read_bytes()
        assert os.access(retained, os.X_OK)
    else:
        assert result.returncode != 0, result.stdout
        assert not retained.exists()


@pytest.mark.parametrize("failure", ["build", "tests"])
def test_installed_linux_tests_keep_their_failure_after_build_separation(tmp_path, failure):
    steps = rust_workflow()["jobs"]["focused-pr"]["steps"]
    build = next(step for step in steps if step.get("id") == "linux_host_inputs")
    tests = next(step for step in steps if step.get("name") == "Test installed native policy commands")
    assert steps.index(build) < steps.index(tests)
    assert not tests.get("continue-on-error")
    commands = tmp_path / "commands"
    commands.mkdir()
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    build_calls = tmp_path / "build-calls"
    cargo = scripts / "cargo_with_space.sh"
    cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$FIXTURE_BUILD_CALLS"\nexit ' + ("29" if failure == "build" else "0") + '\n')
    cargo.chmod(0o755)
    uv = commands / "uv"
    uv.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$FIXTURE_UV_CALLS"\nexit 23\n')
    uv.chmod(0o755)
    calls = tmp_path / "uv-calls"
    script = tmp_path / "installed-tests.sh"
    script.write_text(tests["run"])
    # Hosted Bash has no sandbox startup file that replaces the fixture PATH.
    result = subprocess.run(["bash", "-e", str(script)], cwd=tmp_path,
                            capture_output=True, text=True,
                            env=dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}",
                                     BASH_ENV=os.devnull, RUNNER_TEMP=str(tmp_path),
                                     FIXTURE_BUILD_CALLS=str(build_calls), FIXTURE_UV_CALLS=str(calls)))
    assert build_calls.read_text().splitlines() == [
        "build --release --manifest-path proxy/Cargo.toml --locked --bin safeyolo --bin safeyolo-coord --bin safeyolo-proxy"
    ]
    if failure == "build":
        assert result.returncode == 29, result.stderr
        assert not calls.exists()
    else:
        assert result.returncode == 23, result.stderr
        assert calls.read_text().splitlines() == [
            "run --frozen pytest -q tests/proxy_contracts/test_native_policy_cli.py "
            "tests/proxy_contracts/test_first_agent_launch.py "
            "cli/tests/test_host_setup_scripts.py::test_claude_host_state_choice_controls_auth_preferences_and_extensions "
            "cli/tests/test_host_setup_scripts.py::test_claude_setup_does_not_write_through_guest_created_host_links "
            f"--basetemp {tmp_path}/native-policy"
        ]


@pytest.mark.parametrize("failure", [None, "build", "fixture"])
def test_quick_coord_fixture_preserves_producer_and_consumer_failures(tmp_path, failure):
    """Run the workflow commands with controlled build and pytest exits."""
    steps = rust_workflow()["jobs"]["focused-pr"]["steps"]
    build = next(step for step in steps if step.get("id") == "linux_host_inputs")
    fixture = next(step for step in steps if step.get("name") == "Test current native Coord fixture boundaries")
    assert steps.index(build) < steps.index(fixture)
    assert not build.get("continue-on-error") and not fixture.get("continue-on-error")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    cargo = scripts / "cargo_with_space.sh"
    cargo.write_text('#!/bin/sh\nprintf "native preparation\\n"\nexit "$FIXTURE_BUILD_EXIT"\n')
    cargo.chmod(0o755)
    commands = tmp_path / "commands"
    commands.mkdir()
    uv = commands / "uv"
    uv.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$FIXTURE_UV_CALLS"\n'
                  'printf "fixture command diagnostic\\n" >&2\nexit "$FIXTURE_TEST_EXIT"\n')
    uv.chmod(0o755)
    calls = tmp_path / "uv-calls"
    result = subprocess.run(
        ["bash", "-e", "-c", build["run"] + "\n" + fixture["run"]], cwd=tmp_path,
        capture_output=True, text=True,
        env=dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}", BASH_ENV=os.devnull,
                 FIXTURE_BUILD_EXIT="29" if failure == "build" else "0",
                 FIXTURE_TEST_EXIT="23" if failure == "fixture" else "0", FIXTURE_UV_CALLS=str(calls)),
    )
    assert "native preparation" in result.stdout
    assert result.returncode == {None: 0, "build": 29, "fixture": 23}[failure]
    if failure == "build":
        assert not calls.exists()
    else:
        assert calls.read_text().splitlines() == ["run --frozen pytest -q tests/test_proxy_rust_coord_fixture.py"]
        assert "fixture command diagnostic" in result.stderr


@pytest.mark.parametrize("packages,architecture,source,ref,expected", [
    (True, "all", "a" * 40, "refs/heads/master", ["amd64", "arm64"]),
    (True, "amd64", "a" * 40, "refs/heads/master", ["amd64"]),
    (True, "arm64", "a" * 40, "refs/heads/master", ["arm64"]),
    (False, "amd64", "", "refs/heads/master", ["amd64", "arm64"]),
    (False, "", "", "refs/heads/ci/proxy-rust-620", ["amd64", "arm64"]),
    (True, "all", "", "refs/heads/master", None),
    (True, "all", "master", "refs/heads/master", None),
    (True, "all", "a" * 7, "refs/heads/master", None),
    (True, "all", "b" * 40, "refs/heads/master", None),
    (True, "all", "a" * 40, "refs/heads/feature", None),
    (True, "all", "a" * 40, "refs/tags/master", None),
    (True, "x86_64", "a" * 40, "refs/heads/master", None),
    (True, 'arm64"; exit 0; #', "a" * 40, "refs/heads/master", None),
    (True, "all", "$(exit 0)", "refs/heads/master", None),
])
def test_package_dispatch_selects_exact_source_before_starting_producers(
    tmp_path, packages, architecture, source, ref, expected
):
    job = rust_workflow()["jobs"]["package-inputs"]
    step = job["steps"][0]
    assert step["env"] == {
        "PACKAGES_ONLY": "${{ github.event_name == 'workflow_dispatch' && inputs.packages_only }}",
        "SOURCE_REVISION": "${{ inputs.source_revision }}",
        "PACKAGE_ARCHITECTURE": "${{ inputs.package_architecture }}",
        "DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
    }
    assert "${{" not in step["run"]
    output = tmp_path / "github-output"
    result = subprocess.run(["bash", "-eo", "pipefail", "-c", step["run"]],
                            env={**os.environ, "PACKAGES_ONLY": str(packages).lower(),
                                 "SOURCE_REVISION": source, "PACKAGE_ARCHITECTURE": architecture,
                                 "DEFAULT_BRANCH": "master", "GITHUB_REF": ref, "GITHUB_SHA": "a" * 40,
                                 "GITHUB_OUTPUT": str(output)},
                            capture_output=True, text=True, timeout=10)
    if expected is None:
        assert result.returncode != 0 and "::error::" in result.stdout, result
        assert not output.exists()
    else:
        assert result.returncode == 0, result.stderr
        assert json.loads(output.read_text().removeprefix("architectures=")) == expected


def test_package_dispatch_keeps_existing_producer_identity_profile_and_retention():
    workflow = rust_workflow()
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    assert inputs["packages_only"]["default"] is False
    assert inputs["package_architecture"]["options"] == ["all", "amd64", "arm64"]
    job = workflow["jobs"]["guest-inputs"]
    assert job["needs"] == "package-inputs"
    assert workflow["jobs"]["package-inputs"]["outputs"]["architectures"] == "${{ steps.select.outputs.architectures }}"
    assert job["strategy"]["matrix"]["architecture"] == "${{ fromJSON(needs.package-inputs.outputs.architectures) }}"
    assert job["uses"] == "./.github/workflows/guest-test-inputs.yml"
    assert job["with"] == {
        "revision": "${{ github.event.pull_request.head.sha || github.sha }}",
        "profile": "production", "architecture": "${{ matrix.architecture }}",
        "host_inputs": True, "retain_packages": True,
    }
    assert workflow["permissions"] == {"contents": "read"}
    assert "continue-on-error" not in job


@pytest.mark.parametrize("workflow_name", ["ci.yml", "proxy-rust.yml"])
def test_linux_input_callers_pin_the_supported_ubuntu_runtime_baseline(workflow_name):
    workflow = yaml.safe_load(WORKFLOW.with_name(workflow_name).read_text())
    caller = workflow["jobs"]["guest-inputs"]
    assert caller["uses"] == "./.github/workflows/guest-test-inputs.yml"
    assert caller["with"]["architecture"] == "${{ matrix.architecture }}"
    assert caller["with"]["profile"] == "production"
    shared = yaml.safe_load(WORKFLOW.with_name("guest-test-inputs.yml").read_text())
    assert shared[True]["workflow_call"]["inputs"]["architecture"]["default"] == "amd64"
    build = shared["jobs"]["build"]
    assert build["runs-on"] == (
        "${{ inputs.architecture == 'arm64' && 'ubuntu-24.04-arm' || 'ubuntu-24.04' }}"
    )
    steps = {step.get("name"): step for step in build["steps"]}
    package = steps["Retain complete Linux production bundle"]["run"]
    # Acquire tmux on the same baseline as the host build and package assembly.
    assert "sudo -n apt-get install -y -qq --no-install-recommends tmux" in package
    assert '--artifacts proxy/target/release --guest-artifacts guest/command/target/release' in package
    assert '--runtime-artifacts "$(dirname "$(command -v tmux)")" --profile production' in package


def test_full_matrix_is_overnight_or_explicit_and_uses_the_exact_head() -> None:
    job = rust_workflow()["jobs"]["contracts"]
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)"
    )
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "macos-latest"]
    checkout = job["steps"][0]
    expected_head = "${{ github.event.pull_request.head.sha || github.sha }}"
    assert checkout["with"]["ref"] == expected_head
    assert job["steps"][1]["env"]["EXPECTED_HEAD"] == expected_head
    assert "git rev-parse HEAD" in job["steps"][1]["run"]
    steps = {step.get("name"): step for step in job["steps"]}
    assert steps["Test the Rust proxy"]["timeout-minutes"] == (
        "${{ matrix.os == 'macos-latest' && 20 || 15 }}"
    )
    assert steps["Stop the native Coord fixture"]["if"] == "always()"
    peer = steps["Provide the macOS owned HTTP peer addresses"]
    assert peer["if"] == "matrix.os == 'macos-latest'"
    assert "ifconfig lo0 alias 127.0.0.2" in peer["run"]
    assert "ifconfig lo0 alias 127.0.0.3" in peer["run"]
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
    assert named["Test the Rust proxy"]["env"]["SAFEYOLO_PYTHON"] == (
        "${{ github.workspace }}/.venv/bin/python"
    )
    rendered = str(steps)
    assert "--proxy-backend python" not in rendered
    assert "-- --ignored" not in rendered
    assert "git fetch --no-tags --depth=1 origin" not in rendered
    assert "SAFEYOLO_PYTHON_SOURCE" not in rendered


def test_overnight_compilation_prepares_shared_outputs_then_keeps_all_release_targets():
    job = rust_workflow()["jobs"]["contracts"]
    steps = {step.get("name"): step for step in job["steps"]}
    library = steps["Compile Rust library contract target"]
    binaries = steps["Compile Rust binary contract targets"]
    complete = steps["Compile Rust contract executables"]
    assert library["run"] == (
        "../scripts/cargo_with_space.sh test --release --locked "
        "--lib --no-run --timings --verbose"
    )
    assert binaries["run"] == (
        "../scripts/cargo_with_space.sh test --release --locked "
        "--bins --test version --no-run --timings --verbose"
    )
    assert complete["run"] == (
        "../scripts/cargo_with_space.sh test --release --locked --no-run --timings --verbose"
    )
    for step in (library, binaries, complete):
        assert step["working-directory"] == "proxy"
        assert step["timeout-minutes"] == "${{ matrix.os == 'macos-latest' && 20 || 25 }}"
        assert step["env"] == {"SAFEYOLO_PYTHON": "${{ github.workspace }}/.venv/bin/python"}
        assert "if" not in step
        assert not step.get("continue-on-error")
    ordered = [steps[name] for name in (
        "Compile production native executables", "Compile Rust library contract target",
        "Compile Rust binary contract targets",
        "Compile Rust contract executables", "Retain Rust compilation timings",
        "Start the native Coord fixture", "Test the Rust proxy",
    )]
    assert [job["steps"].index(step) for step in ordered] == sorted(
        job["steps"].index(step) for step in ordered
    )
    timings = steps["Retain Rust compilation timings"]
    assert timings["if"] == "always()"
    assert timings["with"]["path"] == "proxy/target/cargo-timings/*.html"
    assert timings["with"]["if-no-files-found"] == "ignore"
    execution = steps["Test the Rust proxy"]["run"]
    assert "../scripts/cargo_with_space.sh test --release --locked\n" in execution
    assert "inventory::native_inventory_uses_current_grants_and_fixture_provider_evidence_across_restart -- --exact --ignored" in execution
    assert "../scripts/cargo_with_space.sh build --release --locked --bins" in execution


@pytest.mark.parametrize("macos", [False, True], ids=["linux", "macos"])
@pytest.mark.parametrize("package_exit", [0, 19], ids=["prepared", "refused"])
def test_overnight_harness_callers_receive_prepared_native_inputs(tmp_path, macos, package_exit):
    job = rust_workflow()["jobs"]["contracts"]
    steps = {step.get("name"): step for step in job["steps"]}
    consumer = steps["Run native proxy component contracts"]
    assert consumer["shell"] == "bash"
    assert "if" not in consumer
    for producer in ("Compile production native executables", "Restore Linux guest executable permissions",
                     "Start the native Coord fixture", "Prepare macOS VM package inputs"):
        assert job["steps"].index(steps[producer]) < job["steps"].index(consumer)

    commands, scripts = tmp_path / "commands", tmp_path / "scripts"
    commands.mkdir()
    scripts.mkdir()
    calls = tmp_path / "calls.jsonl"
    recorder = (
        f"#!{sys.executable}\nimport json, os, pathlib, sys\n"
        f"with pathlib.Path({str(calls)!r}).open('a') as output:\n"
        "    output.write(json.dumps({'command': pathlib.Path(sys.argv[0]).name, 'args': sys.argv[1:],\n"
        "        'inputs': {key: os.environ.get(key) for key in "
        "('SAFEYOLO_TEST_NATIVE_CLI', 'SAFEYOLO_NATIVE_BUNDLE', 'SAFEYOLO_COORD_NATS_BINARY')}}) + '\\n')\n"
    )
    package = scripts / "build_host_packages.sh"
    package.write_text(recorder + f"raise SystemExit({package_exit})\n")
    uv = commands / "uv"
    uv.write_text(recorder)
    for path in (package, uv, commands / "tmux", tmp_path / "nats-server"):
        if not path.exists():
            path.touch()
        path.chmod(0o755)
    # Match hosted Bash without the sandbox's PATH-changing startup file.
    environment = dict(os.environ, BASH_ENV=os.devnull,
                       PATH=f"{commands}:{os.environ['PATH']}", RUNNER_TEMP=str(tmp_path),
                       SAFEYOLO_NATIVE_ARTIFACTS="/prepared/host", SAFEYOLO_GUEST_ARTIFACTS="/prepared/guest",
                       SAFEYOLO_NATIVE_VM_ARTIFACTS="/prepared/vm" if macos else "",
                       SAFEYOLO_NATIVE_CLI="/prepared/host/safeyolo",
                       SAFEYOLO_COORD_NATS_BINARY=str(tmp_path / "nats-server"))
    result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", consumer["run"]],
                            cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode == package_exit, result.stderr
    observed = [json.loads(line) for line in calls.read_text().splitlines()]
    bundle = str(tmp_path / "native-contract-bundle")
    assert observed[0]["command"] == "build_host_packages.sh"
    assert observed[0]["args"] == [
        "--directory", bundle, "--artifacts", "/prepared/host", "--guest-artifacts", "/prepared/guest",
        "--runtime-artifacts", str(commands), "--profile", "production",
    ] + (["--vm-artifacts", "/prepared/vm"] if macos else [])
    if package_exit:
        assert len(observed) == 1
        return
    assert len(observed) == 3
    for call in observed[1:]:
        assert call["inputs"] == {"SAFEYOLO_TEST_NATIVE_CLI": "/prepared/host/safeyolo",
                                  "SAFEYOLO_NATIVE_BUNDLE": bundle,
                                  "SAFEYOLO_COORD_NATS_BINARY": str(tmp_path / "nats-server")}
    assert observed[1]["args"] == ["run", "--frozen", "pytest", "-q"] + [
        f"tests/test_blackbox_harness.py::{name}" for name in (
            "test_prepared_inputs_reach_native_lifecycle_with_fresh_state",
            "test_shared_approval_transport_keeps_owned_selection_when_preparation_fails",
            "test_blackbox_coord_binding_reaches_real_native_start_and_restart",
            "test_access_launcher_targets_match_selected_guest_requests",
            "test_lifecycle_owner_prepares_pinned_nats_on_independent_ports",
        )
    ]
    assert observed[2]["args"] == ["run", "--frozen", "pytest", "-q", "tests/proxy_contracts", "--proxy-backend", "rust"]


def test_existing_graph_integrity_check_runs_for_quick_cli_and_before_guest_compilation():
    ci = yaml.safe_load(WORKFLOW.with_name("ci.yml").read_text())
    inputs = yaml.safe_load(WORKFLOW.with_name("guest-test-inputs.yml").read_text())
    for job, check_name, following in (
        (ci["jobs"]["test-cli"], "Check acceptance tool source bindings", "Quick CLI checks"),
        (inputs["jobs"]["build"], "Check acceptance tool source bindings before compilation", "Build Linux guest executables and receipts"),
    ):
        steps = {step.get("name"): step for step in job["steps"]}
        check = steps[check_name]
        assert "if" not in check
        assert 'runpy.run_path("cli/tests/test_host_setup_scripts.py")' in check["run"]
        assert 'test_safeyolo_acceptance_graph_tool_hashes_match_sources' in check["run"]
        assert job["steps"].index(check) < job["steps"].index(steps[following])
    producer = inputs["jobs"]["build"]["steps"]
    check = next(step for step in producer if step.get("name") == "Check acceptance tool source bindings before compilation")
    assert "uv export --frozen --only-group dev" in check["run"]
    assert '"--require-hashes"' in check["run"]
    assert 'if package["name"] in ("pytest", "pyyaml")' in check["run"]
    assert "uv sync" not in check["run"]


def test_native_producers_and_consumers_share_the_existing_compatible_dependency_cache():
    """The pinned action's shared-key replaces its automatic per-job prefix."""
    shared = yaml.safe_load(WORKFLOW.with_name("guest-test-inputs.yml").read_text())
    for workflow in (rust_workflow(), shared):
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if not str(step.get("uses", "")).startswith("Swatinem/rust-cache@"):
                    continue
                options = step["with"]
                expected = "production-focused-pr" if workflow is not shared else "${{ inputs.profile }}-focused-pr"
                assert options["shared-key"] == expected
                assert "key" not in options  # The pinned action ignores key when shared-key is set.
                assert options["workspaces"].splitlines() == ["proxy -> target", "guest/command -> target"]
                assert options["cache-bin"] is False
                assert "add-rust-environment-hash-key" not in options
                assert "env-vars" not in options


def test_rust_caches_use_the_selected_compiler_without_disabling_compatibility_hashes():
    for path in WORKFLOW.parent.glob("*.yml"):
        workflow = yaml.safe_load(path.read_text())
        for job in workflow["jobs"].values():
            for index, step in enumerate(job.get("steps", [])):
                if not str(step.get("uses", "")).startswith("Swatinem/rust-cache@"):
                    continue
                options = step["with"]
                assert options["cmd-format"] == (
                    'bash "${{ github.workspace }}/scripts/rust_cache_command.sh" {0}'
                )
                assert options.get("add-rust-environment-hash-key", True) is True
                selection = next(
                    previous for previous in job["steps"][:index]
                    if previous.get("name") == "Install the pinned Rust toolchain"
                )
                assert selection["working-directory"] == "proxy"
                assert "rustup show active-toolchain" in selection["run"]
                assert "RUSTUP_TOOLCHAIN=%s" in selection["run"]
                assert selection.get("if") == step.get("if")


@pytest.mark.parametrize("ambient", ["1.98.1", "1.99.0"])
def test_rust_cache_inventory_ignores_unselected_installed_compilers(tmp_path, ambient):
    rustup = tmp_path / "rustup"
    rustup.write_text('#!/bin/sh\nprintf "%s\\n" "$RUSTUP_TOOLCHAIN" "$AMBIENT_TOOLCHAIN"\n')
    rustup.chmod(0o755)
    selected = "1.94.0-aarch64-apple-darwin"
    command = WORKFLOW.parents[2] / "scripts/rust_cache_command.sh"
    environment = dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}",
                       RUSTUP_TOOLCHAIN=selected, AMBIENT_TOOLCHAIN=ambient, BASH_ENV="")
    installed = subprocess.run(
        ["rustup", "toolchain", "list", "--quiet"],
        env=environment, text=True, capture_output=True, check=True,
    )
    assert installed.stdout == f"{selected}\n{ambient}\n"
    inventory = subprocess.run(
        ["bash", str(command), "rustup", "toolchain", "list", "--quiet"],
        env=environment, text=True, capture_output=True, check=True,
    )
    assert inventory.stdout == f"{selected}\n"
    # Without the job's explicit compiler, a cache failure must stay visible.
    environment.pop("RUSTUP_TOOLCHAIN")
    missing = subprocess.run(
        ["bash", str(command), "rustup", "toolchain", "list", "--quiet"],
        env=environment, text=True, capture_output=True,
    )
    assert missing.returncode != 0
    assert "Set RUSTUP_TOOLCHAIN" in missing.stderr


def test_rust_cache_command_preserves_metadata_arguments_environment_and_failure(tmp_path):
    command = WORKFLOW.parents[2] / "scripts/rust_cache_command.sh"
    probe = tmp_path / "metadata command"
    probe.write_text('#!/bin/sh\nprintf "%s\\n" "$RUSTFLAGS" "$CARGO_PROFILE_RELEASE_LTO" "$PWD" "$@"\nexit 23\n')
    probe.chmod(0o755)
    arguments = ["metadata", "--manifest-path", "path with spaces/Cargo.toml", "--locked"]
    result = subprocess.run(
        ["bash", str(command), str(probe), *arguments], cwd=tmp_path,
        env=dict(os.environ, RUSTFLAGS="-C opt-level=2", CARGO_PROFILE_RELEASE_LTO="thin"),
        text=True, capture_output=True,
    )
    assert result.returncode == 23
    assert result.stdout.splitlines() == ["-C opt-level=2", "thin", str(tmp_path), *arguments]


def test_platform_changes_add_relevant_macos_checks_without_full_contract_matrix():
    jobs = rust_workflow()["jobs"]
    job = jobs["macos-pr"]
    assert job["needs"] == "focused-pr"
    assert job["if"] == "needs.focused-pr.outputs.macos == 'true'"
    assert job["runs-on"] == "macos-latest"
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    assert "test_vm_control.py" in runs
    assert "--test native_host_identity" in runs
    assert "test_vm_diagnostics.py" in runs
    assert "--test native_runtime_dependency" in runs
    assert "tests/proxy_contracts --proxy-backend rust" not in runs
    assert "install.sh" not in runs and "bootstrap" not in runs


@pytest.mark.parametrize("path,expected,matcher", [
    ("tests/reference/safeyolo/platform/linux.py", {"linux": "true"}, "available"),
    ("tests/reference/safeyolo/platform/darwin.py", {"macos": "true"}, "available"),
    ("proxy/src/host_platform.rs", {"rust": "true", "linux": "true", "macos": "true"}, "available"),
    ("tests/proxy_contracts/test_native_policy_cli.py", {"rust": "true"}, "available"),
    ("tests/proxy_contracts/test_first_agent_launch.py", {"rust": "true"}, "available"),
    ("tests/proxy_contracts/test_readiness.py", {}, "available"),
    ("docs/DEVELOPERS.md", {}, "available"),
    ("site/index.md", {"dispatch": "true"}, "available"),
    (".github/workflows/pages.yml", {"dispatch": "true"}, "available"),
    (".github/workflows/proxy-rust.yml", {"rust": "true", "macos": "true"}, "available"),
    (".github/workflows/guest-test-inputs.yml", {"rust": "true", "macos": "true"}, "available"),
    (".github/workflows/ci.yml", {"rust": "true", "macos": "true"}, "available"),
    ("scripts/rust_cache_command.sh", {"rust": "true", "macos": "true"}, "available"),
    ("scripts/cargo_with_space.sh", {"rust": "true"}, "available"),
    ("tests/test_proxy_rust_coord_fixture.py", {"rust": "true"}, "available"),
    ("tests/test_proxy_rust_ci_events.py", {}, "available"),
    ("tests/test_blackbox_harness.py", {}, "available"),
    ("guest/command/src/main.rs", {"guest": "true"}, "available"),
    ("proxy/src/host_platform.rs", {}, "missing"),
    ("proxy/src/host_platform.rs", {}, "failing"),
], ids=["linux-only", "mac-only", "shared-native", "native-policy-only", "first-agent-only", "readiness-only",
        "docs-only", "dispatch-content", "dispatch-workflow",
        "native-profile-workflow", "shared-profile-workflow", "python-profile-workflow", "rust-cache-command",
        "cargo-wrapper-only", "coord-fixture-only", "workflow-controls-only", "blackbox-only", "guest-only",
        "missing-grep", "failing-grep"])
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
    steps = rust_workflow()["jobs"]["focused-pr"]["steps"]
    step = next(step for step in steps if step.get("id") == "changes")
    # Actions' unspecified Linux shell uses Bash -e, without nounset or pipefail.
    result = subprocess.run([str(commands / "bash"), "-e", "-c", step["run"]],
                            cwd=tmp_path, capture_output=True, text=True, check=False,
                            env=dict(os.environ, PATH=str(commands), BASE=base,
                                     RUNNER_TEMP=str(tmp_path), GITHUB_OUTPUT=str(output), BASH_ENV=os.devnull))
    if matcher == "available":
        assert result.returncode == 0, result.stderr
        assert not result.stderr
    else:
        assert result.returncode == 2
        assert "changed-path matcher failed" in result.stderr
    actual = dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}
    assert actual == expected
    if matcher == "available":
        fixture = next(step for step in steps if step.get("name") == "Test current native Coord fixture boundaries")
        build = next(step for step in steps if step.get("id") == "linux_host_inputs")
        boundaries = next(step for step in steps if step.get("name") == "Test workflow, fixture, deletion, and blackbox runner boundaries")
        assert "tests/test_proxy_rust_coord_fixture.py" not in boundaries["run"]
        assert fixture["if"] == build["if"] == "steps.changes.outputs.rust == 'true'"
        assert steps.index(build) < steps.index(fixture)
        assert fixture["env"] == {
            "SAFEYOLO_NATIVE_CLI": "${{ github.workspace }}/proxy/target/release/safeyolo",
            "SAFEYOLO_RUST_PROXY": "${{ github.workspace }}/proxy/target/release/safeyolo-proxy",
        }
        assert rust_workflow()["jobs"]["focused-pr"]["env"]["SAFEYOLO_BUILD_REVISION"] == (
            "${{ github.event.pull_request.head.sha || github.sha }}"
        )
    if matcher != "available" or expected.get("guest") or expected.get("dispatch"):
        return
    installed = next(step for step in steps if step.get("name") == "Test installed native policy commands")
    for name in (
        "Install the pinned Rust toolchain", "Restore Rust dependency cache", "Install Linux guest build tools",
        "Build the native guest command artifact", "Build Linux production inputs",
        "Build the native CLI for recovery and Dispatch checks", "Install uv",
        "Install the native CLI test environment", "Install preview test system dependency",
        "Install the pinned Codex execpolicy test consumer", installed["name"],
    ):
        prerequisite = next(step for step in steps if step.get("name") == name)
        assert steps.index(prerequisite) <= steps.index(installed)
        condition = prerequisite.get("if", "true")
        for key in ("rust", "guest", "dispatch"):
            condition = condition.replace(f"steps.changes.outputs.{key}", shlex.quote(actual.get(key, "")))
        # These string comparisons and disjunctions share Actions' truth table.
        admission = subprocess.run(["bash", "-e", "-c", f"[[ {condition} ]]"],
                                   capture_output=True, text=True, env=dict(os.environ, BASH_ENV=os.devnull))
        selected = expected.get("rust") == "true" or "if" not in prerequisite
        assert admission.returncode == (0 if selected else 1), (name, condition, admission.stderr)


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
