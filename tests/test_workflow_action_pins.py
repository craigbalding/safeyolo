"""Supply-chain and syntax contracts for shipped GitHub Actions workflows."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
ACTION_LINE = re.compile(
    r"^\s*(?:-\s*)?uses:\s+(?P<action>[^@\s]+)@(?P<ref>[^\s#]+)"
    r"(?:\s+#\s+(?P<version>\S+))?\s*$"
)
FULL_SHA = re.compile(r"[0-9a-f]{40}")
EXPECTED_ACTIONS = {
    "actions/checkout": (
        "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "v7.0.1",
    ),
    "astral-sh/setup-uv": (
        "20cfd1bf945f4377ade1205e4dbc17946fc9a30d",
        "v10.0.1",
    ),
}


def workflow_paths() -> list[Path]:
    return sorted((*WORKFLOW_DIR.glob("*.yml"), *WORKFLOW_DIR.glob("*.yaml")))


def test_workflows_parse_as_yaml() -> None:
    for path in workflow_paths():
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(workflow, dict), f"{path}: workflow root must be a mapping"
        assert isinstance(workflow.get("jobs"), dict), f"{path}: jobs must be a mapping"


def test_external_actions_use_documented_full_sha_pins() -> None:
    migrated_actions: set[str] = set()

    for path in workflow_paths():
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "uses:" not in line:
                continue
            # Local reusable workflows use this checkout's source, not an
            # external action ref. GitHub's job-level syntax has no @ref.
            if re.fullmatch(r"\s+uses: \./\.github/workflows/[\w-]+\.ya?ml\s*", line):
                continue
            match = ACTION_LINE.fullmatch(line)
            assert match is not None, f"{path}:{line_number}: cannot validate action pin"

            action = match["action"]
            if action.startswith("./"):
                continue
            assert FULL_SHA.fullmatch(match["ref"]), (
                f"{path}:{line_number}: {action} must use an immutable full SHA"
            )
            assert match["version"], (
                f"{path}:{line_number}: {action} must document its release version"
            )

            expected = EXPECTED_ACTIONS.get(action)
            if expected is not None:
                migrated_actions.add(action)
                assert (match["ref"], match["version"]) == expected, (
                    f"{path}:{line_number}: unexpected {action} release pin"
                )

    assert migrated_actions == EXPECTED_ACTIONS.keys()


def test_setup_uv_preserves_v5_cache_pruning_behavior() -> None:
    for path in workflow_paths():
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if not str(step.get("uses", "")).startswith("astral-sh/setup-uv@"):
                    continue
                assert step.get("with", {}).get("version") == ("0.12.8" if path.name == "proxy-rust.yml" else "0.9.24")
                assert step.get("with", {}).get("prune-cache") is True


def test_proxy_rust_compilation_and_execution_have_platform_limits() -> None:
    workflow = yaml.safe_load((WORKFLOW_DIR / "proxy-rust.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["contracts"]["steps"]
    for name in ("Compile production native executables", "Compile Rust contract executables", "Test the Rust proxy"):
        bounded_step = next(step for step in steps if step.get("name") == name)
        assert bounded_step["timeout-minutes"] == "${{ matrix.os == 'macos-latest' && 20 || 15 }}"
    named = {step.get("name"): step for step in steps}
    assert "test --release --locked --no-run" in named["Compile Rust contract executables"]["run"]
    assert "build --release --locked --bins" in named["Compile production native executables"]["run"]
    assert "test --release --locked" in named["Test the Rust proxy"]["run"]


def test_codex_test_lock_covers_wrapper_and_all_platform_packages() -> None:
    directory = REPO_ROOT / "tools/codex-execpolicy"
    manifest = json.loads((directory / "package.json").read_text())
    packages = json.loads((directory / "package-lock.json").read_text())["packages"]
    assert manifest["private"] is True
    assert manifest["dependencies"] == packages[""]["dependencies"] == {"@openai/codex": "0.159.1"}
    wrapper = packages["node_modules/@openai/codex"]
    assert wrapper["version"] == "0.159.1"
    platforms = {f"{system}-{cpu}" for system in ("linux", "darwin", "win32") for cpu in ("arm64", "x64")}
    assert set(wrapper["optionalDependencies"]) == {f"@openai/codex-{platform}" for platform in platforms}
    for platform in platforms:
        name = f"@openai/codex-{platform}"
        package = packages[f"node_modules/{name}"]
        assert wrapper["optionalDependencies"][name] == f"npm:@openai/codex@{package['version']}"
        assert package["version"] == f"0.159.1-{platform}"
        system, cpu = platform.split("-")
        assert package["os"] == [system] and package["cpu"] == [cpu]
    for name, package in packages.items():
        if name:
            algorithm, digest = package["integrity"].split("-", 1)
            assert algorithm == "sha512" and len(base64.b64decode(digest, validate=True)) == 64
            assert package["resolved"] == f"https://registry.npmjs.org/@openai/codex/-/codex-{package['version']}.tgz"


@pytest.mark.parametrize("changed_package", ["wrapper", "platform"])
def test_codex_workflow_refuses_changed_package_bytes_before_export(tmp_path, changed_package) -> None:
    if shutil.which("npm") is None:
        pytest.skip("the workflow's npm prerequisite is unavailable")
    directory = tmp_path / "tools/codex-execpolicy"
    directory.mkdir(parents=True)
    shutil.copyfile(REPO_ROOT / "tools/codex-execpolicy/package.json", directory / "package.json")
    lock = json.loads((REPO_ROOT / "tools/codex-execpolicy/package-lock.json").read_text())
    changed = tmp_path / "codex-changed.tgz"
    changed_manifest = tmp_path / "changed-package.json"
    changed_manifest.write_text(json.dumps({"name": "@openai/codex", "version": "0.159.1"}))
    with tarfile.open(changed, "w:gz") as archive:
        archive.add(changed_manifest, arcname="package/package.json")
    wrapper = lock["packages"]["node_modules/@openai/codex"]
    if changed_package == "wrapper":
        wrapper["resolved"] = changed.as_uri()
    else:
        platform = subprocess.check_output(["node", "-p", "process.platform + '-' + process.arch"], text=True).strip()
        name = f"@openai/codex-{platform}"
        lock["packages"][f"node_modules/{name}"]["resolved"] = changed.as_uri()
        # A controlled wrapper reports the right version even without its native
        # package. The workflow must refuse before that command can export PATH.
        valid_wrapper = tmp_path / "wrapper.tgz"
        metadata = {"name": "@openai/codex", "version": "0.159.1", "bin": wrapper["bin"],
                    "optionalDependencies": wrapper["optionalDependencies"]}
        with tarfile.open(valid_wrapper, "w:gz") as archive:
            for name_in_archive, content in (
                ("package/package.json", json.dumps(metadata).encode()),
                ("package/bin/codex.js", b"#!/usr/bin/env node\nconsole.log('codex-cli 0.159.1');\n"),
            ):
                member = tarfile.TarInfo(name_in_archive)
                member.size = len(content)
                member.mode = 0o755
                archive.addfile(member, io.BytesIO(content))
        wrapper["resolved"] = valid_wrapper.as_uri()
        wrapper["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(valid_wrapper.read_bytes()).digest()).decode()
        # Reproduce an ambient install that would mask the missing local package.
        ambient = tmp_path / "ambient" / name
        ambient.mkdir(parents=True)
        (ambient / "package.json").write_text(json.dumps({"name": name, "version": f"0.159.1-{platform}"}))
    (directory / "package-lock.json").write_text(json.dumps(lock))
    workflow = yaml.safe_load((WORKFLOW_DIR / "proxy-rust.yml").read_text())
    setup = next(step for step in workflow["jobs"]["contracts"]["steps"]
                 if step.get("name") == "Install the pinned Codex execpolicy test consumer")
    github_path = tmp_path / "github-path"
    environment = dict(os.environ, RUNNER_TEMP=str(tmp_path / "runner"), GITHUB_PATH=str(github_path),
                       npm_config_cache=str(tmp_path / "npm-cache"), npm_config_offline="true")
    if changed_package == "platform":
        environment["NODE_PATH"] = str(tmp_path / "ambient")
    result = subprocess.run(["bash", "-eo", "pipefail", "-c", setup["run"]], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=30)
    expected = "EINTEGRITY" if changed_package == "wrapper" else "Codex must use the locked local platform package"
    assert result.returncode != 0 and expected in result.stderr, (result.stdout, result.stderr)
    assert not github_path.exists(), "a rejected checker must not reach the test PATH"
