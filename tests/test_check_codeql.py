from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_codeql.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_codeql", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def check_codeql() -> ModuleType:
    return _load_script()


def _invoke(monkeypatch: pytest.MonkeyPatch, module: ModuleType, *arguments: str) -> int:
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), *arguments])
    return module.main()


def _manifest(platform_key: str) -> dict[str, object]:
    return {
        "bundle_version": "2.26.3",
        "assets": {
            platform_key: [
                {
                    "archive": "codeql-test.tar.gz",
                    "sha256": "0" * 64,
                }
            ]
        },
    }


@pytest.mark.parametrize("machine", ["aarch64", "arm64"])
def test_linux_arm64_default_skips_without_download_or_analysis(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    check_codeql: ModuleType,
    machine: str,
) -> None:
    monkeypatch.delenv("SAFEYOLO_CODEQL_BIN", raising=False)
    monkeypatch.setattr(check_codeql.platform, "system", lambda: "Linux")
    monkeypatch.setattr(check_codeql.platform, "machine", lambda: machine)
    monkeypatch.setattr(check_codeql, "_load_manifest", lambda: _manifest("linux-x86_64"))
    monkeypatch.setattr(
        check_codeql,
        "_download",
        lambda *_args, **_kwargs: pytest.fail("unsupported ARM must not download"),
    )
    monkeypatch.setattr(
        check_codeql,
        "_run_analysis",
        lambda *_args, **_kwargs: pytest.fail("unsupported ARM must not analyze"),
    )

    assert _invoke(monkeypatch, check_codeql) == 0
    error = capsys.readouterr().err
    assert f"unavailable for Linux {machine}" in error
    assert "was skipped" in error
    assert "no pinned official stable native bundle" in error
    assert "GitHub CI CodeQL remains the required analysis gate" in error
    assert "found no issues" not in error


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Linux", "amd64", "linux-x86_64"),
        ("Linux", "x86_64", "linux-x86_64"),
        ("Linux", "aarch64", "linux-arm64"),
        ("Linux", "arm64", "linux-arm64"),
        ("Darwin", "amd64", "macos-x86_64"),
        ("Darwin", "x86_64", "macos-x86_64"),
        ("Darwin", "aarch64", "macos-x86_64"),
        ("Darwin", "arm64", "macos-x86_64"),
    ],
)
def test_platform_key_recognizes_supported_and_linux_arm64_platforms(
    monkeypatch: pytest.MonkeyPatch,
    check_codeql: ModuleType,
    system: str,
    machine: str,
    expected: str,
) -> None:
    monkeypatch.setattr(check_codeql.platform, "system", lambda: system)
    monkeypatch.setattr(check_codeql.platform, "machine", lambda: machine)

    assert check_codeql._platform_key() == expected


@pytest.mark.parametrize(
    ("system", "machine", "platform_key"),
    [
        ("Linux", "x86_64", "linux-x86_64"),
        ("Darwin", "arm64", "macos-x86_64"),
    ],
)
def test_supported_platform_uses_cached_official_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    check_codeql: ModuleType,
    system: str,
    machine: str,
    platform_key: str,
) -> None:
    monkeypatch.delenv("SAFEYOLO_CODEQL_BIN", raising=False)
    monkeypatch.setattr(check_codeql.platform, "system", lambda: system)
    monkeypatch.setattr(check_codeql.platform, "machine", lambda: machine)
    monkeypatch.setattr(check_codeql, "_load_manifest", lambda: _manifest(platform_key))
    monkeypatch.setattr(check_codeql, "_cache_root", lambda: tmp_path)
    binary = tmp_path / "2.26.3" / platform_key / "codeql" / "codeql"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)

    assert check_codeql._ensure_codeql() == binary


def test_adding_official_linux_arm64_capability_enables_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    check_codeql: ModuleType,
) -> None:
    platform_key = "linux-arm64"
    monkeypatch.delenv("SAFEYOLO_CODEQL_BIN", raising=False)
    monkeypatch.setattr(check_codeql.platform, "system", lambda: "Linux")
    monkeypatch.setattr(check_codeql.platform, "machine", lambda: "aarch64")
    monkeypatch.setitem(
        check_codeql.ASSET_LAYOUT,
        platform_key,
        (("codeql-bundle-linux-arm64.tar.zst", "zstd"),),
    )
    monkeypatch.setattr(check_codeql, "_load_manifest", lambda: _manifest(platform_key))
    monkeypatch.setattr(check_codeql, "_cache_root", lambda: tmp_path)
    binary = tmp_path / "2.26.3" / platform_key / "codeql" / "codeql"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)

    assert check_codeql._ensure_codeql() == binary


@pytest.mark.parametrize(
    ("system", "machine", "platform_key"),
    [
        ("Linux", "x86_64", "linux-x86_64"),
        ("Darwin", "arm64", "macos-x86_64"),
    ],
)
def test_supported_platform_manifest_failure_is_not_skipped(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    check_codeql: ModuleType,
    system: str,
    machine: str,
    platform_key: str,
) -> None:
    monkeypatch.delenv("SAFEYOLO_CODEQL_BIN", raising=False)
    monkeypatch.setattr(check_codeql.platform, "system", lambda: system)
    monkeypatch.setattr(check_codeql.platform, "machine", lambda: machine)
    monkeypatch.setattr(
        check_codeql,
        "_load_manifest",
        lambda: {"bundle_version": "2.26.3", "assets": {}},
    )

    assert _invoke(monkeypatch, check_codeql) == 2
    error = capsys.readouterr().err
    assert f"missing {platform_key} asset" in error
    assert "skipped" not in error


def test_invalid_explicit_binary_on_linux_arm64_remains_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    check_codeql: ModuleType,
) -> None:
    missing = tmp_path / "missing-codeql"
    monkeypatch.setenv("SAFEYOLO_CODEQL_BIN", str(missing))
    monkeypatch.setattr(check_codeql.platform, "system", lambda: "Linux")
    monkeypatch.setattr(check_codeql.platform, "machine", lambda: "aarch64")

    assert _invoke(monkeypatch, check_codeql) == 2
    error = capsys.readouterr().err
    assert "SAFEYOLO_CODEQL_BIN is not executable" in error
    assert "skipped" not in error


@pytest.mark.parametrize(
    ("system", "machine"),
    [("Linux", "x86_64"), ("Darwin", "arm64")],
)
def test_supported_platform_findings_still_block_push(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    check_codeql: ModuleType,
    system: str,
    machine: str,
) -> None:
    binary = tmp_path / "codeql"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CODEQL_BIN", str(binary))
    monkeypatch.setattr(check_codeql.platform, "system", lambda: system)
    monkeypatch.setattr(check_codeql.platform, "machine", lambda: machine)
    monkeypatch.setattr(
        check_codeql.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout="2.26.3\n"),
    )
    monkeypatch.setattr(check_codeql, "_run_analysis", lambda _binary: ([{}], 0))

    assert _invoke(monkeypatch, check_codeql) == 1
    assert "Local CodeQL found 1 issue(s)" in capsys.readouterr().err


def test_explicit_binary_runs_analysis_on_linux_arm64(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    check_codeql: ModuleType,
) -> None:
    binary = tmp_path / "codeql"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CODEQL_BIN", str(binary))
    monkeypatch.setattr(
        check_codeql.platform,
        "system",
        lambda: pytest.fail("explicit binary must bypass platform selection"),
    )
    monkeypatch.setattr(
        check_codeql.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout="2.26.3\n"),
    )
    analyzed = []
    monkeypatch.setattr(
        check_codeql,
        "_run_analysis",
        lambda selected: (analyzed.append(selected) or [], 0),
    )

    assert _invoke(monkeypatch, check_codeql) == 0
    assert analyzed == [binary.resolve()]
    assert "found no issues" in capsys.readouterr().err


def test_install_only_with_explicit_binary_does_not_analyze(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    check_codeql: ModuleType,
) -> None:
    binary = tmp_path / "codeql"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CODEQL_BIN", str(binary))
    monkeypatch.setattr(
        check_codeql.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout="2.26.3\n"),
    )
    monkeypatch.setattr(
        check_codeql,
        "_run_analysis",
        lambda *_args: pytest.fail("--install-only must not analyze"),
    )

    assert _invoke(monkeypatch, check_codeql, "--install-only") == 0


def test_install_only_without_linux_arm64_bundle_fails_explicitly(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    check_codeql: ModuleType,
) -> None:
    monkeypatch.delenv("SAFEYOLO_CODEQL_BIN", raising=False)
    monkeypatch.setattr(check_codeql.platform, "system", lambda: "Linux")
    monkeypatch.setattr(check_codeql.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(check_codeql, "_load_manifest", lambda: _manifest("linux-x86_64"))

    assert _invoke(monkeypatch, check_codeql, "--install-only") == 2
    error = capsys.readouterr().err
    assert "local CodeQL install failed" in error
    assert "GitHub CI CodeQL remains the required analysis gate" in error
    assert "skipped" not in error


def test_verify_version_is_platform_independent(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    check_codeql: ModuleType,
) -> None:
    monkeypatch.setattr(check_codeql, "_load_manifest", lambda: _manifest("linux-x86_64"))
    monkeypatch.setattr(
        check_codeql,
        "_platform_key",
        lambda: pytest.fail("--verify-version must not select a platform"),
    )

    assert _invoke(monkeypatch, check_codeql, "--verify-version", "2.26.3") == 0
    assert "versions match" in capsys.readouterr().out


def test_update_bundle_is_platform_independent(
    monkeypatch: pytest.MonkeyPatch,
    check_codeql: ModuleType,
) -> None:
    updated = []
    monkeypatch.setattr(check_codeql, "_update_manifest", updated.append)
    monkeypatch.setattr(
        check_codeql,
        "_platform_key",
        lambda: pytest.fail("--update-bundle must not select a platform"),
    )

    assert _invoke(monkeypatch, check_codeql, "--update-bundle", "2.27.0") == 0
    assert updated == ["2.27.0"]


def test_pre_push_default_hook_skips_linux_arm64_without_analysis(
    monkeypatch: pytest.MonkeyPatch,
    check_codeql: ModuleType,
) -> None:
    config = yaml.safe_load((REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    hook = next(
        hook
        for repository in config["repos"]
        for hook in repository["hooks"]
        if hook["id"] == "local-codeql"
    )
    assert hook["entry"] == "uv run python scripts/check_codeql.py"
    assert hook["stages"] == ["pre-push"]
    assert hook["always_run"] is True
    assert "args" not in hook

    monkeypatch.delenv("SAFEYOLO_CODEQL_BIN", raising=False)
    monkeypatch.setattr(check_codeql.platform, "system", lambda: "Linux")
    monkeypatch.setattr(check_codeql.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(check_codeql, "_load_manifest", lambda: _manifest("linux-x86_64"))
    monkeypatch.setattr(
        check_codeql,
        "_run_analysis",
        lambda *_args: pytest.fail("pre-push default must not analyze without a native bundle"),
    )

    assert _invoke(monkeypatch, check_codeql) == 0
