"""Hermetic acceptance tests for the source checkout installer."""

import os
import subprocess
from pathlib import Path
from textwrap import dedent

REPO_ROOT = Path(__file__).resolve().parents[1]


def make_fake_uv(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Create a fake uv that records interpreter and tool-install requests."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "uv.log"
    state = tmp_path / "python-installed"
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        dedent(
            r"""
            #!/bin/bash
            set -u

            printf 'argv:' >> "$FAKE_UV_LOG"
            for arg in "$@"; do
                printf ' [%s]' "$arg" >> "$FAKE_UV_LOG"
            done
            printf '\n' >> "$FAKE_UV_LOG"

            if [[ "${1:-}" == python && "${2:-}" == find ]]; then
                if [[ "${FAKE_HOST_DEFAULT:-}" == 3.14 && "${3:-}" == 3.14 ]]; then
                    echo "fake uv rejected unsupported host default" >&2
                    exit 18
                fi
                if [[ "${FAKE_UV_FIND_MODE:-ok}" == always-missing ]] ||
                   [[ "${FAKE_UV_FIND_MODE:-ok}" == missing && ! -e "$FAKE_UV_STATE" ]]; then
                    echo "fake uv interpreter lookup failed" >&2
                    exit 17
                fi
                printf '%s\n' "${FAKE_UV_INTERPRETER:-/fake/python-3.13}"
                exit 0
            fi

            if [[ "${1:-}" == python && "${2:-}" == install ]]; then
                if [[ "${FAKE_UV_INSTALL_MODE:-ok}" == fail ]]; then
                    echo "${FAKE_UV_DIAGNOSTIC:-fake acquisition failure}" >&2
                    exit 19
                fi
                echo "fake uv installed Python"
                echo "fake uv download completed" >&2
                : > "$FAKE_UV_STATE"
                exit 0
            fi

            if [[ "${1:-}" == tool && "${2:-}" == install ]]; then
                override_file=
                while [[ $# -gt 0 ]]; do
                    if [[ "$1" == --overrides ]]; then
                        override_file="$2"
                        break
                    fi
                    shift
                done
                if [[ -z "$override_file" || ! -r "$override_file" ]]; then
                    echo "fake uv cannot open the overrides file" >&2
                    exit 25
                fi
                while IFS= read -r pin; do
                    printf 'override: %s\n' "$pin" >> "$FAKE_UV_LOG"
                done < "$override_file"
                if [[ "${FAKE_UV_TOOL_MODE:-ok}" == fail ]]; then
                    echo "${FAKE_UV_DIAGNOSTIC:-fake tool failure}" >&2
                    exit 23
                fi
                exit 0
            fi

            if [[ "${1:-}" == tool && "${2:-}" == uninstall ]]; then
                exit 0
            fi

            echo "fake uv received an unexpected command" >&2
            exit 24
            """
        ).strip()
        + "\n",
    )
    fake_uv.chmod(0o755)
    return fake_bin, log, state


def run_installer(
    checkout: Path,
    fake_bin: Path,
    log: Path,
    state: Path,
    action: str = "install",
    **settings: str,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}:{environment['PATH']}",
            "BASH_ENV": "/dev/null",
            "FAKE_UV_LOG": str(log),
            "FAKE_UV_STATE": str(state),
            **settings,
        }
    )
    return subprocess.run(
        ["bash", str(checkout / "install.sh"), action],
        cwd=checkout,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_install_and_reinstall_select_supported_python_for_tool_environment(
    tmp_path: Path,
) -> None:
    """Both tool-environment paths pass uv a supported interpreter."""
    fake_bin, log, state = make_fake_uv(tmp_path)

    install = run_installer(
        REPO_ROOT,
        fake_bin,
        log,
        state,
        FAKE_UV_FIND_MODE="ok",
        FAKE_UV_INTERPRETER="/fake/python-3.13",
        FAKE_HOST_DEFAULT="3.14",
    )
    reinstall = run_installer(
        REPO_ROOT,
        fake_bin,
        log,
        state,
        action="reinstall",
        FAKE_UV_FIND_MODE="ok",
        FAKE_UV_INTERPRETER="/fake/python-3.13",
        FAKE_HOST_DEFAULT="3.14",
    )

    assert install.returncode == 0, install.stderr
    assert reinstall.returncode == 0, reinstall.stderr
    lines = log.read_text().splitlines()
    assert any(
        "[python] [find] [>=3.12,<3.14] [--resolve-links]" in line
        for line in lines
    )
    tool_lines = [line for line in lines if "[tool] [install]" in line]
    assert len(tool_lines) == 2
    assert all("[--python] [/fake/python-3.13]" in line for line in tool_lines)
    assert all("[--editable]" in line and "[--overrides]" in line for line in tool_lines)
    assert "[--reinstall]" not in tool_lines[0]
    assert "[--reinstall]" in tool_lines[1]
    assert lines.count("override: h2==4.4.1") == 2


def test_install_acquires_supported_python_when_system_lookup_fails(
    tmp_path: Path,
) -> None:
    """uv may acquire the declared range before creating the tool environment."""
    fake_bin, log, state = make_fake_uv(tmp_path)

    result = run_installer(
        REPO_ROOT,
        fake_bin,
        log,
        state,
        FAKE_UV_FIND_MODE="missing",
    )

    assert result.returncode == 0, result.stderr
    lines = log.read_text().splitlines()
    assert lines[0].startswith("argv: [python] [find] [>=3.12,<3.14]")
    assert lines[1].startswith("argv: [python] [install] [>=3.12,<3.14]")
    assert lines[2].startswith("argv: [python] [find] [>=3.12,<3.14]")
    assert any("[tool] [install] [--python] [/fake/python-3.13]" in line for line in lines)
    assert "asking uv to acquire one" in result.stderr
    assert "fake uv installed Python" in result.stderr
    assert "fake uv download completed" in result.stderr


def test_install_preserves_acquisition_failure_details(
    tmp_path: Path,
) -> None:
    """Acquisition failures retain the cause alongside the suggested action."""
    fake_bin, log, state = make_fake_uv(tmp_path)
    diagnostic = "error: Python download failed: no space left on device"

    result = run_installer(
        REPO_ROOT,
        fake_bin,
        log,
        state,
        FAKE_UV_FIND_MODE="missing",
        FAKE_UV_INSTALL_MODE="fail",
        FAKE_UV_DIAGNOSTIC=diagnostic,
    )

    assert result.returncode != 0
    assert "unable to acquire a Python interpreter satisfying >=3.12,<3.14" in result.stderr
    assert "install a supported Python or allow uv Python downloads" in result.stderr
    assert diagnostic in result.stderr


def test_install_derives_changed_python_boundaries_from_pyproject(tmp_path: Path) -> None:
    """Changing project metadata changes the uv request without installer edits."""
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "install.sh").write_text((REPO_ROOT / "install.sh").read_text())
    project = (REPO_ROOT / "pyproject.toml").read_text()
    project = project.replace('requires-python = ">=3.12,<3.14"', 'requires-python = ">=3.11,<3.13"')
    (checkout / "pyproject.toml").write_text(project)
    (checkout / "install.sh").chmod(0o755)
    fake_bin, log, state = make_fake_uv(tmp_path)

    result = run_installer(
        checkout,
        fake_bin,
        log,
        state,
        FAKE_UV_INTERPRETER="/fake/python-3.12",
    )

    assert result.returncode == 0, result.stderr
    lines = log.read_text()
    assert ">=3.11,<3.13" in lines
    assert ">=3.12,<3.14" not in lines
    assert "[--python] [/fake/python-3.12]" in lines


def test_install_tool_failure_preserves_uv_diagnostics(tmp_path: Path) -> None:
    """Tool-resolution failures preserve uv's explanation of the conflict."""
    fake_bin, log, state = make_fake_uv(tmp_path)
    diagnostic = "error: no solution found when resolving dependencies"

    result = run_installer(
        REPO_ROOT,
        fake_bin,
        log,
        state,
        FAKE_UV_TOOL_MODE="fail",
        FAKE_UV_DIAGNOSTIC=diagnostic,
    )

    assert result.returncode != 0
    assert "uv tool install failed with a Python interpreter satisfying >=3.12,<3.14" in result.stderr
    assert diagnostic in result.stderr


def test_install_avoids_empty_nounset_array_expansion() -> None:
    """The install path must remain compatible with macOS Bash 3.2."""
    source = (REPO_ROOT / "install.sh").read_text()

    assert "reinstall_args=()" not in source
    assert 'local tool_args=(--python)' in source
    assert 'uv tool install "${tool_args[@]}"' in source
