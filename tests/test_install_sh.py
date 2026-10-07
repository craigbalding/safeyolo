"""Hermetic acceptance tests for the source checkout installer."""

import os
import shutil
import subprocess
import tomllib
from pathlib import Path
from textwrap import dedent

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def make_install_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "checkout"
    (checkout / "proxy").mkdir(parents=True)
    for relative in ("install.sh", "pyproject.toml", "proxy/Cargo.toml"):
        shutil.copy2(REPO_ROOT / relative, checkout / relative)
    # Interpreter controls supply the guest artifact, as a macOS source
    # install must. They do not compile or execute guest code.
    (checkout / "safeyolo-guest").write_bytes(b"supplied Linux guest fixture\n")
    return checkout


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
                if [[ " $* " == *" --resolve-links "* ]] ||
                   [[ "${FAKE_UV_FIND_MODE:-ok}" == invocation-error ]]; then
                    echo "error: unexpected argument '--resolve-links' found" >&2
                    exit 2
                fi
                if [[ "${FAKE_HOST_DEFAULT:-}" == 3.14 && "${3:-}" == 3.14 ]]; then
                    echo "fake uv rejected unsupported host default" >&2
                    exit 18
                fi
                if [[ "${FAKE_UV_FIND_MODE:-ok}" == always-missing ]] ||
                   [[ "${FAKE_UV_FIND_MODE:-ok}" == missing && ! -e "$FAKE_UV_STATE" ]]; then
                    echo "error: No interpreter found for Python ${3:-}" >&2
                    exit 2
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
    fake_cargo = fake_bin / "cargo"
    fake_cargo.write_text(
        "#!/bin/bash\n"
        "mkdir -p proxy/target/release\n"
        'printf "#!/bin/sh\\nexit 0\\n" > proxy/target/release/safeyolo-proxy\n'
        "chmod +x proxy/target/release/safeyolo-proxy\n"
    )
    fake_cargo.chmod(0o755)
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
            "SAFEYOLO_GUEST_HELPER": str(checkout / "safeyolo-guest"),
            # The fake cargo executable creates the expected release artifact.
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
    checkout = make_install_checkout(tmp_path)

    install = run_installer(
        checkout,
        fake_bin,
        log,
        state,
        FAKE_UV_FIND_MODE="ok",
        FAKE_UV_INTERPRETER="/fake/python-3.13",
        FAKE_HOST_DEFAULT="3.14",
    )
    reinstall = run_installer(
        checkout,
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
        "[python] [find] [>=3.12,<3.14]" in line
        for line in lines
    )
    tool_lines = [line for line in lines if "[tool] [install]" in line]
    assert len(tool_lines) == 2
    assert all("[--python] [/fake/python-3.13]" in line for line in tool_lines)
    assert all("[--editable]" not in line and "[--overrides]" not in line for line in tool_lines)
    assert all(f"[{checkout}]" in line for line in tool_lines)
    assert "[--reinstall]" not in tool_lines[0]
    assert "[--reinstall]" in tool_lines[1]


def test_install_preserves_lookup_invocation_error_without_acquiring_python(tmp_path: Path) -> None:
    fake_bin, log, state = make_fake_uv(tmp_path)
    checkout = make_install_checkout(tmp_path)
    result = run_installer(
        checkout, fake_bin, log, state, FAKE_UV_FIND_MODE="invocation-error",
    )

    assert result.returncode != 0
    assert "uv python find failed: error: unexpected argument" in result.stderr
    assert "no installed Python" not in result.stderr
    assert "[python] [install]" not in log.read_text()
    assert "[tool] [install]" not in log.read_text()


def test_install_acquires_supported_python_when_system_lookup_fails(
    tmp_path: Path,
) -> None:
    """uv may acquire the declared range before creating the tool environment."""
    fake_bin, log, state = make_fake_uv(tmp_path)
    checkout = make_install_checkout(tmp_path)

    result = run_installer(
        checkout,
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
    checkout = make_install_checkout(tmp_path)
    diagnostic = "error: Python download failed: no space left on device"

    result = run_installer(
        checkout,
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
    checkout = make_install_checkout(tmp_path)
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


def test_install_missing_guest_artifact_preserves_input_error(tmp_path: Path) -> None:
    """An absent supplied artifact must fail before creating the tool environment."""
    checkout = make_install_checkout(tmp_path)
    fake_bin, log, state = make_fake_uv(tmp_path)
    result = run_installer(
        checkout, fake_bin, log, state,
        SAFEYOLO_GUEST_HELPER=str(tmp_path / "missing-guest"),
    )
    assert result.returncode != 0
    assert "provide SAFEYOLO_GUEST_HELPER with the matching Linux guest artifact" in result.stderr
    assert not log.exists()


def test_install_tool_failure_preserves_uv_diagnostics(tmp_path: Path) -> None:
    """Tool-resolution failures preserve uv's explanation of the conflict."""
    fake_bin, log, state = make_fake_uv(tmp_path)
    checkout = make_install_checkout(tmp_path)
    diagnostic = "error: no solution found when resolving dependencies"

    result = run_installer(
        checkout,
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


def test_install_builds_native_proxy_without_factory_disk_reserve(tmp_path: Path) -> None:
    """A source install can start its native build below the factory's reserve."""
    checkout = make_install_checkout(tmp_path)
    (checkout / "scripts").mkdir()
    shutil.copy2(REPO_ROOT / "scripts/cargo_with_space.sh", checkout / "scripts/cargo_with_space.sh")

    fake_bin, log, state = make_fake_uv(tmp_path)
    cargo_log = tmp_path / "cargo.log"
    fake_cargo = fake_bin / "cargo"
    fake_cargo.write_text(
        "#!/bin/bash\n"
        'printf "%s\\n" "$*" >> "$FAKE_CARGO_LOG"\n'
        "mkdir -p proxy/target/release\n"
        'printf "#!/bin/sh\\nexit 0\\n" > proxy/target/release/safeyolo-proxy\n'
        "chmod +x proxy/target/release/safeyolo-proxy\n"
    )
    fake_cargo.chmod(0o755)
    fake_df = fake_bin / "df"
    fake_df.write_text(
        "#!/bin/bash\n"
        "printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n'\n"
        "printf 'testfs 2097152 1048576 1048576 50%% /tmp\\n'\n"
    )
    fake_df.chmod(0o755)

    result = run_installer(
        checkout,
        fake_bin,
        log,
        state,
        FAKE_CARGO_LOG=str(cargo_log),
    )

    assert result.returncode == 0, result.stderr
    assert cargo_log.read_text() == "build --locked --release --manifest-path proxy/Cargo.toml\n"
    assert (checkout / "proxy/target/release/safeyolo-proxy").is_file()


@pytest.mark.parametrize("source", ["clean", "dirty", "explicit"])
def test_install_binds_host_and_guest_builds_to_the_same_source(tmp_path, monkeypatch, source):
    """The real guest helper rebuild must retain the host's source identity."""
    monkeypatch.delenv("SAFEYOLO_BUILD_REVISION", raising=False)
    checkout = make_install_checkout(tmp_path)
    (checkout / "scripts").mkdir()
    for name in ("build_guest_command.sh", "cargo_with_space.sh"):
        shutil.copy2(REPO_ROOT / "scripts" / name, checkout / "scripts" / name)
    (checkout / ".gitignore").write_text("**/target/\n")
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.test", "commit", "-qm", "installer fixture"], check=True)
    revision = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    if source == "dirty":
        with (checkout / "pyproject.toml").open("a") as stream:
            stream.write("\n# dirty source fixture\n")
    fake_bin, log, state = make_fake_uv(tmp_path)
    cargo_log = tmp_path / "native-builds"
    (fake_bin / "cargo").write_text(
        '#!/bin/bash\nset -eu\n'
        'printf "%s\\n" "${SAFEYOLO_BUILD_REVISION:-unknown}" >> "$FAKE_CARGO_LOG"\n'
        'directory=${CARGO_TARGET_DIR:-proxy/target}/release\n'
        'mkdir -p "$directory"\n'
        'for name in safeyolo safeyolo-proxy safeyolo-coord safeyolo-guest; do\n'
        '  printf "#!/bin/sh\\nprintf \'%s\\\\n\'\\n" "$name 0.1.0 commit=${SAFEYOLO_BUILD_REVISION:-unknown} profile=production" > "$directory/$name"\n'
        '  chmod +x "$directory/$name"\n'
        'done\n'
    )
    (fake_bin / "df").write_text(
        "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n"
        "testfs 67108864 1048576 66060288 2%% /\\n'\n"
    )
    (fake_bin / "df").chmod(0o755)
    (fake_bin / "uname").write_text("#!/bin/sh\nprintf 'Linux\\n'\n")
    (fake_bin / "uname").chmod(0o755)
    settings = {"SAFEYOLO_GUEST_HELPER": "", "FAKE_CARGO_LOG": str(cargo_log)}
    if source == "explicit":
        settings["SAFEYOLO_BUILD_REVISION"] = "a" * 40
    result = run_installer(checkout, fake_bin, log, state, **settings)
    assert result.returncode == 0, result.stderr
    expected = "unknown" if source == "dirty" else "a" * 40 if source == "explicit" else revision
    assert cargo_log.read_text().splitlines() == [expected] * 3
    guest = checkout / "guest/command/target/release"
    for name in ("safeyolo-guest", "safeyolo-coord"):
        assert (guest / f"{name}.version").read_text().strip() == f"{name} 0.1.0 commit={expected} profile=production"


def test_wheel_maps_the_built_native_proxy_into_the_runtime_package() -> None:
    """A normal wheel carries the executable selected by the native default."""
    source = (REPO_ROOT / "hatch_build.py").read_text()

    assert '"proxy" / "target" / "release" / "safeyolo-proxy"' in source
    assert 'safeyolo/bin/safeyolo-proxy' in source


def test_wheel_excludes_the_obsolete_python_policy_package() -> None:
    """The native wheel does not ship the old policy decision point."""
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    packages = project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]

    assert "pdp" not in packages
