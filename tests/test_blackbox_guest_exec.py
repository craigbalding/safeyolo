"""Reach maintained guest-command callers without booting a sandbox."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from tests.blackbox import guest_exec, installed_access, installed_lifecycle, installed_workloads


def test_cli_bootstrap_works_without_an_ambient_safeyolo_package(tmp_path):
    """The full --cli path selects the installed interpreter before package imports."""
    ambient = tmp_path / "ambient"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(ambient)
    python = ambient / "bin/python"
    root = tmp_path / "selected instance"
    (root / "bin").mkdir(parents=True)
    native = root / "bin/safeyolo"
    native.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit 7\n")
    native.chmod(0o755)
    environment = dict(os.environ, SAFEYOLO_CONFIG_DIR=str(root))
    environment.pop("PYTHONPATH", None)
    environment.pop("SAFEYOLO_NATIVE_CONFIG_PATH", None)
    subprocess.run([str(python), "-c", "import importlib.util; assert importlib.util.find_spec('safeyolo') is None"],
                   env=environment, cwd=tmp_path, check=True, timeout=10)
    command = "printf '%s' 'literal $(must not execute)'"
    result = subprocess.run([
        str(python), str(Path(guest_exec.__file__).resolve()), "--cli",
        str(Path(sys.executable).with_name("safeyolo")), "marker", "-c", command,
    ], env=environment, cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 7, result.stderr
    assert result.stdout.splitlines() == ["--root", str(root), "agent", "shell", "marker", "-c", command]
    assert not (root / "agents").exists()


def test_installed_interpreter_and_native_root_win_over_path_and_pythonpath(tmp_path, monkeypatch):
    """The real script cannot run the retired package alias or ambient decoys."""
    root = tmp_path / "selected instance"
    (root / "bin").mkdir(parents=True)
    native = root / "bin/safeyolo"
    native.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\"\n"
        "exit 7\n"
    )
    native.chmod(0o755)
    decoy = tmp_path / "decoy"
    (decoy / "safeyolo").mkdir(parents=True)
    (decoy / "safeyolo/__init__.py").write_text("raise AssertionError('ambient package imported')\n")
    (decoy / "safeyolo/agent_lifecycle.py").write_text("raise AssertionError('ambient lifecycle imported')\n")
    marker = tmp_path / "decoy-called"
    decoy_cli = decoy / "safeyolo-command"
    decoy_cli.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 99\n")
    decoy_cli.chmod(0o755)
    (decoy / "bin").mkdir()
    (decoy / "bin/safeyolo").symlink_to(decoy_cli)
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(root))
    monkeypatch.delenv("SAFEYOLO_NATIVE_CONFIG_PATH", raising=False)
    monkeypatch.setenv("PATH", str(decoy / "bin") + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("PYTHONPATH", str(decoy))
    package_cli = Path(sys.executable).with_name("safeyolo")
    command = "printf '%s' 'literal $(must not execute)'"
    args = guest_exec.guest_command_args(str(package_cli), "marker", command)
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    assert result.returncode == 7, result.stderr
    assert result.stdout.splitlines() == ["--root", str(root), "agent", "shell", "marker", "-c", command]
    assert not marker.exists()
    assert not (root / "agents").exists()


def test_runner_readiness_and_both_isolation_invocations_reach_the_dispatcher(tmp_path, monkeypatch):
    """Run the actual shell command lines with their forwarded guest payloads."""
    source = Path("tests/blackbox/run-tests.sh").read_text().splitlines()
    selected = [line.strip() for line in source if '"$SCRIPT_DIR/guest_exec.py"' in line]
    assert len(selected) == 3
    calls = []
    # The subprocess exercises the script's real parser and --cli re-exec.
    cli = tmp_path / "package-cli"
    cli.write_text(f"#!{sys.executable}\nraise SystemExit('retired package shell was called')\n")
    cli.chmod(0o755)
    root = tmp_path / "instance"
    (root / "bin").mkdir(parents=True)
    record = tmp_path / "calls"
    native = root / "bin/safeyolo"
    native.write_text(
        f"#!{sys.executable}\nimport json,sys\n"
        f"with open({str(record)!r}, 'a') as stream:\n"
        "    stream.write(json.dumps(['native', *sys.argv[1:]]) + '\\n')\n"
        "if sys.argv[3:5] == ['agent', 'status']:\n"
        "    print(json.dumps({'runtime_state': 'running', 'exec': True}))\n"
    )
    native.chmod(0o755)
    (root / "data/shell-sockets").mkdir(parents=True)
    (root / "data/shell-sockets/marker.sock").touch()
    (root / "data/vm_ssh_key").touch()
    tools = tmp_path / "tools"
    tools.mkdir()
    ssh = tools / "ssh"
    ssh.write_text(
        f"#!{sys.executable}\nimport json,sys\n"
        "assert sys.stdin.read() == '', 'noninteractive SSH must close stdin'\n"
        f"with open({str(record)!r}, 'a') as stream:\n"
        "    stream.write(json.dumps(['ssh', *sys.argv[1:]]) + '\\n')\n"
    )
    ssh.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(root))
    monkeypatch.delenv("SAFEYOLO_NATIVE_CONFIG_PATH", raising=False)
    environment = dict(os.environ, SCRIPT_DIR=str(Path("tests/blackbox").resolve()),
                       INSTALLED_CLI=str(cli), AGENT_NAME="marker",
                       PATH=str(tools) + os.pathsep + os.environ["PATH"])
    for line in selected:
        if line.startswith("if "):
            invocation = line.removeprefix("if ").removesuffix("; then")
        else:
            invocation = line.removesuffix("\\") + " 'printf literal'"
        result = subprocess.run(["bash", "-c", invocation], env=environment,
                                input="runner stdin", capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        calls.append([json.loads(row) for row in record.read_text().splitlines()])
        record.unlink()
    prefix = ["native", "--root", str(root), "agent"]
    assert calls[0] == [[*prefix, "shell", "marker", "-c", "true"]]
    assert calls[1] == [[*prefix, "shell", "marker", "-c", "printf literal"]]
    root_command = calls[2][-1][-1]
    if sys.platform == "darwin":
        assert calls[2][0] == [*prefix, "status", "marker"]
        ssh_args = calls[2][1]
        assert ssh_args[0] == "ssh" and "root@sandbox" in ssh_args and "-t" not in ssh_args
        assert str(root / "data/vm_ssh_key") in ssh_args
        assert f"ProxyCommand=nc -U {root / 'data/shell-sockets/marker.sock'}" in ssh_args
        assert "--nofile=65536:65536" in root_command
        assert "/usr/local/bin/sudo" not in root_command
        assert root_command.endswith("printf literal")
    else:
        assert calls[2] == [[*prefix, "shell", "marker", "-c", root_command]]
        assert shlex.split(root_command)[:5] == ["exec", "sudo", "-n", "/bin/bash", "-lc"]
        assert shlex.split(root_command)[5].endswith("printf literal")


def test_workload_producer_preserves_root_identity_and_literal_arguments():
    cli = str(Path(sys.executable).with_name("safeyolo"))
    literal = "with spaces $(not-expanded)"
    args = installed_workloads.guest_args(cli, "marker", literal, "package", "--sha", "abc")
    assert Path(args[0]).samefile(sys.executable)
    assert Path(args[0]).parent == Path(sys.executable).parent and args[1] == "-I"
    assert args[3:7] == ["marker", "--user", "root", "-c"]
    command = shlex.split(args[-1])
    assert command[:4] == ["cd", "/workspace", "&&", "python3"]
    assert command[command.index("--marker") + 1] == literal
    for args in (installed_access.guest_command(cli, "marker", "systrap", literal, "coord"),
                 installed_lifecycle.guest_command(cli, "marker", "tls", literal)):
        assert args[3:7] == ["marker", "--user", "agent", "-c"]


@pytest.fixture
def macos_root(tmp_path, monkeypatch):
    from safeyolo import platform
    from safeyolo.platform import darwin

    root = tmp_path / "instance"
    (root / "bin").mkdir(parents=True)
    native = root / "bin/safeyolo"
    native.write_text(
        f"#!{sys.executable}\nimport os,sys\n"
        "assert sys.argv[3:] == ['agent', 'status', 'marker']\n"
        "print(os.environ['FIXTURE_NATIVE_STATUS'])\n"
    )
    native.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(root))
    monkeypatch.delenv("SAFEYOLO_NATIVE_CONFIG_PATH", raising=False)
    monkeypatch.setenv("FIXTURE_NATIVE_STATUS", json.dumps({"runtime_state": "running", "exec": True}))
    monkeypatch.setattr(guest_exec.sys, "platform", "darwin")
    monkeypatch.setattr(platform, "get_platform", darwin.DarwinPlatform)
    (root / "data/shell-sockets").mkdir(parents=True)
    (root / "data/shell-sockets/marker.sock").touch()
    (root / "data/vm_ssh_key").touch()
    record = tmp_path / "ssh-call"
    ssh = root / "bin/ssh"
    ssh.write_text(
        f"#!{sys.executable}\nimport json,sys\n"
        "assert sys.stdin.read() == '', 'noninteractive SSH must close stdin'\n"
        f"with open({str(record)!r}, 'w') as stream: json.dump(sys.argv[1:], stream)\n"
        "sys.exit(11)\n"
    )
    ssh.chmod(0o755)
    monkeypatch.setenv("PATH", str(ssh.parent) + os.pathsep + os.environ["PATH"])
    return root, record


def test_macos_root_uses_the_existing_root_ssh_login_and_limits(macos_root):
    root, record = macos_root
    literal = "printf '%s' 'literal $(must not execute)'"
    assert guest_exec.main(["marker", "--user", "root", "-c", literal]) == 11
    command = json.loads(record.read_text())
    assert "root@sandbox" in command and "-t" not in command
    assert str(root / "data/vm_ssh_key") in command
    assert f"ProxyCommand=nc -U {root / 'data/shell-sockets/marker.sock'}" in command
    assert "--nofile=65536:65536" in command[-1]
    assert "/usr/local/bin/sudo" not in command[-1]
    assert command[-1].endswith(literal)


@pytest.mark.parametrize("status,error", [
    ("", "invalid JSON"),
    ("{", "invalid JSON"),
    ("[]", "no status object"),
    ('{"exec": true}', "no runtime state"),
    ('{"runtime_state": "running", "exec": false}', "exec control is unavailable"),
])
def test_macos_root_refuses_invalid_or_unavailable_native_status(macos_root, monkeypatch, status, error):
    _, record = macos_root
    monkeypatch.setenv("FIXTURE_NATIVE_STATUS", status)
    with pytest.raises(RuntimeError, match=error):
        guest_exec.main(["marker", "--user", "root", "-c", "must-not-execute"])
    assert not record.exists()


def test_macos_root_refuses_a_missing_shell_socket(macos_root):
    root, record = macos_root
    (root / "data/shell-sockets/marker.sock").unlink()
    with pytest.raises(RuntimeError, match="Shell bridge socket.*not found"):
        guest_exec.main(["marker", "--user", "root", "-c", "must-not-execute"])
    assert not record.exists()
