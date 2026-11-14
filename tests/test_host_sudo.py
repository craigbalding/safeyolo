"""Exercise command disclosure through the installer and native CLI.

Authentication modes and missing host prerequisites are controlled fixtures.
Guest extraction/ownership uses real guest sudo, not production host privilege.
"""

import json
import os
import shlex
import shutil
import subprocess
import sys

import pytest

from tests import test_guest_acquisition as acquisition
from tests import test_host_packages as packages
from tests import test_linux_host as linux_host
from tests.test_guest_acquisition import PREFIX, compressed_archive, install, release
from tests.test_host_packages import build_bundle
from tests.test_linux_host import command, own, payload

native_cli = acquisition.native_cli
guest_store = acquisition.guest_store
package_info = acquisition.package_info
registry = acquisition.registry
package_inputs = packages.package_inputs
owned_stage = linux_host.owned_stage


def disclosed_calls(stderr):
    previews, calls = [], []
    for line in stderr.splitlines():
        if "Host command: " in line:
            previews.append(shlex.split(line.split("Host command: ", 1)[1]))
        if "SUDO_EXEC " in line:
            arguments = json.loads(line.split("SUDO_EXEC ", 1)[1])
            assert ["sudo", *arguments] in previews, stderr
            calls.append(arguments)
    return previews, calls


@pytest.mark.parametrize("state", ["fresh", "cached", "passwordless", "refused"])
@pytest.mark.parametrize("missing_directory", [False, True])
def test_command_install_discloses_literal_arguments_and_reuses_matching_link(
        package_inputs, tmp_path, state, missing_directory):
    bundle = build_bundle(package_inputs, tmp_path)
    parent = tmp_path / "commands 'quotes' $(touch NEVER); &"
    parent.mkdir()
    commands = parent / "new directory" if missing_directory else parent
    root = tmp_path / "instance 'quotes' $value; &"
    tools = tmp_path / "tools"
    tools.mkdir()
    sudo = tools / "sudo"
    sudo.write_text(
        f"#!{sys.executable}\nimport json, os, subprocess, sys\n"
        "print('SUDO_EXEC ' + json.dumps(sys.argv[1:]), file=sys.stderr, flush=True)\n"
        + ("print('fixture fresh sudo authentication', file=sys.stderr, flush=True)\n" if state == "fresh" else "")
        + ("raise SystemExit(77)\n" if state == "refused" else "")
        + f"os.chmod({str(parent)!r}, 0o755)\n"
        "try:\n    status = subprocess.run(sys.argv[1:], check=False).returncode\n"
        f"finally:\n    os.chmod({str(parent)!r}, 0o555)\n"
        "raise SystemExit(status)\n")
    sudo.chmod(0o755)
    parent.chmod(0o555)
    environment = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"}
    arguments = [str(bundle / "install.sh"), "--root", str(root), "--command-dir", str(commands)]
    try:
        result = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=30)
        previews, calls = disclosed_calls(result.stderr)
        expected = ([["mkdir", "-p", str(commands)]] if missing_directory else []) + [
            ["ln", "-s", "-T", str(root / "bin/safeyolo"), str(commands / "safeyolo")]]
        assert calls == (expected[:1] if state == "refused" else expected)
        assert ["sudo", *expected[0]] in previews
        assert result.stderr.index("Host command:") < result.stderr.index("checking and preparing the Linux host")
        assert "user-writable directory to avoid sudo" in result.stderr
        assert result.returncode == (77 if state == "refused" else 0), result.stderr
        if state == "fresh":
            assert result.stderr.index("Host command:") < result.stderr.index("fixture fresh sudo authentication")
        if state == "refused":
            assert "Completed host preparation" in result.stderr and "retry with this root" in result.stderr
            assert not (commands / "safeyolo").exists()
            return
        assert (commands / "safeyolo").resolve() == root / "bin/safeyolo"
        # The controlled package's init only writes settings. Supply its other
        # retained-instance files before exercising the shell repeat path.
        for name in ("policy.toml", "data/admin_token", "data/agent_token", "data/instance_id",
                     "certs/mitmproxy-ca.pem", "certs/mitmproxy-ca-cert.pem"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n")
        repeated = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=30)
        assert repeated.returncode == 0, repeated.stderr
        assert disclosed_calls(repeated.stderr) == ([], [])
        assert not (tmp_path / "NEVER").exists()
    finally:
        parent.chmod(0o755)


@pytest.mark.parametrize("decision", ["decline", "eof", "interactive", "yes"])
def test_host_change_commands_and_helper_effects_precede_consent(native_cli, tmp_path, decision):
    runtime = payload(tmp_path / "runtime 'quotes' $value; &")
    tools = tmp_path / "tools"
    tools.mkdir()
    # Only ssh is missing. No actual package, account or AppArmor change is
    # allowed: the controlled sudo refuses the first accepted command.
    for name in ("getent", "newuidmap", "newgidmap", "setfacl", "getfacl", "unshare", "nsenter", "ip", "curl", "tar"):
        if path := shutil.which(name):
            (tools / name).symlink_to(path)
        else:
            (tools / name).write_text("#!/bin/sh\nexit 0\n")
            (tools / name).chmod(0o755)
    (tools / "sudo").write_text(
        f"#!{sys.executable}\nimport json, sys\n"
        "print('SUDO_EXEC ' + json.dumps(sys.argv[1:]), file=sys.stderr, flush=True)\n"
        "raise SystemExit(77)\n")
    (tools / "sudo").chmod(0o755)
    for name, content in (("subuid", ""), ("subgid", ""), ("restriction", "1\n"), ("release", "ID=ubuntu\n")):
        (tmp_path / name).write_text(content)
    source = '#define _GNU_SOURCE\n#include <dlfcn.h>\n#include <fcntl.h>\n#include <stdarg.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
    for name in ("open", "open64"):
        source += f'''
int {name}(const char *path, int flags, ...) {{
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {{
        va_list args; va_start(args, flags); mode = va_arg(args, unsigned int); va_end(args);
    }}
    const char *replacement = NULL;
    if (!strcmp(path, "/etc/subuid")) replacement = "subuid";
    if (!strcmp(path, "/etc/subgid")) replacement = "subgid";
    if (!strcmp(path, "/etc/os-release")) replacement = "release";
    if (!strcmp(path, "/proc/sys/kernel/apparmor_restrict_unprivileged_userns")) replacement = "restriction";
    char selected[4096];
    if (replacement) {{ snprintf(selected, sizeof(selected), "%s/%s", getenv("HOST_FIXTURE"), replacement); path = selected; }}
    int (*original)(const char *, int, ...) = dlsym(RTLD_NEXT, "{name}");
    return original(path, flags, mode);
}}
'''
    shim = tmp_path / "host-files.so"
    subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Werror", "-x", "c", "-", "-ldl", "-o", str(shim)],
                   input=source, text=True, check=True, timeout=15)
    root, settings = tmp_path / "instance", tmp_path / "settings.toml"
    arguments = [str(native_cli), "--root", str(root), "host", "prepare", "--system-runsc", str(runtime), "--write-settings", str(settings)]
    if decision == "yes":
        arguments.append("--yes")
    result = subprocess.run(arguments, input={"decline": "n\n", "interactive": "y\n"}.get(decision, ""),
                            env={**os.environ, "PATH": str(tools), "LD_PRELOAD": str(shim), "HOST_FIXTURE": str(tmp_path)},
                            capture_output=True, text=True, timeout=30)
    assert result.returncode != 0, result.stderr
    previews, calls = disclosed_calls(result.stderr)
    assert any(
        command[:6] == ["sudo", "--", "apt-get", "install", "-y", "--no-install-recommends"] and "openssh-client" in command for command in previews)
    for operation, target in (("allocate-ids", str(os.getuid())), ("load-profile", str(runtime)),
                              ("load-namespace-profile", str(root / "host/namespace-entry"))):
        assert ["sudo", "--", str(native_cli), "host", operation, target] in previews
    assert "65536-ID UID/GID ranges" in result.stderr and "/etc/subuid and /etc/subgid" in result.stderr
    assert "/etc/apparmor.d/safeyolo-runsc-" in result.stderr and "/etc/apparmor.d/safeyolo-userns-" in result.stderr
    assert "apparmor_parser -r" in result.stderr and "Final ACL commands" in result.stderr
    if decision == "yes":
        assert "Allow these host changes?" not in result.stderr
    else:
        before_consent = result.stderr.split("Allow these host changes?", 1)[0]
        assert len(disclosed_calls(before_consent)[0]) == len(previews) - len(calls)
    if decision in ("decline", "eof"):
        assert not calls and "Host changes and attempted operations: none" in result.stderr
    else:
        assert calls == [["--", "apt-get", "update", "-qq"]]
        assert "attempted refresh Ubuntu package indexes" in result.stderr and "run the installer again" in result.stderr
    assert not settings.exists() and not root.exists()


@pytest.mark.parametrize("state", ["fresh", "cached", "passwordless", "refused"])
def test_acl_sudo_preview_precedes_authentication_and_prepared_retry_is_a_noop(native_cli, owned_stage, state):
    parent, _stage = owned_stage
    private = parent / "private 'quotes' $value; &"
    runtime = payload(private / "runtime")
    own(private, 0, os.getgid())
    subprocess.run(["sudo", "-n", "chmod", "0710", str(private)], check=True)
    tools = parent / "tools"
    tools.mkdir()
    (tools / "sudo").write_text(
        f"#!{sys.executable}\nimport json, os, sys\n"
        "print('SUDO_EXEC ' + json.dumps(sys.argv[1:]), file=sys.stderr, flush=True)\n"
        + ("print('fixture fresh sudo password:', file=sys.stderr, flush=True)\n"
           "assert sys.stdin.readline().strip() == 'fixture-password'\n" if state == "fresh" else "")
        + ("raise SystemExit(77)\n" if state == "refused" else "")
        + f"os.execv({shutil.which('sudo')!r}, ['sudo', *sys.argv[1:]])\n")
    (tools / "sudo").chmod(0o755)
    environment = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"}
    settings = parent / "settings.toml"
    arguments = ("--root", parent / "instance", "host", "prepare", "--system-runsc", runtime, "--write-settings", settings)
    declined = command(native_cli, *arguments, env=environment, input="n\n")
    assert "declined" in declined.stderr and not disclosed_calls(declined.stderr)[1]
    prepared = command(native_cli, *arguments, "--yes", env=environment,
                       input="fixture-password\n" if state == "fresh" else "")
    previews, calls = disclosed_calls(prepared.stderr)
    assert calls and any(call[:4] == ["--", "setfacl", "--no-mask", "-m"] for call in calls)
    if state == "fresh":
        assert prepared.stderr.index("Host command:") < prepared.stderr.index("fixture fresh sudo password:")
    if state == "refused":
        assert prepared.returncode != 0 and not settings.exists()
        assert "Host changes and attempted operations:" in prepared.stderr
        assert "run the installer again" in prepared.stderr
        return
    assert prepared.returncode == 0, prepared.stderr
    assert ["sudo", *calls[0]] in disclosed_calls(declined.stderr)[0]
    selected = json.loads(prepared.stdout)
    assert selected["linux"]["runsc"] == str(runtime)
    settings.unlink()
    repeated = command(native_cli, *arguments, "--yes", env=environment)
    assert repeated.returncode == 0, repeated.stderr
    assert json.loads(repeated.stdout)["applied"] == []
    assert disclosed_calls(repeated.stderr) == ([], [])


@pytest.mark.parametrize("early", [False, True])
@pytest.mark.parametrize("failure", [None, "tar", "remap", "cleanup"])
def test_guest_commands_are_disclosed_before_real_guest_sudo_and_retry_reuses_archive(
        registry, native_cli, guest_store, package_info, tmp_path, early, failure):
    contents, requests, _faults, environment = registry
    guest = compressed_archive()
    contents.update(release(guest))
    tools = tmp_path / "tools"
    tools.mkdir()
    sudo = tools / "sudo"
    sudo.write_text(
        f"#!{sys.executable}\nimport json, os, sys\n"
        "print('SUDO_EXEC ' + json.dumps(sys.argv[1:]), file=sys.stderr, flush=True)\n"
        "failure = os.environ.get('SUDO_FIXTURE_FAILURE')\n"
        "if (failure == 'tar' and 'tar' in sys.argv) or (failure in ('remap', 'cleanup') and 'remap-rootfs' in sys.argv) or (failure == 'cleanup' and 'rm' in sys.argv):\n    raise SystemExit(77)\n"
        f"os.execv({shutil.which('sudo')!r}, ['sudo', *sys.argv[1:]])\n")
    sudo.chmod(0o755)
    environment = {**environment, "PATH": f"{tools}:{os.environ['PATH']}"}
    if failure:
        environment["SUDO_FIXTURE_FAILURE"] = failure
    store, root = guest_store / "literal 'quotes' $value; &", tmp_path / "instance"
    if early:
        result = subprocess.run([str(native_cli), "guest", "download", "--package-info", str(package_info),
                                 "--store", str(store), "--prepare"], env=environment, capture_output=True, text=True, timeout=30)
    else:
        result = install(native_cli, root, store, environment, package_info)
    previews, calls = disclosed_calls(result.stderr)
    assert calls and len(previews) >= len(calls)
    assert any("tar" in call for call in calls)
    if early:
        assert all(call[0] == "-n" for call in calls)
    if failure in ("remap", "cleanup"):
        assert any("rm" in call for call in calls)
        assert "remove only this failed private guest stage" in result.stderr
    if failure != "tar":
        assert "from published IDs 100000..165535 to UID" in result.stderr
        assert f"host {os.getuid()}:{os.getgid()}" in result.stderr
    if failure == "cleanup":
        assert result.returncode != 0 and "staging cleanup failed" in result.stderr
        assert "before retrying" in result.stderr
        for stage in (store / "trees/sha256").glob("extract-*"):
            subprocess.run([shutil.which("sudo"), "-n", "rm", "-rf", "--", str(stage)], check=True)
    elif early or failure is None:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
    environment.pop("SUDO_FIXTURE_FAILURE", None)
    retry = install(native_cli, root, store, environment, package_info)
    assert retry.returncode == 0, retry.stderr
    # Both config and archive fetches happen only once; retries reuse blobs.
    assert len([path for path in requests if path.startswith(PREFIX + "blobs/")]) == 2
