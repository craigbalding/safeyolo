"""Run static init with real Bash/keygen and controlled mounts and CA setup."""

import os
import pwd
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
KEYGEN = shutil.which("ssh-keygen")
INSTALL = shutil.which("install")


@pytest.fixture
def guest(tmp_path):
    assert KEYGEN and INSTALL, "Static-init controls require ssh-keygen and install"
    for directory in (
        "bin", "dev", "etc/ssh", "safeyolo", "safeyolo-status", "var/log",
        "usr/local/share/ca-certificates",
    ):
        (tmp_path / directory).mkdir(parents=True)
    (tmp_path / "safeyolo/authorized_keys").write_text("operator-public-key\n")
    (tmp_path / "safeyolo/mitmproxy-ca-cert.pem").write_text("fixture CA\n")
    (tmp_path / "pid1-limits").write_text("Max open files 65536 65536 files\n")
    for name in ("guest-init", "guest-init-static"):
        source = (REPO_ROOT / f"cli/src/safeyolo/{name}.sh").read_text()
        # Keep both complete shell programs and the real static-init-done
        # boundary. Redirect paths; no host mounts, network or accounts change.
        source = re.sub(
            r"(?<![\w/.-])/(?:dev|etc|home/agent|root|run|safeyolo(?:-status)?|var/log|workspace"
            r"|usr/local/share/ca-certificates)\b",
            lambda match: str(tmp_path) + match[0], source,
        ).replace("/usr/sbin/sshd", str(tmp_path / "bin/sshd"))
        source = source.replace("/proc/1/limits", str(tmp_path / "pid1-limits"))
        # Use host descriptors on macOS too; dangling /proc links break a retry.
        source = source.replace("/proc/self/fd", "/dev/fd")
        path = tmp_path / "safeyolo" / name
        path.write_text(source)
        path.chmod(0o755)
    per_run = tmp_path / "safeyolo/guest-init-per-run"
    per_run.write_text('#!/bin/bash\ntouch "$TEST_ROOT/per-run-started"\n')
    per_run.chmod(0o755)
    (tmp_path / "safeyolo/per-run-go").touch()
    commands = {
        "hostname": "echo fixture-guest\n",
        "mountpoint": (
            '[ "$TEST_PREBOUND" = 1 ] || [ -f "$TEST_ROOT/workspace-mounted" ]\n'
        ),
        "mount": (
            'echo "$3" >> "$TEST_ROOT/mounts"\n'
            '[ "$3" != "$TEST_FAIL_MOUNT" ] || exit 24\n'
            '[ "$3" != workspace ] || touch "$TEST_ROOT/workspace-mounted"\n'
            'if [ "$3" = extra0 ] && [ -d "$TEST_ROOT/mounted-ssh" ]; then\n'
            '    mv "$4" "$TEST_ROOT/hidden-ssh"\n'
            '    mv "$TEST_ROOT/mounted-ssh" "$4"\n'
            'fi\n'
        ),
        "chown": "exit 0\n",
        "sysctl": "exit 0\n",
        "prlimit": "exit 0\n",
        # Trust correctness is covered by test_guest_ca_trust with the real
        # updater. Gate the CA copy here to exercise overlap and fatal cleanup.
        "install": (
            'if [ "${@: -1}" = "$TEST_ROOT/usr/local/share/ca-certificates/safeyolo.crt" ]; then\n'
            '    printf "ca-started\\n" >&"$TEST_EVENTS_FD"\n'
            '    read -r release <&"$TEST_CA_GATE"\n'
            '    [ "$TEST_CA_STATUS" = 0 ] || exit "$TEST_CA_STATUS"\n'
            'elif [ "${@: -1}" = "$TEST_ROOT/run/safeyolo/" ]; then\n'
            '    [ "$TEST_STAGE_STATUS" = 0 ] || exit "$TEST_STAGE_STATUS"\n'
            'fi\n'
            'exec "$TEST_INSTALL" "$@"\n'
        ),
        "update-ca-certificates": "exit 0\n",
        "usermod": 'printf "authorized-keys-ready\\n" >&"$TEST_EVENTS_FD"\n',
        "sshd": (
            'touch "$TEST_ROOT/sshd-started"\n'
            'printf "sshd-started\\n" >&"$TEST_EVENTS_FD"\n'
        ),
        "ip": (
            '[ "$*" != "link set lo up" ] || exit 0\n'
            'exit 1\n'
        ),
        "ssh-keygen": (
            '[ "$*" = -A ] || exit 90\n'
            'echo "$$" > "$TEST_ROOT/keygen-pid"\n'
            'printf "keygen-started\\n" >&"$TEST_EVENTS_FD"\n'
            'read -r release <&"$TEST_KEYGEN_GATE"\n'
            '[ "$TEST_KEYGEN_FAIL" = 0 ] || exit 1\n'
            '"$TEST_KEYGEN" -A -f "$TEST_ROOT" || exit $?\n'
            'printf "keygen-finished\\n" >&"$TEST_EVENTS_FD"\n'
        ),
    }
    for name, command in commands.items():
        path = tmp_path / "bin" / name
        path.write_text("#!/bin/bash\nset -e\n" + command)
        path.chmod(0o755)
    return tmp_path


@contextmanager
def _boot(root, *, fail_keygen=False, ca_status=0, prebound=True, fail_mount="", stage_status=0):
    for marker in (
        "sshd-started", "safeyolo-status/static-init-done", "per-run-started",
        "usr/local/share/ca-certificates/safeyolo.crt",
        "mounts", "workspace-mounted",
    ):
        (root / marker).unlink(missing_ok=True)
    with ExitStack() as stack:
        pipes = [os.pipe() for _ in range(3)]
        for pipe in pipes:
            for descriptor in pipe:
                stack.callback(os.close, descriptor)
        (events, events_write), (keygen, keygen_release), (ca, ca_release) = pipes
        environment = os.environ | {
            "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
            "TEST_ROOT": str(root), "TEST_KEYGEN": KEYGEN, "TEST_INSTALL": INSTALL,
            "TEST_EVENTS_FD": str(events_write),
            "TEST_KEYGEN_GATE": str(keygen), "TEST_CA_GATE": str(ca),
            "TEST_KEYGEN_FAIL": str(int(fail_keygen)),
            "TEST_CA_STATUS": str(ca_status),
            "TEST_STAGE_STATUS": str(stage_status),
            "TEST_PREBOUND": str(int(prebound)), "TEST_FAIL_MOUNT": fail_mount,
        }
        process = subprocess.Popen(
            ["/bin/bash", str(root / "safeyolo/guest-init")], env=environment,
            pass_fds=(events_write, keygen, ca),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        try:
            yield process, events, keygen_release, ca_release
        finally:
            # Also clean up descendants if an assertion exposes a broken join
            # or cancellation path in the candidate being tested.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The entire fixture process group has already exited.
            process.communicate(timeout=10)


def _wait_events(descriptor, *expected):
    received = set()
    while set(expected) - received:
        assert select.select([descriptor], [], [], 10)[0], (
            f"Missing static-init events: {set(expected) - received}"
        )
        received.update(os.read(descriptor, 4096).decode().splitlines())


def _finish(process, expected_status=0):
    stdout, stderr = process.communicate(timeout=20)
    assert process.returncode == expected_status, stdout + stderr


def test_keygen_overlaps_setup_but_sshd_and_static_completion_wait(guest):
    # An old image's shared keys must be replaced, even when work is parallel.
    old_key = guest / "etc/ssh/ssh_host_ed25519_key"
    subprocess.run(
        [KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(old_key)],
        check=True, capture_output=True, timeout=10,
    )
    old_public = old_key.with_suffix(".pub").read_bytes()
    with _boot(guest) as (process, events, keygen, ca):
        _wait_events(events, "keygen-started", "ca-started")
        assert not old_key.exists()
        os.write(ca, b"continue\n")
        _wait_events(events, "authorized-keys-ready")
        assert not (guest / "sshd-started").exists()
        assert not (guest / "safeyolo-status/static-init-done").exists()
        assert not (guest / "per-run-started").exists()
        assert not (guest / "etc/ssh/.safeyolo-host-keys-generated").exists()
        for home in ("home/agent", "root"):
            ssh = guest / home / ".ssh"
            assert (ssh / "authorized_keys").read_text() == "operator-public-key\n"
            assert stat.S_IMODE(ssh.stat().st_mode) == 0o700
            assert stat.S_IMODE((ssh / "authorized_keys").stat().st_mode) == 0o600
        os.write(keygen, b"continue\n")
        _wait_events(events, "keygen-finished", "sshd-started")
        _finish(process)

    assert (guest / "safeyolo-status/static-init-done").read_text() == "ready\n"
    assert (guest / "per-run-started").is_file()
    assert (guest / "etc/ssh/.safeyolo-host-keys-generated").is_file()
    assert old_key.with_suffix(".pub").read_bytes() != old_public
    keys = list((guest / "etc/ssh").glob("ssh_host_*_key"))
    assert keys
    for key in keys:
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        subprocess.run(
            [KEYGEN, "-l", "-f", str(key)], check=True, capture_output=True, timeout=10,
        )

    # A retained overlay keeps its identity and does not generate keys again.
    public_keys = {path.name: path.read_bytes() for path in old_key.parent.glob("*.pub")}
    with _boot(guest) as (process, events, _keygen, ca):
        _wait_events(events, "ca-started")
        os.write(ca, b"continue\n")
        _wait_events(events, "authorized-keys-ready", "sshd-started")
        _finish(process)
    assert {path.name: path.read_bytes() for path in old_key.parent.glob("*.pub")} == public_keys


def test_completed_keygen_does_not_skip_remaining_ca_setup(guest):
    with _boot(guest) as (process, events, keygen, ca):
        _wait_events(events, "keygen-started", "ca-started")
        os.write(keygen, b"continue\n")
        _wait_events(events, "keygen-finished")
        assert not (guest / "safeyolo-status/static-init-done").exists()
        assert not (guest / "per-run-started").exists()
        assert not (guest / "sshd-started").exists()
        os.write(ca, b"continue\n")
        _wait_events(events, "authorized-keys-ready", "sshd-started")
        _finish(process)


def test_failed_static_setup_cancels_and_reaps_keygen(guest):
    with _boot(guest, ca_status=23) as (process, events, _keygen, ca):
        _wait_events(events, "keygen-started", "ca-started")
        keygen_pid = int((guest / "keygen-pid").read_text())
        os.write(ca, b"fail\n")
        _finish(process, expected_status=23)
        with pytest.raises(ProcessLookupError):
            os.kill(keygen_pid, 0)
    assert not (guest / "sshd-started").exists()
    assert not (guest / "safeyolo-status/static-init-done").exists()
    assert not (guest / "per-run-started").exists()
    assert not (guest / "etc/ssh/.safeyolo-host-keys-generated").exists()


def test_keygen_failure_remains_retryable(guest):
    with _boot(guest, fail_keygen=True) as (process, events, keygen, ca):
        _wait_events(events, "keygen-started", "ca-started")
        os.write(ca, b"continue\n")
        _wait_events(events, "authorized-keys-ready")
        os.write(keygen, b"fail\n")
        _wait_events(events, "sshd-started")
        _finish(process)
    # Keep the existing best-effort keygen failure behavior, including retry.
    assert not (guest / "etc/ssh/.safeyolo-host-keys-generated").exists()
    with _boot(guest) as (process, events, keygen, ca):
        _wait_events(events, "keygen-started", "ca-started")
        os.write(keygen, b"continue\n")
        os.write(ca, b"continue\n")
        _wait_events(events, "keygen-finished", "authorized-keys-ready", "sshd-started")
        _finish(process)
    assert (guest / "etc/ssh/.safeyolo-host-keys-generated").is_file()


@pytest.mark.parametrize("helper_present", [False, True])
def test_static_stages_executable_run_files_before_readiness(guest, helper_present):
    script = guest / "safeyolo/guest-init-per-run"
    script.chmod(0o644)
    sources = [script]
    if helper_present:
        helper = guest / "safeyolo/safeyolo-guest"
        helper.write_text("fixture native helper\n")
        helper.chmod(0o644)
        sources.append(helper)
    with _boot(guest) as (process, events, keygen, ca):
        _wait_events(events, "keygen-started", "ca-started")
        os.write(keygen, b"continue\n")
        os.write(ca, b"continue\n")
        _wait_events(events, "keygen-finished", "authorized-keys-ready", "sshd-started")
        _finish(process)
    for source in sources:
        staged = guest / "run/safeyolo" / source.name
        assert staged.read_bytes() == source.read_bytes()
        assert stat.S_IMODE(staged.stat().st_mode) == 0o755
    assert (guest / "per-run-started").exists()
    assert (guest / "run/safeyolo/safeyolo-guest").exists() == helper_present


def test_failed_static_staging_does_not_publish_readiness(guest):
    with _boot(guest, stage_status=29) as (process, events, keygen, ca):
        _wait_events(events, "keygen-started", "ca-started")
        os.write(keygen, b"continue\n")
        os.write(ca, b"continue\n")
        _wait_events(events, "keygen-finished", "authorized-keys-ready", "sshd-started")
        _finish(process, expected_status=29)
    assert not (guest / "safeyolo-status/static-init-done").exists()
    assert not (guest / "per-run-started").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Real Linux guest ownership checks")
def test_host_key_permissions_skip_root_chown_and_repair_other_owners(tmp_path):
    account = pwd.getpwuid(os.getuid())
    sudo = shutil.which("sudo")
    if account.pw_uid == 0 or not sudo:
        pytest.skip("Ownership control needs an ordinary account and guest sudo")
    if subprocess.run([sudo, "-n", "true"], capture_output=True, timeout=10).returncode:
        pytest.skip("Ownership control needs passwordless guest sudo")
    owners = {"retained": "0:0", "user": f"{account.pw_uid}:0", "group": f"0:{account.pw_gid or 1}"}
    for name, owner in owners.items():
        key = tmp_path / f"ssh_host_{name}_key"
        key.write_text(f"fixture {name} key\n")
        key.chmod(0o666)
        subprocess.run(
            [sudo, "-n", "chown", owner, str(key)],
            check=True, capture_output=True, timeout=10,
        )
    # A non-file glob match must remain untouched.
    ignored = tmp_path / "ssh_host_directory_key"
    ignored.mkdir(mode=0o755)
    source = (REPO_ROOT / "cli/src/safeyolo/guest-init-static.sh").read_text()
    block = source[source.index("ssh_host_keys=()"):source.index("# Refresh guest-root support")]
    block = block.replace("/etc/ssh/", '"$TEST_ROOT"/')
    command = (
        'chown() { printf "%s\\n" "${2##*/}" >> "$TEST_ROOT/chown-calls"; command chown "$@"; };\n'
        + block
    )
    result = subprocess.run(
        [sudo, "-n", "env", f"TEST_ROOT={tmp_path}", "/bin/bash", "-ec", command],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert set((tmp_path / "chown-calls").read_text().splitlines()) == {
        "ssh_host_user_key", "ssh_host_group_key",
    }
    for name in owners:
        key = tmp_path / f"ssh_host_{name}_key"
        details = key.stat()
        assert (details.st_uid, details.st_gid, stat.S_IMODE(details.st_mode)) == (0, 0, 0o600)
    assert stat.S_IMODE(ignored.stat().st_mode) == 0o755


def test_oci_prebound_shares_need_no_virtiofs_attempts(guest):
    extra = guest / "extra"
    (guest / "safeyolo/host-mounts").write_text(f"extra0:{extra}\n")
    with _boot(guest) as (process, events, keygen, ca):
        _wait_events(events, "keygen-started", "ca-started")
        os.write(keygen, b"continue\n")
        os.write(ca, b"continue\n")
        _wait_events(events, "keygen-finished", "authorized-keys-ready", "sshd-started")
        _finish(process)
    assert not (guest / "mounts").exists()
    for directory in ("workspace", "safeyolo-status", "home/agent", "extra"):
        assert (guest / directory).is_dir()
    assert (guest / "per-run-started").exists()


@pytest.mark.parametrize("failed", ["workspace", "status", "home", "extra0"])
def test_vz_mount_failure_stops_static_init(guest, failed):
    (guest / "safeyolo/host-mounts").write_text(f"extra0:{guest / 'extra'}\n")
    with _boot(guest, prebound=False, fail_mount=failed) as (process, _events, _keygen, _ca):
        _finish(process, expected_status=24)
    expected = ["workspace", "status", "home", "extra0"]
    assert (guest / "mounts").read_text().splitlines() == expected[:expected.index(failed) + 1]
    assert (guest / "workspace-mounted").exists() == (failed != "workspace")
    for marker in (
        "keygen-pid", "sshd-started", "safeyolo-status/static-init-done", "per-run-started",
    ):
        assert not (guest / marker).exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Real Linux guest identity transitions")
@pytest.mark.parametrize("helper", ["setpriv", "missing", "unusable"])
def test_home_skeleton_uses_agent_identity_and_preserves_retained_entries(tmp_path, helper):
    account = pwd.getpwuid(os.getuid())
    if account.pw_uid == 0:
        pytest.skip("Ownership control needs an ordinary test account")
    sudo, setpriv, su = (shutil.which(name) for name in ("sudo", "setpriv", "su"))
    if not sudo or subprocess.run([sudo, "-n", "true"], capture_output=True, timeout=10).returncode:
        pytest.skip("Ownership control needs passwordless guest sudo")
    assert setpriv and su, "Home controls require setpriv and su"
    skel, home, commands = (tmp_path / name for name in ("skel", "home", "bin"))
    for directory in (skel, home, commands):
        directory.mkdir()
    for name in ("ordinary", ".hidden", "..hidden", "retained", "dangling"):
        (skel / name).write_text(f"skeleton {name}\n")
    (skel / "directory").mkdir()
    (skel / "directory/nested").write_text("nested\n")
    (skel / ".new-directory").mkdir()
    (skel / ".new-directory/nested").write_text("new nested file\n")
    (skel / "link").symlink_to("absent-source-target")
    (home / "dangling").symlink_to("absent-retained-target")
    (home / "retained").write_text("operator file\n")
    (home / "retained").chmod(0o640)
    # A root-owned retained file also catches an unwanted recursive chown.
    subprocess.run(
        [sudo, "-n", "chown", f"0:{account.pw_gid}", str(home / "retained")], check=True,
        capture_output=True, timeout=10,
    )
    retained = (home / "retained").stat()
    (home / "directory").mkdir()
    (home / "directory/retained").write_text("operator directory\n")
    calls = tmp_path / "identity-calls"
    for name, executable in (("setpriv", setpriv), ("su", su)):
        path = commands / name
        path.write_text(
            f'#!/bin/sh\necho {name} >> "{calls}"\n' +
            ("exit 1\n" if name == "setpriv" and helper == "unusable" else
             f'exec "{executable}" "$@"\n'),
        )
        path.chmod(0o755)
    source = (REPO_ROOT / "cli/src/safeyolo/guest-init-static.sh").read_text()
    block = source[source.index("if [ -d /etc/skel ]"):source.index("# Host config directory mounts")]
    block = re.sub(
        r"/etc/skel|/home/agent", lambda match: str(skel if match[0] == "/etc/skel" else home), block,
    )
    block = block.replace("--reuid=agent", f"--reuid={account.pw_uid}")
    block = block.replace("--regid=agent", f"--regid={account.pw_gid}")
    block = block.replace("su agent", f"su {account.pw_name}")
    if helper == "missing":
        block = (
            'command() { if [ "$1" = -v ] && [ "$2" = setpriv ]; then return 1; fi; '
            'builtin command "$@"; };\n' + block
        )
    result = subprocess.run(
        [sudo, "-n", "env", f"PATH={commands}:{os.environ['PATH']}", "/bin/bash", "-ec", block],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls.read_text().splitlines() == {
        "setpriv": ["setpriv", "setpriv"], "missing": ["su"], "unusable": ["setpriv", "su"],
    }[helper]
    for name in ("ordinary", ".hidden", "..hidden", ".new-directory/nested"):
        path = home / name
        assert path.read_bytes() == (skel / name).read_bytes()
        assert (path.stat().st_uid, path.stat().st_gid) == (account.pw_uid, account.pw_gid)
    assert (home / "link").readlink() == Path("absent-source-target")
    assert (home / "link").lstat().st_uid == account.pw_uid
    assert (home / "dangling").readlink() == Path("absent-retained-target")
    assert (home / "retained").read_text() == "operator file\n"
    after = (home / "retained").stat()
    assert (after.st_uid, after.st_gid, after.st_mode, after.st_mtime_ns) == (
        retained.st_uid, retained.st_gid, retained.st_mode, retained.st_mtime_ns,
    )
    assert list((home / "directory").iterdir()) == [home / "directory/retained"]


@pytest.mark.parametrize("retained_keys", [False, True], ids=["empty-mount", "retained-mount"])
def test_host_keys_and_generated_marker_use_final_mounted_directory(guest, retained_keys):
    mounted = guest / "mounted-ssh"
    mounted.mkdir()
    visible = guest / "etc/ssh"
    marker = ".safeyolo-host-keys-generated"
    public_key = "ssh_host_ed25519_key.pub"
    if retained_keys:
        subprocess.run(
            [KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f",
             str(mounted / "ssh_host_ed25519_key")],
            check=True, capture_output=True, timeout=10,
        )
        (mounted / marker).touch()
        retained_public = (mounted / public_key).read_bytes()
    else:
        # A marker hidden by the mount must not suppress fresh generation.
        (visible / marker).touch()
    config = visible / "sshd_config"
    (mounted / config.name).write_text(f"HostKey {visible / 'ssh_host_ed25519_key'}\n")
    (guest / "safeyolo/host-mounts").write_text(f"extra0:{visible}\n")
    # Renaming directories models the visibility change of a successful VZ
    # overmount. It requires no real mount or host privilege.
    with _boot(guest, prebound=False) as (process, events, keygen, ca):
        if retained_keys:
            _wait_events(events, "ca-started")
        else:
            _wait_events(events, "ca-started", "keygen-started")
        assert (guest / "hidden-ssh").is_dir()
        if not retained_keys:
            os.write(keygen, b"continue\n")
            _wait_events(events, "keygen-finished")
        os.write(ca, b"continue\n")
        _wait_events(events, "authorized-keys-ready", "sshd-started")
        _finish(process)
    assert (visible / marker).is_file()
    assert (visible / public_key).is_file()
    assert (guest / "safeyolo-status/static-init-done").is_file()
    assert (guest / "mounts").read_text().splitlines() == ["workspace", "status", "home", "extra0"]
    if retained_keys:
        assert (visible / public_key).read_bytes() == retained_public
    assert not list((guest / "hidden-ssh").glob("ssh_host_*_key"))
    subprocess.run(
        [KEYGEN, "-l", "-f", str(visible / "ssh_host_ed25519_key")],
        check=True, capture_output=True, timeout=10,
    )
    if sshd := shutil.which("sshd"):
        subprocess.run(
            [sshd, "-t", "-f", str(config)], check=True, capture_output=True, timeout=10,
        )
