"""Exercise the disposable Mac fixture's admission and uncertain cleanup paths."""

import importlib.util
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import create_autospec, patch

SOURCE = Path(__file__).resolve().parents[1] / "contrib/macos-seatbelt-agent"


def shell_source(tmp_path):
    source = (SOURCE / "test-configure-ssh.sh").read_text()
    for path, name in (("/Library/PrivilegedHelperTools/seatbelt-agent", "entry"),
                       ("/Users/$account", "home"),
                       ("/etc/sudoers.d/seatbelt-acceptance-test", "sudoers")):
        source = source.replace(path, str(tmp_path / name))
    for command in ("pgrep", "pkill", "crontab"):
        source = source.replace(f"/usr/bin/{command}", command)
    return source.replace("/bin/launchctl", "launchctl")


def check_admission(tmp_path, case):
    source = shell_source(tmp_path)
    admission = source[source.index("account="):source.index("lab=$(mktemp")]
    if case in {"entry", "home", "sudoers"}:
        (tmp_path / case).symlink_to(tmp_path / "missing")
    script = f"""
set -eu
dscl() {{
    [ '{case}' != list_error ] || return 3
    case '{case}' in
        name_used) echo 'sy-seatbelt-test 501';;
        uid_used) echo 'someone-else 59900';;
        *) echo 'admin 501';;
    esac
}}
pgrep() {{
    case '{case}' in process_error) return 3;; process_live) return 0;; *) return 1;; esac
}}
{admission}
echo ALLOCATION_REACHED
"""
    result = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=10)
    assert (result.returncode == 0) == (case == "absent"), result.stderr
    assert ("ALLOCATION_REACHED" in result.stdout) == (case == "absent")


def check_cleanup(tmp_path, case):
    for name in ("entry", "home", "lab"):
        (tmp_path / name).mkdir()
    for name in ("account", "sudoers", "lab/log"):
        (tmp_path / name).touch()
    if case == "root_pending":
        (tmp_path / "lab/live-sshd.pending").write_text("pid=12345\n")
    if case == "owned_cron":
        (tmp_path / "lab/owned.crontab").write_text("owned\n")
    source = shell_source(tmp_path)
    cleanup = source[source.index("cleanup() {"):source.index("trap cleanup EXIT")]
    script = f"""
set -eu
account=sy-seatbelt-test
entry='{tmp_path}/entry'
lab='{tmp_path}/lab'
created=yes
dseditgroup() {{ :; }}
dscl() {{ rm '{tmp_path}/account'; }}
pkill() {{ :; }}
sleep() {{ :; }}
pgrep() {{
    case '{case}' in process_error) return 3;; process_live) return 0;; *) return 1;; esac
}}
crontab() {{
    [ "$3" != -r ] || {{ touch '{tmp_path}/cron_removed'; return 0; }}
    case '{case}' in
        owned_cron) echo owned;;
        unknown_cron) echo unknown;;
        cron_error) return 3;;
        *) echo 'crontab: no crontab for sy-seatbelt-test' >&2; return 1;;
    esac
}}
launchctl() {{
    if [ "$1" = bootout ]; then
        touch '{tmp_path}/bootout'
        [ '{case}' != bootout_failed ]
    else
        case '{case}' in
            launchd_error) return 3;;
            still_loaded) return 0;;
            loaded|bootout_failed) [ -e '{tmp_path}/bootout' ] && return 113; return 0;;
            *) return 113;;
        esac
    fi
}}
{cleanup}
trap cleanup EXIT
exit 0
"""
    result = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=10)
    clean = case in {"absent", "loaded", "owned_cron"}
    assert (result.returncode == 0) == clean, result.stderr
    for name in ("account", "entry", "home", "lab/log"):
        assert (tmp_path / name).exists() != clean, (name, result.stderr)
    assert not (tmp_path / "sudoers").exists()
    if not clean:
        assert str(tmp_path / "lab") in result.stderr
    if case == "owned_cron":
        assert (tmp_path / "cron_removed").exists()


def check_sshd(tmp_path, case):
    spec = importlib.util.spec_from_file_location("seatbelt_live_client", SOURCE / "test-client-live.py")
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    pending = tmp_path / "live-sshd.pending"
    pending.write_text("owned root daemon\n")
    # Popen sets pid on its instances. A reaped harmless child supplies the
    # complete instance interface without starting an SSH daemon.
    with subprocess.Popen(["/usr/bin/true"]) as prototype:
        daemon = create_autospec(prototype, spec_set=True)
    daemon.pid = 12345
    daemon.poll.return_value = 0 if case == "already_exited" else None
    if case == "exited_during_inspection":
        daemon.poll.side_effect = [None, 0]
    daemon.wait.side_effect = {
        "kill_then_reap": [subprocess.TimeoutExpired("sshd", 5), 0],
        "wait_error": [subprocess.TimeoutExpired("sshd", 5), subprocess.TimeoutExpired("sshd", 5)],
    }.get(case)
    status = {"session_error": 3, "session_live": 0}.get(case, 1)
    inspect = create_autospec(subprocess.run, spec_set=True,
                              return_value=subprocess.CompletedProcess([], status, stdout=b"", stderr=b""))
    clean = case in {"absent", "kill_then_reap"}
    with patch.object(client.subprocess, "run", inspect), \
            patch.object(client.time, "monotonic", autospec=True, side_effect=[0, 6]):
        if clean:
            client.stop_sshd(daemon, tmp_path)
        else:
            with TestCase().assertRaises((RuntimeError, subprocess.TimeoutExpired)):
                client.stop_sshd(daemon, tmp_path)
    assert pending.exists() != clean
    daemon.terminate.assert_called_once_with()
    assert daemon.wait.called
    if case in {"kill_then_reap", "wait_error"}:
        daemon.kill.assert_called_once_with()


class FixtureSafetyTests(TestCase):
    def test_admission(self):
        for case in ("absent", "list_error", "name_used", "uid_used", "process_error",
                     "process_live", "entry", "home", "sudoers"):
            with self.subTest(case=case), TemporaryDirectory() as directory:
                check_admission(Path(directory), case)

    def test_cleanup(self):
        for case in ("absent", "loaded", "owned_cron", "process_live", "process_error",
                     "launchd_error", "bootout_failed", "still_loaded", "root_pending",
                     "unknown_cron", "cron_error"):
            with self.subTest(case=case), TemporaryDirectory() as directory:
                check_cleanup(Path(directory), case)

    def test_root_sshd(self):
        for case in ("absent", "kill_then_reap", "wait_error", "session_error",
                     "session_live", "already_exited", "exited_during_inspection"):
            with self.subTest(case=case), TemporaryDirectory() as directory:
                check_sshd(Path(directory), case)


if __name__ == "__main__":
    main()
