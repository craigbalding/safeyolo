"""Exercise the disposable Mac fixture's admission and uncertain cleanup paths."""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main, skipUnless
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


@skipUnless(sys.platform == "darwin", "requires native macOS filesystem and Seatbelt")
class LaunchAgentsAliasTests(TestCase):
    @classmethod
    def setUpClass(cls):
        build = TemporaryDirectory(prefix="seatbelt-preflight-", dir=Path.home())
        cls.addClassCleanup(build.cleanup)
        driver = Path(build.name) / "check-launchagents.c"
        # Run the actual post-identity filesystem check as this normal test
        # user. The root account/scheduler/SSH entrypoint is never called.
        driver.write_text('#define main account_preflight_main\n#include '
                          + json.dumps(str(SOURCE / "check-account.c"))
                          + '\n#undef main\nint main(int argc, char **argv) {\n'
                          'if (argc != 2) return 2; launchagents_path(argv[1]); return 0; }\n')
        cls.binary = Path(build.name) / "check-launchagents"
        compiled = subprocess.run(["/usr/bin/xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-O2",
                                   str(driver), "-o", str(cls.binary)], capture_output=True, text=True, timeout=30)
        if compiled.returncode:
            raise RuntimeError(compiled.stderr)

    def setUp(self):
        directory = TemporaryDirectory(prefix="seatbelt-alias-", dir=Path.home())
        self.addCleanup(directory.cleanup)
        self.home = Path(directory.name) / "home"
        self.inputs = self.home / "Library/LaunchAgents"
        self.inputs.mkdir(parents=True)
        self.plist = self.inputs / "owned.plist"
        self.plist.write_text("original")

    def preflight(self):
        return subprocess.run([str(self.binary), str(self.home)], capture_output=True, text=True, timeout=10)

    def test_preexisting_hardlinks_are_refused_without_changes(self):
        for mode in (0o644, 0o444):
            with self.subTest(mode=oct(mode)):
                alias = self.home / "earlier-hardlink"
                os.link(self.plist, alias)
                self.plist.chmod(mode)
                result = self.preflight()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("writable hardlink aliases", result.stderr)
                self.assertIn(str(self.plist), result.stderr)
                self.assertEqual(self.plist.read_text(), "original")
                self.assertEqual(alias.read_text(), "original")
                self.plist.chmod(0o644)
                alias.unlink()
                self.assertEqual(self.preflight().returncode, 0)

    def test_nested_hardlink_is_refused(self):
        nested = self.inputs / "nested"
        nested.mkdir()
        self.plist.rename(nested / "owned.plist")
        os.link(nested / "owned.plist", self.home / "earlier-hardlink")
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(nested / "owned.plist"), result.stderr)
        self.assertEqual((nested / "owned.plist").read_text(), "original")
        self.assertEqual((self.home / "earlier-hardlink").read_text(), "original")

    def test_unaliased_and_internal_symlink_inputs_remain_protected(self):
        (self.inputs / "internal.plist").symlink_to(self.plist)
        self.assertEqual(self.preflight().returncode, 0)
        result = subprocess.run(["/usr/bin/sandbox-exec", "-f", str(SOURCE / "agent-dev.sb"),
                                 "-D", f"AGENT_HOME={self.home}", "-D", "TOOLCHAIN_ROOT=/opt/homebrew",
                                 "/usr/bin/python3", "-I", "-B", "-c",
                                 'import errno,sys; from pathlib import Path\n'
                                 'home=Path(sys.argv[1]); (home/"ordinary-cache").write_text("works")\n'
                                 'try: (home/"Library/LaunchAgents/owned.plist").write_text("changed")\n'
                                 'except OSError as error: assert error.errno == errno.EPERM, error\n'
                                 'else: raise AssertionError("protected write succeeded")\n', str(self.home)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.plist.read_text(), "original")
        self.assertEqual((self.home / "ordinary-cache").read_text(), "works")

    def test_symlink_to_writable_home_input_is_refused(self):
        target = self.home / "editable-input"
        self.plist.rename(target)
        self.plist.symlink_to(target)
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(self.plist), result.stderr)
        self.assertIn(str(target), result.stderr)
        self.assertTrue(self.plist.is_symlink())
        self.assertEqual(target.read_text(), "original")

    def test_symlink_to_protected_system_input_is_accepted(self):
        target = next(Path("/System/Library/LaunchAgents").glob("*.plist"))
        self.plist.unlink()
        self.plist.symlink_to(target)
        result = self.preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.plist.resolve(), target.resolve())

    def test_unresolved_symlink_is_refused_without_removal(self):
        self.plist.unlink()
        self.plist.symlink_to(self.home / "missing-input")
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(self.plist), result.stderr)
        self.assertTrue(self.plist.is_symlink())


if __name__ == "__main__":
    main()
