"""Focused observer checks; no SafeYolo product, external network, VM or provider is run."""

import errno
import importlib.util
import json
import os
import pty
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

spec = importlib.util.spec_from_file_location("observer", Path(__file__).resolve().parents[2] / "tests/blackbox/ubuntu_onboarding.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ObserverChecks(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="239-observer-check-", dir=Path.home())
        self.addCleanup(self.scratch.cleanup)
        base = Path(self.scratch.name)
        m.root, m.project, m.private = [base / name for name in ["root", "project", "private"]]
        for path in [m.root, m.project, m.private]:
            path.mkdir()
        m.out = m.private / "result.json"
        m.archive = base / "absent-archive"
        m.store = base / "absent-store"
        m.sampled = set()
        m.x = {"observations": [], "product_commands": [], "interactions": [], "phase_observations": []}
        m.cli = base / "safeyolo"
        m.cli.write_text('#!/bin/sh\nprintf "observer-test-version\\n"\n')
        m.cli.chmod(0o755)
        (m.project / "onboarding-fixture.txt").write_text("SAFEYOLO_ONBOARDING_FIXTURE\n")

    def test_banner_is_not_readiness_even_when_chunk_ends_at_sign_in(self):
        for banner in [b"SafeYolo: Claude Code is installed; opening the session. Sign in",
                       b"Starting or resuming claude. First use may download tools; sign in"]:
            self.assertEqual(m.login_label(banner), [])
        self.assertEqual(m.login_label(b"\x1b[1mSign in\x1b[0m"), ["sign in"])
        self.assertIn("/login", m.login_label(b"Use /login to begin"))
        self.assertIsNone(m.theme_prompt(b"Unknown guest prompt: press Enter"))

    def test_marker_and_positive_failure_do_not_skip_workspace_or_direct_controls(self):
        m.cli.write_text("#!/usr/bin/env python3\nimport subprocess,sys\n"
            f"project={str(m.project)!r}\n"
            "code=sys.argv[-1]\n"
            "if 'printf %s' in code:\n sys.exit(subprocess.call(['sh','-c',code.replace('/workspace',project)]))\n"
            "if 'httpbin.org' in code:\n print('503',end='');sys.exit(0)\n"
            "if '--noproxy' in code:sys.exit(7)\n"
            "sys.exit(1)\n")
        (m.root / "policy.toml").write_text("policy hash must stay private")
        with patch.object(m, "live_record", autospec=True, side_effect=OSError("runtime read denied")), \
             patch.object(m, "processes", autospec=True, return_value=[]), patch.object(m, "listeners", autospec=True, return_value=[]):
            m.witness("after-reentry")
        row = m.x["after-reentry"]
        self.assertIn("observation_error", row["runtime"])
        self.assertEqual(row["marker"]["exit"], 1)
        self.assertTrue(row["workspace_matches"])
        self.assertEqual([n["kind"] for n in row["network"]], ["positive", "direct-http", "direct-https"])
        self.assertEqual([n["expected_result"] for n in row["network"]], [False, True, True])
        self.assertNotIn(m.digest(m.root / "policy.toml"), m.out.read_text())

    def test_launch_environment_is_never_saved(self):
        directory = m.root / "agents/first"
        directory.mkdir(parents=True)
        (directory / "current-launch.json").write_text(json.dumps({"launch_id": "launch-test",
            "command": "PRIVATE_COMMAND_SENTINEL", "env": {"token": "PRIVATE_ENV_SENTINEL"}}))
        m.capture(m.x, "launch", m.launch_record)
        self.assertEqual(m.x["launch"]["launch_id"], "launch-test")
        self.assertNotIn("PRIVATE_", m.out.read_text())

    def test_terminal_attachment_keeps_only_nonsecret_pane_facts(self):
        binary = m.root / "bin/tmux"
        binary.parent.mkdir()
        binary.write_text("#!/bin/sh\nprintf 'launch-test\\t0\\t123\\tclaude\\t$0\\t1\\n'\n")
        binary.chmod(0o755)
        row = m.terminal_attachment("warm", {"tmux_socket": "/owned/socket", "pane_id": "%7"})
        self.assertEqual(row["exit"], 0)
        self.assertIn("launch-test", row["stdout"])
        self.assertIn("#{session_attached}", row["command"][-1])
        self.assertNotIn("capture-pane", row["command"])
        self.assertIn("unavailable", m.terminal_attachment("warm", {"pane_id": "%7"}))

    def test_real_tmux_screen_requires_the_matching_visible_pane_and_stays_private(self):
        binary = shutil.which("tmux")
        if binary is None:
            self.skipTest("real tmux screen check requires tmux")
        (m.root / "bin").mkdir()
        (m.root / "bin/tmux").symlink_to(binary)
        directory = m.root / "agents/first"
        directory.mkdir(parents=True)
        # Only this short socket uses /tmp, including on macOS.
        with tempfile.TemporaryDirectory(prefix="sy-pane-", dir="/tmp") as socket_dir:
            socket_path = str(Path(socket_dir) / "tmux.sock")
            command = [binary, "-S", socket_path]
            viewer = None
            master, slave = pty.openpty()
            try:
                created = subprocess.run([*command, "-f", "/dev/null", "new-session", "-d", "-P", "-F", "#{pane_id}",
                    "-s", "onboarding", "printf 'SafeYolo: Claude Code is installed; opening the session. Sign in if Claude asks.\\n'; "
                    "read -r response; printf 'Sign in\\nPRIVATE_PANE_SENTINEL\\n'; cat"],
                    capture_output=True, text=True, check=True)
                pane = created.stdout.strip()
                subprocess.run([*command, "set-option", "-p", "-t", pane, "@safeyolo_launch_id", "launch-test"], check=True)
                record = {"tmux_socket": socket_path, "pane_id": pane, "launch_id": "launch-test"}
                (directory / "current-launch.json").write_text(json.dumps(record))
                self.assertFalse(m.pane_screen("warm")["matching_live_visible_pane"])
                viewer = subprocess.Popen([*command, "attach-session", "-t", "onboarding"],
                    stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                    env={**os.environ, "TERM": "xterm-256color"})
                deadline = time.monotonic() + 3
                while True:
                    row = m.pane_screen("warm")
                    if row.get("matching_live_visible_pane") or time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
                self.assertTrue(row["matching_live_visible_pane"])
                self.assertEqual(row.get("labels"), [])
                subprocess.run([*command, "send-keys", "-t", pane, "Enter"], check=True)
                while True:
                    row = m.capture(m.x, "pane_screen", lambda: m.pane_screen("warm"))
                    if row.get("labels") or time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
                self.assertEqual(row.get("labels"), ["sign in"])
                self.assertIn(b"PRIVATE_PANE_SENTINEL", (m.private / "warm-pane.screen").read_bytes())
                self.assertNotIn("PRIVATE_PANE_SENTINEL", m.out.read_text())
                record["launch_id"] = "different-launch"
                (directory / "current-launch.json").write_text(json.dumps(record))
                wrong = m.pane_screen("warm")
                self.assertFalse(wrong["matching_live_visible_pane"])
                self.assertNotIn("labels", wrong)
            finally:
                subprocess.run([*command, "kill-server"], capture_output=True)
                if viewer is not None:
                    viewer.wait(timeout=3)
                os.close(slave)
                os.close(master)

    def test_private_state_is_observed_without_exporting_bytes_or_hashes(self):
        for name in m.PRIVATE_STATE:
            path = m.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("PRIVATE_STATE_SENTINEL")
        with patch.object(m, "live_record", autospec=True, return_value={}), \
             patch.object(m, "processes", autospec=True, return_value=[]), \
             patch.object(m, "listeners", autospec=True, return_value=[]), \
             patch.object(m, "guest", autospec=True, return_value={"exit": 1}):
            before = m.witness("before-return")
            (m.root / m.PRIVATE_STATE[0]).write_text("changed token")
            (m.root / m.PRIVATE_STATE[1]).unlink()
            after = m.witness("after-reentry")
        self.assertNotEqual(before[m.PRIVATE_STATE[0]], after[m.PRIVATE_STATE[0]])
        self.assertIsNone(after[m.PRIVATE_STATE[1]])
        self.assertEqual(before[m.PRIVATE_STATE[2]], after[m.PRIVATE_STATE[2]])
        self.assertTrue(all(name in before and before[name] is None and name in after and after[name] is None
                            for name in m.OPTIONAL_PRIVATE_STATE))
        exported = m.out.read_text()
        self.assertNotIn("PRIVATE_STATE_SENTINEL", exported)
        for value in before.values():
            if value:
                self.assertNotIn(value, exported)

    def test_one_unreadable_state_file_does_not_erase_other_state(self):
        (m.root / "policy.toml").write_text("retained policy")
        unreadable = m.root / m.PRIVATE_STATE[0]
        unreadable.parent.mkdir(parents=True)
        unreadable.write_text("private token")
        digest = m.digest

        def read_digest(path):
            if path == unreadable:
                raise PermissionError("controlled private-state read error")
            return digest(path)

        with patch.object(m, "digest", autospec=True, side_effect=read_digest), \
             patch.object(m, "live_record", autospec=True, return_value={}), \
             patch.object(m, "processes", autospec=True, return_value=[]), \
             patch.object(m, "listeners", autospec=True, return_value=[]), \
             patch.object(m, "guest", autospec=True, return_value={"exit": 1}):
            state = m.witness("after-reentry")
        self.assertEqual(state["policy.toml"], digest(m.root / "policy.toml"))
        self.assertNotIn(m.PRIVATE_STATE[0], state)
        self.assertIn(m.PRIVATE_STATE[0], m.x["after-reentry"]["state_observation_errors"])

    def observer_cli(self, home, *args, script=None):
        return subprocess.run([sys.executable, "-I", "-B", script or m.__file__, "--host", os.uname().nodename,
            "--platform", "linux-arm64", "--observation-dir", str(home / "observation"), *args],
            cwd=home, env={**os.environ, "HOME": str(home)}, capture_output=True, text=True, timeout=10)

    def test_arm_binding_and_existing_installation_refusal_precede_product_commands(self):
        home = Path(self.scratch.name) / "home"
        root = home / ".safeyolo"
        root.mkdir(parents=True)
        sentinel = root / "policy.toml"
        sentinel.write_text("existing policy")
        result = self.observer_cli(home)
        self.assertEqual(result.returncode, 2, result.stderr)
        record = json.loads((home / "observation/result.json").read_text())
        self.assertEqual(record["expected_host_package"]["machine"], "aarch64")
        self.assertEqual(record["expected_host_package"]["bytes"], 176869006)
        self.assertEqual(record["expected_host_package"]["sha256"], "eab9b709b3e4c6b536614eeb6b422d12c2b55826149085f78c326b31637922af")
        self.assertEqual(record["product_commands"], [])
        self.assertEqual(sentinel.read_text(), "existing policy")
        cleanup = self.observer_cli(home, "--cleanup-only")
        self.assertNotEqual(cleanup.returncode, 0)
        self.assertIn("No matching owned attempt", cleanup.stderr)
        self.assertEqual(sentinel.read_text(), "existing policy")

    def test_workflow_staged_observer_runs_isolated_normal_and_cleanup_callers(self):
        base = Path(self.scratch.name)
        workspace = base / "workspace"
        workspace.mkdir()
        repo = Path(__file__).resolve().parents[2]
        (workspace / "observer-source").symlink_to(repo, target_is_directory=True)
        work = base / "work"
        (work / "observer").mkdir(parents=True)
        workflow = yaml.safe_load((repo / ".github/workflows/installed-arm64.yml").read_text())
        stage = next(step["run"] for step in workflow["jobs"]["public-install"]["steps"]
                     if step.get("name") == "Stage only the Python observer outside the checkout")
        subprocess.run(["bash", "-c", stage], check=True, capture_output=True, text=True, timeout=10,
                       env={**os.environ, "GITHUB_WORKSPACE": str(workspace), "PUBLIC_INSTALL_WORK": str(work)})
        shutil.rmtree(workspace)
        script = str(work / "observer/ubuntu_onboarding.py")
        home = base / "staged-home"
        binary = home / ".safeyolo/bin/safeyolo"
        binary.parent.mkdir(parents=True)
        calls = home / "calls"
        binary.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{calls}'\n")
        binary.chmod(0o755)
        result = self.observer_cli(home, script=script)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(calls.exists())
        private = home / "observation"
        (home / "239-onboarding-project").mkdir()
        record = {"owns_product_attempt": True, "platform": "linux-arm64", "observations": [],
                  "baseline": {"hostname": os.uname().nodename, "uid": os.getuid()},
                  "fixture_preparation": {"project": str(home / "239-onboarding-project")}}
        (private / "result.json").write_text(json.dumps(record))
        cleanup = self.observer_cli(home, "--cleanup-only", script=script)
        observed = json.loads((private / "result.json").read_text())
        # These Ubuntu scans may be unavailable on the test host. That failure
        # must stay visible, while both isolated callers load only staged code.
        self.assertIn(cleanup.returncode, (0, 1), cleanup.stderr)
        self.assertEqual(len(calls.read_text().splitlines()), 6)
        self.assertIn("cleanup_rechecked", observed)
        if not observed["cleanup_verified"]:
            self.assertEqual(cleanup.returncode, 1)
        else:
            self.assertEqual(cleanup.returncode, 0)

    def test_cleanup_recovery_stops_only_recorded_attempt_and_does_not_replay_verified_stop(self):
        home = Path(self.scratch.name) / "home"
        binary = home / ".safeyolo/bin/safeyolo"
        binary.parent.mkdir(parents=True)
        calls = home / "calls"
        binary.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{calls}'\nexit 0\n")
        binary.chmod(0o755)
        project = home / "239-onboarding-project"
        project.mkdir()
        private = home / "observation"
        private.mkdir()
        record = {"owns_product_attempt": True, "platform": "linux-arm64", "observations": [],
                  "baseline": {"hostname": os.uname().nodename, "uid": os.getuid()},
                  "fixture_preparation": {"project": str(project)}}
        (private / "result.json").write_text(json.dumps(record))
        argv = [m.__file__, "--host", os.uname().nodename, "--platform", "linux-arm64", "--cleanup-only",
                "--observation-dir", str(private)]
        # The separate process/listener test exercises /proc. This case isolates
        # recovery ownership from unrelated unreadable processes on the test host.
        with patch.object(sys, "argv", argv), patch.object(m.Path, "home", autospec=True, return_value=home), \
             patch.object(m, "processes", autospec=True, return_value=[]), \
             patch.object(m, "listeners", autospec=True, return_value=[]):
            self.assertEqual(m.main(), 0)
        self.assertTrue(json.loads((private / "result.json").read_text())["cleanup_verified"])
        first_calls = calls.read_text()
        self.assertEqual(len(first_calls.splitlines()), 6)
        with patch.object(sys, "argv", argv), patch.object(m.Path, "home", autospec=True, return_value=home):
            self.assertEqual(m.main(), 0)
        self.assertEqual(calls.read_text(), first_calls)

    def test_unreadable_process_keeps_cleanup_unverified(self):
        def scan():
            m.x["latest_process_scan"] = {"unreadable_pids": [123]}
            return []
        with patch.object(m, "processes", autospec=True, side_effect=scan), \
             patch.object(m, "listeners", autospec=True, return_value=[]):
            m.cleanup()
        self.assertFalse(m.x["cleanup_verified"])

    def test_unfinished_console_group_keeps_cleanup_unverified(self):
        for console in [{"console_reaped": False},
                        {"console_reaped": True, "console_group_shutdown": {"verified": False}}]:
            m.x["product_commands"] = [console]
            with patch.object(m, "processes", autospec=True, return_value=[]), \
                 patch.object(m, "listeners", autospec=True, return_value=[]):
                m.cleanup()
            self.assertFalse(m.x["cleanup_verified"])

    def test_timed_out_diagnostic_preserves_result_and_next_command_runs(self):
        row = m.observe("timeout", [sys.executable, "-c", "import time;print('reached',flush=True);time.sleep(10)"], 0.1)
        self.assertTrue(row["timeout"])
        self.assertIn("reached", row["stdout"])
        self.assertEqual(m.observe("next", [sys.executable, "-c", "print('next')"])["exit"], 0)

    def test_process_and_listener_capture_excludes_unrelated_process(self):
        # These are explicit Linux process-file inputs, including on Mac.
        proc = Path(self.scratch.name) / "proc"
        for pid, argv, executable, inode in [
            (10101, str(m.root), str(m.cli), 123),
            (20202, "unrelated-observer-control", "/unrelated/python", 456),
        ]:
            entry = proc / str(pid)
            (entry / "fd").mkdir(parents=True)
            (entry / "cmdline").write_bytes(argv.encode())
            (entry / "exe").symlink_to(executable)
            (entry / "fd/3").symlink_to(f"socket:[{inode}]")
        (proc / "net").mkdir()
        (proc / "net/tcp").write_text("header\n0: 0100007F:1234 00000000:0000 0A 0 0 0 0 0 123\n"
                                       "1: 0100007F:5678 00000000:0000 0A 0 0 0 0 0 456\n")
        for name in ("tcp6", "unix"):
            (proc / "net" / name).write_text("header\n")

        def linux_path(value):
            return proc / str(value).removeprefix("/proc").lstrip("/")

        with patch.object(m, "Path", autospec=True, side_effect=linux_path), \
             patch.object(m, "birth", autospec=True, side_effect=lambda pid: f"linux:boot:{pid}:1"):
            rows = m.processes()
            self.assertEqual([r["pid"] for r in rows], [10101])
            self.assertEqual(m.listeners(rows), [{"family": "tcp", "inode": "123", "address": "0100007F:1234"}])
        if sys.platform == "darwin":
            return
        # Also retain the actual Linux owned/unrelated process and listener proof.
        code = "import socket,time;s=socket.socket();s.bind(('127.0.0.1',0));s.listen();print('ready',flush=True);time.sleep(20)"
        owned = subprocess.Popen([sys.executable, "-c", code, str(m.root)], stdout=subprocess.PIPE)
        unrelated = subprocess.Popen([sys.executable, "-c", code, "unrelated-observer-control"], stdout=subprocess.PIPE)
        try:
            self.assertEqual(owned.stdout.readline(), b"ready\n")
            self.assertEqual(unrelated.stdout.readline(), b"ready\n")
            rows = m.processes()
            self.assertIn(owned.pid, [r["pid"] for r in rows])
            self.assertNotIn(unrelated.pid, [r["pid"] for r in rows])
            self.assertEqual(len(m.listeners(rows)), 1)
            saved = m.birth(owned.pid)
            self.assertIsNotNone(saved)
            owned.terminate()
            owned.wait(timeout=3)
            self.assertNotEqual(m.birth(owned.pid), saved)
            self.assertIsNone(unrelated.poll())
        finally:
            for process in [owned, unrelated]:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=3)
                process.stdout.close()

    def run_console(self, message, seconds, phase="warm", theme=False, capture_error=False, descendant=False):
        stub = m.project / "console.py"
        display_choice = ("print('Starting or resuming claude.',flush=True)\n"
            "print('Choose the text style that looks best with your terminal\\r\\n> 1. Dark mode',flush=True)\n"
            "assert os.read(0,100)==b'\\r'\n") if theme else ""
        helper = ("import json,os,signal,socket,time\n"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "signal.signal(signal.SIGHUP,signal.SIG_IGN)\n"
            "s=socket.socket();s.bind(('127.0.0.1',0));s.listen()\n"
            "print(json.dumps({'pid':os.getpid(),'pgid':os.getpgrp(),'port':s.getsockname()[1]}),flush=True)\n"
            "time.sleep(30)\n")
        descendant_start = ("import json,subprocess\n"
            f"helper=subprocess.Popen([sys.executable,'-c',{helper!r}],stdout=subprocess.PIPE)\n"
            f"open({str(m.project / 'descendant.json')!r},'w').write(helper.stdout.readline().decode())\n") if descendant else ""
        stub.write_text("import os,sys,tty\ntty.setraw(0)\n" + descendant_start + display_choice +
            f"print({message!r},flush=True)\n"
            "pending=b''\n"
            "while b'\\x02d' not in pending:pending+=os.read(0,100)\n"
            "print('SafeYolo host> ',end='',flush=True)\n"
            "pending=b''\n"
            "while b'q\\n' not in pending:pending+=os.read(0,100)\n")
        def record_capture(phase, start_marker=False):
            row = m.x["product_commands"][-1]
            self.assertIsNotNone(m.birth(row["console_pid"]))
            self.assertNotIn("viewer_detach", row)
            m.x[phase] = {"captured_before_detach": True}
            if descendant:
                child = json.loads((m.project / "descendant.json").read_text())
                child["birth"] = m.birth(child["pid"])
                self.assertIsNotNone(child["birth"])
                m.x[phase]["descendant"] = child
                self.assertEqual(child["pgid"], row["console_pid"])
                if sys.platform.startswith("linux"):
                    self.assertNotIn(child["pid"], [r["pid"] for r in m.processes()])
                with socket.create_connection(("127.0.0.1", child["port"]), timeout=1):
                    pass
            m.save()
            if capture_error:
                raise ValueError("capture failed after retaining reached operands")
            return {}
        with patch.object(m, "LAUNCH", [sys.executable, str(stub)]), \
             patch.object(m, "witness", autospec=True, side_effect=record_capture), \
             patch.dict(os.environ, {"PATH": str(m.cli.parent) + ":" + os.environ["PATH"]}):
            row, _ = m.entered(phase, seconds)
        return row

    def test_real_pty_normal_q_and_same_terminal_discovery(self):
        row = self.run_console("Sign in", 2)
        self.assertIn("signed_out_label", row)
        self.assertIn("ordinary_q", row)
        self.assertEqual(row["exit_code"], 0)
        self.assertEqual(row["discovery_exit"], 0)
        self.assertEqual(row["version_exit"], 0)
        self.assertEqual(row["discovery_stdout"], str(m.cli))
        self.assertEqual(row["version_stdout"], "observer-test-version")
        self.assertNotIn("observer_terminated_viewer", row)

    def test_real_pty_drains_small_final_chunks_after_shell_exit(self):
        read = os.read
        with patch.object(m.os, "read", autospec=True, side_effect=lambda fd, count: read(fd, min(count, 16))):
            row = self.run_console("Sign in", 2)
        self.assertEqual(row["command_exit"], 0)
        self.assertEqual(row["discovery_stdout"], str(m.cli))
        self.assertEqual(row["version_exit"], 0)

    def test_terminal_eof_waits_for_child_exit_without_observer_intervention(self):
        read, exited = os.read, m.child_exited
        eof = False
        unfinished = 0

        def terminal_read(fd, count):
            nonlocal eof
            if not os.isatty(fd):
                return read(fd, count)
            try:
                chunk = read(fd, count)
            except OSError as error:
                if error.errno == errno.EIO:
                    eof = True
                raise
            eof = not chunk
            return chunk

        def delayed_exit(pid):
            nonlocal unfinished
            if not eof:
                return False
            if unfinished < 2:
                unfinished += 1
                return False
            return exited(pid)

        with patch.object(m.os, "read", autospec=True, side_effect=terminal_read), \
             patch.object(m, "child_exited", autospec=True, side_effect=delayed_exit):
            row = self.run_console("Sign in", 2)
        self.assertTrue(eof)
        self.assertEqual(unfinished, 2)
        self.assertEqual(row["exit_code"], 0)
        self.assertTrue(row["console_reaped"])
        self.assertEqual(row["version_exit"], 0)
        self.assertNotIn("observer_terminated_viewer", row)

    def test_missing_console_observation_is_not_an_empty_group(self):
        with patch.object(m.sys, "platform", "darwin"), \
             patch.object(m.subprocess, "run", autospec=True, return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaises(ChildProcessError):
                m.console_group(os.getpid())
            with self.assertRaises(ChildProcessError):
                m.child_exited(os.getpid())

    def test_observer_intervention_stays_visible_on_zero_exit(self):
        code = ("import os,signal\n"
                "signal.signal(signal.SIGTERM,lambda *_:os._exit(0))\n"
                "print('Sign in',flush=True)\n"
                "signal.pause()\n")
        with patch.object(m, "LAUNCH", ["exec", sys.executable, "-c", code]), \
             patch.object(m, "witness", autospec=True, side_effect=ValueError("capture failed")):
            with self.assertRaisesRegex(ValueError, "capture failed"):
                m.entered("warm", 2)
        row = m.x["product_commands"][-1]
        self.assertIn("observer_terminated_viewer", row)
        self.assertEqual(row["exit_code"], 0)
        self.assertTrue(row["console_reaped"])
        self.assertTrue(row["console_group_shutdown"]["verified"])

    def test_real_pty_unclassified_ui_still_captures_before_detach(self):
        row = self.run_console("UNKNOWN UI", 0.2)
        self.assertNotIn("signed_out_label", row)
        self.assertIn("readiness_unclassified_at_deadline", row)
        self.assertTrue(m.x["after-reentry"]["captured_before_detach"])
        self.assertIn("ordinary_q", row)
        self.assertNotIn("observer_terminated_viewer", row)

    def test_real_pty_reentry_can_observe_the_visible_pane_without_new_prompt_output(self):
        with patch.object(m, "pane_screen", autospec=True,
                          return_value={"matching_live_visible_pane": True, "labels": ["/login"]}):
            row = self.run_console("UNKNOWN UI", 2)
        self.assertEqual(row["signed_out_label"]["source"], "attached-pane-screen")
        self.assertNotIn("readiness_unclassified_at_deadline", row)
        self.assertTrue(m.x["after-reentry"]["captured_before_detach"])
        self.assertIn("ordinary_q", row)

    def test_real_pty_early_exit_is_captured_and_reaped(self):
        with patch.object(m, "LAUNCH", [sys.executable, "-c", "raise SystemExit(3)"]), \
             patch.object(m, "witness", autospec=True, return_value={}), \
             patch.dict(os.environ, {"PATH": str(m.cli.parent) + ":" + os.environ["PATH"]}):
            row, _ = m.entered("cold", 0.2)
        self.assertEqual(row["exit_code"], 3)
        self.assertTrue(row["console_reaped"])
        self.assertTrue(row["console_group_shutdown"]["verified"])
        self.assertIsNone(m.birth(row["console_pid"]))

    def test_real_pty_capture_error_stops_descendant_listener_and_preserves_unrelated_control(self):
        control = subprocess.Popen([sys.executable, "-c",
            "import socket,time;s=socket.socket();s.bind(('127.0.0.1',0));s.listen();"
            "print(s.getsockname()[1],flush=True);time.sleep(30)"],
            stdout=subprocess.PIPE, start_new_session=True)
        child = None
        try:
            port = int(control.stdout.readline())
            control_birth = m.birth(control.pid)
            self.assertIsNotNone(control_birth)
            with self.assertRaisesRegex(ValueError, "capture failed"):
                self.run_console("Sign in", 2, capture_error=True, descendant=True)
            child = m.x["after-reentry"]["descendant"]
            row = m.x["product_commands"][-1]
            self.assertIn("observer_terminated_viewer", row)
            self.assertIsNone(m.birth(row["console_pid"]))
            self.assertTrue(m.x["after-reentry"]["captured_before_detach"])
            with self.assertRaises(OSError):
                with socket.create_connection(("127.0.0.1", child["port"]), timeout=0.2):
                    pass
            self.assertTrue(row["console_reaped"])
            self.assertTrue(row["console_group_shutdown"]["verified"])
            self.assertEqual(row["console_group_shutdown"]["remaining"], [])
            self.assertIn("sigkill", row["console_group_shutdown"])
            self.assertEqual(m.birth(control.pid), control_birth)
            self.assertIsNone(control.poll())
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        finally:
            child = child or m.x.get("after-reentry", {}).get("descendant")
            if child and m.birth(child["pid"]) == child["birth"]:
                try:
                    os.kill(child["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    # The test child exited between its birth check and cleanup.
                    pass
            control.terminate()
            control.wait(timeout=3)
            control.stdout.close()

    def test_real_pty_cold_theme_default_is_counted_before_signed_out_capture(self):
        row = self.run_console("Sign in", 2, phase="cold", theme=True)
        choices = [v for v in m.x["interactions"] if v.get("kind") == "guest display choice"]
        self.assertEqual(len(choices), 1)
        self.assertEqual(choices[0]["answer"], "Enter (default theme)")
        self.assertIn("choose the text style", choices[0]["prompt"])
        self.assertIn("signed_out_label", row)
        self.assertIn("ordinary_q", row)
        self.assertTrue(m.x["before-return"]["captured_before_detach"])


if __name__ == "__main__":
    unittest.main()
