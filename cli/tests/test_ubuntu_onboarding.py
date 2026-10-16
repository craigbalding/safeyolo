"""Focused observer checks; no SafeYolo product, network, VM or provider is run."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def observer_cli(self, home, *args):
        return subprocess.run([sys.executable, "-I", "-B", m.__file__, "--host", os.uname().nodename,
            "--platform", "linux-arm64", "--observation-dir", str(home / "observation"), *args],
            env={**os.environ, "HOME": str(home)}, capture_output=True, text=True, timeout=10)

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
             patch.object(m, "processes", autospec=True, return_value=[]):
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

    def test_timed_out_diagnostic_preserves_result_and_next_command_runs(self):
        row = m.observe("timeout", [sys.executable, "-c", "import time;print('reached',flush=True);time.sleep(10)"], 0.1)
        self.assertTrue(row["timeout"])
        self.assertIn("reached", row["stdout"])
        self.assertEqual(m.observe("next", [sys.executable, "-c", "print('next')"])["exit"], 0)

    def test_process_and_listener_capture_excludes_unrelated_process(self):
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

    def run_console(self, message, seconds, phase="warm", theme=False, capture_error=False):
        stub = m.project / "console.py"
        display_choice = ("print('Starting or resuming claude.',flush=True)\n"
            "print('Choose the text style that looks best with your terminal\\r\\n> 1. Dark mode',flush=True)\n"
            "assert os.read(0,100)==b'\\r'\n") if theme else ""
        stub.write_text("import os,sys,tty\ntty.setraw(0)\n" + display_choice +
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

    def test_real_pty_unclassified_ui_still_captures_before_detach(self):
        row = self.run_console("UNKNOWN UI", 0.2)
        self.assertNotIn("signed_out_label", row)
        self.assertIn("readiness_unclassified_at_deadline", row)
        self.assertTrue(m.x["after-reentry"]["captured_before_detach"])
        self.assertIn("ordinary_q", row)
        self.assertNotIn("observer_terminated_viewer", row)

    def test_real_pty_capture_error_reaps_only_its_owned_console(self):
        with self.assertRaisesRegex(ValueError, "capture failed"):
            self.run_console("Sign in", 2, capture_error=True)
        row = m.x["product_commands"][-1]
        self.assertIn("observer_terminated_viewer", row)
        self.assertIsNone(m.birth(row["console_pid"]))
        self.assertTrue(m.x["after-reentry"]["captured_before_detach"])

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
