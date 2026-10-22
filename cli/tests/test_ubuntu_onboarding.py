"""Focused observer checks; no SafeYolo product, external network, VM or provider is run."""

import errno
import http.server
import importlib.util
import json
import os
import pty
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
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

    def canonical_task(self, error=None):
        # Operator7955 recovered these four redacted producer records from
        # successful 7843, original lines 5/23/25/43. Intermediate parent events
        # are omitted; envelope keys, types, order and ID relationships remain.
        fixture = Path(__file__).parent / "fixtures/claude-connected-7843.jsonl"
        rows = [json.loads(line) for line in fixture.read_text().splitlines()]
        body = rows[1]["message"]["content"][0]["input"]["content"]
        if error:
            # The failure is a synthetic control; no raw expired-login record
            # was supplied. Do not label its envelope as an observed producer.
            rows = [rows[0], {"type": "assistant", "message": {"content": [{"type": "text", "text": error}]}}]
        return rows, body

    def test_signed_out_accounting_counts_controls_without_claiming_a_task_or_human_time(self):
        m.x.update(product_commands=[{"command": m.DOWNLOAD}, {"phase": "cold"}, {"phase": "warm"}],
            observations=[{"label": "bootstrap-download", "role": "product", **m.stamp()},
                          {"label": "native-version", "role": "observer", **m.stamp()}],
            interactions=[{"phase": "cold", "prompt": "Allow host changes?", "seen": m.stamp(), "sent": m.stamp()},
                          {"phase": "warm", "kind": "return to host", "answer": "Ctrl-b d"},
                          {"phase": "warm", "kind": "keep session and exit", "answer": "q"}])
        m.record_reading("cold", "normal instructions", m.SIGNED_OUT_PROSE.encode())
        m.signed_out_accounting()
        self.assertEqual(m.x["counts"]["cold_product_commands"], 2)
        self.assertEqual(m.x["counts"]["warm_product_commands"], 1)
        self.assertEqual(m.x["counts"]["product_interactions"], 3)
        self.assertEqual(m.x["counts"]["material_decisions"], 1)
        self.assertEqual(m.x["counts"]["canonical_task_submissions"], 0)
        self.assertEqual(m.x["counts"]["observer_diagnostic_commands"], 1)
        self.assertEqual([row["label"] for row in m.x["timings"]["observer_intervals"]], ["native-version"])
        self.assertEqual(m.x["counts"]["required_reading_words"], len(m.SIGNED_OUT_PROSE.split()))
        self.assertNotIn("cold_total_to_first_task_seconds", m.x["timings"])
        self.assertIn("do not measure human", m.x["timings"]["wait_limit"])

    def test_canonical_submission_write_result_and_file_must_match_in_order(self):
        rows, body = self.canonical_task()
        self.assertTrue(m.task_records(rows, body)["successful_task"])
        self.assertTrue(m.task_records(rows[:3], body)["successful_task"])
        for changed in [rows[:2], rows[1:], [rows[0], rows[2], rows[1], rows[3]], rows + [rows[0]]]:
            self.assertFalse(m.task_records(changed, body)["successful_task"])
        self.assertFalse(m.task_records(rows, "unrelated existing file")["successful_task"])
        rows[2]["message"]["content"][0]["tool_use_id"] = "other-write"
        self.assertFalse(m.task_records(rows, body)["successful_task"])
        rows, body = self.canonical_task()
        rows[0]["message"]["content"] = m.TASK.replace("external dependencies", "external\n  dependencies")
        self.assertFalse(m.task_records(rows, body)["successful_task"])
        rows, _ = self.canonical_task("Login expired · Please run /login")
        self.assertEqual(m.task_records(rows, None)["errors"], ["Login expired"])

    def test_partial_canonical_line_and_multiple_conversations_are_not_success(self):
        rows, body = self.canonical_task()
        home = m.root / "agents/first/home/.claude/projects/-workspace"
        home.mkdir(parents=True)
        transcript = home / "session.jsonl"
        transcript.write_text("".join(json.dumps(row) + "\n" for row in rows[:2]) + json.dumps(rows[2]))
        (m.project / "index.html").write_text(body)
        self.assertFalse(m.task_observation({})["successful_task"])
        with transcript.open("a") as output:
            output.write("\n")
        self.assertTrue(m.task_observation({})["successful_task"])
        (home / "other.jsonl").write_bytes(transcript.read_bytes())
        self.assertFalse(m.task_observation({})["successful_task"])

    def test_preparation_counts_do_not_hide_required_commands_or_count_fixture_auth_as_product(self):
        start = {"at": "2026-10-18T14:00:00+00:00", "monotonic": 100}
        ready = {"at": "2026-10-18T14:01:00+00:00", "monotonic": 160}
        m.x.update(started=start, product_commands=[{**start, "role": "product"},
            {**start, "phase": "cold", "connected_ready": ready}])
        preparation = m.private / "preparation.json"
        data = {"required_user_commands_complete": True, "required_user_reading_complete": True, "required_reading": [], "decisions": [], "commands": [
            {"role": "fixture", "command": ["openssl", "cms", "<private input>"],
             "reason": "Provision the already authorized test account into normal host locations",
             "started_at": "2026-10-18T13:58:00+00:00", "ended_at": "2026-10-18T13:59:00+00:00"}]}
        preparation.write_text(json.dumps(data))
        m.preparation_accounting(preparation)
        m.record_reading("cold", "host consent", b"PRIVATE_ACCOUNT_SCREEN three words")
        m.connected_accounting()
        self.assertEqual(m.x["counts"]["total_required_user_commands_to_first_task"], 2)
        self.assertEqual(m.x["counts"]["fixture_preparation_commands"], 1)
        self.assertEqual(m.x["timings"]["cold_total_to_first_task_seconds"], 60)
        self.assertNotIn("PRIVATE_ACCOUNT_SCREEN", m.out.read_text())
        data["required_reading"].append({"text": "Read this required prerequisite."})
        preparation.write_text(json.dumps(data))
        m.preparation_accounting(preparation)
        m.connected_accounting()
        self.assertIsNone(m.x["timings"]["cold_total_to_first_task_seconds"])
        data["required_reading"][0]["seen_at"] = "2026-10-18T13:57:00+00:00"
        preparation.write_text(json.dumps(data))
        m.preparation_accounting(preparation)
        m.connected_accounting()
        self.assertEqual(m.x["timings"]["cold_total_to_first_task_seconds"], 240)
        data["required_reading"] = []
        data["commands"].append({"role": "required-user", "command": ["required-helper"],
            "reason": "Actual missing prerequisite", "started_at": "2026-10-18T13:59:00+00:00",
            "ended_at": "2026-10-18T13:59:30+00:00"})
        preparation.write_text(json.dumps(data))
        m.preparation_accounting(preparation)
        m.connected_accounting()
        self.assertEqual(m.x["counts"]["total_required_user_commands_to_first_task"], 3)
        self.assertEqual(m.x["timings"]["cold_total_to_first_task_seconds"], 120)
        data["decisions"].append({"role": "required-user", "description": "Required account interaction",
            "seen_at": "2026-10-18T13:57:00+00:00", "answered_at": "2026-10-18T13:58:00+00:00"})
        preparation.write_text(json.dumps(data))
        m.preparation_accounting(preparation)
        m.connected_accounting()
        self.assertEqual(m.x["counts"]["required_user_preparation_decisions"], 1)
        self.assertEqual(m.x["timings"]["cold_total_to_first_task_seconds"], 240)
        data["decisions"][0]["seen_at"] = None
        preparation.write_text(json.dumps(data))
        m.preparation_accounting(preparation)
        m.connected_accounting()
        self.assertIsNone(m.x["timings"]["cold_total_to_first_task_seconds"])
        data["required_user_commands_complete"] = False
        preparation.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "unknown"):
            m.preparation_accounting(preparation)

    def test_reading_excludes_wrapped_task_and_command_echoes_but_keeps_decision_prose_private(self):
        screen = "Review this workspace.\n" + m.TASK.replace(" as ", "\n as ") + "\n" + shlex.join(m.LAUNCH)
        m.record_reading("cold", "decision screen", screen.encode())
        self.assertEqual(m.x["required_reading"][0]["words"], 3)
        self.assertNotIn("Review this workspace", m.out.read_text())

    def test_recorded_reading_does_not_drop_prose_outside_the_prompt_search_buffer(self):
        terminal = m.private / "cold.terminal"
        terminal.write_text("Earlier consent prose\n" + " " * 60001 + "Current prompt\n")
        m.record_reading("cold", "host consent")
        self.assertEqual(m.x["required_reading"][0]["words"], 5)
        with terminal.open("a") as stream:
            stream.write("Next actual prompt\n")
        m.record_reading("cold", "next consent")
        self.assertEqual(m.x["required_reading"][1]["words"], 3)

    def test_missing_preparation_decisions_and_naive_times_stop_before_product_execution(self):
        path = m.private / "preparation.json"
        data = {"required_user_commands_complete": True, "required_user_reading_complete": True,
                "required_reading": [], "commands": []}
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "decisions must be recorded"):
            m.preparation_accounting(path)
        data.update(decisions=[], commands=[{"role": "required-user", "command": ["required-helper"],
                    "reason": "Actual prerequisite", "started_at": "2026-10-18T13:59:00"}])
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "UTC offset"):
            m.preparation_accounting(path)
        self.assertEqual(m.x["product_commands"], [])

    def test_provider_wait_projection_keeps_only_actual_nonsecret_operands_and_unknowns(self):
        logs = m.root / "logs"
        logs.mkdir()
        rows = [{"event": "traffic.request", "host": "api.anthropic.com", "request_id": "req-1", "ts": "first"},
                {"event": "traffic.response", "host": "api.anthropic.com", "request_id": "req-1", "ts": "last",
                 "details": {"ms": 3000, "status": 200, "private": "PRIVATE_HEADER"}},
                {"event": "traffic.request", "host": "mcp-proxy.anthropic.com", "request_id": "req-2", "ts": "open"}]
        (logs / "audit.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
        observed = m.provider_intervals()
        self.assertEqual(observed["responses"][0]["recorded_duration_ms"], 3000)
        self.assertEqual(observed["requests_without_response"], {"req-2": "open"})
        self.assertNotIn("PRIVATE_", json.dumps(observed))

    def test_connected_main_accepts_existing_host_auth_and_binds_the_public_package(self):
        for platform, machine, expected in [("linux-amd64", "x86_64", m.CONNECTED_PACKAGE),
                                            ("linux-arm64", "aarch64", m.PACKAGES["linux-arm64"])]:
            with self.subTest(platform=platform):
                home = Path(self.scratch.name) / platform
                (home / ".claude").mkdir(parents=True)
                for path in [home / ".claude.json", home / ".claude/.credentials.json"]:
                    path.write_text("PRIVATE_AUTH_SENTINEL")
                preparation = home / "preparation.json"
                preparation.write_text(json.dumps({"required_user_commands_complete": True,
                    "required_user_reading_complete": True, "commands": [], "required_reading": [], "decisions": []}))
                original = os.uname()
                uname = os.uname_result((*original[:4], machine))
                environment = {key: value for key, value in os.environ.items() if not key.startswith("SAFEYOLO_")
                               and key not in ["GH_TOKEN", "GITHUB_TOKEN", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"]}
                argv = [m.__file__, "--host", original.nodename, "--platform", platform, "--connected",
                        "--preparation", str(preparation), "--observation-dir", str(home / "private")]
                with patch.object(sys, "argv", argv), patch.object(m.Path, "home", autospec=True, return_value=home), \
                     patch.object(m.os, "uname", autospec=True, return_value=uname), patch.dict(os.environ, environment, clear=True), \
                     patch.object(sys.stdin, "isatty", autospec=True, return_value=True), patch.object(sys.stdout, "isatty", autospec=True, return_value=True), \
                     patch.object(m, "processes", autospec=True, return_value=[]), patch.object(m, "listeners", autospec=True, return_value=[]), \
                     patch.object(m, "connected_run", autospec=True, side_effect=ValueError("controlled stop before product execution")) as run:
                    self.assertEqual(m.main(), 1)
                run.assert_called_once()
                self.assertIn("host-" + expected["source"], m.LAUNCH)
                record = json.loads((home / "private/result.json").read_text())
                self.assertNotIn("baseline_unavailable", record)
                self.assertEqual(record["native_source"], expected["source"])
                self.assertEqual(record["expected_host_package"], expected)
                self.assertEqual(record["product_commands"], [])
                self.assertEqual((home / ".claude/.credentials.json").read_text(), "PRIVATE_AUTH_SENTINEL")
                self.assertNotIn("PRIVATE_AUTH_SENTINEL", json.dumps(record))

    def test_foreground_public_approval_input_retains_the_displayed_scope_without_secret_text(self):
        seen = m.stamp()
        row = {"terminal_output_last_seen": seen}
        journey = m.ConnectedJourney("cold", row)
        read_fd, write_fd = os.pipe()
        try:
            pending = (b'Request: credential-request\nStatus: pending\n'
                b'SafeYolo effect: Allow the selected credential for mcp-proxy.anthropic.com only\n'
                b'Helper reason (untrusted text): "PRIVATE_REASON"\n'
                b'approve / reject / Enter to leave unchanged: ')
            with patch.object(m, "pane_screen", autospec=True, return_value={"matching_live_visible_pane": False}):
                journey.forward(write_fd, b"approve\r", pending)
                journey.forward(write_fd, b"\x1b]10;rgb:1111/2222/3333\x07", pending)
            self.assertEqual(os.read(read_fd, 1024), b"approve\r\x1b]10;rgb:1111/2222/3333\x07")
            self.assertEqual(len(m.x["interactions"]), 1)
            interaction = m.x["interactions"][0]
            self.assertEqual(interaction["displayed_approval"]["status"], "pending")
            self.assertIn("mcp-proxy.anthropic.com only", interaction["displayed_approval"]["effect"])
            self.assertTrue(interaction["classification_complete"])
            self.assertEqual(interaction["seen"], seen)
            self.assertGreaterEqual(interaction["first_key"]["monotonic"], seen["monotonic"])
            self.assertNotIn("PRIVATE_REASON", m.out.read_text())
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_live_return_reports_mutable_vendor_files_and_requires_stable_state_and_present_auth(self):
        (m.project / "install-safeyolo.sh").write_text("# controlled bootstrap input\n")
        (m.project / "index.html").write_text("controlled first file")
        m.archive.write_bytes(b"controlled package")
        package = {"source": m.PACKAGES["linux-arm64"]["source"],
                   "bytes": m.archive.stat().st_size, "sha256": m.digest(m.archive)}
        (m.root / "package-info").write_text(f"source_commit={package['source']}\nprofile=production\nplatform=linux-arm64\n")
        required = m.PUBLIC_STATE + m.PRIVATE_STATE + ["agents/first/home/.claude/.credentials.json"]
        before = dict.fromkeys(required, "same")
        before["agents/first/home/.claude.json"] = "old usage metadata"
        for change, expected in [("usage", True), ("policy", False), ("authentication missing", False),
                                 ("wrong package source", False)]:
            with self.subTest(change=change):
                m.x.update(observation_outcome="partial", product_commands=[], observations=[], required_reading=[], interactions=[],
                           preparation={"required_reading": []})
                after = {**before, "agents/first/home/.claude.json": "new usage metadata"}
                if change == "wrong package source":
                    (m.root / "package-info").write_text(f"source_commit={m.CONNECTED_SOURCE}\nprofile=production\nplatform=linux-arm64\n")
                if change == "policy":
                    after["policy.toml"] = "different"
                if change == "authentication missing":
                    after["agents/first/home/.claude/.credentials.json"] = None
                def enter(phase, *args, **kwargs):
                    stage = "before-return" if phase == "cold" else "after-reentry"
                    m.x[stage] = {"runtime": {"live_births": {key: {"observed": key, "recorded": key}
                        for key in ["holder", "backend"]}}, "launch": {"launch_id": "same"},
                        "task": {"conversations": [{"file": "same-session.jsonl"}]}}
                    return {"connected_ready": m.stamp(), "ordinary_q": m.stamp(), "exit_code": 0,
                            "discovery_exit": 0, "version_exit": 0}, before if phase == "cold" else after
                with patch.object(m, "entered", autospec=True, side_effect=enter) as entered, \
                     patch.object(m, "observe", autospec=True, return_value={"exit": 0}):
                    m.connected_run(m.argparse.Namespace(platform="linux-arm64", cold_seconds=1800), package)
                self.assertEqual(entered.call_args_list[0].args, ("cold", 1800))
                self.assertEqual(entered.call_args_list[1].args, ("warm", 180))
                self.assertEqual(m.x["observation_outcome"] != "partial", expected)
                self.assertFalse(m.x["selected_state_equality"]["agents/first/home/.claude.json"]["equal"])

    def connected_console(self, error=None, echo=True, uncertain_literal=False, displayed_task=None,
                          changed_selection=False, capture_failure=False):
        """Run the actual driver through a real PTY, tmux, literal input and JSONL producer."""
        binary = shutil.which("tmux")
        if binary is None:
            self.skipTest("foreground connected check requires tmux")
        bin_dir = m.root / "bin"
        bin_dir.mkdir(exist_ok=True)
        (bin_dir / "tmux").symlink_to(binary)
        (bin_dir / "safeyolo").symlink_to(m.cli)
        (m.project / "onboarding-fixture.txt").unlink()
        rows, body = self.canonical_task(error)
        harness = m.private / "harness.py"
        canonical = m.root / "agents/first/home/.claude/projects/-workspace/session.jsonl"
        canonical.parent.mkdir(parents=True)
        harness.write_text("import json,os,sys,time,termios,tty\n"
            + ("state=termios.tcgetattr(0);state[3]&=~termios.ECHO;termios.tcsetattr(0,termios.TCSANOW,state)\n" if not echo else "")
            + ("tty.setcbreak(0)\n" if displayed_task is not None else "")
            + "print('Claude Code\\n❯ ',end='',flush=True)\n"
            + ("task=sys.stdin.readline().strip()\n" if displayed_task is None else
               f"task=b''\nwhile len(task)<{len(m.TASK)}:task+=os.read(0,{len(m.TASK)}-len(task))\n"
               f"print('\\x1b[2J\\x1b[H'+{displayed_task!r},end='',flush=True)\nassert os.read(0,1)==b'\\n'\ntask=task.decode()\n")
            + f"assert task=={m.TASK!r}\nrows={rows!r}\n"
            + f"open({str(canonical)!r},'w').write(''.join(json.dumps(row)+'\\n' for row in rows))\n"
            + (f"open({str(m.project / 'index.html')!r},'w').write({body!r})\n" if not error else "")
            + f"print({(error or 'index.html: Hello from SafeYolo')!r},flush=True)\n"
            + "print('❯ ',end='',flush=True)\n"
            + "while sys.stdin.readline():pass\n")
        socket_path = str(m.root / "tmux.sock")
        tm = [binary, "-S", socket_path]
        wrapper = m.private / "launch.py"
        wrapper.write_text("import json,os,subprocess,sys\n"
            f"tm={tm!r}\nrecord={str(m.root / 'agents/first/current-launch.json')!r}\n"
            "if not os.path.exists(record):\n"
            + " for prompt in ['Allow these host changes? [y/N]', 'Run this setup and share this workspace? [y/N]', 'Copy this selected host authentication and settings? [y/N]']:\n"
            + "  print('Actual consent prose: '+prompt,flush=True);assert sys.stdin.readline().strip()=='y'\n"
            + f" pane=subprocess.check_output(tm+['-f','/dev/null','new-session','-d','-x','120','-y','30','-P','-F','#{{pane_id}}','-s','public',{shlex.join([sys.executable,str(harness)])!r}],text=True).strip()\n"
            + " subprocess.run(tm+['set-option','-p','-t',pane,'@safeyolo_launch_id','launch-connected'],check=True)\n"
            + f" open(record,'w').write(json.dumps({{'tmux_socket':{socket_path!r},'tmux_session':'public','pane_id':pane,'launch_id':'launch-connected'}}))\n"
            + "subprocess.run(tm+['attach-session','-t','public'],check=True)\n"
            + "print('SafeYolo host> ',end='',flush=True);assert sys.stdin.readline().strip()=='q'\n")
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        self.addCleanup(lambda: subprocess.run([*tm, "kill-server"], capture_output=True))
        trigger = ("import os,subprocess,sys,time\n"
            f"tm={tm!r}\ndeadline=time.monotonic()+8\n"
            "while time.monotonic()<deadline:\n"
            " facts=subprocess.run(tm+['display-message','-p','-t','public','#{pane_dead} #{window_active} #{pane_active} #{session_attached}'],capture_output=True,text=True)\n"
            " screen=subprocess.run(tm+['capture-pane','-p','-t','public'],capture_output=True)\n"
            f" if facts.stdout.strip()=='0 1 1 1' and '❯'.encode() in screen.stdout:os.write({write_fd},b'\\x1d');sys.exit(0)\n"
            " time.sleep(.05)\n"
            "sys.exit('No live attached input pane')\n")
        worker = subprocess.Popen([sys.executable, "-c", trigger], pass_fds=[write_fd], stderr=subprocess.PIPE)
        run = subprocess.run
        def send_once(command, **kwargs):
            if capture_failure and "capture-pane" in command and m.x["product_commands"][-1].get("task_input"):
                command = [*command[:-1], "%999"]
            result = run(command, **kwargs)
            if changed_selection and "send-keys" in command and "-l" in command:
                record = m.root / "agents/first/current-launch.json"
                selection = json.loads(record.read_text())
                selection["launch_id"] = "changed-launch"
                run([*tm, "set-option", "-p", "-t", selection["pane_id"],
                     "@safeyolo_launch_id", selection["launch_id"]], check=True)
                record.write_text(json.dumps(selection))
            if uncertain_literal and "send-keys" in command and "-l" in command:
                raise subprocess.TimeoutExpired(command, 3)
            return result
        try:
            with patch.object(m, "LAUNCH", [sys.executable, str(wrapper)]), \
                 patch.object(m.Path, "home", autospec=True, return_value=Path(self.scratch.name)), \
                 patch.object(m.subprocess, "run", autospec=True, side_effect=send_once), \
                 patch.dict(os.environ, {"PATH": str(bin_dir) + ":" + os.environ["PATH"]}):
                cold, _ = m.entered("cold", 10, connected=True, operator_fd=read_fd)
                warm = None
                if cold.get("connected_ready"):
                    warm, _ = m.entered("warm", 5, connected=True, operator_fd=read_fd)
            self.assertEqual(worker.wait(timeout=9), 0, worker.stderr.read().decode())
            return cold, warm, canonical
        finally:
            if worker.poll() is None:
                worker.terminate()
            worker.wait(timeout=3)
            worker.stderr.close()

    def test_real_foreground_connected_driver_submits_once_and_returns_without_another_task(self):
        cold, warm, canonical = self.connected_console()
        self.assertEqual(cold["task_input"]["literal_transmissions"], 1)
        self.assertTrue(cold["task_input"]["input_visible"])
        self.assertEqual(cold["task_input"]["facts_before_input"][1:], ["0", "1", "1", "1"])
        self.assertIn("connected_ready", cold)
        self.assertIn("connected_ready", warm)
        self.assertEqual(cold["exit_code"], 0)
        self.assertEqual(warm["exit_code"], 0)
        self.assertNotIn("task_input", warm)
        self.assertEqual(len([row for row in map(json.loads, canonical.read_text().splitlines())
                              if row.get("message", {}).get("content") == m.TASK]), 1)
        self.assertTrue(all(row["task_observation"]["successful_task"] for row in [cold, warm]))
        self.assertEqual([i["answer"] for i in m.x["interactions"] if i.get("prompt")], ["y", "y", "y"])

    def test_real_foreground_expired_login_keeps_submission_and_never_runs_a_warm_task(self):
        cold, warm, canonical = self.connected_console(error="Login expired · Please run /login")
        self.assertIsNone(warm)
        self.assertIn("connected_failure", cold)
        self.assertEqual(len(cold["task_observation"]["conversations"][0]["users"]), 1)
        self.assertFalse((m.project / "index.html").exists())
        self.assertEqual(len(canonical.read_text().splitlines()), 2)

    def test_real_foreground_missing_literal_readback_does_not_send_enter(self):
        with self.assertRaisesRegex(ValueError, "readback failed"):
            self.connected_console(echo=False)
        row = m.x["product_commands"][-1]
        self.assertEqual(row["task_input"]["literal_transmissions"], 1)
        self.assertNotIn("enter_attempted", row["task_input"])
        self.assertNotIn("observer_error", row)

    def test_real_foreground_observed_task_wrap_submits_once_and_returns(self):
        # Operator7971 supplied these exact nonsecret input rows, including ANSI,
        # prompt, borders and explicit wrapping. JSON preserves the screen bytes.
        frame = json.loads((Path(__file__).parent / "fixtures/claude-input-7960.json").read_text())
        displayed = ('Create /workspace/index.html as a complete HTML page with the heading '
                     '"Hello from SafeYolo". Use no external\n  dependencies.')
        self.assertIn(displayed, frame)
        self.assertEqual(" ".join(displayed.split()), m.TASK)
        cold, warm, canonical = self.connected_console(displayed_task=frame)
        screen = (m.private / "cold-input-pane.screen").read_bytes()
        self.assertIn(displayed.encode(), screen)
        self.assertNotIn(m.TASK.encode(), screen)
        self.assertTrue(cold["task_input"]["input_visible"])
        self.assertEqual(cold["task_input"]["literal_transmissions"], 1)
        self.assertEqual(m.x["observer_tmux_commands"]["send-keys"], 2)
        self.assertTrue(all(row["task_observation"]["successful_task"] for row in [cold, warm]))
        self.assertNotIn("task_input", warm)
        self.assertEqual([row["message"]["content"] for row in map(json.loads, canonical.read_text().splitlines())
                          if row.get("message", {}).get("content") == m.TASK], [m.TASK])

    def test_real_foreground_changed_task_display_does_not_send_enter(self):
        displayed = m.TASK.replace("Use no external dependencies.", "Use external\n  dependencies.")
        with self.assertRaisesRegex(ValueError, "readback failed"):
            self.connected_console(displayed_task=displayed)
        row = m.x["product_commands"][-1]
        self.assertEqual(row["task_input"]["literal_transmissions"], 1)
        self.assertFalse(row["task_input"]["input_visible"])
        self.assertNotIn("enter_attempted", row["task_input"])
        self.assertEqual(m.x["observer_tmux_commands"]["send-keys"], 1)
        self.assertEqual(m.conversation_offsets(), {})
        self.assertFalse((m.project / "index.html").exists())

    def test_real_foreground_changed_selection_does_not_send_enter(self):
        frame = json.loads((Path(__file__).parent / "fixtures/claude-input-7960.json").read_text())
        with self.assertRaisesRegex(ValueError, "readback failed"):
            self.connected_console(displayed_task=frame, changed_selection=True)
        task = m.x["product_commands"][-1]["task_input"]
        self.assertTrue(task["input_visible"])
        self.assertTrue(task["input_readback"]["matching_live_visible_pane"])
        self.assertNotEqual(task["selection"], task["input_readback"]["selection"])
        self.assertEqual(task["literal_transmissions"], 1)
        self.assertNotIn("enter_attempted", task)
        self.assertEqual(m.x["observer_tmux_commands"]["send-keys"], 1)
        self.assertEqual(m.conversation_offsets(), {})
        self.assertFalse((m.project / "index.html").exists())

    def test_real_foreground_truncated_task_display_does_not_send_enter(self):
        with self.assertRaisesRegex(ValueError, "readback failed"):
            self.connected_console(displayed_task=m.TASK.removesuffix("dependencies."))
        task = m.x["product_commands"][-1]["task_input"]
        self.assertFalse(task["input_visible"])
        self.assertEqual(task["literal_transmissions"], 1)
        self.assertNotIn("enter_attempted", task)
        self.assertEqual(m.x["observer_tmux_commands"]["send-keys"], 1)
        self.assertEqual(m.conversation_offsets(), {})
        self.assertFalse((m.project / "index.html").exists())

    def test_real_foreground_failed_capture_does_not_send_enter(self):
        with self.assertRaisesRegex(ValueError, "readback failed"):
            self.connected_console(capture_failure=True)
        task = m.x["product_commands"][-1]["task_input"]
        self.assertTrue(task["input_readback"]["matching_live_visible_pane"])
        self.assertEqual(task["input_readback"]["exit"], 1)
        self.assertEqual(task["literal_transmissions"], 1)
        self.assertNotIn("enter_attempted", task)
        self.assertEqual(m.x["observer_tmux_commands"]["send-keys"], 1)
        self.assertEqual(m.conversation_offsets(), {})
        self.assertFalse((m.project / "index.html").exists())

    def test_real_foreground_uncertain_literal_effect_is_unknown_and_never_replayed(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.connected_console(uncertain_literal=True)
        row = m.x["product_commands"][-1]
        self.assertIsNone(row["task_input"]["literal_transmissions"])
        self.assertNotIn("enter_attempted", row["task_input"])
        self.assertEqual(m.x["observer_tmux_commands"]["send-keys"], 1)

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

    def test_network_response_and_local_event_correlation_keep_raw_diagnostics_private(self):
        logs = m.root / "logs"
        logs.mkdir()
        for name in ("audit.jsonl", "proxy.log"):
            (logs / name).touch()
        request_id = "req-" + "1" * 32

        class Proxy(http.server.BaseHTTPRequestHandler):
            decision = "error"
            def do_GET(self):
                self.send_response(502)
                self.send_header("X-SafeYolo-Request-Id", request_id)
                self.send_header("Set-Cookie", "PRIVATE_COOKIE_SENTINEL")
                self.send_header("X-Blocked-By", "PRIVATE_HEADER_SENTINEL")
                self.end_headers()
                self.wfile.write(b"PRIVATE_BODY_SENTINEL")
                with (logs / "audit.jsonl").open("a") as stream:
                    for identifier in ("req-" + "2" * 32, request_id):
                        stream.write(json.dumps({"event": "traffic.request_outcome", "host": "httpbin.org",
                            "request_id": identifier,
                            **({"decision": self.decision} if self.decision == "allow" else {}),
                            "details": {"status": 502, "decision": self.decision,
                                        "private": "PRIVATE_EVENT_SENTINEL"}}) + "\n")
                with (logs / "proxy.log").open("a") as stream:
                    stream.write(f"request {request_id} failed: PRIVATE_ERROR_SENTINEL\n")
            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        m.cli.write_text("#!/bin/sh\nexec sh -c \"$7\"\n")
        try:
            with patch.dict(os.environ, {"HTTP_PROXY": f"http://127.0.0.1:{server.server_port}"}):
                for decision in ("error", "allow"):
                    Proxy.decision = decision
                    row = m.network_probe("cold", "positive", m.PROBES[0][1], time.monotonic() + 10)
                    self.assertFalse(row["expected_result"])
                    self.assertEqual(row["operand"]["exit"], 0)
                    self.assertEqual(row["response"]["http_code"], 502)
                    self.assertEqual(row["response"]["request_id"], request_id)
                    self.assertTrue(row["response"]["blocked_by_header_present"])
                    self.assertNotIn("blocked_by_header", row["response"])
                    self.assertEqual(row["proxy_logs"]["audit.jsonl"]["matches"],
                        [{"request_id": request_id, "correlation": "request-id", "status": 502, "decision": decision}])
                    self.assertEqual(row["proxy_logs"]["proxy.log"]["matches"][0]["stage"], "request-failed")
                    self.assertNotIn("PRIVATE_", json.dumps(row))
                    self.assertNotIn("PRIVATE_", m.out.read_text())
                    self.assertIn("PRIVATE_COOKIE_SENTINEL", (m.private / "cold-positive.stderr").read_text())
                    self.assertNotIn("stdout", row["operand"])
        finally:
            server.shutdown()
            worker.join(timeout=3)
            server.server_close()

    def test_network_missing_response_and_identity_error_remain_distinct_from_success(self):
        logs = m.root / "logs"
        logs.mkdir()
        (logs / "audit.jsonl").touch()
        proxy_log = logs / "proxy.log"
        proxy_log.touch()
        identifier = "req-" + "3" * 32
        m.cli.write_text(f"#!/bin/sh\nprintf 'request {identifier} identity reconciliation failed: PRIVATE_IDENTITY\\n' >> {proxy_log}\n"
                         "exec sh -c \"$7\"\n")
        row = m.network_probe("cold", "positive", "true", time.monotonic() + 10)
        self.assertFalse(row["expected_result"])
        self.assertEqual(row["metrics_error"], "JSONDecodeError")
        self.assertEqual(row["proxy_logs"]["proxy.log"]["matches"], [{"request_id": identifier,
            "stage": "identity-reconciliation", "correlation": "time-window-only"}])
        self.assertNotIn("PRIVATE_", json.dumps(row))
        for status in (7, 28):
            row = m.network_probe("cold", "direct-http", 'printf \'{"http_code":0}\'; exit ' + str(status), time.monotonic() + 10)
            self.assertTrue(row["expected_result"])
            self.assertEqual(row["operand"]["exit"], status)
            self.assertEqual(row["response"]["http_code"], 0)

    def test_process_permission_read_records_original_stage_and_scoped_retry(self):
        entry = Path("/proc") / str(os.getpid())
        row = {}
        denied = PermissionError(errno.EACCES, "denied")
        observed = subprocess.CompletedProcess([], 0, b"/usr/bin/python3\n", b"PRIVATE_RETRY_DIAGNOSTIC")
        with patch.object(m.os, "readlink", autospec=True, side_effect=denied), \
             patch.object(m.subprocess, "run", autospec=True, return_value=observed) as run:
            self.assertEqual(m.process_read(entry, "exe", row), b"/usr/bin/python3")
        self.assertEqual(run.call_args.args[0], ["sudo", "-n", "/usr/bin/readlink", "--", str(entry / "exe")])
        self.assertEqual(row["permission_reads"][0]["errno"], errno.EACCES)
        self.assertEqual(row["permission_reads"][0]["stage"], "exe")
        self.assertEqual(row["permission_reads"][0]["sudo_exit"], 0)
        self.assertNotIn("PRIVATE_", json.dumps(row))
        with patch.object(m.os, "readlink", autospec=True, side_effect=denied), \
             patch.object(m.subprocess, "run", autospec=True, side_effect=FileNotFoundError("sudo absent")):
            with self.assertRaises(PermissionError):
                m.process_read(entry, "exe", row)
        self.assertEqual(row["permission_reads"][-1]["sudo_error"], "FileNotFoundError")

    def test_process_scan_recovery_requires_same_birth_and_keeps_ownership_operands(self):
        proc = Path(self.scratch.name) / "proc"
        entry = proc / "10101"
        entry.mkdir(parents=True)
        (entry / "cmdline").write_bytes(b"PRIVATE_UNRELATED_ARG")
        (entry / "exe").symlink_to("/usr/bin/unrelated")
        real_readlink = os.readlink

        def denied_exe(path):
            if str(path).endswith("/10101/exe"):
                raise PermissionError(errno.EACCES, "controlled exe denial")
            return real_readlink(path)

        for changed in (False, True):
            with patch.object(m, "Path", autospec=True, side_effect=lambda _path: proc), \
                 patch.object(m, "birth", autospec=True, side_effect=["linux:boot:10101:1", "linux:boot:10101:2" if changed else "linux:boot:10101:1"]), \
                 patch.object(m.os, "readlink", autospec=True, side_effect=denied_exe), \
                 patch.object(m.subprocess, "run", autospec=True,
                              return_value=subprocess.CompletedProcess([], 0, b"/usr/bin/unrelated\n", b"")):
                self.assertEqual(m.processes(), [])
            scan = m.x["latest_process_scan"]
            self.assertEqual(scan["unreadable_pids"], [10101] if changed else [])
            detail = scan["read_details"][0]
            self.assertEqual(detail["uid"], os.getuid())
            self.assertEqual(detail["executable"], "/usr/bin/unrelated")
            self.assertFalse(detail["argv_root_match"])
            self.assertEqual(detail["ownership"], "unknown" if changed else "unrelated")
            self.assertNotIn("PRIVATE_", json.dumps(scan))

    def test_denied_owned_listener_read_is_not_an_empty_listener_list(self):
        process = {"pid": os.getpid(), "birth": m.birth(os.getpid())}
        with patch.object(m, "process_read", autospec=True, side_effect=PermissionError(errno.EACCES, "fd denied")):
            result = m.capture(m.x, "remaining_owned_listeners", lambda: m.listeners([process]))
        self.assertIn("observation_error", result)

    def test_runtime_with_another_uid_is_included_only_at_its_recorded_birth(self):
        proc = Path(self.scratch.name) / "proc"
        entry = proc / "10101"
        entry.mkdir(parents=True)
        (entry / "cmdline").write_bytes(b"tail\0-f\0/dev/null\0")
        (entry / "exe").symlink_to("/usr/bin/tail")
        runtime = m.root / "agents/first/runtime.json"
        runtime.parent.mkdir(parents=True)
        token = "linux:boot:10101:1"
        for expected in (token, "linux:boot:10101:2"):
            runtime.write_text(json.dumps({"backend_pid": 10101, "backend_token": expected}))
            with patch.object(m, "Path", autospec=True, return_value=proc), \
                 patch.object(m.os, "getuid", autospec=True, return_value=os.getuid() + 1), \
                 patch.object(m, "birth", autospec=True, return_value=token):
                rows = m.processes()
            self.assertEqual([r["pid"] for r in rows], [10101] if expected == token else [])

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux /proc ownership observer")
    def test_cleanup_tracks_runtime_holder_without_installation_path_in_command(self):
        holder = subprocess.Popen(["sleep", "20"])
        token = m.birth(holder.pid)
        self.assertIsNotNone(token)
        runtime = m.root / "agents/first/runtime.json"
        runtime.parent.mkdir(parents=True)
        runtime.write_text(json.dumps({"holder_pid": holder.pid, "holder_token": token}))
        try:
            m.cleanup()
            self.assertIn(holder.pid, [p["pid"] for p in m.x["remaining_owned_processes"]])
            self.assertEqual(m.x["tracked_births_still_live"][token], holder.pid)
            self.assertFalse(m.x["cleanup_verified"])
            holder.terminate()
            holder.wait(timeout=3)
            m.cleanup()
            self.assertNotIn(token, m.x["tracked_births_still_live"])
            self.assertNotIn(holder.pid, [p["pid"] for p in m.x["remaining_owned_processes"]])
        finally:
            if holder.poll() is None:
                holder.terminate()
            holder.wait(timeout=3)

    def test_reused_listener_pid_remains_unverified(self):
        process = {"pid": os.getpid(), "birth": "old-birth"}
        with patch.object(m, "process_read", autospec=True) as read:
            result = m.capture(m.x, "remaining_owned_listeners", lambda: m.listeners([process]))
        self.assertIn("observation_error", result)
        read.assert_not_called()

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
        for name in m.PRIVATE_STATE + m.OPTIONAL_PRIVATE_STATE[:1]:
            path = m.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("PRIVATE_STATE_SENTINEL")
        with patch.object(m, "live_record", autospec=True, return_value={}), \
             patch.object(m, "processes", autospec=True, return_value=[]), \
             patch.object(m, "listeners", autospec=True, return_value=[]), \
             patch.object(m, "guest", autospec=True, return_value={"exit": 1}):
            before = m.witness("before-return")
            self.assertEqual(m.x["before-return"]["selected_private_state_present"],
                             m.PRIVATE_STATE + m.OPTIONAL_PRIVATE_STATE[:1])
            (m.root / m.PRIVATE_STATE[0]).write_text("changed token")
            (m.root / m.PRIVATE_STATE[1]).unlink()
            after = m.witness("after-reentry")
        self.assertEqual(m.x["after-reentry"]["selected_private_state_present"],
                         [p for p in m.PRIVATE_STATE if p != m.PRIVATE_STATE[1]] + m.OPTIONAL_PRIVATE_STATE[:1])
        self.assertNotEqual(before[m.PRIVATE_STATE[0]], after[m.PRIVATE_STATE[0]])
        self.assertIsNone(after[m.PRIVATE_STATE[1]])
        self.assertEqual(before[m.PRIVATE_STATE[2]], after[m.PRIVATE_STATE[2]])
        self.assertTrue(all(name in before and before[name] is None and name in after and after[name] is None
                            for name in m.OPTIONAL_PRIVATE_STATE[1:]))
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
        self.assertNotIn(m.PRIVATE_STATE[0], m.x["after-reentry"]["selected_private_state_present"])

    def observer_cli(self, home, *args, script=None):
        return subprocess.run([sys.executable, "-I", "-B", script or m.__file__, "--host", os.uname().nodename,
            "--platform", "linux-arm64", "--observation-dir", str(home / "observation"), *args],
            cwd=home, env={**os.environ, "HOME": str(home)}, capture_output=True, text=True, timeout=10)

    def test_cold_allowance_keeps_elapsed_bootstrap_warm_clock_and_saved_partial_result(self):
        for selected, allowance in [(None, 900), (1800, 1800), (5, 5)]:
            with self.subTest(selected=selected):
                home = Path(self.scratch.name) / f"allowance-{selected}"
                home.mkdir()
                clock = [100.0]

                def observe(label, command, *args, **kwargs):
                    row = {"exit": 0, "monotonic": clock[0]}
                    if label == "bootstrap-download":
                        (m.project / "install-safeyolo.sh").write_text("controlled download")
                        clock[0] += 12
                    row["ended"] = {"monotonic": clock[0]}
                    return row

                def entered(phase, seconds):
                    m.x["before-return" if phase == "cold" else "after-reentry"] = {}
                    return {"monotonic": clock[0], "ended": {"monotonic": clock[0]},
                            "ordinary_q": True, "exit_code": 0}, {}

                argv = [m.__file__, "--host", os.uname().nodename, "--platform", "linux-arm64",
                        "--observation-dir", str(home / "observation"), "--execution-mode", "qemu-tcg"]
                if selected is not None:
                    argv += ["--cold-seconds", str(selected)]
                environment = {key: value for key, value in os.environ.items() if not key.startswith("SAFEYOLO_")
                               and key not in ["GH_TOKEN", "GITHUB_TOKEN", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"]}
                uname = os.uname_result((*os.uname()[:4], "aarch64"))
                with patch.object(sys, "argv", argv), patch.object(m.Path, "home", autospec=True, return_value=home), \
                     patch.object(m.os, "uname", autospec=True, return_value=uname), \
                     patch.dict(os.environ, environment, clear=True), patch.object(m.time, "monotonic", autospec=True, side_effect=lambda: clock[0]), \
                     patch.object(m, "observe", autospec=True, side_effect=observe), \
                     patch.object(m, "entered", autospec=True, side_effect=entered) as enter, \
                     patch.object(m, "guest", autospec=True, return_value={}), \
                     patch.object(m, "live_record", autospec=True, return_value={}), \
                     patch.object(m, "processes", autospec=True, return_value=[]), \
                     patch.object(m, "cleanup", autospec=True) as cleanup:
                    self.assertEqual(m.main(), 1)
                self.assertEqual(enter.call_args_list[0].args, ("cold", max(1, allowance - 12)))
                self.assertEqual(enter.call_args_list[1].args, ("warm", 180))
                cleanup.assert_called_once()
                result = json.loads((home / "observation/result.json").read_text())
                self.assertEqual(result["cold_allowance_seconds"], allowance)
                self.assertEqual(result["execution_mode"], "qemu-tcg")
                self.assertEqual(result["timings"]["bootstrap_seconds"], 12)
                self.assertIsNone(result["timings"]["cold_readiness_seconds"])
                self.assertEqual(result["observation_outcome"], "partial")
                self.assertIn("ended", result)

    def test_invalid_cold_allowance_stops_before_observer_or_product_mutation(self):
        home = Path(self.scratch.name)
        for value in ["0", "-1", "1.5"]:
            with self.subTest(value=value):
                result = self.observer_cli(home, "--cold-seconds", value)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--cold-seconds", result.stderr)
                self.assertFalse((home / "observation").exists())

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
        self.assertEqual(record["expected_host_package"], m.PACKAGES["linux-arm64"])
        self.assertEqual(record["native_source"], m.PACKAGES["linux-arm64"]["source"])
        self.assertEqual(record["cold_allowance_seconds"], 900)
        self.assertEqual(record["execution_mode"], "unknown")
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
                  "cold_allowance_seconds": 1800, "execution_mode": "qemu-tcg",
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
        self.assertEqual(observed["cold_allowance_seconds"], 1800)
        self.assertEqual(observed["execution_mode"], "qemu-tcg")
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

    def test_launch_summary_classifies_only_known_product_errors_and_exports_no_excerpt(self):
        private_text = "PRIVATE_AUTH_MODEL_TERMINAL_CANARY"
        launch_id = "launch-" + "a" * 32
        errors = [("coding-agent observation timed out", "coding-agent-observation-timeout"),
                  ("coding-agent observation failed", "coding-agent-observation-failed"),
                  ("coding-agent observation is unverified", "coding-agent-observation-unverified"),
                  ("guest did not reach per-run startup", "guest-startup-unready"),
                  ("guest did not reach per-run startup; sandbox cleanup failed: " + private_text,
                   "guest-startup-unready"),
                  ("runsc did not identify its backend", "runsc-backend-unidentified"),
                  ("runsc create failed: " + private_text, "runsc-create-failed"),
                  ("runsc start failed: " + private_text, "runsc-start-failed"),
                  (private_text, "unknown")]
        with patch.object(m, "launch_record", autospec=True, return_value={"launch_id": launch_id, "command": private_text}):
            for message, category in errors:
                with self.subTest(category=category):
                    row = {"phase": "cold", "command_exit": 1}
                    output = (private_text + "\n\x1b[31msafeyolo: First-agent sandbox/harness startup failed: "
                              + message + ". Saved agent state is retained.\x1b[0m\n" + private_text).encode()
                    m.record_launch_result(row, output)
                    result = row["launch_result"]
                    self.assertEqual(result["error_category"], category)
                    self.assertEqual(result["failure_phase"], "sandbox-harness-start")
                    self.assertEqual(result["launch_id"], launch_id)
                    self.assertNotIn(private_text, json.dumps(result))
                    self.assertLess(len(json.dumps(result)), 700)
                    self.assertIn("monotonic", result)
            known_error = (b"safeyolo: First-agent sandbox/harness startup failed: "
                           b"coding-agent observation timed out. Saved agent state is retained.")
            for output, exit_code in [(b"coding-agent observation timed out", 1),
                (b"Unrecognized private failure", 1),
                (b"SY239_COMMAND_EXIT=1\n" + known_error, 1),
                (known_error, 0), (known_error, None)]:
                row = {"phase": "cold", "command_exit": exit_code}
                m.record_launch_result(row, output)
                self.assertEqual(row["launch_result"]["failure_phase"], "unknown")
                self.assertEqual(row["launch_result"]["error_category"], "unknown")

    def test_native_startup_failure_without_a_launch_is_saved_before_runtime_queries(self):
        private_text = "PRIVATE_NATIVE_STARTUP_DETAIL"
        message = ("Starting or resuming claude.\n"
                   "safeyolo: First-agent sandbox/harness startup failed: guest did not reach per-run startup. "
                   "Saved agent state is retained. " + private_text)
        stub = m.project / "native-startup.py"
        stub.write_text(f"print({message!r},flush=True);raise SystemExit(1)")
        def witness(*args, **kwargs):
            saved = json.loads(m.out.read_text())["product_commands"][-1]["launch_result"]
            self.assertEqual(saved["failure_phase"], "sandbox-harness-start")
            self.assertEqual(saved["error_category"], "guest-startup-unready")
            self.assertEqual(saved["identity_status"], "unavailable")
            self.assertIsNone(saved["launch_id"])
            self.assertNotIn(private_text, m.out.read_text())
            return {}
        with patch.object(m, "LAUNCH", [sys.executable, str(stub)]), \
             patch.object(m, "witness", autospec=True, side_effect=witness), \
             patch.dict(os.environ, {"PATH": str(m.cli.parent) + ":" + os.environ["PATH"]}):
            row, _ = m.entered("cold", 2)
        self.assertEqual(row["command_exit"], 1)
        self.assertEqual(row["discovery_exit"], 0)
        self.assertEqual(row["version_exit"], 0)

    def test_real_failed_launch_is_saved_before_witness_and_cleanup(self):
        launch_id = "launch-" + "b" * 32
        directory = m.root / "agents/first"
        directory.mkdir(parents=True)
        (directory / "current-launch.json").write_text(json.dumps({"launch_id": launch_id}))
        private_text = "PRIVATE_TERMINAL_STRING"
        message = ("Starting or resuming claude.\n" + private_text + "\n"
                   "safeyolo: First-agent sandbox/harness startup failed: coding-agent observation timed out. "
                   "Saved agent state is retained. " + private_text)
        stub = m.project / "failed-launch.py"
        stub.write_text(f"print({message!r},flush=True);raise SystemExit(1)")
        def witness(*args, **kwargs):
            saved = json.loads(m.out.read_text())["product_commands"][-1]["launch_result"]
            self.assertEqual(saved["failure_phase"], "sandbox-harness-start")
            self.assertEqual(saved["last_observed_phase"], "sandbox-harness-start")
            self.assertEqual(saved["error_category"], "coding-agent-observation-timeout")
            self.assertEqual(saved["launch_id"], launch_id)
            self.assertNotIn(private_text, m.out.read_text())
            return {}
        with patch.object(m, "LAUNCH", [sys.executable, str(stub)]), \
             patch.object(m, "witness", autospec=True, side_effect=witness), \
             patch.dict(os.environ, {"PATH": str(m.cli.parent) + ":" + os.environ["PATH"]}):
            row, _ = m.entered("cold", 2)
        self.assertEqual(row["command_exit"], 1)
        self.assertEqual(row["exit_code"], 1)
        self.assertEqual(row["discovery_exit"], 0)
        self.assertEqual(row["version_exit"], 0)
        self.assertNotIn("ordinary_q", row)
        self.assertNotIn("final_capture_error", row)

    def test_unreadable_launch_identity_does_not_export_private_error_or_skip_summary(self):
        row = {"phase": "cold"}
        with patch.object(m, "launch_record", autospec=True, side_effect=ValueError("PRIVATE_IDENTITY_ERROR")):
            m.record_launch_result(row, b"private terminal")
        self.assertEqual(row["launch_result"]["identity_status"], "unreadable")
        self.assertIsNone(row["launch_result"]["launch_id"])
        self.assertEqual(row["launch_result"]["error_category"], "unknown")
        self.assertNotIn("PRIVATE", m.out.read_text())
        with patch.object(m, "launch_record", autospec=True, return_value={"launch_id": "PRIVATE_INVALID_ID"}):
            m.record_launch_result(row, b"private terminal")
        self.assertEqual(row["launch_result"]["identity_status"], "unavailable")
        self.assertNotIn("PRIVATE", m.out.read_text())

    def test_split_multidigit_exit_marker_is_complete_before_saving_summary(self):
        stub = m.project / "exit127.py"
        stub.write_text("raise SystemExit(127)\n")
        read = os.read
        with patch.object(m, "LAUNCH", [sys.executable, str(stub)]), \
             patch.object(m, "witness", autospec=True, return_value={}), \
             patch.object(m.os, "read", autospec=True, side_effect=lambda fd, count: read(fd, min(count, 1))):
            row, _ = m.entered("cold", 10)
        self.assertEqual(row["launch_result"]["command_exit"], 127)
        self.assertEqual(row["command_exit"], 127)

    def test_complete_launch_result_is_saved_before_a_simultaneous_deadline(self):
        launch_id = "launch-" + "c" * 32
        directory = m.root / "agents/first"
        directory.mkdir(parents=True)
        (directory / "current-launch.json").write_text(json.dumps({"launch_id": launch_id}))
        private_text = "PRIVATE_DEADLINE_TERMINAL_CANARY"
        message = ("Starting or resuming claude.\n" + private_text + "\n"
                   "safeyolo: First-agent sandbox/harness startup failed: coding-agent observation timed out. "
                   "Saved agent state is retained.")
        stub = m.project / "deadline-exit127.py"
        stub.write_text(f"print({message!r},flush=True);raise SystemExit(127)\n")
        m.cli.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(0.3)\nprint('observer-test-version')\n")
        read, monotonic = os.read, time.monotonic
        received = b""
        marker_received = False
        saved_at_witness = []

        def terminal_read(fd, count):
            nonlocal received, marker_received
            chunk = read(fd, count)
            if os.isatty(fd):
                received += chunk
                marker_received = b"SY239_COMMAND_EXIT=127\r\n" in received
            return chunk

        def clock():
            return monotonic() + (20 if marker_received else 0)

        def witness(*args, **kwargs):
            saved_at_witness.append(json.loads(m.out.read_text())["product_commands"][-1].get("launch_result"))
            return {}

        with patch.object(m, "LAUNCH", [sys.executable, str(stub)]), \
             patch.object(m, "witness", autospec=True, side_effect=witness), \
             patch.object(m.os, "read", autospec=True, side_effect=terminal_read), \
             patch.object(m.time, "monotonic", autospec=True, side_effect=clock), \
             patch.dict(os.environ, {"PATH": str(m.cli.parent) + ":" + os.environ["PATH"]}):
            row, _ = m.entered("cold", 10)
        self.assertTrue(marker_received)
        self.assertEqual(saved_at_witness, [row["launch_result"]])
        self.assertEqual(row["command_exit"], 127)
        self.assertEqual(row["launch_result"]["command_exit"], 127)
        self.assertEqual(row["launch_result"]["failure_phase"], "sandbox-harness-start")
        self.assertEqual(row["launch_result"]["error_category"], "coding-agent-observation-timeout")
        self.assertEqual(row["launch_result"]["launch_id"], launch_id)
        self.assertEqual(row["exit_code"], 127)
        self.assertEqual(row["discovery_exit"], 0)
        self.assertEqual(row["discovery_stdout"], str(m.cli))
        self.assertEqual(row["version_exit"], 0)
        self.assertEqual(row["version_stdout"], "observer-test-version")
        self.assertTrue(row["console_reaped"])
        self.assertNotIn("observer_terminated_viewer", row)
        self.assertNotIn("viewer_detach", row)
        self.assertNotIn("readiness_unclassified_at_deadline", row)
        self.assertNotIn("final_capture_error", row)
        self.assertNotIn(private_text, m.out.read_text())
        self.assertIn(private_text, (m.private / "cold.terminal").read_text())

    def test_completed_launch_does_not_wait_forever_for_stalled_diagnostics(self):
        m.cli.write_text(f"#!{sys.executable}\nimport signal\nprint('version-stalled',flush=True)\nsignal.pause()\n")
        started = time.monotonic()
        with patch.object(m, "LAUNCH", [sys.executable, "-c", "raise SystemExit(127)"]), \
             patch.object(m, "witness", autospec=True, return_value={}), \
             patch.dict(os.environ, {"PATH": str(m.cli.parent) + ":" + os.environ["PATH"]}):
            row, _ = m.entered("cold", 0.1)
        self.assertLess(time.monotonic() - started, 6)
        self.assertEqual(row["command_exit"], 127)
        self.assertEqual(row["launch_result"]["command_exit"], 127)
        self.assertEqual(row["discovery_exit"], 0)
        self.assertIn("version-stalled", (m.private / "cold.terminal").read_text())
        self.assertNotIn("version_exit", row)
        self.assertNotIn("viewer_detach", row)
        self.assertIn("observer_terminated_viewer", row)
        self.assertEqual(row["exit_code"], -signal.SIGTERM)
        self.assertTrue(row["console_reaped"])
        self.assertTrue(row["console_group_shutdown"]["verified"])

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

    def test_console_cleanup_signals_while_output_is_continuously_ready(self):
        code = ("import os,signal\n"
                "signal.signal(signal.SIGTERM,lambda *_:os._exit(0))\n"
                "signal.signal(signal.SIGHUP,lambda *_:os._exit(0))\n"
                "while True:os.write(1,b'NOISY_PRIVATE_OUTPUT\\n'*32768)\n")
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.execv(sys.executable, [sys.executable, "-c", code])
            finally:
                os._exit(1)
        read = m.read_console
        reaped = False

        def slow_read(fd):
            chunk = read(fd)
            # Model a slow consumer without replacing the real PTY read.
            time.sleep(0.002)
            return chunk

        try:
            self.assertTrue(select.select([fd], [], [], 3)[0])
            row = {}
            with patch.object(m, "read_console", autospec=True, side_effect=slow_read):
                m.stop_console_group(pid, fd, row)
            self.assertTrue(row["console_group_shutdown"]["verified"])
            self.assertEqual(row["console_group_shutdown"]["remaining"], [])
            self.assertNotIn("sigkill", row["console_group_shutdown"])
            waited, status = os.waitpid(pid, os.WNOHANG)
            reaped = waited == pid
            self.assertTrue(reaped)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        finally:
            os.close(fd)
            if not reaped:
                # Closing this owned PTY sends HUP to the child's group.
                os.waitpid(pid, 0)

    def test_observer_intervention_stays_visible_on_zero_exit(self):
        self.check_finite_term_response(gapped=False)

    def test_observer_intervention_stays_visible_on_zero_exit_with_gapped_output(self):
        self.check_finite_term_response(gapped=True)

    def check_finite_term_response(self, gapped):
        private_text = "PRIVATE_SHUTDOWN_TERMINAL_CANARY"
        write = " while data:data=data[os.write(1,data):]\n"
        if gapped:
            write = (" while data:\n"
                     "  chunk,data=data[:4096],data[4096:]\n"
                     "  while chunk:chunk=chunk[os.write(1,chunk):]\n"
                     "  time.sleep(0.002)\n")
        code = ("import os,signal,time\n"
                "def stop(*_):\n"
                f" data=({private_text!r}+'\\n').encode()*4096\n"
                + write +
                " os._exit(0)\n"
                "signal.signal(signal.SIGTERM,stop)\n"
                "print('Sign in',flush=True)\n"
                "signal.pause()\n")
        stub = m.project / "shutdown.py"
        stub.write_text(code)
        group, read = m.console_group, os.read

        def slow_group(pid):
            members = group(pid)
            # Preserve real ownership scans, but make per-read scans too slow
            # to drain the finite TERM response before the existing deadline.
            time.sleep(0.05)
            return members

        with patch.object(m, "LAUNCH", ["exec", sys.executable, str(stub)]), \
             patch.object(m, "witness", autospec=True, side_effect=ValueError("capture failed")), \
             patch.object(m, "console_group", autospec=True, side_effect=slow_group), \
             patch.object(m.os, "read", autospec=True,
                          side_effect=lambda fd, count: read(fd, min(count, 1024))):
            with self.assertRaisesRegex(ValueError, "capture failed"):
                m.entered("warm", 2)
        row = m.x["product_commands"][-1]
        self.assertIn("observer_terminated_viewer", row)
        self.assertEqual(row["exit_code"], 0)
        self.assertTrue(row["console_reaped"])
        self.assertTrue(row["console_group_shutdown"]["verified"])
        self.assertNotIn("sigkill", row["console_group_shutdown"])
        self.assertNotIn(private_text, m.out.read_text())

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
