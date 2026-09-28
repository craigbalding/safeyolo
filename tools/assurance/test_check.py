"""Fixed controls for the real Semgrep extraction and trusted comparison path."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from check import AnalysisError, analyze, changed_controls, compare

ROOT = Path(__file__).resolve().parents[2]
SEMGREP = ROOT / "tools/acceptance/.venv/bin/semgrep"
BASE_RUST = """fn authorize(allowed: bool) -> bool {
    if allowed { true } else { false }
}

fn dial() {
    TcpStream::connect("example.test:443");
}
"""
MAP = """[[decisions]]
id = "request"
inputs = "Agent request"
authority = "Operator policy"
checks = "Authorize before dial"
effects = "Origin connection"
failure = "Deny locally"
tests = ["tools/assurance/test_check.py"]
symbols = ["proxy/src/lib.rs::authorize", "cli/src/safeyolo/launcher.py::launch"]
"""


class DriftControls(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="assurance-test-", dir=Path.home() / ".cache")
        self.addCleanup(self.temp.cleanup)
        directory = Path(self.temp.name)
        self.trusted = directory / "trusted"
        self.candidate = directory / "candidate"
        self.write(self.trusted, "proxy/src/lib.rs", BASE_RUST)
        self.write(self.trusted, "cli/src/safeyolo/launcher.py", "def launch():\n    return True\n")
        self.write(self.trusted, "proxy/Cargo.toml", "[package]\nname = 'example'\n")
        self.write(self.trusted, "docs/assurance-map.toml", MAP)
        self.write(self.trusted, "tools/assurance/check.py", "trusted checker\n")
        self.write(self.trusted, ".github/workflows/proxy-assurance.yml", "trusted workflow\n")
        self.write(self.trusted, ".github/CODEOWNERS", "trusted owners\n")
        self.write(self.trusted, "tools/acceptance/uv.lock", "trusted tool lock\n")
        destination = self.trusted / "tools/assurance/rules.yml"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "tools/assurance/rules.yml", destination)
        self.environment = patch.dict(os.environ, {"SAFEYOLO_ASSURANCE_SEMGREP": str(SEMGREP)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        accepted = analyze(self.trusted, self.trusted)
        self.write(self.trusted, "tools/assurance/accepted.json", json.dumps(accepted))
        shutil.copytree(self.trusted, self.candidate)
        self.accepted = accepted

    @staticmethod
    def write(root: Path, name: str, value: str) -> None:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def report(self) -> dict:
        current = analyze(self.trusted, self.candidate)
        return compare(self.accepted, current, changed_controls(self.trusted, self.candidate))

    def test_clean_and_benign_code(self) -> None:
        self.assertEqual(self.report()["status"], "clean")
        self.write(self.candidate, "proxy/src/lib.rs", BASE_RUST + "\nfn harmless() { let value = 1; }\n")
        self.assertEqual(self.report()["status"], "clean")

    def test_new_sink_in_helper_and_nosem_suppression(self) -> None:
        self.write(self.candidate, "proxy/src/lib.rs", BASE_RUST + "\nfn helper() { TcpStream::connect(\"other.test:443\"); // nosemgrep\n}\n")
        report = self.report()
        self.assertEqual(report["status"], "drift")
        self.assertTrue(any(item["rule"] == "rust-network" and item["symbol"] == "helper" for item in report["operations_added"]))

    def test_qualified_rust_operations_in_new_helpers(self) -> None:
        calls = {
            "plain_tcp": ("rust-network", 'TcpStream::connect("example.test:443")'),
            "std_tcp": ("rust-network", 'std::net::TcpStream::connect("example.test:443")'),
            "tokio_tcp": ("rust-network", 'tokio::net::TcpStream::connect("example.test:443")'),
            "std_unix": ("rust-network", 'std::os::unix::net::UnixStream::connect("/tmp/example.sock")'),
            "tokio_unix": ("rust-network", 'tokio::net::UnixStream::connect("/tmp/example.sock")'),
            "std_tcp_listener": ("rust-network", 'std::net::TcpListener::bind("127.0.0.1:0")'),
            "tokio_tcp_listener": ("rust-network", 'tokio::net::TcpListener::bind("127.0.0.1:0")'),
            "std_unix_listener": ("rust-network", 'std::os::unix::net::UnixListener::bind("/tmp/example.sock")'),
            "tokio_unix_listener": ("rust-network", 'tokio::net::UnixListener::bind("/tmp/example.sock")'),
            "tokio_dns": ("rust-network", 'tokio::net::lookup_host("example.test:443")'),
            "std_create": ("rust-file", 'std::fs::File::create("/tmp/example")'),
            "tokio_create": ("rust-file", 'tokio::fs::File::create("/tmp/example")'),
            "std_open": ("rust-file", 'std::fs::File::open("/tmp/example")'),
            "tokio_open": ("rust-file", 'tokio::fs::File::open("/tmp/example")'),
            "std_options": ("rust-file", "std::fs::OpenOptions::new()"),
            "tokio_options": ("rust-file", "tokio::fs::OpenOptions::new()"),
            "tokio_read": ("rust-file", 'tokio::fs::read("/tmp/example")'),
            "std_command": ("rust-process-ffi", 'std::process::Command::new("example")'),
            "tokio_command": ("rust-process-ffi", 'tokio::process::Command::new("example")'),
        }
        helpers = "\n".join(f"fn {name}() {{ {call}; }}" for name, (_, call) in calls.items())
        self.write(self.candidate, "proxy/src/lib.rs", BASE_RUST + "\n" + helpers + "\n")
        result = Path(self.temp.name) / "qualified.json"
        command = ["python3", "-I", str(ROOT / "tools/assurance/check.py"), "check",
                   "--trusted-root", str(self.trusted), "--candidate", str(self.candidate),
                   "--json", str(result)]
        run = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(result.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "drift")
        self.assertEqual(
            {(rule, name) for name, (rule, _) in calls.items()},
            {(item["rule"], item["symbol"]) for item in report["operations_added"]},
        )

    def test_changed_authorization_with_existing_sink(self) -> None:
        self.write(self.candidate, "proxy/src/lib.rs", BASE_RUST.replace("if allowed", "if !allowed"))
        report = self.report()
        self.assertEqual(report["status"], "drift")
        self.assertIn("proxy/src/lib.rs::authorize", report["mapped_decisions_changed"])
        self.assertEqual(report["operations_added"], [])

    def test_moved_and_deleted_mapped_code(self) -> None:
        self.write(self.candidate, "proxy/src/lib.rs", BASE_RUST.replace("fn authorize(allowed: bool) -> bool {\n    if allowed { true } else { false }\n}\n\n", ""))
        self.write(self.candidate, "proxy/src/new_policy.rs", "fn authorize(allowed: bool) -> bool { allowed }\n")
        report = self.report()
        self.assertEqual(report["status"], "drift")
        self.assertIn("proxy/src/lib.rs::authorize", report["stale_symbols"])
        self.assertIn("proxy/src/new_policy.rs", report["source_files_added"])

    def test_moved_sensitive_operation(self) -> None:
        self.write(self.candidate, "proxy/src/lib.rs", BASE_RUST.replace(
            "fn dial() {\n    TcpStream::connect(\"example.test:443\");\n}\n", ""))
        self.write(self.candidate, "proxy/src/new_dial.rs", "fn new_dial() { TcpStream::connect(\"example.test:443\"); }\n")
        report = self.report()
        self.assertEqual(report["status"], "drift")
        self.assertTrue(any(item["from"]["symbol"] == "dial" and item["to"]["symbol"] == "new_dial"
                            for item in report["operations_moved"]))

    def test_relevant_feature_change(self) -> None:
        self.write(self.candidate, "proxy/Cargo.toml", "[package]\nname = 'example'\n[features]\nbypass = []\n")
        report = self.report()
        self.assertEqual(report["status"], "drift")
        self.assertIn("proxy/Cargo.toml", report["input_changes"])

    def test_new_build_script_is_input_change(self) -> None:
        self.write(self.candidate, "proxy/build.rs", "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n")
        report = self.report()
        self.assertEqual(report["status"], "drift")
        self.assertIn("proxy/build.rs", report["input_changes"])

    def test_candidate_control_edit_cannot_accept_its_sink(self) -> None:
        self.write(self.candidate, "proxy/src/lib.rs", BASE_RUST + "\nfn helper() { TcpStream::connect(\"other.test:443\"); }\n")
        self.write(self.candidate, "tools/assurance/rules.yml", "rules: []\n")
        self.write(self.candidate, "tools/assurance/check.py", "def check(): return 'clean'\n")
        self.write(self.candidate, "tools/assurance/accepted.json", "{}\n")
        self.write(self.candidate, ".github/workflows/proxy-assurance.yml", "name: suppressed\n")
        self.write(self.candidate, ".semgrepignore", "proxy/src/**\n")
        report = self.report()
        self.assertEqual(report["status"], "drift")
        self.assertIn("tools/assurance/rules.yml", report["control_changes"])
        self.assertIn("tools/assurance/check.py", report["control_changes"])
        self.assertIn("tools/assurance/accepted.json", report["control_changes"])
        self.assertIn(".github/workflows/proxy-assurance.yml", report["control_changes"])
        self.assertIn(".semgrepignore", report["control_changes"])
        self.assertTrue(report["operations_added"])

    def test_legitimate_trusted_snapshot_evolution(self) -> None:
        self.write(self.candidate, "proxy/src/lib.rs", BASE_RUST.replace("if allowed", "if !allowed"))
        self.assertEqual(self.report()["status"], "drift")
        approved = analyze(self.trusted, self.candidate)
        self.write(self.trusted, "tools/assurance/accepted.json", json.dumps(approved))
        # The candidate incorporates the operator-controlled baseline update.
        self.write(self.candidate, "tools/assurance/accepted.json", json.dumps(approved))
        self.accepted = approved
        self.assertEqual(self.report()["status"], "clean")

    def test_missing_analysis_fails_visibly(self) -> None:
        with patch.dict(os.environ, {"SAFEYOLO_ASSURANCE_SEMGREP": "/absent/semgrep"}):
            with self.assertRaisesRegex(AnalysisError, "missing Semgrep executable"):
                analyze(self.trusted, self.candidate)
            result = Path(self.temp.name) / "missing.json"
            command = ["python3", "-I", str(ROOT / "tools/assurance/check.py"), "check",
                       "--trusted-root", str(self.trusted), "--candidate", str(self.candidate),
                       "--json", str(result)]
            run = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(result.read_text(encoding="utf-8"))["status"], "error")


if __name__ == "__main__":
    unittest.main()
