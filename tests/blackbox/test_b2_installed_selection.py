"""Focused source-selection controls for the post-deletion Linux pilot."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.blackbox.kvm_p1_ingress import installed_identity

ROOT = Path(__file__).resolve().parents[2]
FROZEN_R = "2faba3306de7c099e2913e0eebc8907ff3eba148"
POST_DELETION = "d680ef82e4cdd9f1b725a421bccf8496123fd55a"


@pytest.mark.parametrize("selected", [FROZEN_R, POST_DELETION[:12]])
@pytest.mark.skipif(sys.platform != "linux", reason="the selected B2 host is Linux")
def test_b2_linux_rejects_frozen_or_ambiguous_source_before_install(selected):
    result = subprocess.run(
        [str(ROOT / "tests/blackbox/run-b2-linux.sh"), selected],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "B2 Linux pilot: installed source" not in result.stdout
    assert ("does not contain the reviewed post-deletion B1 head" if selected == FROZEN_R else "Usage:") in result.stderr


def test_selected_installed_identity_requires_exact_wheel_stamp_and_binary(tmp_path):
    revision = POST_DELETION
    checkout = tmp_path / "source"
    built = checkout / "proxy/target/release/safeyolo-proxy"
    built.parent.mkdir(parents=True)
    built.write_bytes(b"selected-native-binary")

    package = tmp_path / "tool/safeyolo"
    packaged = package / "bin/safeyolo-proxy"
    packaged.parent.mkdir(parents=True)
    packaged.write_bytes(built.read_bytes())
    (package / "_build_identity.json").write_text(json.dumps({"source_revision": revision, "state": "known"}))
    cli = tmp_path / "tool/bin/safeyolo"
    cli.parent.mkdir(parents=True)
    diagnostic = {
        "checks": [
            {
                "name": "Runtime identity",
                "status": "pass",
                "message": f"Running {packaged.resolve()}",
                "detail": "PID 4242",
            }
        ],
    }
    cli.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"if sys.argv[1] == 'doctor': print({json.dumps(json.dumps(diagnostic))})\n"
        "else: print('native running 4242')\n"
    )
    cli.chmod(0o755)
    runtime = {
        "status": "attached_ready",
        "cli": {"path": str(cli), "package_location": str(package / "__init__.py")},
        "candidate": {"path": str(packaged), "sha256": hashlib.sha256(built.read_bytes()).hexdigest()},
        "runtime": {
            "status": "ready",
            "pid": 4242,
            "actual_executable": str(packaged),
            "authenticated_runtime_identity": {"status": "authenticated"},
        },
        "native": {},
    }

    selected = installed_identity(runtime, checkout, expected_revision=revision)
    assert selected["build_identity"]["source_revision"] == revision
    assert selected["cli_diagnostics"]["detail"] == "PID 4242"
    with pytest.raises(AssertionError, match="selected source build identity"):
        installed_identity(runtime, checkout, expected_revision=FROZEN_R)
    wrong_diagnostic = {"checks": [{**diagnostic["checks"][0], "message": "Running /wrong/proxy"}]}
    cli.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"if sys.argv[1] == 'doctor': print({json.dumps(json.dumps(wrong_diagnostic))})\n"
        "else: print('native running 4242')\n"
    )
    with pytest.raises(AssertionError):
        installed_identity(runtime, checkout, expected_revision=revision)


def test_install_commit_option_needs_an_installed_pilot(tmp_path):
    result = subprocess.run(
        [str(ROOT / "tests/blackbox/run-tests.sh"), "--install-commit", POST_DELETION],
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(tmp_path),
            "SAFEYOLO_TEST_CONFIG_DIR": str(tmp_path / "test-instance"),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "requires a P2, P3, or P4 installed selection" in result.stderr
    assert not (tmp_path / "test-instance").exists()
