"""Focused executable checks for Cargo target retirement."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "retire_cargo_target.py"


def _commit() -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
    ).strip()


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    target = tmp_path / "target-623-parser"
    debug = target / "debug"
    debug.mkdir(parents=True)
    binary = debug / "candidate-proxy"
    binary.write_bytes(b"candidate binary\n")
    binary.chmod(0o755)
    receipt = tmp_path / "sol-receipt.md"
    commit = _commit()
    receipt.write_text(f"accepted candidate commit: {commit}\n")
    record = tmp_path / "retirements.jsonl"
    return target, receipt, record, commit


def _run(
    target: Path, receipt: Path, record: Path, commit: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--target",
            str(target),
            "--receipt",
            str(receipt),
            "--commit",
            commit,
            "--record",
            str(record),
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_external_target_retirement_preserves_receipt_hash_evidence(tmp_path: Path) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    receipt_hash = hashlib.sha256(receipt.read_bytes()).hexdigest()

    result = _run(target, receipt, record, commit)

    assert result.returncode == 0, result.stderr
    event = json.loads(result.stdout)
    assert event["candidate_commit"] == commit
    assert event["acceptance_receipt_sha256"] == receipt_hash
    assert event["top_level_debug_binaries"]["candidate-proxy"] == hashlib.sha256(
        b"candidate binary\n"
    ).hexdigest()
    assert record.read_text().splitlines() == [json.dumps(event, sort_keys=True)]
    assert receipt.read_bytes() == f"accepted candidate commit: {commit}\n".encode()
    assert not target.exists()


@pytest.mark.parametrize("nested_option", ["receipt", "record"])
def test_evidence_paths_inside_target_are_refused(
    tmp_path: Path, nested_option: str
) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    if nested_option == "receipt":
        receipt = target / "sol-receipt.md"
        receipt.write_text(f"accepted candidate commit: {commit}\n")
    else:
        record = target / "retirements.jsonl"

    result = _run(target, receipt, record, commit)

    assert result.returncode != 0
    assert f"--{nested_option} must be outside --target" in result.stderr
    assert target.is_dir()


def _start_owner(target: Path, owner_kind: str) -> subprocess.Popen[bytes]:
    environment = os.environ.copy()
    environment.pop("CARGO_TARGET_DIR", None)
    environment["PWD"] = "/"
    options: dict[str, object] = {"env": environment, "cwd": "/"}
    if owner_kind == "env":
        environment["CARGO_TARGET_DIR"] = str(target)
    elif owner_kind == "cwd":
        options["cwd"] = target
    else:
        held = target / "held-open"
        held.write_bytes(b"held")
        descriptor = os.open(held, os.O_RDONLY)
        options["pass_fds"] = (descriptor,)
    owner = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        **options,
    )
    if owner_kind == "open-fd":
        os.close(descriptor)
    return owner


@pytest.mark.parametrize("owner_kind", ["env", "cwd", "open-fd"])
def test_external_target_refuses_live_owner_without_path_in_argv_or_env(
    tmp_path: Path, owner_kind: str
) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    owner = _start_owner(target, owner_kind)
    try:
        deadline = time.monotonic() + 2
        while owner.poll() is None and time.monotonic() < deadline:
            result = _run(target, receipt, record, commit)
            if result.returncode != 0:
                break
            time.sleep(0.05)
        else:
            pytest.fail("live owner fixture did not remain running")

        assert result.returncode != 0
        assert f"target is still referenced by live process {owner.pid}" in result.stderr
        assert target.is_dir()
        assert not record.exists()
    finally:
        owner.terminate()
        owner.wait(timeout=5)
