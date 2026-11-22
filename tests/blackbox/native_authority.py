#!/usr/bin/env python3
"""Run curated native authority tests with the existing procedure receipts.

On Linux, first build the current native_coord Cargo test and its native CLI,
proxy and Coord executables. Set SAFEYOLO_COORD_NATS_BINARY to the pinned NATS
binary. Supply the test executable and a new disk-backed output directory.
Each selected test creates and cleans up its own instances and real brokers.
These process tests do not establish a real-guest or two-host tailnet result.

For --suite host-execution on Linux/macOS, supply the built unix_native fixture
and a separately installed --executor. Set SAFEYOLO_HOST_EXECUTOR_PROBE to the
probe built from host-executor/tests/native_fixture.c and
SAFEYOLO_HOST_EXECUTOR_SERVICE to an owned prepared user service. Linux also
needs SAFEYOLO_HOST_EXECUTOR_CGROUP and the existing native runtime prerequisites.
The fixture creates disposable state and controls that service. Missing inputs
fail the attempt. This selection does not establish Windows or gateway workflows.
"""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import uuid
from pathlib import Path

from tests.blackbox.execution_receipt import ProcedureReceipt, controller_identity, save
from tests.blackbox.installed_host_smoke import _sha256
from tests.blackbox.selections import HOST_EXECUTION_AUTHORITY, NATIVE_AUTHORITY


def run(executable: Path, output: Path, *, suite="coord", executor: Path | None = None) -> None:
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    run_id = os.environ.get("SAFEYOLO_BLACKBOX_RUN_ID") or uuid.uuid4().hex
    selected_controls = HOST_EXECUTION_AUTHORITY if suite == "host-execution" else NATIVE_AUTHORITY
    boundary = ("installed Unix host executor; authenticated local HTTP and independent host observers"
                if suite == "host-execution" else "native processes and real NATS; no guest")
    summary = {"run_id": run_id, "suite": suite, "boundary": boundary,
               "controller": controller_identity(),
               "host": {"platform": platform.platform(), "machine": platform.machine(),
                        "uid": os.getuid(), "gid": os.getgid()}, "complete": False,
               "controls": {control: {"selected": list(cases), "executed": [], "complete": False}
                            for control, cases in selected_controls.items()}}
    save(output / "result.json", summary)
    try:
        executable = executable.resolve(strict=True)
        inputs = {"test_executable": {"path": str(executable), "sha256": _sha256(executable)}}
        if suite == "host-execution":
            if executor is None:
                raise ValueError("host-execution requires the installed --executor")
            executor = executor.resolve(strict=True)
            probe = Path(os.environ["SAFEYOLO_HOST_EXECUTOR_PROBE"]).resolve(strict=True)
            if not os.environ.get("SAFEYOLO_HOST_EXECUTOR_SERVICE"):
                raise ValueError("set SAFEYOLO_HOST_EXECUTOR_SERVICE to the prepared owned service")
            if os.uname().sysname == "Linux" and not os.environ.get("SAFEYOLO_HOST_EXECUTOR_CGROUP"):
                raise ValueError("set SAFEYOLO_HOST_EXECUTOR_CGROUP to the delegated cgroup subtree")
            if os.uname().sysname == "Linux":
                bubblewrap = Path(os.environ.get("SAFEYOLO_HOST_EXECUTOR_BWRAP", "/usr/bin/bwrap")).resolve(strict=True)
                inputs["bubblewrap"] = {"path": str(bubblewrap), "sha256": _sha256(bubblewrap)}
            version = subprocess.run([str(executor), "--version"], capture_output=True, text=True,
                                     check=True, timeout=10).stdout.strip()
            inputs.update(executor={"path": str(executor), "sha256": _sha256(executor), "version": version},
                          probe={"path": str(probe), "sha256": _sha256(probe)},
                          service=os.environ["SAFEYOLO_HOST_EXECUTOR_SERVICE"],
                          cgroup=os.environ.get("SAFEYOLO_HOST_EXECUTOR_CGROUP"))
        else:
            broker = Path(os.environ["SAFEYOLO_COORD_NATS_BINARY"]).resolve(strict=True)
            inputs["nats"] = {"path": str(broker), "sha256": _sha256(broker)}
    except (OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        summary["prerequisite_error"] = str(error)
        save(output / "result.json", summary)
        raise
    summary["inputs"] = inputs
    save(output / "result.json", summary)
    env = os.environ | {"TMPDIR": str(output.resolve()), "SAFEYOLO_BLACKBOX_RUN_ID": run_id,
                        "SAFEYOLO_BLACKBOX_LANE": "native-process"}
    # Match coord_test_runner.sh: these cases own their brokers and state.
    env.pop("SAFEYOLO_COORD_DATA_DIR", None)
    env.pop("SAFEYOLO_NATS_TEST_INSTANCE", None)
    if executor is not None:
        env["SAFEYOLO_HOST_EXECUTOR_BIN"] = str(executor)
    failures = []
    for control, selected in selected_controls.items():
        directory = output / control
        directory.mkdir()
        receipt = ProcedureReceipt("native-authority", directory / "result.json")
        receipt.document.update(run_id=run_id, lane="native-process")
        save(receipt.path, receipt.document)
        report = {"control": control, "run_id": run_id, "controller": summary["controller"],
                  "boundary": summary["boundary"],
                  **inputs,
                  "selected": list(selected), "executed": [], "complete": False}
        save(directory / "result.json", report)
        summary["controls"][control] = report
        save(output / "result.json", summary)
        for case in selected:
            row = {"case": case, "passed": False, "exit": None}
            execution_started = False
            try:
                inventory = subprocess.run([str(executable), case, "--exact", "--ignored", "--list"],
                                           capture_output=True, text=True, env=env, check=True, timeout=30)
                if inventory.stdout.splitlines().count(case + ": test") != 1:
                    raise ValueError("missing exact native case")
                log = directory / (case.replace("::", "-") + ".log")
                execution_started = True
                with log.open("w") as diagnostics:
                    command = [str(executable), case, "--exact", "--ignored", "--test-threads=1"]
                    if suite == "host-execution":
                        command.append("--nocapture")
                    result = subprocess.run(command,
                                            stdout=diagnostics, stderr=subprocess.STDOUT, env=env, timeout=300)
                row.update(exit=result.returncode,
                           passed=result.returncode == 0 and f"test {case} ... ok" in log.read_text())
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                row["error"] = type(error).__name__ + ": " + str(error)
                if execution_started and isinstance(error, subprocess.TimeoutExpired):
                    row["cleanup"] = "unverified after test timeout; remaining cases did not run"
            report["executed"].append(row)
            save(directory / "result.json", report)
            save(output / "result.json", summary)
            if row.get("cleanup"):
                raise RuntimeError("native test timed out; inspect owned fixture processes before continuing")
            if not row["passed"]:
                failures.append(case)
        if all(row["passed"] for row in report["executed"]):
            receipt.checkpoint('selected-cases')
            report["complete"] = True
            save(directory / "result.json", report)
            receipt.checkpoint('finished')
        save(output / "result.json", summary)
    summary["complete"] = not failures
    save(output / "result.json", summary)
    assert not failures, "native authority failures; inspect retained per-control receipts: " + ", ".join(failures)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-executable", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--suite", choices=("coord", "host-execution"), default="coord")
    parser.add_argument("--executor", type=Path, help="installed host executor for --suite host-execution")
    args = parser.parse_args()
    run(args.test_executable, args.output, suite=args.suite, executor=args.executor)


if __name__ == "__main__":
    main()
