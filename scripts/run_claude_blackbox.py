#!/usr/bin/env python3
"""Run the trusted installed Claude check on an operator-owned Ubuntu host.

Invoke through the existing Rundeck run/script and ssh_exec.sh boundary. The
operator supplies a provisioning executable; no provider secret is an argument
or a report field. This entry does not install a schedule or approve requests.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    from tests.blackbox.retained_inputs import controller_identity
else:
    from tests.blackbox.retained_inputs import controller_identity


def read_json(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("report must contain a JSON mapping")
    return value


def select_inputs(args: argparse.Namespace, attempt: Path, log) -> Path:
    inputs = attempt / "inputs"
    selection_command = [ROOT / ".venv/bin/python", ROOT / "scripts/select_blackbox_artifacts.py",
                         "--platform", "linux-amd64", "--output", inputs]
    if args.host_run is not None:
        selection_command += ["--host-run", str(args.host_run)]
    if args.guest_index is not None:
        selection_command += ["--guest-index", args.guest_index]
    subprocess.run([str(value) for value in selection_command], cwd=ROOT, stdout=log,
                   stderr=subprocess.STDOUT, check=True)
    selection = read_json(inputs / "selection.json")
    if args.ref != "refs/heads/" + selection["default_branch"]:
        raise ValueError("invocation must use the repository default branch")
    if args.source_revision and selection["host"]["source_revision"] != args.source_revision:
        raise ValueError("selected production package does not match the requested source revision")
    return inputs / "selection.json"


def collect_reports(report: dict, attempt: Path) -> None:
    """Return maintained nonsecret reports, keeping raw diagnostics private."""
    for name, path in (("selection", "inputs/selection.json"),
                       ("readiness", "readiness/retained-run.json"),
                       ("installed", "readiness/installed-inputs.json"),
                       ("smoke", "smoke/guest/claude/claude-smoke.json"),
                       ("cleanup", "smoke/guest/installed-sections.json")):
        if (attempt / path).is_file():
            try:
                report[name] = read_json(attempt / path)
            except (OSError, ValueError) as exc:
                report.setdefault("report_failures", {})[name] = type(exc).__name__
    if report["exit"] == 0 and (any(name not in report for name in ("selection", "readiness", "installed", "smoke", "cleanup"))
                               or report["smoke"].get("status") != "passed"
                               or report["smoke"].get("exit") != 0
                               or report["smoke"].get("cleanup") != "stopped"):
        report.update(exit=2, stage="report-return", failure="maintained success and cleanup reports are unavailable")


def run(args: argparse.Namespace) -> dict:
    """Select, check without credentials, provision, then admit one smoke."""
    attempt = args.output.resolve()
    attempt.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = {"trigger": args.trigger, "ref": args.ref, "requested_revision": args.source_revision,
              "started_at": datetime.now(UTC).isoformat(), "stage": "admission", "exit": 2,
              "selection_mode": "exact" if args.host_run is not None or args.guest_index is not None else "newest-completed",
              **controller_identity()}
    python = ROOT / ".venv/bin/python"
    readiness = attempt / "readiness"
    smoke = attempt / "smoke"

    try:
        if args.trigger not in {"nightly", "manual", "merge"}:
            raise ValueError("only trusted nightly, manual and default-branch merge invocations are supported")
        if args.trigger == "merge" and not re.fullmatch(r"[0-9a-f]{40}", args.source_revision or ""):
            raise ValueError("merge requires the full merged source revision")
        if not args.credential:
            raise ValueError("host credential name is required")
        if report["controller_dirty"] or not report["controller_revision"]:
            raise ValueError("requires a clean pinned trusted controller")
        with (attempt / "private.log").open("xb") as log:
            report["stage"] = "selection"
            selection = select_inputs(args, attempt, log)
            report["stage"] = "credential-free-installed"
            subprocess.run([str(python), str(ROOT / "tests/blackbox/retained_inputs.py"), "run",
                            "--lane", "systrap", "--yes", "--selection", str(selection),
                            "--artifacts", str(readiness)], cwd=ROOT, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
            if read_json(readiness / "retained-run.json")["exit"] != 0:
                raise ValueError("credential-free installed readiness did not pass")
            prepared = Path(read_json(readiness / "guest/installed-sections.json")["preparation"]["config_dir"])
            report["stage"] = "host-service-binding"
            # The trusted operator helper consumes its existing sealed access-only
            # provisioning route. Renewal ownership stays in the host vault.
            # Provisioner output can contain authentication material. Retain
            # only its exit, never its stdout/stderr, even in the private log.
            subprocess.run([str(args.provision), str(prepared), args.credential], cwd=ROOT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            report["stage"] = "claude"
            environment = dict(os.environ, SAFEYOLO_CLAUDE_SMOKE_CREDENTIAL=args.credential)
            subprocess.run([str(python), str(ROOT / "tests/blackbox/retained_inputs.py"), "run",
                            "--lane", "systrap", "--selection", str(selection),
                            "--prepared-config", str(prepared), "--section", "claude",
                            "--artifacts", str(smoke)], cwd=ROOT, env=environment, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
            report["stage"] = "complete"
            report["exit"] = 0
    except subprocess.CalledProcessError as exc:
        report["exit"] = exc.returncode if exc.returncode >= 0 else 128 - exc.returncode
        report["failure"] = "command failed"
    except (OSError, ValueError, KeyError, TypeError) as exc:
        report["failure"] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    finally:
        collect_reports(report, attempt)
        report["finished_at"] = datetime.now(UTC).isoformat()
        (attempt / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trigger", choices=("nightly", "manual", "merge"))
    parser.add_argument("--ref", required=True, help="Trusted trigger ref; must be the repository default branch")
    parser.add_argument("--source-revision", help="Full source SHA; required for a merge invocation")
    parser.add_argument("--host-run", type=int, help="Exact default-branch production run")
    parser.add_argument("--guest-index", help="Exact completed staged index, sha256:DIGEST")
    parser.add_argument("--provision", type=Path, required=True,
                        help="Trusted executable: PROGRAM INSTALLED_ROOT CREDENTIAL_NAME; host secrets stay private")
    parser.add_argument("--credential", required=True, help="Host credential name created by the provisioner")
    parser.add_argument("--output", type=Path, required=True, help="New private attempt directory on disk")
    args = parser.parse_args()
    args.provision = args.provision.resolve()
    os.umask(0o077)
    try:
        report = run(args)
    except OSError as exc:
        parser.exit(2, f"Trusted Claude invocation failed: {type(exc).__name__}\n")
    print(json.dumps(report))
    return report["exit"]


if __name__ == "__main__":
    raise SystemExit(main())
