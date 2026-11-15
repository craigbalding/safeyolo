#!/usr/bin/env python3
"""Check a retained native Linux storage receipt without replaying its commands.

Supply the source report, digest and candidate revision from the execution
owner's canonical result. This observes the recorded boundary; it neither
authenticates an arbitrary report author nor independently accepts BB-33.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

if __package__:
    from .execution_receipt import ROOT, read_json, save
    from .installed_linux_update import same_guest_base
else:
    from execution_receipt import ROOT, read_json, save
    from installed_linux_update import same_guest_base


STORAGE_ACTIONS = (
    "verify-host-package", "runsc-version", "host-filesystem", "subuids", "subgids",
    "native-download", "native-acquire", "mapped-root-acls", "install-acquired-assets",
    "create-agent", "start-proxy", "initial-start", "initial-mount-acls", "initial-uid-map",
    "initial-gid-map", "initial-backend", "initial-agent", "initial-root", "initial-stop",
    "restart-start", "restart-mount-acls", "restart-uid-map", "restart-gid-map",
    "restart-backend", "restart-agent", "restart-root", "restart-stop",
    "workspace-filesystem", "home-filesystem", "cleanup-agent", "cleanup-proxy", "cleanup-coord",
)
CASES = ("candidate-and-guest", "recorded-storage-actions", "repeat-cache-operands",
         "same-index-upgrade-operands", "guest-and-host-persistence", "host-sudo-unavailable", "owned-cleanup")
REMAINING = (
    "Full #1554 independent acceptance and BB-33 acceptance remain separate.",
    "Installation/repeat/upgrade commands are reported by the execution owner; the named actions cover storage only.",
    "Same-index cache reuse does not establish upgrade to changed guest bytes.",
    "This storage receipt does not establish distinct UID/GID bases, other identities or extended/special metadata.",
    "This storage receipt does not establish failure/cancellation or preservation of an existing usable installation.",
    "This storage receipt does not establish macOS production installation or deployed recurring cadence.",
)


def require(condition: bool, description: str) -> None:
    if not condition:
        raise ValueError(description)


def observe(source: dict, candidate: str, observed: list[str]) -> None:
    """Recompute the bounded obligations from the actual retained operands."""
    require(source["controller_source"] == source["package"]["source_commit"] == candidate,
            "candidate/controller revision mismatch")
    package, selection, settings = source["package"], source["selection"], source["linux_settings"]
    require(bool(package["profile"]), "package build profile missing")
    require(package["platform"] in {"linux-amd64", "linux-arm64"}
            and selection["platform"] == package["platform"].replace("-", "/", 1), "platform mismatch")
    require(selection["archive"] == {"digest": "sha256:" + source["archive"]["sha256"],
                                     "size": source["archive"]["bytes"]}, "archive mismatch")
    require(selection["repository"] == package["guest_repository"]
            and selection["compatibility"] == package["guest_compatibility"], "guest selection mismatch")
    require(source["uid"] == settings["host_uid"] != 0 and settings["host_gid"] != 0,
            "ordinary host identity missing")
    require(bool(settings["apparmor_profile"]), "prepared namespace authorization missing")
    require((source["mapped_root"]["uid"], source["mapped_root"]["gid"])
            == (settings["uid_base"], settings["gid_base"]), "root mapping mismatch")
    observed.append("candidate-and-guest")

    actions = source["actions"]
    require(tuple(row["label"] for row in actions) == STORAGE_ACTIONS, "missing/reordered storage actions")
    require(all(type(row["exit"]) is int and row["exit"] == 0 and row["command"]
                and row["ended"] >= row["started"] for row in actions), "failed/incomplete storage action")
    execution = source["guest_execution"]
    require(type(source["execution"]["execution"]) is int and source["execution"]["execution"] > 0,
            "native execution identity missing")
    require(type(execution["exit_code"]) is int and execution["exit_code"] == 0
            and all(execution[key] is False for key in ("timed_out", "stdout_truncated", "stderr_truncated")),
            "execution failed, timed out or truncated")
    observed.append("recorded-storage-actions")

    operands = [row for row in source["cache_operands"] if "before" in row]
    require([row["phase"] for row in operands] == ["repeat", "explicit-cached-upgrade"], "missing cache operands")
    for row, case in zip(operands, CASES[2:4]):
        before, after = row["before"], row["after"]
        require(before["selection"] == after["selection"], "cache operation changed selection")
        require(all(before["selection"][key] == selection[key] for key in ("index", "manifest", "archive")),
                "cache operands belong to another guest")
        require(same_guest_base(before["guest_inputs"], after["guest_inputs"]), "guest base/cache inode changed")
        observed.append(case)

    initial, restart = source["initial-host-files"], source["restart-host-files"]
    require(set(initial) == {"home-agent", "home-root", "workspace-agent", "workspace-root"}
            and initial == restart, "host persistent file identity changed or missing")
    for name, row in initial.items():
        expected = (settings["uid_base"], settings["gid_base"]) if name.endswith("root") else (
            settings["host_uid"], settings["host_gid"])
        require((row["uid"], row["gid"]) == expected and row["mode"] == 0o644, "host persistent owner/mode mismatch")
    initial_files = {**source["initial-agent"]["files"], **source["initial-root"]["files"]}
    require(len(initial_files) == 4, "initial guest files are not distinct")
    for phase in ("initial", "restart"):
        for user, uid in (("agent", 1000), ("root", 0)):
            row = source[phase + "-" + user]
            require(row["uid"] == uid and row["overlay_present"] is (phase == "initial" and user == "root"),
                    "guest identity/overlay mismatch")
            expected_names = set(initial) if phase == "restart" else {name for name in initial if name.endswith(user)}
            files = row["files"]
            require(isinstance(files, dict) and len(files) == len(expected_names), "missing guest persistent files")
            require(phase == "initial" or files == initial_files, "guest persistent paths/metadata changed")
            for name in expected_names:
                matching = [value for path, value in files.items()
                            if path.startswith("/home/agent/" if name.startswith("home") else "/workspace/")
                            and path.endswith("-" + name.split("-", 1)[1])]
                owner = 0 if name.endswith("root") else 1000
                require(matching == [{"uid": owner, "gid": owner, "mode": 0o644}], "guest persistent owner/mode mismatch")
    observed.append("guest-and-host-persistence")
    require(source["operator_setup"]["post_prepare_sudo_attempts_successful_run"] is False,
            "host sudo was attempted or not observed")
    observed.append("host-sudo-unavailable")
    require(source["result"] == "storage_passed" and source["cleanup_failures"] == [], "storage/cleanup failed")
    observed.append("owned-cleanup")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-report", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--install-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", default=os.environ.get("SAFEYOLO_BLACKBOX_RUN_ID"), required=False)
    args = parser.parse_args()
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    # Resolving paths does not detect a hard link at the writer's temporary path.
    if args.source_report.resolve() in {args.output.resolve(), temporary.resolve()} or (
        args.source_report.exists() and temporary.exists() and temporary.samefile(args.source_report)
    ):
        parser.error("output would overwrite source evidence")
    report = {"phase": "rootless-preparation", "boundary": "retained-native-linux-storage",
              "run_id": args.run_id, "source_report": str(args.source_report), "source_sha256": args.source_sha256,
              "candidate": args.install_commit, "selected": list(CASES), "observed": [],
              "complete": False, "control_complete": False, "remaining": list(REMAINING),
              "controller_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "working_tree_changed": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))}
    try:
        source = read_json(args.source_report, sha256=args.source_sha256)
        # Keep original platform, prerequisite and execution facts attributed to
        # their producer. Local observation time is not another native run.
        report["source_observation"] = source
        observe(source, args.install_commit, report["observed"])
        report["complete"] = report["observed"] == report["selected"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        report["observer_error"] = f"{type(error).__name__}: {error}"
    save(args.output, report)
    print(f"{'Complete' if report['complete'] else 'Incomplete'} retained Linux witness; BB-33 incomplete: {args.output}")
    return 0 if report["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
