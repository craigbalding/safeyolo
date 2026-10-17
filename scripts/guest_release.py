#!/usr/bin/env python3
"""Record verified guest staging and promote the same bytes after quarantine."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from . import select_blackbox_artifacts as selection
else:
    import select_blackbox_artifacts as selection

STAGING = selection.STAGING_TYPE
SMOKE = "application/vnd.safeyolo.guest.smoke.v1+json"
DECISION = "application/vnd.safeyolo.guest.promotion.v1+json"
JSON = "application/json"
QUARANTINE_SECONDS = 172800


def stamp() -> str:
    return datetime.now(UTC).isoformat()


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def command(*args: str) -> str:
    return selection.capture(*args).decode().strip()


def branch() -> str:
    return json.loads(command("gh", "api", f"repos/{selection.REPOSITORY}"))["default_branch"]


def producer(job_key: str, original_attempt: int | None = None) -> dict:
    run_id = int(os.environ["GITHUB_RUN_ID"])
    attempt = original_attempt if original_attempt is not None else int(os.environ["GITHUB_RUN_ATTEMPT"])
    jobs = selection.pages(f"actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100", "jobs")
    matches = [job for job in jobs if job["name"] == job_key]
    if len(matches) != 1:
        raise ValueError("staging producer job is unavailable or ambiguous")
    return {"repository": selection.REPOSITORY, "workflow": selection.GUEST_WORKFLOW,
            "run_id": run_id, "run_attempt": attempt, "job_id": matches[0]["id"]}


def attach(index: dict, kind: str, document: dict, files: list[Path] | None = None) -> None:
    """Use OCI referrers; read every attached byte back before reporting success."""
    reference = f"{selection.GUEST_REPOSITORY}@{index['digest']}"
    with tempfile.TemporaryDirectory(prefix="safeyolo-receipt-") as temporary:
        receipt = Path(temporary) / "receipt.json"
        write(receipt, document)
        arguments = ["oras", "attach", "--format", "json", "--artifact-type", kind, reference,
                     f"receipt.json:{kind}"]
        for number, path in enumerate(files or []):
            name = f"{number}-{path.name}"
            (Path(temporary) / name).symlink_to(path.resolve())
            arguments.append(f"{name}:{JSON if path.suffix == '.json' else 'application/octet-stream'}")
        result = json.loads(subprocess.check_output(arguments, cwd=temporary, timeout=1800))
        descriptor, value = selection.manifest(f"{selection.GUEST_REPOSITORY}@{result['digest']}")
        if value["artifactType"] != kind or value["subject"] != index:
            # ORAS subjects contain the three descriptor fields only.
            if any(value["subject"].get(key) != index[key] for key in ("digest", "size", "mediaType")):
                raise ValueError("uploaded receipt subject differs")
        discovered = json.loads(command("oras", "discover", "--format", "json", "--depth", "1",
                                        "--artifact-type", kind, reference))
        if descriptor["digest"] not in {row["digest"] for row in discovered["referrers"]}:
            raise ValueError("uploaded receipt cannot be discovered")
        for layer in value["layers"]:
            raw = selection.capture("oras", "blob", "fetch", "--output", "-",
                                    f"{selection.GUEST_REPOSITORY}@{layer['digest']}")
            selection.verify_bytes(raw, layer)
        raw = selection.capture("oras", "blob", "fetch", "--output", "-",
                                f"{selection.GUEST_REPOSITORY}@{value['layers'][0]['digest']}")
        if raw != receipt.read_bytes():
            raise ValueError("uploaded receipt differs from its original bytes")


def document(index: dict, kind: str, attachment: dict) -> dict:
    _, value = selection.manifest(f"{selection.GUEST_REPOSITORY}@{selection.digest(attachment['digest'])}")
    if value["artifactType"] != kind or any(value["subject"].get(key) != index[key] for key in ("digest", "size", "mediaType")):
        raise ValueError("receipt is not bound to the selected index")
    layers = [row for row in value["layers"] if row["mediaType"] == kind]
    if len(layers) != 1:
        raise ValueError("attachment must contain one receipt")
    raw = selection.capture("oras", "blob", "fetch", "--output", "-",
                            f"{selection.GUEST_REPOSITORY}@{selection.digest(layers[0]['digest'])}")
    selection.verify_bytes(raw, layers[0])
    return json.loads(raw)


def records(index: dict, kind: str) -> list[dict]:
    result = json.loads(command("oras", "discover", "--format", "json", "--depth", "1", "--artifact-type", kind,
                                f"{selection.GUEST_REPOSITORY}@{index['digest']}"))
    return [document(index, kind, row) for row in result["referrers"]]


def stage(args: argparse.Namespace) -> dict:
    index, value = selection.manifest(f"{selection.GUEST_REPOSITORY}@{selection.digest(args.index)}")
    source = value["annotations"]["org.opencontainers.image.revision"]
    if source != os.environ["GITHUB_SHA"]:
        raise ValueError("staged index differs from this workflow source")
    # Reuse only the original trustworthy completed receipt. Do not rewrite its
    # time or producer on a retry. An untrusted receipt requires investigation.
    prior = selection.staging_receipt(index, source)
    if prior:
        validate_stage({"index": index, "source_revision": source, **prior}, branch(), datetime.now(UTC))
        return {"decision": "original staging receipt retained", "index_digest": index["digest"], **prior}
    identity = producer("stage", args.stage_attempt)
    receipt = {"schema": "safeyolo.guest-staging/v1", "index_digest": index["digest"], "source_revision": source,
               "staged_at": args.staged_at, "producer": identity, "recorded_at": stamp()}
    validate_stage({"index": index, "source_revision": source, **receipt}, branch(), datetime.now(UTC))
    if not (args.provenance / "publisher-builder.txt").is_file():
        raise ValueError("publisher compiler identity is missing")
    files = sorted(path for path in args.provenance.rglob("*") if path.is_file())
    inputs = json.loads((args.provenance / "inputs.json").read_bytes())
    receipt["inputs"] = inputs
    resolution = inputs["producer"]
    resolution_job = selection.verify_producer(resolution, source, selection.GUEST_WORKFLOW, branch())
    if not (selection.utc(resolution_job["started_at"]) <= selection.utc(inputs["resolution_started_at"])
            <= selection.utc(inputs["resolved_at"]) <= selection.utc(resolution_job["completed_at"])):
        raise ValueError("input resolution time is outside its successful producer job")
    receipt["resolution_producer"] = {**{key: resolution[key] for key in ("repository", "workflow", "run_id", "run_attempt")},
                                      "job_id": resolution_job["id"]}
    receipt["resolution_job_url"] = f"https://github.com/{selection.REPOSITORY}/actions/runs/{resolution['run_id']}/job/{resolution_job['id']}"
    receipt["assembled_at"] = value["annotations"]["org.opencontainers.image.created"]
    receipt["builds"] = {}
    for arch in ("amd64", "arm64"):
        receipt["builds"][arch] = build_inventory(args.provenance / arch, arch, receipt)
    receipt["publisher"] = {"version": (args.provenance / "publisher-oras.txt").read_text().strip(), "source_revision": os.environ["GITHUB_SHA"],
                            "inputs": json.loads((args.provenance / "oras-inputs.json").read_bytes())}
    receipt["run_url"] = f"https://github.com/{selection.REPOSITORY}/actions/runs/{identity['run_id']}/attempts/{identity['run_attempt']}"
    receipt["job_url"] = f"https://github.com/{selection.REPOSITORY}/actions/runs/{identity['run_id']}/job/{identity['job_id']}"
    if json.loads((args.provenance / "arm64/kernel-inputs.json").read_bytes()) != inputs:
        raise ValueError("kernel inputs differ from the shared frozen resolution")
    for name in ("kernel.config", "kernel-builder.txt", "kernel-verification.json"):
        if not (args.provenance / "arm64" / name).is_file():
            raise ValueError("required kernel identity is missing: " + name)
    # Differences are a rendering of retained receipts, not another catalogue.
    previous, _ = selection.staged_guest_candidates(value["annotations"]["dev.safeyolo.guest.compatibility"], None)
    previous = sorted(previous, key=lambda row: selection.utc(row[0]["staged_at"]), reverse=True)
    previous_receipt = records(previous[0][0]["index"], STAGING)[0] if previous else None
    receipt["differences"] = compare_receipts(previous_receipt, receipt)
    attach(index, STAGING, receipt, files)
    return receipt


def build_inventory(directory: Path, arch: str, receipt: dict) -> dict:
    if json.loads((directory / "inputs.json").read_bytes()) != receipt["inputs"]:
        raise ValueError("architecture inputs differ from the shared frozen resolution")
    build_producer = producer(f"build ({arch})", int((directory / "run-attempt.txt").read_text()))
    build_job = selection.verify_producer(build_producer, receipt["source_revision"], selection.GUEST_WORKFLOW, branch())
    for name in (f"dpkg-{arch}.tsv", f"apt-sources-{arch}.txt", f"apt-{arch}.tar", f"apt-indexes-{arch}.sha256", f"builder-{arch}.txt",
                 f"mise-version-{arch}.txt", f"gh-version-{arch}.txt"):
        if not (directory / name).is_file() or (directory / name).stat().st_size == 0:
            raise ValueError("required build inventory is missing: " + name)
    build = {"producer": build_producer, "started_at": (directory / "build-started-at.txt").read_text().strip(),
                                 "completed_at": (directory / "build-completed-at.txt").read_text().strip(),
                                 "base_manifest": (directory / "build-base.txt").read_text().strip(),
                                 "packages": (directory / f"dpkg-{arch}.tsv").read_text().splitlines()}
    if not (selection.utc(build_job["started_at"]) <= selection.utc(build["started_at"])
            <= selection.utc(build["completed_at"]) <= selection.utc(build_job["completed_at"])):
        raise ValueError("build times are outside the successful architecture job")
    if (selection.utc(build["started_at"]) < selection.utc(receipt["inputs"]["resolved_at"])
            or selection.utc(build["completed_at"]) > selection.utc(receipt["staged_at"])):
        raise ValueError("build/resolution/staging times are out of order")
    if build["base_manifest"] != receipt["inputs"]["debian"]["manifests"][arch]["reference"].removeprefix("docker://"):
        raise ValueError("build base differs from resolved Trixie architecture")
    build["job_url"] = f"https://github.com/{selection.REPOSITORY}/actions/runs/{build_producer['run_id']}/job/{build_producer['job_id']}"
    return build


def validate_stage(candidate: dict, default_branch: str, now: datetime) -> datetime:
    staged = selection.utc(candidate["staged_at"])
    if staged > now:
        raise ValueError("verified staging time is in the future")
    job = selection.verify_producer(candidate["producer"], candidate["source_revision"], selection.GUEST_WORKFLOW, default_branch)
    if not selection.utc(job["started_at"]) <= staged <= selection.utc(job["completed_at"]):
        raise ValueError("staging time is outside its successful producer job")
    return staged


def newest_eligible(candidates: list[tuple[dict, dict]], default_branch: str, now: datetime) -> dict | None:
    # Newer quarantined candidates never reset an earlier candidate's clock.
    for candidate, _ in sorted(candidates, key=lambda row: (selection.utc(row[0]["staged_at"]), row[0]["index"]["digest"]), reverse=True):
        staged = selection.utc(candidate["staged_at"])
        if staged > now:
            raise ValueError("verified staging time is in the future")
        if (now - staged).total_seconds() < QUARANTINE_SECONDS:
            continue
        validate_stage(candidate, default_branch, now)
        return candidate
    return None


def smoke_result(reports: Path, gate_url: str) -> dict:
    """Read the existing installed runner's result; no second smoke suite."""
    frozen = json.loads((reports / "selection.json").read_bytes())
    run = json.loads((reports / "retained-run.json").read_bytes())
    installed = json.loads((reports / "installed-inputs.json").read_bytes())
    sections = json.loads((reports / "guest/installed-sections.json").read_bytes())
    platform = frozen["platform"]
    lanes = {"linux-amd64": {"systrap", "kvm"}, "linux-arm64": {"systrap", "kvm"}, "darwin-arm64": {"vz"}}
    if (frozen["status"] != "selected" or run["exit"] != 0 or run["lane"] not in lanes[platform]
            or run["controller_dirty"] or re.fullmatch(r"[0-9a-f]{40}", run["controller_revision"] or "") is None
            or not run["host_id"] or not gate_url):
        raise ValueError("smoke requires a successful retained installed guest run and its result link")
    system, architectures = ("Darwin", {"arm64", "aarch64"}) if platform == "darwin-arm64" else (
        "Linux", {"x86_64", "amd64"} if platform == "linux-amd64" else {"arm64", "aarch64"})
    if run["host_system"] != system or run["host_architecture"] not in architectures:
        raise ValueError("smoke host does not match the required platform")
    if not sections["sections"] or not any(row["section"] == "isolation" for row in sections["sections"]) or any(
        row["exit"] != 0 or row["result"] != "passed" for row in sections["sections"]
    ):
        raise ValueError("smoke has missing or failed installed guest/cleanup evidence")
    guest = frozen["guest"]
    for actual, expected in (("index", "index"), ("manifest", "child"), ("archive", "archive")):
        if installed["guest"][actual] != {key: guest[expected][key] for key in ("digest", "size")}:
            raise ValueError("smoke installed different guest bytes")
    if (installed["platform"] != platform or sections["lane"] != run["lane"]
            or sections["source_revision"] != frozen["host"]["source_revision"]):
        raise ValueError("smoke section platform/source differs from the installed host")
    if (installed["installed_files_sha256"] != frozen["host"]["executables_sha256"]
            or installed["host_source_revision"] != frozen["host"]["source_revision"]
            or frozen["host"]["compatibility"] != guest["compatibility"] or installed["profile"] != "production"):
        raise ValueError("smoke host/helper identity differs from the frozen compatible host")
    return {"schema": "safeyolo.guest-smoke/v1", "index_digest": guest["index"]["digest"], "platform": platform,
            "finished_at": run["finished_at"], "result": "passed", "host_id": run["host_id"], "lane": run["lane"],
            "host": frozen["host"], "guest": guest, "controller_revision": run["controller_revision"],
            "gate_url": gate_url}


def record_smoke(args: argparse.Namespace) -> dict:
    try:
        result = smoke_result(args.reports, args.gate_url)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        frozen = json.loads((args.reports / "selection.json").read_bytes())
        result = {"schema": "safeyolo.guest-smoke/v1", "index_digest": frozen["guest"]["index"]["digest"],
                  "platform": frozen["platform"], "result": "failed", "finished_at": stamp(),
                  "controller_revision": frozen["controller_revision"], "gate_url": args.gate_url,
                  "reason": str(exc) if isinstance(exc, ValueError) else type(exc).__name__}
    index, _ = selection.manifest(f"{selection.GUEST_REPOSITORY}@{result['index_digest']}")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        run_id, attempt = (int(os.environ[key]) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
        jobs = selection.pages(f"actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100", "jobs")
        running = [job for job in jobs if job["runner_name"] == os.environ["RUNNER_NAME"] and job["status"] == "in_progress"]
        if len(running) != 1:
            raise ValueError("installed smoke job is unavailable or ambiguous")
        result["producer"] = {"repository": selection.REPOSITORY, "run_id": run_id, "run_attempt": attempt,
                              "workflow": os.environ["GITHUB_WORKFLOW_REF"].split("@", 1)[0].split(selection.REPOSITORY + "/", 1)[1],
                              "job_id": running[0]["id"]}
    else:
        # The trusted operator may attest physical evidence outside Actions.
        actor = json.loads(command("gh", "api", "user"))["login"]
        verify_operator(actor)
        result["operator"] = actor
    attach(index, SMOKE, result, [args.reports / path for path in
                                 ("selection.json", "retained-run.json", "installed-inputs.json", "guest/installed-sections.json")
                                 if (args.reports / path).is_file()])
    return result


def verify_operator(actor: str) -> None:
    permission = selection.gh(f"collaborators/{actor}/permission")["permission"]
    if permission not in {"admin", "maintain", "write"}:
        raise ValueError("physical smoke needs an attestation from an authorized repository operator")


def verify_smoke_origin(result: dict, default_branch: str) -> None:
    if "operator" in result:
        verify_operator(result["operator"])
    else:
        origin = result["producer"]
        if origin["workflow"] not in {".github/workflows/blackbox.yml", ".github/workflows/installed-arm64.yml"}:
            raise ValueError("smoke producer is not the maintained installed workflow")
        job = selection.verify_producer(origin, result["controller_revision"], origin["workflow"], default_branch)
        if not selection.utc(job["started_at"]) <= selection.utc(result["finished_at"]) <= selection.utc(job["completed_at"]):
            raise ValueError("smoke time is outside the successful producer job")

def verify_smoke_result(candidate: dict, result: dict, default_branch: str) -> None:
    verify_smoke_origin(result, default_branch)
    host = result["host"]
    if (not result["host_id"] or not result["gate_url"] or host["profile"] != "production"
            or host["platform"] != result["platform"] or host["compatibility"] != candidate["compatibility"]
            or re.fullmatch(r"[0-9a-f]{40}", host["source_revision"]) is None):
        raise ValueError("smoke lacks its compatible installed host identity or result link")
    selection.digest("sha256:" + host["archive"]["sha256"])
    platform = result["platform"]
    if platform == "darwin-arm64" and result["lane"] != "vz":
        raise ValueError("Darwin smoke must boot a physical VZ guest")
    if result["guest"]["index"] != candidate["index"] or result["guest"]["compatibility"] != candidate["compatibility"]:
        raise ValueError("smoke guest descriptor/compatibility differs")
    if not selection.utc(candidate["staged_at"]) <= selection.utc(result["finished_at"]) <= datetime.now(UTC):
        raise ValueError("smoke time predates staging or is in the future")

def gates(candidate: dict, evidence: list[dict], default_branch: str) -> list[dict]:
    newest = {}
    for result in evidence:
        if result["index_digest"] != candidate["index"]["digest"] or result["schema"] != "safeyolo.guest-smoke/v1":
            raise ValueError("smoke receipt identity differs")
        platform = result["platform"]
        if platform not in newest or selection.utc(result["finished_at"]) > selection.utc(newest[platform]["finished_at"]):
            newest[platform] = result
    successful = {}
    for result in newest.values():
        if result["result"] != "passed":
            raise ValueError("latest installed smoke failed: " + result["platform"])
        platform = result["platform"]
        verify_smoke_result(candidate, result, default_branch)
        successful[platform] = result
    missing = set(selection.PLATFORMS) - successful.keys()
    if missing:
        raise ValueError("missing successful installed guest smoke: " + ", ".join(sorted(missing)))
    return [successful[platform] for platform in selection.PLATFORMS]


def channel(compatibility: str) -> str | None:
    # Listing distinguishes an absent initial channel from an authentication or
    # network error. Transport failures never masquerade as an empty channel.
    tags = json.loads(command("oras", "repo", "tags", "--format", "json", selection.GUEST_REPOSITORY))["tags"]
    tag = f"compat-{compatibility}"
    return command("oras", "resolve", f"{selection.GUEST_REPOSITORY}:{tag}") if tag in tags else None


def verify_content(candidate: dict, verifier: Path, directory: Path) -> None:
    subprocess.run(["oras", "cp", "--to-oci-layout", f"{selection.GUEST_REPOSITORY}@{candidate['index']['digest']}",
                    str(directory)], check=True, timeout=1800)
    subprocess.run([str(verifier), str(directory), candidate["index"]["digest"], candidate["compatibility"]], check=True)


def differences(current: dict | None, candidate: dict) -> dict:
    following = records(candidate["index"], STAGING)[0]
    previous = records(current["index"], STAGING)[0] if current else None
    return compare_receipts(previous, following)


def compare_receipts(previous: dict | None, following: dict) -> dict:
    result = {"previous_receipt_available": previous is not None,
              "source": {"old": previous["source_revision"] if previous else None, "new": following["source_revision"]},
              "base": {"old": previous["inputs"]["debian"] if previous else None, "new": following["inputs"]["debian"]},
              "tools": {}, "packages": {}}
    for tool, value in following["inputs"]["tools"].items():
        old = previous["inputs"]["tools"].get(tool, {}).get("version") if previous else None
        if old != value["version"]:
            result["tools"][tool] = {"old": old, "new": value["version"]}
    for arch, build in following["builds"].items():
        old = set(previous["builds"][arch]["packages"]) if previous else set()
        new = set(build["packages"])
        result["packages"][arch] = {"removed": sorted(old - new), "added": sorted(new - old)}
    return result


def paused() -> bool:
    return selection.gh("actions/workflows/guest-oci.yml")["state"] != "active"


def promotion_context() -> dict:
    context = {"source_revision": os.environ.get("GITHUB_SHA") or command("git", "rev-parse", "HEAD"),
               "controller_dirty": bool(command("git", "status", "--porcelain")),
               "publisher_version": command("oras", "version")}
    if os.environ.get("GITHUB_ACTIONS") == "true":
        context["producer"] = producer("promote")
        origin = context["producer"]
        context["job_url"] = f"https://github.com/{selection.REPOSITORY}/actions/runs/{origin['run_id']}/job/{origin['job_id']}"
    return context


def promote(args: argparse.Namespace) -> dict:
    now = datetime.now(UTC)
    default_branch = branch()
    if paused():
        return {"decision": "held", "reason": "guest-oci workflow is disabled", "at": now.isoformat()}
    candidates, legacy = selection.staged_guest_candidates(args.compatibility, None)
    candidate = newest_eligible(candidates, default_branch, now)
    if candidate is None:
        return {"decision": "held", "reason": "no trusted complete candidate has reached 172800 seconds", "legacy_indexes": legacy}
    old = channel(args.compatibility)
    result = {"schema": "safeyolo.guest-promotion/v1", "at": now.isoformat(), "index_digest": candidate["index"]["digest"],
              "old_index": old, "new_index": candidate["index"]["digest"], "decision": "held", **promotion_context()}
    tag_attempted = False
    try:
        if old == candidate["index"]["digest"]:
            result.update(decision="unchanged", reason="candidate is already selected")
            return result
        current = next((row for row, _ in candidates if row["index"]["digest"] == old), None)
        if current and (validate_stage(current, default_branch, now), current["index"]["digest"]) >= (
                selection.utc(candidate["staged_at"]), candidate["index"]["digest"]):
            raise ValueError("current channel is a newer accepted selection")
        result["gates"] = gates(candidate, records(candidate["index"], SMOKE), default_branch)
        with tempfile.TemporaryDirectory(prefix="safeyolo-promote-", dir=args.work_directory) as temporary:
            verify_content(candidate, args.verifier, Path(temporary) / "layout")
        result["differences"] = differences(current, candidate)
        # The existing workflow publication concurrency group serializes writers.
        # Recheck after verification so stale preparations cannot move the tag.
        if channel(args.compatibility) != old:
            raise ValueError("compatibility selection changed during verification")
        if paused():
            raise ValueError("automatic promotion was paused during verification")
        # Persist the full gate decision before its one mutable tag write.
        result.update(decision="qualified", reason="172800 seconds and all installed platform gates passed")
        attach(candidate["index"], DECISION, result)
        tag_attempted = True
        command("oras", "tag", f"{selection.GUEST_REPOSITORY}@{candidate['index']['digest']}", f"compat-{args.compatibility}")
        if channel(args.compatibility) != candidate["index"]["digest"]:
            raise ValueError("compatibility tag readback differs")
        result.update(decision="promoted", promoted_at=stamp())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        result.update(decision="publication-uncertain" if tag_attempted else "held",
                      reason=str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
        attach(candidate["index"], DECISION, result)
        raise ValueError(f"{result['decision']}: {result['reason']}") from exc
    attach(candidate["index"], DECISION, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    staging = commands.add_parser("record-stage")
    staging.add_argument("--index", required=True)
    staging.add_argument("--staged-at", required=True)
    staging.add_argument("--stage-attempt", type=int, required=True)
    staging.add_argument("--provenance", type=Path, required=True)
    promotion = commands.add_parser("promote")
    promotion.add_argument("--compatibility", default="v1")
    promotion.add_argument("--verifier", type=Path, required=True)
    promotion.add_argument("--work-directory", type=Path, required=True)
    smoke = commands.add_parser("record-smoke")
    smoke.add_argument("--reports", type=Path, required=True)
    smoke.add_argument("--gate-url", required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--reference", required=True)
    args = parser.parse_args()
    failed = False
    try:
        if args.operation == "record-stage":
            result = stage(args)
        elif args.operation == "record-smoke":
            result = record_smoke(args)
        elif args.operation == "promote":
            result = promote(args)
        else:
            index, value = selection.manifest(args.reference)
            result = {"index": index, "annotations": value["annotations"], "staging": records(index, STAGING),
                      "smoke": records(index, SMOKE), "promotion": records(index, DECISION)}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        failed = True
        result = {"decision": "failed", "reason": str(exc) if isinstance(exc, ValueError) else type(exc).__name__, "at": stamp()}
    rendered = json.dumps(result, indent=2)
    print(rendered)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write("```json\n" + rendered + "\n```\n")
    if failed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
