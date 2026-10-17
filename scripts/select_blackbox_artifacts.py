#!/usr/bin/env python3
"""Freeze retained production host inputs and a completed staged guest for blackbox."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

REPOSITORY = "craigbalding/safeyolo"
GUEST_REPOSITORY = "ghcr.io/craigbalding/safeyolo-guest"
HOST_WORKFLOW = ".github/workflows/proxy-rust.yml"
GUEST_WORKFLOW = ".github/workflows/guest-oci.yml"
STAGING_TYPE = "application/vnd.safeyolo.guest.staging.v1+json"
PLATFORMS = ("linux-amd64", "linux-arm64", "darwin-arm64")
ROOT = Path(__file__).resolve().parents[1]


def capture(*arguments: str) -> bytes:
    # Tool diagnostics stay on the private console, never in the selection report.
    return subprocess.check_output(arguments, timeout=180)


def gh(endpoint: str) -> dict:
    return json.loads(capture("gh", "api", f"repos/{REPOSITORY}/{endpoint}"))


def pages(endpoint: str, field: str) -> list[dict]:
    result = json.loads(capture("gh", "api", "--paginate", "--slurp",
                                f"repos/{REPOSITORY}/{endpoint}"))
    return [row for page in result for row in page[field]]


def digest(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError("expected a complete SHA-256 digest")
    return value


def utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("producer time must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("producer time must be a UTC timestamp") from None
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("producer time must be UTC")
    return parsed


def verify_bytes(data: bytes, descriptor: dict) -> None:
    expected = digest(descriptor["digest"])
    if len(data) != descriptor["size"] or "sha256:" + hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("retained bytes differ from their descriptor")


def public_descriptor(value: dict) -> dict:
    digest(value["digest"])
    if type(value["size"]) is not int or value["size"] < 0:
        raise ValueError("OCI descriptor size must be a nonnegative integer")
    return {key: value[key] for key in ("digest", "size", "mediaType")}


def installed_binaries(platform: str) -> tuple[str, ...]:
    names = ("bin/safeyolo", "bin/safeyolo-proxy", "bin/safeyolo-coord",
             "assets/guest/safeyolo-guest", "assets/guest/safeyolo-coord")
    return names + (("bin/safeyolo-vm", "bin/vsock-term") if platform == "darwin-arm64" else ())


def verify_producer(producer: dict, source: str, workflow: str, branch: str,
                    *, require_success: bool = True) -> dict | None:
    """Verify identity; automatic qualification can skip known unsuccessful jobs."""
    if producer["repository"] != REPOSITORY or producer["workflow"] != workflow:
        raise ValueError("untrusted producer repository/workflow")
    run_id, attempt = (producer[key] for key in ("run_id", "run_attempt"))
    if any(type(value) is not int or value <= 0 for value in (run_id, attempt)):
        raise ValueError("producer run, attempt and job must be positive IDs")
    run = gh(f"actions/runs/{run_id}/attempts/{attempt}")
    if (run["head_sha"] != source or run["head_branch"] != branch or run["path"] != workflow
            or run["event"] not in {"schedule", "workflow_dispatch"} or run["run_attempt"] != attempt):
        raise ValueError("producer must be the selected default-branch production attempt")
    jobs = pages(f"actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100", "jobs")
    if "job_id" in producer:
        selected = [job for job in jobs if job["id"] == producer["job_id"]]
    elif "job_name" in producer:
        selected = [job for job in jobs if job["name"] == producer["job_name"]]
    else:
        selected = [job for job in jobs if job["runner_name"] == producer["runner_name"]
                    and job["name"].split(" / ")[-1] == producer["job_key"]]
    if len(selected) != 1:
        raise ValueError("the selected producer job is unavailable or ambiguous")
    job = selected[0]
    if job["status"] != "completed" or job["conclusion"] != "success":
        if not require_success:
            return None
        raise ValueError("the selected producer job did not complete successfully")
    return job


def select_host(platform: str, branch: str, run_id: int | None) -> dict:
    name = f"nightly-host-{platform}-production"
    endpoint = (f"actions/runs/{run_id}/artifacts?per_page=100" if run_id else
                f"actions/artifacts?name={name}&per_page=100")
    candidates = [artifact for artifact in pages(endpoint, "artifacts")
                  if artifact["name"] == name and artifact["workflow_run"]["head_branch"] == branch]
    job_key = "macos-host" if platform == "darwin-arm64" else "build"
    job_name = f"guest-inputs ({platform.rsplit('-', 1)[1]}) / {job_key}"
    # Order identities first. An unavailable unselected historical run is irrelevant.
    for artifact in sorted(candidates, key=lambda item: (utc(item["created_at"]), item["id"]), reverse=True):
        run = gh(f"actions/runs/{artifact['workflow_run']['id']}")
        if (run["path"] != HOST_WORKFLOW or run["event"] not in {"schedule", "workflow_dispatch"}
                or run["head_branch"] != branch):
            continue
        producer = {"repository": REPOSITORY, "workflow": HOST_WORKFLOW,
                    "run_id": artifact["workflow_run"]["id"], "run_attempt": run["run_attempt"]}
        job = verify_producer({**producer, "job_name": job_name}, artifact["workflow_run"]["head_sha"], HOST_WORKFLOW, branch,
                              require_success=bool(run_id))
        # Only production completion qualifies an upload; blackbox outcomes do not.
        if job is None:
            continue
        if artifact["expired"]:
            raise ValueError(f"selected host artifact {artifact['id']} has expired")
        digest(artifact["digest"])
        return {**{key: artifact[key] for key in ("id", "name", "digest", "size_in_bytes", "created_at", "workflow_run")},
                "producer": {**producer, "job_id": job["id"]}}
    raise ValueError(f"no retained default-branch production host bundle for {platform}")


def download_host(artifact: dict, directory: Path, platform: str, branch: str) -> dict:
    archive_zip = directory / "host.zip"
    with archive_zip.open("xb") as output:
        subprocess.run(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip"],
                       stdout=output, check=True, timeout=600)
    with archive_zip.open("rb") as stream:
        actual = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != artifact["digest"]:
        raise ValueError("host artifact ZIP checksum differs")
    archive_name = f"safeyolo-{platform}-production.tar.gz"
    with zipfile.ZipFile(archive_zip) as bundle:
        if sorted(bundle.namelist()) != sorted([archive_name, "SHA256SUMS", "build.json"]):
            raise ValueError("selected host artifact is incomplete or has unexpected files")
        # Read only fixed names. Never extract paths supplied by the ZIP.
        for name in (archive_name, "SHA256SUMS", "build.json"):
            with bundle.open(name) as source, (directory / name).open("xb") as output:
                shutil.copyfileobj(source, output)
    return verify_host(artifact, directory, platform, branch)


def verify_host(artifact: dict, directory: Path, platform: str, branch: str) -> dict:
    archive_name = f"safeyolo-{platform}-production.tar.gz"
    build = json.loads((directory / "build.json").read_bytes())
    if (build["schema"] != "safeyolo.host-build/v1" or build["platform"] != platform
            or build["profile"] != "production" or build["archive"]["name"] != archive_name
            or build["source_revision"] != artifact["workflow_run"]["head_sha"]
            or build["producer"]["run_id"] != artifact["workflow_run"]["id"]):
        raise ValueError("host artifact source/profile/platform/producer differs")
    job = verify_producer(build["producer"], build["source_revision"], HOST_WORKFLOW, branch)
    if not utc(job["started_at"]) <= utc(build["built_at"]) <= utc(job["completed_at"]):
        raise ValueError("host build time is outside its successful producer job")
    producer = {key: build["producer"][key] for key in ("repository", "workflow", "run_id", "run_attempt")}
    producer["job_id"] = job["id"]
    if producer != artifact["producer"]:
        raise ValueError("host artifact producer differs from the selected production attempt/job")
    archive = directory / archive_name
    with archive.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    if checksum != build["archive"]["sha256"] or archive.stat().st_size != build["archive"]["size"]:
        raise ValueError("host archive checksum/size differs")
    if f"{checksum}  {archive_name}" not in (directory / "SHA256SUMS").read_text().splitlines():
        raise ValueError("host archive is absent from producer SHA256SUMS")
    with tarfile.open(archive, "r:gz") as package:
        stream = package.extractfile(archive_name.removesuffix(".tar.gz") + "/package-info")
        if stream is None:
            raise ValueError("host archive has no package-info")
        info = dict(line.split("=", 1) for line in stream.read().decode().splitlines())
        stream = package.extractfile(archive_name.removesuffix(".tar.gz") + "/SHA256SUMS")
        if stream is None:
            raise ValueError("host archive has no executable checksums")
        checksums = dict(reversed(line.split("  ", 1)) for line in stream.read().decode().splitlines())
    binaries = {name: digest("sha256:" + checksums["./" + name]).removeprefix("sha256:")
                for name in installed_binaries(platform)}
    for key, value in {"source_commit": build["source_revision"], "profile": "production", "platform": platform,
                       "guest_repository": GUEST_REPOSITORY}.items():
        if info.get(key) != value:
            raise ValueError(f"host package-info differs: {key}")
    return {**{key: build[key] for key in ("source_revision", "platform", "profile", "built_at")},
            "producer": producer, "archive": {"name": archive_name, "sha256": checksum, "size": archive.stat().st_size},
            "artifact": {key: artifact[key] for key in ("id", "name", "digest", "created_at")},
            "compatibility": info["guest_compatibility"], "executables_sha256": binaries}


def manifest(reference: str) -> tuple[dict, dict]:
    descriptor = json.loads(capture("oras", "manifest", "fetch", "--descriptor", reference))
    raw = capture("oras", "manifest", "fetch", "--output", "-", f"{GUEST_REPOSITORY}@{digest(descriptor['digest'])}")
    verify_bytes(raw, descriptor)
    return public_descriptor(descriptor), json.loads(raw)


def staging_receipt(index: dict, source: str) -> dict | None:
    reference = f"{GUEST_REPOSITORY}@{index['digest']}"
    discovery = json.loads(capture("oras", "discover", "--format", "json", "--depth", "1",
                                   "--artifact-type", STAGING_TYPE, reference))
    attachments = discovery["referrers"]
    if not attachments:
        return None
    if len(attachments) != 1:
        raise ValueError("guest must have one original completed-staging receipt")
    descriptor, attachment = manifest(f"{GUEST_REPOSITORY}@{digest(attachments[0]['digest'])}")
    if attachment["artifactType"] != STAGING_TYPE or not isinstance(attachment["subject"], dict) or any(
        attachment["subject"].get(key) != index[key] for key in ("digest", "size", "mediaType")
    ):
        raise ValueError("staging attachment is not bound to the selected guest index")
    layers = [layer for layer in attachment["layers"] if layer["mediaType"] == STAGING_TYPE]
    if len(layers) != 1:
        raise ValueError("staging attachment must contain one staging receipt")
    raw = capture("oras", "blob", "fetch", "--output", "-", f"{GUEST_REPOSITORY}@{digest(layers[0]['digest'])}")
    verify_bytes(raw, layers[0])
    receipt = json.loads(raw)
    if (receipt["schema"] != "safeyolo.guest-staging/v1" or receipt["index_digest"] != index["digest"]
            or receipt["source_revision"] != source):
        raise ValueError("staging receipt source/index differs")
    return {"staged_at": receipt["staged_at"], "producer": {
        key: receipt["producer"][key] for key in ("repository", "workflow", "run_id", "run_attempt", "job_id")},
            "receipt_manifest": descriptor, "receipt_blob": public_descriptor(layers[0])}


def staged_guest_candidates(compatibility: str, explicit: str | None) -> tuple[list[tuple[dict, dict]], list[str]]:
    """Discover immutable receipt identities and times before looking up producers."""
    references = [f"{GUEST_REPOSITORY}@{digest(explicit)}"] if explicit else [
        f"{GUEST_REPOSITORY}:{tag}" for tag in
        json.loads(capture("oras", "repo", "tags", "--format", "json", GUEST_REPOSITORY))["tags"]
        if re.fullmatch(r"guest-\d{4}-\d{2}-\d{2}\.\d+", tag)]
    candidates, unstaged = [], []
    for reference in references:
        index, value = manifest(reference)
        if (value["schemaVersion"] != 2 or value["mediaType"] != "application/vnd.oci.image.index.v1+json"
                or value["artifactType"] != "application/vnd.safeyolo.guest.v1"):
            raise ValueError("guest index differs from the maintained OCI contract")
        annotations = value["annotations"]
        if annotations["dev.safeyolo.guest.compatibility"] != compatibility:
            if explicit:
                raise ValueError("selected guest is incompatible with the host")
            continue
        source = annotations["org.opencontainers.image.revision"]
        if annotations["org.opencontainers.image.source"] != f"https://github.com/{REPOSITORY}" or re.fullmatch(r"[0-9a-f]{40}", source) is None or re.fullmatch(
            r"guest-\d{4}-\d{2}-\d{2}\.\d+", annotations["org.opencontainers.image.version"]
        ) is None:
            raise ValueError("guest source/version identity is malformed")
        staged = staging_receipt(index, source)
        if staged is None:
            unstaged.append(index["digest"])
            continue
        candidates.append(({"index": index, "source_revision": source, "compatibility": compatibility,
                            "version": annotations["org.opencontainers.image.version"], **staged}, value))
    return candidates, unstaged


def select_guest(compatibility: str, platform: str, branch: str, explicit: str | None) -> dict:
    candidates, unstaged = staged_guest_candidates(compatibility, explicit)
    for selected, value in sorted(candidates, key=lambda item: (utc(item[0]["staged_at"]), item[0]["index"]["digest"]), reverse=True):
        try:
            job = verify_producer(selected["producer"], selected["source_revision"], GUEST_WORKFLOW, branch,
                                  require_success=bool(explicit))
            if job is None:
                unstaged.append(selected["index"]["digest"])
                continue
            if not utc(job["started_at"]) <= utc(selected["staged_at"]) <= utc(job["completed_at"]):
                raise ValueError("verified staging time is outside its successful producer job")
            children = value["manifests"]
            platforms = [f"{child['platform']['os']}-{child['platform']['architecture']}" for child in children]
            if sorted(platforms) != sorted(PLATFORMS):
                raise ValueError("compatible guest index is partial or has duplicate platforms")
            child = guest_child(children, platforms, platform, value["annotations"])
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            raise ValueError(f"selected guest {selected['index']['digest']}: {reason}") from exc
        return {**selected, **child, "uncompleted_indexes": unstaged}
    raise ValueError("no compatible guest has a trusted completed-staging receipt; #1104 staging input is required")


def guest_child(children: list[dict], platforms: list[str], platform: str, annotations: dict) -> dict:
    # Staging's completed receipt establishes all-platform archive verification.
    # Check immutable children now; native acquisition checks the selected bytes.
    selected = None
    for child, child_platform in zip(children, platforms, strict=True):
        descriptor, value = manifest(f"{GUEST_REPOSITORY}@{digest(child['digest'])}")
        if descriptor["digest"] != child["digest"] or descriptor["size"] != child["size"]:
            raise ValueError("guest child descriptor differs from its index")
        verify_guest_child(value, child_platform, annotations)
        if child_platform == platform:
            selected = {"child": public_descriptor(child), "archive": public_descriptor(value["layers"][0])}
    if selected is None:
        raise ValueError("guest has no selected platform")
    return selected


def verify_guest_child(value: dict, platform: str, annotations: dict) -> None:
    if (value["schemaVersion"] != 2 or value["mediaType"] != "application/vnd.oci.image.manifest.v1+json"
            or value["artifactType"] != "application/vnd.safeyolo.guest.v1" or len(value["layers"]) != 1
            or not isinstance(value["annotations"], dict) or any(value["annotations"].get(key) != annotations[key] for key in (
                "org.opencontainers.image.source", "org.opencontainers.image.revision",
                "org.opencontainers.image.version", "dev.safeyolo.guest.compatibility"))):
        raise ValueError("guest child identity/layout differs from the complete index")
    config, archive = value["config"], value["layers"][0]
    if (config["mediaType"] != "application/vnd.safeyolo.guest.platform.v1+json"
            or archive["mediaType"] != "application/vnd.safeyolo.guest.v1.tar+zstd"):
        raise ValueError("guest config/archive media type differs")
    raw = capture("oras", "blob", "fetch", "--output", "-", f"{GUEST_REPOSITORY}@{digest(config['digest'])}")
    verify_bytes(raw, config)
    os_name, architecture = platform.split("-", 1)
    if json.loads(raw) != {"os": os_name, "architecture": architecture}:
        raise ValueError("guest config differs from the consumer platform")
    available = json.loads(capture("oras", "blob", "fetch", "--descriptor", f"{GUEST_REPOSITORY}@{digest(archive['digest'])}"))
    if any(available[key] != archive[key] for key in ("digest", "size")):
        raise ValueError("complete staged guest archive is unavailable or has a different size")


def download_guest_archive(selection: dict, directory: Path) -> None:
    archive = selection["guest"]["archive"]
    path = directory / "guest.tar.zst"
    subprocess.run(["oras", "blob", "fetch", "--output", str(path),
                    f"{GUEST_REPOSITORY}@{digest(archive['digest'])}"], check=True, timeout=1800)
    with path.open("rb") as stream:
        checksum = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    if checksum != archive["digest"] or path.stat().st_size != archive["size"]:
        raise ValueError("selected guest archive checksum/size differs")


def select(directory: Path, platform: str, host_run: int | None = None, guest_index: str | None = None,
           *, download_guest: bool = False) -> dict:
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": "safeyolo.blackbox-inputs/v1", "status": "selecting", "platform": platform,
              "selected_at": datetime.now(UTC).isoformat(), "stage": "default-branch"}

    def save() -> None:
        (directory / "selection.json").write_text(json.dumps(report, indent=2) + "\n")

    save()
    try:
        repository = json.loads(capture("gh", "api", f"repos/{REPOSITORY}"))
        branch = repository["default_branch"]
        report["default_branch"] = branch
        report["default_branch_head"] = gh(f"commits/{branch}")["sha"]
        report["controller_revision"] = capture("git", "-C", str(ROOT), "rev-parse", "HEAD").decode().strip()
        report["controller_dirty"] = bool(capture("git", "-C", str(ROOT), "status", "--porcelain").strip())
        if report["controller_dirty"]:
            report["controller_revision"] = None
        report["stage"] = "host-selection"
        save()
        artifact = select_host(platform, branch, host_run)
        report["selected_host_artifact"] = {key: artifact[key] for key in ("id", "digest", "name", "producer")}
        report["stage"] = "host-download"
        save()
        host = download_host(artifact, directory, platform, branch)
        report["host"] = host
        report["host_build_age_seconds"] = (datetime.now(UTC) - utc(host["built_at"])).total_seconds()
        if report["host_build_age_seconds"] < 0:
            raise ValueError("host build timestamp is in the future")
        report["stage"] = "guest-selection"
        save()
        report["guest"] = select_guest(host["compatibility"], platform, branch, guest_index)
        if utc(report["guest"]["staged_at"]) > datetime.now(UTC):
            raise ValueError("guest staging timestamp is in the future")
        if download_guest:
            report["stage"] = "guest-download"
            save()
            download_guest_archive(report, directory)
        report.update(status="selected", stage="complete", selected_at=datetime.now(UTC).isoformat())
        report["host_build_age_seconds"] = (utc(report["selected_at"]) - utc(host["built_at"])).total_seconds()
        save()
        return report
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile, tarfile.TarError) as exc:
        report["status"] = "failed"
        # Controlled messages contain no tool stderr, raw receipts or credentials.
        report["failure"] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        save()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=PLATFORMS, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New private directory; earlier attempts are preserved")
    parser.add_argument("--host-run", type=int, help="Exact trusted default-branch producer run, instead of newest build")
    parser.add_argument("--guest-index", help="Exact staged index, instead of newest completed compatible staging")
    parser.add_argument("--download-guest-archive", action="store_true", help="Also retain the exact platform archive for offline hardware execution")
    args = parser.parse_args()
    try:
        report = select(args.output.resolve(), args.platform, args.host_run, args.guest_index,
                        download_guest=args.download_guest_archive)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile, tarfile.TarError) as exc:
        parser.exit(2, f"Artifact selection failed: {exc if isinstance(exc, ValueError) else type(exc).__name__}\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
