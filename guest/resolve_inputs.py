#!/usr/bin/env python3
"""Resolve official stable guest inputs once; verify downloads against that record."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ARCHITECTURES = ("amd64", "arm64")
PROJECTS = {"mise": "jdx/mise", "gh": "cli/cli", "oras": "oras-project/oras"}
KERNEL_KEYS = {"ABAF11C65A2970B130ABE3C479BE3E4300411886", "647F28654894E3BD457199BE38DBBDC86092693E",
               "E27E5D8A3403A2EF66873BBCDEA66FF797772CDC", "AC2B29BD34A6AFDDB3F68F35E7BFC8EC95861109"}


def now() -> str:
    return datetime.now(UTC).isoformat()


def fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("upstream downloads require HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "safeyolo-guest-builder"})
    with urllib.request.urlopen(request, timeout=120) as response:
        if not response.url.startswith("https://"):
            raise ValueError("upstream redirect must retain HTTPS")
        return response.read()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def asset_name(tool: str, version: str, arch: str) -> str:
    if tool == "mise":
        return f"mise-v{version}-linux-{'x64' if arch == 'amd64' else arch}.tar.gz"
    return f"{tool}_{version}_linux_{arch}.tar.gz"


def signed_checksums(tool: str, version: str, names: dict, raw: bytes) -> dict:
    # Trust keys are security identities, not frozen software versions.
    fingerprint = {"mise": "24853EC9F655CE80B48E6C3A8B81C9D17413A06D",
                   "oras": "C6FC42F0DE84A345FAADB742F44418110791EF37"}[tool]
    signature_name = "SHASUMS256.asc" if tool == "mise" else f"oras_{version}_checksums.txt.asc"
    signature_url = names[signature_name]["browser_download_url"]
    key_url = (f"https://keys.openpgp.org/vks/v1/by-fingerprint/{fingerprint}" if tool == "mise" else
               f"https://raw.githubusercontent.com/oras-project/oras/v{version}/KEYS")
    signature, key = fetch(signature_url), fetch(key_url)
    with tempfile.TemporaryDirectory(prefix="safeyolo-release-signature-") as temporary:
        home = Path(temporary)
        (home / "key").write_bytes(key)
        (home / "signature").write_bytes(signature)
        (home / "checksums").write_bytes(raw)
        subprocess.run(["gpg", "--homedir", temporary, "--batch", "--no-autostart", "--import", str(home / "key")],
                       check=True, stdout=subprocess.DEVNULL, timeout=60)
        common = ["gpg", "--homedir", temporary, "--batch", "--no-autostart", "--status-fd", "1"]
        args = (["--output", str(home / "verified"), "--decrypt", str(home / "signature")] if tool == "mise" else
                ["--verify", str(home / "signature"), str(home / "checksums")])
        status = subprocess.check_output([*common, *args], timeout=60).decode()
        valid = {line.split()[-1] for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")}
        if fingerprint not in valid or (tool == "mise" and (home / "verified").read_bytes() != raw):
            raise ValueError("official checksums do not match the trusted release signature")
    return {"signature_url": signature_url, "signature_sha256": sha256(signature),
            "key_url": key_url, "key_sha256": sha256(key), "signer": fingerprint}


def release(tool: str) -> dict:
    explicit = os.environ.get(tool.upper() + "_VERSION")
    endpoint = f"tags/v{explicit}" if explicit else "latest"
    api = f"https://api.github.com/repos/{PROJECTS[tool]}/releases/{endpoint}"
    data = json.loads(fetch(api))
    version = data["tag_name"].removeprefix("v")
    if data["draft"] or data["prerelease"] or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError(f"{tool} release is not a stable release")
    if explicit and explicit != version:
        raise ValueError("explicit tool version differs from release metadata")
    names = {asset["name"]: asset for asset in data["assets"]}
    checksum_name = {"mise": "SHASUMS256.txt", "gh": f"gh_{version}_checksums.txt",
                     "oras": f"oras_{version}_checksums.txt"}[tool]
    checksum_url = names[checksum_name]["browser_download_url"]
    raw = fetch(checksum_url)
    verification = signed_checksums(tool, version, names, raw) if tool in {"mise", "oras"} else {"method": "official-checksums-and-release-api"}
    checksums = {}
    for line in raw.decode().splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?(.+)", line)
        if match:
            name = match[2].removeprefix("./")
            if name in checksums:
                raise ValueError("duplicate official checksum")
            checksums[name] = match[1].lower()
    assets = {}
    for arch in ARCHITECTURES:
        name = asset_name(tool, version, arch)
        value = names[name]
        expected = checksums[name]
        api_digest = value.get("digest")
        if api_digest and api_digest != "sha256:" + expected:
            raise ValueError("release API and official checksum disagree")
        caller = os.environ.get(f"{tool.upper()}_SHA256_{arch.upper()}")
        if caller and caller != expected:
            raise ValueError("explicit checksum differs from the official release")
        assets[arch] = {"url": value["browser_download_url"], "sha256": expected,
                        "checksums_url": checksum_url, "checksums_sha256": sha256(raw), "verification": verification}
    return {"version": version, "release_url": data["html_url"], "metadata_url": api, "assets": assets}


def debian() -> dict:
    reference = "docker://docker.io/library/debian:trixie"
    raw = subprocess.check_output(["skopeo", "inspect", "--raw", reference], timeout=180)
    index = json.loads(raw)
    manifests = {}
    for arch in ARCHITECTURES:
        matches = [row for row in index["manifests"] if row.get("platform", {}).get("os") == "linux"
                   and row["platform"]["architecture"] == arch]
        if len(matches) != 1 or re.fullmatch(r"sha256:[0-9a-f]{64}", matches[0]["digest"]) is None:
            raise ValueError(f"official Trixie index must contain one {arch} manifest")
        digest = matches[0]["digest"]
        pinned = f"docker://docker.io/library/debian@{digest}"
        actual = subprocess.check_output(["skopeo", "inspect", "--raw", pinned], timeout=180)
        if "sha256:" + sha256(actual) != digest or len(actual) != matches[0]["size"]:
            raise ValueError("official Trixie architecture manifest differs from its index")
        config = json.loads(subprocess.check_output(["skopeo", "inspect", "--config", pinned], timeout=180))
        if config["os"] != "linux" or config["architecture"] != arch:
            raise ValueError("official Trixie image architecture differs")
        manifests[arch] = {"reference": pinned, **{key: matches[0][key] for key in ("digest", "size", "mediaType")}}
    return {"channel": "trixie", "index": "docker.io/library/debian@sha256:" + sha256(raw),
            "manifests": manifests}


def kernel() -> dict:
    metadata_url = "https://www.kernel.org/releases.json"
    releases = json.loads(fetch(metadata_url))
    version = os.environ.get("KERNEL_VERSION") or releases["latest_stable"]["version"]
    if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version) is None:
        raise ValueError("kernel must be an upstream stable release")
    base = f"https://cdn.kernel.org/pub/linux/kernel/v{version.split('.')[0]}.x"
    sums_url = base + "/sha256sums.asc"
    raw = fetch(sums_url)
    name = f"linux-{version}.tar.xz"
    matches = re.findall(r"^([0-9a-f]{64})\s+" + re.escape(name) + r"$", raw.decode(), re.M)
    if len(matches) != 1:
        raise ValueError("kernel has no unique official checksum")
    return {"version": version, "metadata_url": metadata_url, "url": f"{base}/{name}",
            "sha256": matches[0], "checksums_url": sums_url, "checksums_sha256": sha256(raw),
            "signature_url": f"{base}/linux-{version}.tar.sign"}


def resolve(tools: list[str], base: bool) -> dict:
    started = now()
    value = {"schema": "safeyolo.guest-inputs/v1", "resolution_started_at": started,
             "tools": {tool: kernel() if tool == "kernel" else release(tool) for tool in tools}}
    if base:
        value["debian"] = debian()
    value["resolved_at"] = now()
    if os.environ.get("GITHUB_ACTIONS") == "true":
        value["producer"] = {"repository": os.environ["GITHUB_REPOSITORY"], "workflow": os.environ["GITHUB_WORKFLOW_REF"].split("@", 1)[0].split(os.environ["GITHUB_REPOSITORY"] + "/", 1)[1],
                             "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                             "job_key": os.environ["GITHUB_JOB"], "runner_name": os.environ["RUNNER_NAME"]}
    return value


def environment(value: dict, arch: str) -> dict:
    if value["schema"] != "safeyolo.guest-inputs/v1":
        raise ValueError("unsupported frozen guest inputs")
    result = {}
    for tool, record in value["tools"].items():
        if tool not in {*PROJECTS, "kernel"}:
            raise ValueError("unknown frozen guest tool")
        result[tool.upper() + "_VERSION"] = record["version"]
        asset = record if tool == "kernel" else record["assets"][arch]
        for key in ("url", "sha256"):
            result[tool.upper() + "_" + key.upper()] = asset[key]
    if "debian" in value:
        result["DEBIAN_IMAGE"] = os.environ.get("DEBIAN_IMAGE") or value["debian"]["manifests"][arch]["reference"]
    return result


def download(record: dict, destination: Path, *, kernel_signature: bool = False) -> None:
    expected = record["sha256"]
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise ValueError("download requires a complete SHA-256 checksum")
    if not destination.exists() or sha256(destination.read_bytes()) != expected:
        raw = fetch(record["url"])
        if sha256(raw) != expected:
            raise ValueError("download differs from the frozen official checksum")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    if kernel_signature:
        # Import only the signer identified by kernel.org's documented
        # fingerprints. Fetch its public key through the same HTTPS/proxy path
        # as the release, including on builders without a DNS resolver.
        with tempfile.TemporaryDirectory(prefix="safeyolo-kernel-signature-") as temporary:
            home = Path(temporary)
            signature = home / "kernel.sign"
            signature.write_bytes(fetch(record["signature_url"]))
            packets = subprocess.check_output(["gpg", "--homedir", temporary, "--batch", "--no-autostart",
                                               "--list-packets", str(signature)], timeout=60).decode()
            signers = [key for key in KERNEL_KEYS if key in packets or key[-16:] in packets]
            if len(signers) != 1:
                raise ValueError("kernel signature does not identify one documented release signer")
            key_url = f"https://keys.openpgp.org/vks/v1/by-fingerprint/{signers[0]}"
            key = fetch(key_url)
            # A fingerprint lookup can omit unverified user IDs. Use the public
            # key packets directly; identity comes from the documented fingerprint.
            keyring = home / "release-key.gpg"
            subprocess.run(["gpg", "--homedir", temporary, "--batch", "--no-autostart", "--dearmor",
                            "--output", str(keyring)], input=key, check=True, timeout=60)
            with tempfile.TemporaryFile(dir=destination.parent) as uncompressed:
                subprocess.run(["xz", "-dc", str(destination)], stdout=uncompressed, check=True)
                uncompressed.seek(0)
                status = subprocess.check_output(["gpg", "--homedir", temporary, "--batch", "--no-autostart",
                                                  "--no-default-keyring", "--keyring", str(keyring), "--status-fd", "1",
                                                  "--verify", str(signature), "-"], stdin=uncompressed, timeout=180).decode()
            fingerprints = {line.split()[-1] for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")}
            if not fingerprints & KERNEL_KEYS:
                raise ValueError("kernel signature does not match a documented upstream release signer")
            destination.with_suffix(destination.suffix + ".verification.json").write_text(json.dumps({
                "signature_url": record["signature_url"], "signature_sha256": sha256(signature.read_bytes()),
                "signers": sorted(fingerprints & KERNEL_KEYS), "key_url": key_url, "key_sha256": sha256(key),
                "method": "kernel.org documented release fingerprint; public key over HTTPS"}, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    resolution = commands.add_parser("resolve")
    resolution.add_argument("--tools", nargs="*", choices=(*PROJECTS, "kernel"), default=list(PROJECTS) + ["kernel"])
    resolution.add_argument("--base", action="store_true")
    resolution.add_argument("--output", type=Path, required=True)
    for command in ("env", "download"):
        sub = commands.add_parser(command)
        sub.add_argument("--inputs", type=Path, required=True)
        sub.add_argument("--architecture", choices=ARCHITECTURES, required=True)
        if command == "download":
            sub.add_argument("--tool", choices=(*PROJECTS, "kernel"), required=True)
            sub.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "resolve":
        args.output.write_text(json.dumps(resolve(args.tools, args.base), indent=2) + "\n")
        return
    value = json.loads(args.inputs.read_bytes())
    if args.command == "env":
        for key, val in environment(value, args.architecture).items():
            print(f"export {key}={shlex.quote(val)}")
    else:
        record = value["tools"][args.tool]
        download(record if args.tool == "kernel" else record["assets"][args.architecture], args.output,
                 kernel_signature=args.tool == "kernel")


if __name__ == "__main__":
    main()
