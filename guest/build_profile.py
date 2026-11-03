#!/usr/bin/env python3
"""Run a staged shell profile and reuse only its completed outputs."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def snapshot(root: Path, destination: Path, paths: list[str]) -> dict:
    """Copy declared inputs before hashing or execution, including their modes."""
    links = {}
    for name in paths:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("profile inputs must be relative to --source")
        source, target = root / relative, destination / relative
        for entry in [source, *source.rglob("*")] if source.is_dir() else [source]:
            if entry.is_symlink():
                links[str(entry.relative_to(root))] = str(entry.readlink())
        target.parent.mkdir(parents=True, exist_ok=True)
        # Parent directories created for individual files must not make the
        # same declared inputs hash differently under another caller's umask.
        for parent in relative.parents:
            if parent != Path("."):
                (destination / parent).chmod(stat.S_IMODE((root / parent).stat().st_mode))
        if source.is_dir():
            shutil.copytree(source, target, dirs_exist_ok=True)
        else:
            shutil.copy2(source, target)
    records = {}
    for path in sorted(destination.rglob("*")):
        record = {"mode": stat.S_IMODE(path.stat().st_mode)}
        if path.is_file():
            record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        records[str(path.relative_to(destination))] = record
    return {"files": records, "symlinks": links}


def execute(script: Path, environment: dict[str, str]) -> None:
    """Forward cancellation, then reap the builder before considering its output."""
    child = subprocess.Popen(["bash", str(script)], env=environment, start_new_session=True,
                             cwd=Path(environment["SAFEYOLO_GUEST_SRC_DIR"]).parent,
                             stdout=sys.stderr)
    interrupted = []

    def forward(signum, _frame):
        interrupted.append(signum)
        if child.poll() is None:
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                # The builder exited between poll and signal; wait still
                # reaps it, and interrupted work is never admitted below.
                pass

    previous = {signum: signal.signal(signum, forward)
                for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        result = child.wait()
        if interrupted:
            raise SystemExit(128 + interrupted[0])
        if result:
            raise subprocess.CalledProcessError(result, ["bash", str(script)])
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def builder_environment(profile: dict, stage: Path, architecture: str,
                        output_kind: str, frozen: dict | None) -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("SAFEYOLO_ROOTFS_OUT_TREE", "SAFEYOLO_ROOTFS_OUT_EXT4", "GUEST_INPUTS"):
        environment.pop(name, None)
    environment.update(profile.get("environment", {}))
    environment.update({
        "SAFEYOLO_AGENT_NAME": profile["name"],
        "SAFEYOLO_TARGET_ARCH": architecture,
        "SAFEYOLO_ROOTFS_BASE": profile["base"],
        "SAFEYOLO_GUEST_SRC_DIR": str(stage / "source/guest"),
        "SAFEYOLO_ROOTFS_WORK_DIR": str(stage / "work"),
        "SAFEYOLO_ROOTFS_OUT_CACHE_PATHS": str(stage / "output/cache-paths.txt"),
        "SAFEYOLO_ROOTFS_OUT_BUILD_BASE": str(stage / "output/build-base.txt"),
        "TMPDIR": str(stage / "work"),
    })
    filename = "rootfs-tree" if output_kind == "tree" else "rootfs-base.ext4"
    environment["SAFEYOLO_ROOTFS_OUT_" + output_kind.upper()] = str(stage / "output" / filename)
    if frozen is not None:
        environment["GUEST_INPUTS"] = str(stage / "guest-inputs.json")
    return environment


def frozen_inputs(path: Path | None, profile: dict) -> dict | None:
    frozen = json.loads(path.read_text()) if path else None
    if profile.get("guest_tools"):
        if frozen is None:
            raise ValueError("this profile requires --guest-inputs with resolved frozen tools")
        if not set(profile["guest_tools"]) <= frozen["tools"].keys():
            raise ValueError("frozen guest inputs omit a declared profile tool")
    return frozen


def check_output(directory: Path, kind: str) -> None:
    if kind == "tree":
        if (directory / "rootfs-tree").is_symlink() or not (directory / "rootfs-tree/etc").is_dir():
            raise ValueError("profile is missing its completed rootfs tree")
    else:
        image = directory / "rootfs-base.ext4"
        if image.is_symlink() or not image.is_file() or not image.stat().st_size:
            raise ValueError("profile is missing its completed ext4 image")


def clean_completed_work(stage: Path) -> None:
    """Do not traverse a build mount when retiring successful scratch files."""
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        mount = Path(re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), line.split()[4]))
        if mount == stage or stage in mount.parents:
            raise ValueError(f"profile left a build mount at {mount}; work was retained")
    try:
        shutil.rmtree(stage / "work")
    except PermissionError:
        # Custom builders can leave root-owned scratch files after removing
        # their mounts. Match the existing installer's narrow cleanup fallback.
        subprocess.run(["sudo", "-n", "rm", "-rf", "--", str(stage / "work")], check=True)
    shutil.rmtree(stage / "source")


def staged_profile_script(source: Path, name: str, files: dict) -> Path:
    """Select only a script whose staged bytes participate in the cache identity."""
    relative = Path(name)
    if relative.is_absolute():
        raise ValueError("profile script must be relative to the staged source")
    script = (source / relative).resolve()
    if (not script.is_relative_to(source) or not script.is_file()
            or "sha256" not in files["files"].get(str(script.relative_to(source)), {})):
        raise ValueError("profile script must be a file in the staged, declared inputs")
    return script


def build(args: argparse.Namespace) -> dict:
    profile = json.loads(args.profile.read_text())
    cache = args.cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="build-", dir=cache))
    source = stage / "source"
    completed = False
    try:
        files = snapshot(args.source.resolve(), source, profile["files"])
        script = staged_profile_script(source, profile["script"], files)
        frozen = frozen_inputs(args.guest_inputs, profile)
        if frozen is not None:
            (stage / "guest-inputs.json").write_bytes(encoded(frozen))
        if profile.get("guest_tools"):
            subprocess.run([sys.executable, str(source / "guest/resolve_inputs.py"), "env",
                            "--inputs", str(stage / "guest-inputs.json"),
                            "--architecture", args.architecture], check=True, stdout=subprocess.DEVNULL)
        inputs = {"profile": profile, "architecture": args.architecture,
                  "output_kind": args.output_kind, "files": files, "guest_inputs": frozen,
                  "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        key = hashlib.sha256(encoded(inputs)).hexdigest()
        selection = cache / (key + ".json")
        # A lock belongs to an input identity, not to a particular agent.
        with (cache / (key + ".lock")).open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if selection.exists() and not args.force:
                destination = cache / json.loads(selection.read_text())["directory"]
                if json.loads((destination / "build-inputs.json").read_text()) != inputs:
                    raise ValueError(f"completed cache input record differs: {destination}")
                check_output(destination, args.output_kind)
                completed = True
                return {"key": key, "assets": str(destination), "cache_hit": True}
            output = stage / "output"
            work = stage / "work"
            output.mkdir()
            work.mkdir()
            environment = builder_environment(profile, stage, args.architecture, args.output_kind, frozen)
            execute(script, environment)
            check_output(output, args.output_kind)
            clean_completed_work(stage)
            if not (output / "cache-paths.txt").exists():
                (output / "cache-paths.txt").write_text("")
            (output / "build-inputs.json").write_bytes(encoded(inputs) + b"\n")
            if not (output / "build-base.txt").exists():
                (output / "build-base.txt").write_text(profile["base"] + "\n")
            # Force builds keep the prior completed output usable on failure.
            # A successful force result gets a fresh path; active readers keep
            # their original inode and no cache tree is modified in place.
            destination = cache / (key + "-" + stage.name)
            output.rename(destination)
            temporary_selection = stage / "selection.json"
            temporary_selection.write_bytes(encoded({"directory": destination.name}))
            temporary_selection.replace(selection)
            completed = True
            return {"key": key, "assets": str(destination), "cache_hit": False}
    finally:
        # A failed builder may have failed its mount cleanup. Keep its owned
        # work for diagnosis; never recursively remove an unproved mount tree.
        if completed:
            shutil.rmtree(stage)
        else:
            print(f"Unpublished profile work retained at {stage}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--output-kind", choices=("tree", "ext4"), default="tree")
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--guest-inputs", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(args)))


if __name__ == "__main__":
    main()
