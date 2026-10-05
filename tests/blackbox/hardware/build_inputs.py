"""Build and package selected offline VZ inputs on the approved Tart host.

The trusted caller owns admission, its attempt result, Tart allocation and
publication. No physical VZ execution or hardware acceptance occurs here.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

if __package__:
    from ..installed_host_smoke import _sha256
    from ..installed_staging import (
        BOOT_FILES,
        package_inputs,
        selected_source,
        staging_environment,
        verify_boot_provenance,
    )
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "cli/src"))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from installed_host_smoke import _sha256
    from installed_staging import (
        BOOT_FILES,
        package_inputs,
        selected_source,
        staging_environment,
        verify_boot_provenance,
    )


def build_command(command: list[str], checkout: Path, env: dict, log, deadline: float) -> None:
    """Bound a command; stop its live process group on timeout or cancellation."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Tart input build deadline expired")
    process = subprocess.Popen(command, cwd=checkout, env=env, stdout=log, stderr=log,
                               start_new_session=True)
    try:
        status = process.wait(timeout=remaining)
    finally:
        if process.poll() is None:
            # The live child leads the session created by this call. Its group
            # cannot have been reused while that child is still alive.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The owned child exited between poll and the signal.
            process.wait()
    if status:
        raise subprocess.CalledProcessError(status, command)


def build_payload(checkout: Path, revision: str, boot_inputs: Path, provenance_path: Path,
                  output: Path, python: Path, timeout: int) -> Path:
    """Reuse one preparation, frozen dependency exports and the staged verifier."""
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("VZ inputs must be built on the approved arm64 Tart host")
    if timeout <= 0:
        raise ValueError("Tart input build requires a positive deadline")
    selected_source(checkout, revision)
    provenance = verify_boot_provenance(json.loads(provenance_path.read_text()),
                                       {name: _sha256(boot_inputs / name) for name in BOOT_FILES})
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    prepared = output / "prepared"
    share = prepared / "share"
    share.mkdir(parents=True)
    # Reused boot bytes keep their original provenance. The selected source
    # and real hardware witnesses still have to establish compatibility.
    for name in BOOT_FILES:
        shutil.copyfile(boot_inputs / name, share / name)
    provenance_file = output / "boot-provenance.json"
    provenance_file.write_text(json.dumps(provenance, indent=2) + "\n")
    # Test/build commands receive runtime and mediated-network settings, not
    # the control process's publication, service or SSH-agent authority.
    env = staging_environment()
    env.update(UV_TOOL_DIR=str(output / "uv-tools"), UV_TOOL_BIN_DIR=str(output / "bin"),
               SAFEYOLO_CONFIG_DIR=str(prepared), SAFEYOLO_LOGS_DIR=str(prepared / "logs"),
               SAFEYOLO_COORD_DATA_DIR=str(prepared / "data/coord"),
               INSTALL_DIR=str(prepared / "bin"), CARGO_BUILD_JOBS="1", BASH_ENV="/dev/null")
    deadline = time.monotonic() + timeout
    wheel_directory = output / "wheels"
    wheelhouse = output / "wheelhouse"
    wheelhouse.mkdir()
    with (output / "build.log").open("wb") as log:
        build_command([str(checkout / "tests/blackbox/run-lane.sh"), "vz", "--install-checkout",
                       str(checkout), "--prepare-only"], checkout, env, log, deadline)
        build_command(["uv", "build", "--wheel", "--out-dir", str(wheel_directory)], checkout, env, log, deadline)
        for name, options in (("runtime", ["--no-dev"]), ("test", ["--group", "dev"])):
            requirements = output / f"{name}-requirements.txt"
            build_command(["uv", "export", "--frozen", "--no-emit-workspace", "--no-header", "--no-annotate",
                           *options, "--output-file", str(requirements)], checkout, env, log, deadline)
            build_command([str(python), "-m", "pip", "download", "--only-binary=:all:", "--require-hashes",
                           "--dest", str(wheelhouse), "--requirement", str(requirements)],
                          checkout, env, log, deadline)
    wheels = list(wheel_directory.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("selected build must produce exactly one product wheel")
    return package_inputs(checkout, revision, wheels[0], wheelhouse, prepared,
                          provenance_file, output / "payload", env=env)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--install-commit", required=True)
    parser.add_argument("--boot-inputs", type=Path, required=True)
    parser.add_argument("--boot-provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True,
                        help="existing compatible build-host Python with pip for locked wheel downloads")
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    args = parser.parse_args()
    # The mailbox can terminate its command. Preserve the same owned-group
    # teardown as Ctrl-C rather than leaving a compiler behind on Tart.
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    index = build_payload(args.checkout.resolve(), args.install_commit, args.boot_inputs.resolve(),
                          args.boot_provenance.resolve(), args.output.resolve(), args.python.resolve(),
                          args.timeout_seconds)
    print(json.dumps({"source_revision": args.install_commit,
                      "staged_inputs": str(index.parent), "input_index_sha256": _sha256(index)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
