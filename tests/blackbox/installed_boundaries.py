"""Run job, mount or Docker checks using one prepared installed product.

The installed section runner supplies a fresh instance and output directory.
Each journey owns its guests and records named checkpoints. The prepared
installation stays unchanged. Hardware execution uses the existing venue
runner; this driver does not schedule or provision hosts.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import tomlkit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests/reference"))

from tests.blackbox.execution_receipt import ProcedureReceipt, save
from tests.blackbox.host import job_network, job_sandbox
from tests.blackbox.installed_host_smoke import _cli_identity, _sha256
from tests.blackbox.installed_sections import cleanup_instance, copy_prepared_nats, prepare_native_instance
from tests.blackbox.retained_inputs import controller_identity
from tests.blackbox.selections import BOUNDARY_SECTIONS

ROOT = Path(__file__).resolve().parents[2]


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def prepare(base, root, port):
    prepare_native_instance(base, root)
    root.chmod(0o755)
    (root / "data").chmod(0o755)
    config = tomlkit.parse((root / "config.toml").read_text())
    config["admin_port"] = port
    prepared = tomlkit.parse((base / "config.toml").read_text())
    for name in ("parent_proxy", "parent_proxy_agents", "parent_proxy_hosts"):
        if name in prepared:
            config[name] = prepared[name]
    (root / "config.toml").write_text(tomlkit.dumps(config))


def run(args):
    output, base, root = args.output, args.prepared_config, args.root
    output.mkdir(parents=True, exist_ok=True)
    receipt = ProcedureReceipt(args.section, output / "result.json")
    result = {"section": args.section, "cleanup_failures": [], "finished": False}
    cli = base / "bin/safeyolo"
    try:
        identity = _cli_identity(cli)
        assert identity["source_revision"] == args.revision, "prepared product differs from the selected revision"
        receipt.document["identities"] = {
            "product": identity,
            "controller": {**controller_identity(),
                           "path": str(Path(__file__).resolve()), "sha256": _sha256(Path(__file__))},
            "guest_selection": json.loads((base / "share/guest-selection.json").read_text()),
        }
        save(receipt.path, receipt.document)
        admin = 46371 if args.lane == "vz" else free_port()
        upstream = 46373 if args.lane == "vz" else free_port()
        if args.section == "job-network":
            scratch = output / "network"
            scratch.mkdir(mode=0o700)
            job_network.run(SimpleNamespace(cli=cli, proxy=base / "bin/safeyolo-proxy", base_root=base,
                                            root=root, scratch=scratch, admin_port=admin, upstream_port=upstream), receipt)
        elif args.section == "docker":
            from tests.blackbox import installed_docker_preflight as docker

            docker.recurring_journey(SimpleNamespace(prepared_config=base, root=root, output=output / "docker", revision=args.revision,
                                       guest_revision=None, proxy_revision=None, admin_port=admin,
                                       reuse_root=False, nested_docker=True, journey=True, gateway=False,
                                       docker_data=None, host_address="127.0.0.1", host_port=upstream), receipt)
        else:
            prepare(base, root, admin)
            if args.section == "job-sandbox":
                scratch = output / "jobs"
                scratch.mkdir()
                observer = os.environ.get("SAFEYOLO_JOB_OBSERVER_PROBE")
                if args.lane == "vz" and not observer:
                    raise ValueError("VZ job proof requires SAFEYOLO_JOB_OBSERVER_PROBE (static Linux guest executable)")
                job_sandbox.run(cli, root, scratch, observer_probe=Path(observer) if observer else None,
                                receipt=receipt, receiver_port=upstream if args.lane == "vz" else 0)
            else:
                from tests.nested_linux_live_mount import run_proof

                copy_prepared_nats(base, root)
                coord = [str(cli), "--root", str(root), "coord", "start"]
                if args.lane == "vz":
                    coord += ["--client-port", "46370", "--monitor-port", "46372"]
                subprocess.run(coord, check=True, timeout=60)
                subprocess.run([str(cli), "--root", str(root), "start"], check=True, timeout=60)
                run_proof(root, output / "mounts", candidate=args.revision, receipt=receipt)
        result["finished"] = True
        return 0
    except (AssertionError, OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        result["cleanup_failures"] = cleanup_instance(cli, root)
        save(output / "boundary-result.json", result)
        if result["cleanup_failures"]:
            raise RuntimeError(f"owned boundary cleanup failed: {result['cleanup_failures']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--section", choices=BOUNDARY_SECTIONS, required=True)
    parser.add_argument("--lane", choices=("systrap", "kvm", "vz"), required=True)
    parser.add_argument("--prepared-config", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    if args.section == "docker" and args.lane != "systrap":
        parser.error("the maintained nested-Docker journey uses Linux systrap")
    # The mount journey lives in a hyphenated source directory. Load that
    # maintained file directly; do not duplicate its implementation.
    if args.section == "mounts":
        import importlib.util

        spec = importlib.util.spec_from_file_location("tests.nested_linux_live_mount", ROOT / "tests/nested-linux/live_mount_backend_proof.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    try:
        return run(args)
    except AssertionError as error:
        print(f"Boundary assertion failed: {error}", file=sys.stderr)
        return 1
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"Boundary preparation or cleanup failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
