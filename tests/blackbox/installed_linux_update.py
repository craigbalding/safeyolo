#!/usr/bin/env python3
"""Run the connected installed Linux update journey on a disposable Ubuntu host.

Use the ordinary host account after prepare-systrap-host.sh. Supply unpacked,
published c9 and c5 production bundles. Python and this checkout are observers;
the native installer discovers the public guest. Native guest upgrade selects
historical G1 and then G2 from public GHCR. No vendor credentials are needed. Keep the output private and
retain only observed.json. An existing output directory is never replayed.
"""

import argparse
import hashlib
import json
import os
import platform
import socket
import stat
import subprocess
import time
import tomllib
import uuid
from pathlib import Path

if __package__:
    from .installed_host_smoke import _native_config, _process_start_token, _runtime_observation, _socket_accepting
    from .installed_sections import cleanup_instance, owned_processes, surviving_processes
else:
    from installed_host_smoke import _native_config, _process_start_token, _runtime_observation, _socket_accepting
    from installed_sections import cleanup_instance, owned_processes, surviving_processes

INITIAL = "c9ecb66b462c2ba0c499f2322f6cfc5c142012da"
TARGET = "c5ce76019b6c997e282ab05cea0212b492e945d2"
G1 = "sha256:df0068692909088a90db2c8f9777807404e3b7d8061ee72bc94a5feabd7dc46e"
G2 = "sha256:b5f3b69562fd4b84730813bd3eb0554b351c975bb363a1be9404f0646147c06b"
CHAINS = {
    "arm64": [
        ("6558c425a728533a79fe03e0d3774ee1b6e2d2fcb78e3bac53495602bcb52858", "2899415b6f4ec2eb3ab2ad3a6ef05c7cc5b9b2de14f9c623ff22b2478c8cb6f5", 223000369),
        ("82bb5240ac189d119a6f52f9c89912d9fde79b21a846768f7672fe917f9575d4", "61038999975eba9a08142c65b8e858b15ab918afed82477022dfe7ee208a2429", 223048157),
    ],
}


def sha(path):
    """Hash one file incrementally."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def info(path):
    """Observe the selected file or directory without copying its contents."""
    row = path.stat()
    return {"path": str(path.resolve()), "device": row.st_dev, "inode": row.st_ino,
            "bytes": row.st_size, "mode": stat.S_IMODE(row.st_mode), "uid": row.st_uid,
            "gid": row.st_gid, "mtime_ns": row.st_mtime_ns}


def operator_settings(path):
    """Read settings while excluding native start/stop's two derived fields."""
    settings = tomllib.loads(path.read_text())
    return {key: value for key, value in settings.items() if key not in {"listeners", "reload_id"}}


def host_executables(package):
    """Identify the packaged host, guest helpers and selected Linux runtime."""
    return {name: sha(package / name) for name in (
        "bin/safeyolo", "bin/safeyolo-proxy", "bin/safeyolo-coord",
        "assets/guest/safeyolo-guest", "assets/guest/safeyolo-coord", "libexec/runsc")}


def check_selection(root, architecture, expected):
    """Require the published index, platform manifest, archive and compatibility."""
    guest = json.loads((root / "share/guest-selection.json").read_text())
    manifest, archive, length = CHAINS[architecture][expected]
    assert guest["index"]["digest"] == (G1, G2)[expected]
    assert guest["manifest"]["digest"] == "sha256:" + manifest
    assert guest["archive"] == {"digest": "sha256:" + archive, "size": length}
    assert guest["platform"] == "linux/" + architecture
    assert guest["compatibility"] == "v1"
    return guest


def guest_inputs(root, guest):
    """Observe the actual selected guest base and its cache-path list."""
    assets = Path(guest.get("installed_assets") or root / "share")
    return {name: info(assets / name) for name in ("rootfs-tree", "cache-paths.txt")} | {
        "curl_sha256": sha(assets / "rootfs-tree/usr/bin/curl")}


def same_guest_base(before, after):
    """A share alias may move; reuse retains the underlying base identity."""
    return all(before[name][key] == after[name][key]
               for name in ("rootfs-tree", "cache-paths.txt") for key in ("device", "inode"))


def redact(text, root):
    """Keep this disposable installation's bearer tokens out of its report."""
    if isinstance(text, bytes):
        text = text.decode(errors="replace")
    for name in ("admin_token", "agent_token"):
        path = root / "data" / name
        if path.is_file():
            token = path.read_text().strip()
            if token:
                text = text.replace(token, "[redacted]")
    return text


def guest_ready_shell(label, markers):
    """Check retained markers before writing new markers and reporting readiness."""
    checks = "; ".join(f"grep -Fx {name} {directory}/.u239-{name}"
                       for name in markers for directory in ("/home/agent", "/workspace"))
    return ("set -eu; " + (checks + "; " if checks else "") +
            f"printf '%s\\n' {label} > /home/agent/.u239-{label}; " +
            f"printf '%s\\n' {label} > /workspace/.u239-{label}; " +
            "id; uname -m; sha256sum /usr/bin/curl /bin/bash; printf 'U239_READY\\n'")


def main():
    """Observe one native installation through updates, boots and owned cleanup."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("initial", "target", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--architecture", choices=CHAINS, default="arm64")
    args = parser.parse_args()
    assert platform.system() == "Linux" and platform.machine() == "aarch64"
    assert os.getuid() != 0, "run as the prepared host's ordinary account"
    args.output = args.output.resolve()
    args.initial, args.target = args.initial.resolve(), args.target.resolve()
    args.output.mkdir(mode=0o700)
    root, home = args.output / "i", args.output / "h"
    home.mkdir(mode=0o700)
    env = dict(os.environ, HOME=str(home), XDG_CACHE_HOME=str(home / ".cache"),
               SAFEYOLO_RUNSC_PLATFORM="systrap", SAFEYOLO_RUNSC_ROOT=str(args.output / "runsc"),
               SAFEYOLO_LOGS_DIR=str(root / "logs"), SAFEYOLO_COORD_DATA_DIR=str(root / "data/coord"),
               SAFEYOLO_NATS_TEST_INSTANCE=uuid.uuid4().hex)
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "GHCR_TOKEN", "REGISTRY_AUTH", "DOCKER_CONFIG",
                "SAFEYOLO_CONFIG_DIR", "SAFEYOLO_HOME", "SAFEYOLO_NATIVE_CONFIG_PATH"):
        env.pop(key, None)
    blocked = args.output / "unavailable-tools"
    blocked.mkdir()
    for name in ("python", "python3", "uv", "oras", "docker", "cargo", "rustc"):
        path = blocked / name
        path.write_text("#!/bin/sh\nprintf '%s\\n' \"$0\" >> \"$HOME/../unexpected-tool\"\nexit 97\n")
        path.chmod(0o755)
    env["PATH"] = str(blocked) + ":" + env["PATH"]
    report = {"platform": platform.uname()._asdict(), "uid": os.getuid(), "root": str(root),
              "backend": "systrap", "observer_source": os.environ.get("GITHUB_SHA", "unknown"),
              "actions": [], "states": {}, "result": "incomplete"}
    output = args.output / "observed.json"
    tracked_listeners = set()

    def save():
        output.write_text(json.dumps(report, indent=2) + "\n")

    def run(label, command, *, json_output=False, timeout=180, check=True):
        command = list(map(str, command))
        row = {"label": label, "command": command, "started": time.time()}
        report["actions"].append(row)
        save()
        started = time.monotonic()
        try:
            process = subprocess.run(command, env=env, cwd=args.output, stdin=subprocess.DEVNULL,
                                     capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            row.update(timeout=True, seconds=time.monotonic() - started,
                       stdout=redact(error.stdout or "", root), stderr=redact(error.stderr or "", root))
            save()
            raise
        row.update(exit=process.returncode, stdout=redact(process.stdout, root), stderr=redact(process.stderr, root),
                   seconds=time.monotonic() - started)
        save()
        if check and process.returncode:
            raise RuntimeError(f"{label}: exit {process.returncode}; see {output}")
        return json.loads(process.stdout) if json_output else process.stdout

    def cli(label, *arguments, binary=None, **kwargs):
        return run(label, [binary or root / "bin/safeyolo", "--root", root, *arguments], **kwargs)

    def state(label, expected):
        guest = check_selection(root, args.architecture, expected)
        row = {"selection": guest, "guest_inputs": guest_inputs(root, guest),
               "host_metadata": (root / "package-info").read_text(),
               "host_executables": host_executables(root)}
        report["states"][label] = row
        save()
        return row

    def processes():
        rows = owned_processes(root)
        holder = root / "agents/bbtest/userns.pid"
        if holder.is_file():
            pid = int(holder.read_text().strip())
            token = _process_start_token(pid)
            if token is not None:
                rows.append({"pid": pid, "start_token": token})
        return rows

    def listeners():
        live = [str(path) for path in root.glob("data/sockets/*/proxy.sock") if _socket_accepting(path)]
        for port in sorted(tracked_listeners):
            with socket.socket() as client:
                client.settimeout(0.5)
                if client.connect_ex(("127.0.0.1", port)) == 0:
                    live.append(f"127.0.0.1:{port}")
        return live

    def remember_listeners():
        for path, fields in ((root / "data/ready.json", ("admin_port",)),
                             (root / "data/coord/nats/process.json", ("client_port", "monitor_port"))):
            if path.is_file():
                value = json.loads(path.read_text())
                tracked_listeners.update(value[key] for key in fields if value.get(key))
        report["owned_tcp_ports"] = sorted(tracked_listeners)
        save()

    def stop(label):
        tracked = processes()
        remember_listeners()
        cli(label + "-stop-agent", "agent", "stop", "bbtest")
        cli(label + "-stop-proxy", "stop")
        cli(label + "-stop-coord", "coord", "stop")
        row = {"tracked": tracked, "survivors": surviving_processes(tracked), "listeners": listeners()}
        report[label + "-stopped"] = row
        save()
        assert not row["survivors"] and not row["listeners"]

    def boot(label, expected, markers, *, install_started=None):
        before = state(label + "-before-boot", expected)
        cli(label + "-start-proxy", "start")
        cli(label + "-start-agent", "agent", "start", "bbtest", "--sandbox-only")
        status = cli(label + "-agent-status", "agent", "status", "bbtest", json_output=True)
        assert status["agent_id"] == report["agent_id"]
        assert status["sandbox_state"] == "running" and status["control_state"] == "ready"
        runtime = _runtime_observation(root, _native_config(root / "config.toml", root),
            root / "bin/safeyolo-proxy", config_path=root / "config.toml", working_directory=root,
            require_running=True, require_authenticated_identity=True)
        result = cli(label + "-shell", "agent", "shell", "bbtest", "-c", guest_ready_shell(label, markers))
        ready = time.monotonic()
        assert "U239_READY" in result
        if install_started is not None:
            report["install_to_ready"] = {"seconds": ready - install_started,
                "start": "immediately before the published c9 bundle's native installer",
                "end": "first credential-free agent shell returns U239_READY",
                "includes": "public default acquisition, explicit historical G1 selection, host preparation, agent creation, proxy/Coord start, identity observations and shell",
                "excludes": "host archive acquisition/unpacking and prepare-systrap-host.sh",
                "target_seconds": 15, "passing_threshold": None}
            save()
        spec = json.loads((root / "agents/bbtest/config.json").read_text())
        guest = check_selection(root, args.architecture, expected)
        assets = Path(guest.get("installed_assets") or root / "share")
        assert Path(spec["root"]["path"]).resolve() == (assets / "rootfs-tree").resolve()
        assert sha(assets / "rootfs-tree/usr/bin/curl") in result
        report["states"][label] = {"status": status, "runtime": runtime,
            "rootfs": str(Path(spec["root"]["path"]).resolve()), "processes": processes()}
        remember_listeners()
        stop(label)
        after = state(label + "-after-stop", expected)
        assert after["host_executables"] == before["host_executables"]

    try:
        for package_name, source in (("initial", INITIAL), ("target", TARGET)):
            package = getattr(args, package_name)
            metadata = dict(line.split("=", 1) for line in (package / "package-info").read_text().splitlines())
            assert metadata["source_commit"] == source
            assert metadata["platform"] == "linux-" + args.architecture
            assert metadata["profile"] == "production" and metadata["guest_compatibility"] == "v1"
            run(package_name + "-verify", ["bash", "-c", 'source "$1/native_package.sh"; verify_native_package "$1"', "verify", package])
            archive = package.parent / "safeyolo-linux-arm64-production.tar.gz"
            report[package_name] = {"metadata": metadata, "host_executables": host_executables(package),
                                    "archive": {"sha256": sha(archive), "bytes": archive.stat().st_size}}
        install_started = time.monotonic()
        # The unchanged c9 installer predates --guest-index. Use its normal
        # public discovery, then its supported explicit historical selection.
        run("install-c9", [args.initial / "install.sh", "--root", root, "--command-dir",
                           args.output / "commands", "--yes"], timeout=600)
        report["initial_discovery"] = json.loads((root / "share/guest-selection.json").read_text())
        cli("select-initial-G1", "guest", "upgrade", "--index", G1, json_output=True, timeout=600)
        (args.output / "workspace").mkdir()
        created = cli("create-agent", "agent", "create", "bbtest", "--workspace",
                      args.output / "workspace", json_output=True)
        report["agent_id"] = created["configuration"]["id"]
        baseline = state("initial-c9-G1", 0)
        assert baseline["host_executables"] == report["initial"]["host_executables"]
        boot("g1", 0, (), install_started=install_started)
        kept_names = ("policy.toml", "data/instance_id", "data/admin_token", "data/agent_token",
                      "certs/mitmproxy-ca.pem", "certs/mitmproxy-ca-cert.pem")
        kept = {name: sha(root / name) for name in kept_names}
        configuration = operator_settings(root / "config.toml")
        boot("restart-g1", 0, ("g1",))
        cli("explicit-G2", "guest", "upgrade", "--index", G2, json_output=True, timeout=600)
        assert state("upgraded-c9-G2", 1)["host_executables"] == baseline["host_executables"]
        boot("g2", 1, ("g1", "restart-g1"))
        before_repeat = state("before-repeat", 1)
        cli("repeat-G2", "guest", "upgrade", "--index", G2, json_output=True)
        after_repeat = state("after-repeat", 1)
        assert before_repeat["selection"] == after_repeat["selection"]
        assert same_guest_base(before_repeat["guest_inputs"], after_repeat["guest_inputs"])
        cli("guest-rollback-G1", "guest", "rollback", json_output=True)
        boot("rollback-g1", 0, ("g1", "restart-g1", "g2"))
        before_host = state("before-host-change", 0)
        updater = args.target / "bin/safeyolo"
        changed = cli("host-only-c5", "upgrade", "--bundle", args.target, binary=updater, json_output=True)
        after_host = state("after-host-change", 0)
        assert same_guest_base(before_host["guest_inputs"], after_host["guest_inputs"])
        assert changed["current"]["guest"] == changed["previous"]["guest"]
        assert after_host["host_executables"] == report["target"]["host_executables"]
        boot("host-only-g1", 0, ("g1", "g2", "rollback-g1"))
        complete = cli("select-complete-pair", "upgrade", "--bundle", args.initial,
                       "--guest-index", G2, binary=updater, json_output=True, timeout=600)
        assert complete["previous"] == changed["current"]
        boot("complete-g2", 1, ("g1", "g2", "host-only-g1"))
        restored = run("restore-complete-pair", [root / "safeyolo-upgrade", "rollback"], json_output=True)
        assert restored["current"] == changed["current"]
        boot("restored-g1", 0, ("g1", "g2", "complete-g2"))
        original = run("restore-original-pair", [root / "safeyolo-upgrade", "rollback"], json_output=True)
        assert original["current"] == changed["previous"]
        assert state("final-c9-G1", 0)["host_executables"] == baseline["host_executables"]
        report["persistent_files_equal"] = {name: sha(root / name) == value for name, value in kept.items()}
        report["operator_configuration_equal"] = configuration == operator_settings(root / "config.toml")
        assert report["operator_configuration_equal"] and all(report["persistent_files_equal"].values())
        assert not (args.output / "unexpected-tool").exists()
        report["result"] = "pass"
    except Exception as error:
        # Preserve the first failure, then propagate it after owned cleanup.
        report.update(result="failed", failure=f"{type(error).__name__}: {error}")
        save()
        raise
    finally:
        if (root / "config.toml").is_file():
            report["pre_cleanup_processes"] = processes()
            remember_listeners()
            cli("cleanup-stop-coord", "coord", "stop", check=False)
            prior_environment = dict(os.environ)
            try:
                os.environ.update(env)
                report["cleanup_failures"] = cleanup_instance(root / "bin/safeyolo", root)
                report["cleanup_failures"].extend(surviving_processes(report["pre_cleanup_processes"]))
                report["cleanup_listeners"] = listeners()
            finally:
                os.environ.clear()
                os.environ.update(prior_environment)
            if report["cleanup_failures"] or report["cleanup_listeners"]:
                report["result"] = "failed"
        save()
        print(json.dumps({"result": report["result"], "observed": str(output)}))
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
