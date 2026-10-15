"""Check isolated startup and late shares in a fresh installed Linux fixture.

Run from this checkout as the ordinary prepared Linux host account. ROOT must
be a fresh installation of this candidate with its proxy and Coord running.
BASE must not exist. TEST_BINARY is the same candidate's native library test
executable, built with --release. The driver creates three synthetic agents,
starts no model, and stops its agents and proxy on every exit.

    .venv/bin/python tests/nested-linux/live_mount_backend_proof.py \
        --root /owned/fresh-instance --base /owned/new-result-directory \
        --native-test-binary /owned/candidate/native-library-test

The test-only typed entry calls production share functions under the existing
lifecycle lock. It adds no product command or general host execution service.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "blackbox"))
from harness.process_identity import process_start_token
from installed_sections import owned_processes, surviving_processes

GUEST_HOLDER = '''import json, mmap, os, sys, time
from pathlib import Path
mode, target, result = sys.argv[1:]
result = Path(result)
opened = mapped = None
if mode == "file":
    opened = open(target + "/host.txt", "r+b", buffering=0)
elif mode == "cwd":
    os.chdir(target)
elif mode == "mmap":
    opened = open(target + "/host.txt", "r+b", buffering=0)
    mapped = mmap.mmap(opened.fileno(), 4096)
elif mode != "marker":
    raise ValueError(mode)
identity = {"pid":os.getpid(), "start":Path("/proc/self/stat").read_text().split(") ")[1].split()[19]}
if mapped is not None:
    result.with_suffix(".mapped-before").write_text(mapped[:64].decode())
result.with_suffix(".ready").write_text(json.dumps(identity))
deadline = time.monotonic() + 300
while not result.with_suffix(".release").exists():
    if time.monotonic() > deadline:
        raise TimeoutError("host did not release owned holder")
    result.with_suffix(".heartbeat").write_text(str(time.monotonic()))
    time.sleep(.1)
try:
    if mode == "file":
        opened.seek(0); data=opened.read(64).decode()
    elif mode == "cwd":
        data=Path("host.txt").read_text()[:64]
    elif mode == "mmap":
        data=mapped[:64].decode()
    else:
        data="marker survived"
    # Retain a successful read even if the following write signals SIGBUS.
    result.with_suffix(".read-result").write_text(json.dumps({"identity":identity, "data":data}))
    if mode == "file":
        opened.seek(128); opened.write(b"guest-open-handle-write")
    elif mode == "cwd":
        Path("guest-cwd-write").write_text("guest-cwd-write")
    elif mode == "mmap":
        mapped[128:151]=b"guest-open-handle-write"; mapped.flush()
    observation={"identity":identity, "accessible":True, "data":data}
except OSError as error:
    observation={"identity":identity, "accessible":False, "errno":error.errno, "error":str(error)}
result.with_suffix(".result").write_text(json.dumps(observation))
'''


def wait_file(path, timeout=20):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() > deadline:
            raise TimeoutError(f"missing probe result: {path}")
        time.sleep(.05)
    return path.read_text()



def process_state(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except FileNotFoundError:
        return None  # An exited owned process can disappear during observation.


def run_proof(root: Path, base: Path, native_test: Path):
    base.mkdir(mode=0o755)
    report = {"root": str(root), "base": str(base), "commands": [], "operations": []}
    cli = [str(root / "bin/safeyolo"), "--root", str(root)]
    agent, second, failed = "proof1042", "proof1042second", "proof1042failed"
    created, initial, handles = [], {}, {}
    marker = None
    sources = ("startup", "startup-ro", "unrelated", "live", "readonly", "second", "failed")

    def save():
        (base / "observed.json").write_text(json.dumps(report, indent=2) + "\n")

    def command(argv, *, check=True, timeout=40, environment=None):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                                timeout=timeout, env=environment)
        report["commands"].append({"argv": list(map(str, argv)), "exit": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        save()
        if check and result.returncode:
            raise RuntimeError(f"command exited {result.returncode}: {argv}")
        return result

    def guest(script, *, selected=agent, check=True):
        return command([*cli, "agent", "shell", selected, "-c", script], check=check)

    def runtime(selected):
        return json.loads((root / "agents" / selected / "runtime.json").read_text())

    def same_run(selected=agent):
        current, before = runtime(selected), initial[selected]
        for key in ("run_id", "holder_pid", "holder_token", "backend_pid", "backend_token"):
            assert current.get(key) == before.get(key), (selected, key)
        context = root / "agents" / selected / "config-share/host-launch-context.json"
        assert json.loads(context.read_text())["generation"] == before["run_id"]
        for kind in ("holder", "backend"):
            assert process_start_token(current[kind + "_pid"]) == current[kind + "_token"]
            assert process_state(current[kind + "_pid"]) not in (None, "Z", "X")

    def operation(kind, operand, *, generation=None):
        same_run()
        environment = dict(os.environ, SAFEYOLO_SHARE_TEST_ROOT=str(root),
                           SAFEYOLO_SHARE_TEST_REVISION=report["candidate"],
                           SAFEYOLO_SHARE_TEST_AGENT=agent,
                           SAFEYOLO_SHARE_TEST_GENERATION=generation or initial[agent]["run_id"],
                           SAFEYOLO_SHARE_TEST_OPERATION=kind,
                           SAFEYOLO_SHARE_TEST_OPERAND=operand)
        result = command([native_test, "--exact", "linux_host::shares::tests::installed_share_operation",
                          "--ignored", "--nocapture"], environment=environment)
        rows = [line.split("SHARE_RESULT=", 1)[1] for line in result.stdout.splitlines()
                if "SHARE_RESULT=" in line]
        if len(rows) != 1:
            raise RuntimeError("native share operation did not return exactly one result")
        value = json.loads(rows[0])
        assert value["commit"] == report["candidate"] and value["profile"] == "production"
        report["operations"].append({"operation": kind, "operand": operand, "result": value})
        save()
        same_run()
        return value

    def holder(mode, target):
        result = base / "workspace" / (mode + "-holder")
        guest("( python3 -I -B /workspace/holder.py " + " ".join(map(shlex.quote,
              [mode, target, "/workspace/" + result.name])) +
              f'; printf \'%s\' "$?" > /workspace/{mode}-holder.exit )' +
              f" </dev/null > /workspace/{mode}.log 2>&1 &")
        identity = json.loads(wait_file(result.with_suffix(".ready")))
        handles[mode] = result
        return result, identity

    def release(result):
        result.with_suffix(".release").touch()
        code = int(wait_file(result.with_suffix(".exit")))
        observation = (json.loads(result.with_suffix(".result").read_text())
                       if result.with_suffix(".result").exists() else {})
        return {**observation, "exit": code}

    def share_processes(share):
        return [{"kind": kind, "pid": share[kind + "_pid"], "token": process_start_token(share[kind + "_pid"]),
                 "cgroup": Path(f"/proc/{share[kind + '_pid']}/cgroup").read_text()}
                for kind in ("launcher", "gofer")]

    def file_observation(target):
        access = guest("cat -- " + shlex.quote(target + "/host.txt"), check=False)
        identity = guest("stat -Lc '%D:%i:%s' -- " + shlex.quote(target + "/host.txt"), check=False)
        mounts = guest("cat /proc/self/mountinfo", check=False)
        return {"access_exit": access.returncode, "access": access.stdout, "access_error": access.stderr,
                "identity_exit": identity.returncode, "identity": identity.stdout, "mountinfo": mounts.stdout}

    def capture_final():
        # Preserve all final operands before assertions and owned teardown.
        final = {"agents": {}, "host_files": {}, "captured_before_cleanup": True}
        for selected, before in initial.items():
            try:
                observation = {"runtime": runtime(selected), "processes": {}}
                for kind in ("holder", "backend"):
                    pid = before[kind + "_pid"]
                    observation["processes"][kind] = {"pid": pid, "token": process_start_token(pid),
                                                        "state": process_state(pid)}
                check = ("test -d /workspace && test -d /home/agent && test -r /safeyolo/host-mounts && "
                         "cat /proc/uptime && cat /mnt/proof1042unrelated/host.txt" if selected == agent
                         else "cat /mnt/proof1042second/host.txt")
                observation["guest_exit"] = guest(check, selected=selected, check=False).returncode
                final["agents"][selected] = observation
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                final["agents"][selected] = {"error": str(error)}
        if marker is not None:
            final["marker_ready"] = json.loads(marker.with_suffix(".ready").read_text())
            final["marker_heartbeat"] = marker.with_suffix(".heartbeat").read_text()
            final["marker_proc"] = guest("cat /proc/" + str(final["marker_ready"]["pid"]) + "/stat", check=False).stdout
        for name in sources:
            source = base / name / "host.txt"
            try:
                info = source.stat()
                final["host_files"][name] = {"device": info.st_dev, "inode": info.st_ino,
                                              "size": info.st_size, "data": source.read_text()}
            except OSError as error:
                final["host_files"][name] = {"error": str(error)}
        report["final"] = final
        save()

    try:
        for name in (*sources, "workspace", "second-workspace", "failed-workspace"):
            directory = base / name
            directory.mkdir()
            (directory / "host.txt").write_text((name + ":host-before").ljust(4096, "."))
        (base / "workspace/holder.py").write_text(GUEST_HOLDER)
        report["os"] = command(["uname", "-a"]).stdout.strip()
        report["host_version"] = command([root / "bin/safeyolo", "--version"]).stdout.strip()
        report["candidate"] = command(["git", "-C", Path(__file__).resolve().parents[2], "rev-parse", "HEAD"]).stdout.strip()
        assert "commit=" + report["candidate"] in report["host_version"]
        assert "profile=production" in report["host_version"]
        settings = tomllib.loads((root / "config.toml").read_text())["linux"]
        report["runsc_version"] = command([settings["runsc"], "--version"]).stdout.strip()
        report["host_before"] = {name: {"device": (base / name / "host.txt").stat().st_dev,
                                          "inode": (base / name / "host.txt").stat().st_ino}
                                 for name in sources}
        # First attach one share, then fail a second attachment at an existing
        # non-directory guest parent. This exercises cleanup of partial work.
        command([*cli, "agent", "create", failed, "--workspace", base / "failed-workspace", "--memory", "512",
                 "--mount", f"{base}/failed:/mnt/failure-first", "--mount", f"{base}/failed:/etc/hostname/impossible"])
        created.append(failed)
        failed_start = command([*cli, "agent", "start", failed, "--sandbox-only"], check=False, timeout=150)
        failed_run = runtime(failed)
        status = command([*cli, "agent", "status", failed], check=False)
        directory = root / "agents" / failed
        report["failed_start"] = {"exit": failed_start.returncode, "runtime": failed_run, "status": status.stdout,
                                  "processes": {kind: {"pid": failed_run[kind + "_pid"], "state": process_state(failed_run[kind + "_pid"])}
                                                for kind in ("holder", "backend")},
                                  "share_processes": [{"kind": kind, "pid": share[kind + "_pid"], "state": process_state(share[kind + "_pid"])}
                                                      for share in failed_run.get("linux", {}).get("extra_shares", [])
                                                      for kind in ("launcher", "gofer") if kind + "_pid" in share],
                                  "per_run_go": (directory / "config-share/per-run-go").exists(),
                                  "per_run_started": (directory / "status/per-run-started").exists(),
                                  "static_init_done": (directory / "status/static-init-done").exists()}
        save()
        assert failed_start.returncode != 0
        assert "/etc/hostname/impossible" in failed_start.stderr
        assert len(failed_run["linux"]["extra_shares"]) == 1, "first attachment must have reached its Gofer"
        assert failed_run["linux"]["extra_shares"][0]["state"] == "removed"
        assert "error" not in failed_run["linux"]["extra_shares"][0], "the first share must have attached before the injected failure"
        assert not any(report["failed_start"][key] for key in ("per_run_go", "per_run_started", "static_init_done"))
        failed_status = json.loads(status.stdout)
        assert failed_status["runtime_state"] == "stopped" and failed_status["exec"] is False
        assert not (root / "run" / ("runsc-safeyolo-" + failed_run["run_id"] + ".sock")).exists()
        for kind in ("holder", "backend"):
            assert process_state(failed_run[kind + "_pid"]) in (None, "Z", "X")
        assert all(process["state"] in (None, "Z", "X") for process in report["failed_start"]["share_processes"])

        command([*cli, "agent", "create", second, "--workspace", base / "second-workspace", "--memory", "512",
                 "--mount", f"{base}/second:/mnt/proof1042second"])
        created.append(second)
        command([*cli, "agent", "start", second, "--sandbox-only"], timeout=150)
        initial[second] = runtime(second)
        (base / "startup-link").symlink_to(base / "startup", target_is_directory=True)
        command([*cli, "agent", "create", agent, "--workspace", base / "workspace", "--memory", "1024",
                 "--mount", f"{base}/startup-link:/mnt/proof1042startup",
                 "--mount", f"{base}/startup-ro:/mnt/proof1042startupro:ro",
                 "--mount", f"{base}/unrelated:/mnt/proof1042unrelated"])
        created.append(agent)
        command([*cli, "agent", "start", agent, "--sandbox-only"], timeout=150)
        initial[agent] = runtime(agent)
        report["initial_runs"] = initial
        holder_pid = initial[agent]["holder_pid"]
        report["uid_map"] = Path(f"/proc/{holder_pid}/uid_map").read_text()
        report["gid_map"] = Path(f"/proc/{holder_pid}/gid_map").read_text()
        report["sandbox_cgroup"] = Path(f"/proc/{initial[agent]['backend_pid']}/cgroup").read_text()
        report["guest_kernel"] = guest("uname -a").stdout.strip()
        same_run(second)
        guest("grep -q startup:host-before /mnt/proof1042startup/host.txt && "
              "grep -q startup-ro:host-before /mnt/proof1042startupro/host.txt && "
              "printf startup-write > /mnt/proof1042startup/guest.txt")
        assert (base / "startup/guest.txt").read_text() == "startup-write"
        refused = guest("printf forbidden > /mnt/proof1042startupro/forbidden", check=False)
        assert refused.returncode != 0 and not (base / "startup-ro/forbidden").exists()
        marker, marker_identity = holder("marker", "/workspace")
        report["marker_before"] = marker_identity
        before_heartbeat = marker.with_suffix(".heartbeat").read_text()
        before_receipts = runtime(agent)
        stale = operation("add", f"{base}/live:/mnt/stale", generation="0" * 32)
        assert not stale["success"] and "incarnation changed" in stale["error"]
        assert runtime(agent) == before_receipts
        invalid = operation("add", f"{base}/live/host.txt:/mnt/file-source")
        assert not invalid["success"] and "regular file" in invalid["error"]
        command([*cli, "mount", "protect", base / "readonly"])
        invalid = operation("add", f"{base}/readonly:/mnt/protected-writable")
        assert not invalid["success"] and "protected" in invalid["error"]
        for name, target, suffix in (("live", "/mnt/proof1042live", ""), ("readonly", "/mnt/proof1042ro", ":ro")):
            added = operation("add", f"{base}/{name}:{target}{suffix}")
            assert added["success"], added
            guest("grep -q " + name + ":host-before " + target + "/host.txt")
        duplicate = operation("add", f"{base}/live:/mnt/proof1042live")
        assert not duplicate["success"] and "already in use" in duplicate["error"]
        guest("printf guest-write > /mnt/proof1042live/guest.txt")
        assert (base / "live/guest.txt").read_text() == "guest-write"
        refused = guest("printf forbidden > /mnt/proof1042ro/forbidden", check=False)
        assert refused.returncode != 0 and not (base / "readonly/forbidden").exists()
        guest("ln -s /safeyolo /workspace/control-alias")
        refused = operation("add", f"{base}/live:/workspace/control-alias")
        assert not refused["success"] and "reserved mount" in refused["error"]
        for mode in ("file", "cwd", "mmap"):
            handle, identity = holder(mode, "/mnt/proof1042live")
            removed = operation("remove", "/mnt/proof1042live")
            with (base / "live/host.txt").open("r+") as changed:
                changed.write((mode + ":host-after-refusal").ljust(64, "."))
                changed.flush()
                os.fsync(changed.fileno())
            observation = release(handle)
            report.setdefault("busy", []).append({"kind": mode, "identity": identity,
                                                   "remove": removed, "access_after": observation})
            save()
            assert not removed["success"] and "busy" in removed["error"].lower()
            assert observation["accessible"] is True and observation["exit"] == 0
        report["live_before_removals"] = (base / "live/host.txt").read_text()
        alias = guest("sudo -n mkdir -p /mnt/proof1042alias && "
                      "sudo -n mount --bind /mnt/proof1042live /mnt/proof1042alias", check=False)
        report["bind_alias"] = {"exit": alias.returncode, "stderr": alias.stderr}
        save()
        assert alias.returncode != 0, "a successful alias needs a separate safe-removal assessment"
        for target in ("/mnt/proof1042live", "/mnt/proof1042ro", "/mnt/proof1042startup", "/mnt/proof1042startupro"):
            receipt = next(share for share in runtime(agent)["linux"]["extra_shares"] if share["guest_path"] == target)
            processes = share_processes(receipt)
            assert all(process["cgroup"] == report["sandbox_cgroup"] for process in processes)
            before = file_observation(target)
            removed = operation("remove", target)
            after = file_observation(target)
            observed = [{**process, "after_token": process_start_token(process["pid"]),
                         "after_state": process_state(process["pid"])} for process in processes]
            report.setdefault("removed", []).append({"target": target, "before": before, "result": removed,
                                                       "after": after, "processes": observed})
            save()
            assert removed["success"], removed
            assert before["access_exit"] == 0 and before["identity_exit"] == 0
            assert after["access_exit"] != 0 and after["identity_exit"] != 0
            assert "safeyolo-share-" + receipt["id"] not in after["mountinfo"]
            assert all(process["after_state"] in (None, "Z", "X") for process in observed)
            same_run()
            same_run(second)
        capture_final()
        assert report["final"]["marker_heartbeat"] != before_heartbeat
        report["marker_after"] = release(marker)
        assert report["marker_after"]["identity"] == marker_identity and report["marker_after"]["exit"] == 0
        for selected in (agent, second):
            same_run(selected)
            assert report["final"]["agents"][selected]["guest_exit"] == 0
        for name in sources:
            observed = report["final"]["host_files"][name]
            assert {key: observed[key] for key in ("device", "inode")} == report["host_before"][name]
            assert observed["size"] == 4096
            if name != "live":
                assert observed["data"] == (name + ":host-before").ljust(4096, ".")
            else:
                assert observed["data"] == report["live_before_removals"]
        report["backend_operations_completed"] = True
        save()
    finally:
        failures = []
        if "final" not in report:
            try:
                capture_final()
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                report["final_capture_error"] = str(error)
        for result in handles.values():
            result.with_suffix(".release").touch()
        try:
            processes = owned_processes(root)
        except (OSError, ValueError, KeyError) as error:
            processes = []
            failures.append(f"owned process inspection failed: {error}")
        stops = [[*cli, "agent", "stop", selected] for selected in reversed(created)]
        stops.append([*cli, "stop"])
        for arguments in stops:
            try:
                result = command(arguments, check=False, timeout=150)
                if result.returncode:
                    failures.append(f"cleanup exited {result.returncode}: {arguments}")
            except (OSError, subprocess.SubprocessError) as error:
                failures.append(f"cleanup failed: {arguments}: {error}")
        failures.extend(surviving_processes(processes))
        report["cleanup_failures"] = failures
        save()
        if failures:
            raise RuntimeError(f"owned instance cleanup failed; inspect {base}/observed.json")
    print(json.dumps({"result": str(base / "observed.json"), "completed": report["backend_operations_completed"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--native-test-binary", type=Path, required=True)
    args = parser.parse_args()
    run_proof(args.root.resolve(strict=True), args.base.resolve(), args.native_test_binary.resolve(strict=True))
