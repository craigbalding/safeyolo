"""Exercise storage protection without a VM, host disk fill or Rundeck job."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.devstack_storage import guard, install

SCRIPT = Path(guard.__file__)
pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Devstack uses Linux allocation and GNU command interfaces")


@pytest.fixture
def config(tmp_path, monkeypatch):
    spool = tmp_path / "temporary"
    spool.mkdir(mode=0o700)
    value = {"filesystems": [str(tmp_path)], "minimum_free_gib": 0, "minimum_free_inodes": 0,
                 "emergency_bytes": 8192,
                 "maximum_output_bytes": 1024, "spool": str(spool), "status_file": str(tmp_path / "status.json")}
    binary = tmp_path / "bin"
    binary.mkdir()
    # The existing SSH boundary executes locally in these controls. No new
    # network route, guest boot or model invocation is needed.
    fake = binary / "ssh"
    fake.write_text('#!/bin/bash\nexec bash -c "${@: -1}"\n')
    fake.chmod(0o700)
    monkeypatch.setenv("PATH", str(binary) + os.pathsep + os.environ["PATH"])
    return value


def invoke(config, *arguments):
    path = Path(config["spool"]).parent / "config.json"
    path.write_text(json.dumps(config))
    return subprocess.run([sys.executable, str(SCRIPT), "--config", str(path), *arguments],
                          capture_output=True, text=True, timeout=15)


def receipt(result):
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.removeprefix("HARNESS_JSON:"))


@pytest.mark.parametrize("failure", ["bytes", "inodes", "unknown", "status"])
def test_actual_child_refusal_and_recovery(config, tmp_path, failure):
    marker = tmp_path / "child-ran"
    arguments = ("ssh-exec", "--key", "unused", "--ip", "fixture", "--script",
                 base64.b64encode(f"touch {shlex.quote(str(marker))}; exit 7\n".encode()).decode())
    normal = dict(config)
    space = os.statvfs(tmp_path)
    if failure == "bytes":
        config["minimum_free_gib"] = (space.f_bavail * space.f_frsize + guard.GIB) / guard.GIB
    elif failure == "inodes":
        config["minimum_free_inodes"] = space.f_favail + 10000
    elif failure == "unknown":
        config["filesystems"] = [str(tmp_path / "missing-filesystem")]
    else:
        config["status_file"] = str(tmp_path / "missing-status-parent" / "status.json")
    result = invoke(config, *arguments)
    assert result.returncode == 75
    assert not marker.exists()
    assert not list(Path(config["spool"]).iterdir())
    recovered = receipt(invoke(normal, *arguments))
    assert recovered["exit_code"] == 7
    assert marker.exists()
    status = Path(normal["status_file"])
    assert json.loads(status.read_text())["state"] == "READY"
    assert status.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".status-*"))


def test_no_output_deadlock_or_remote_interruption(config, tmp_path):
    marker = tmp_path / "completed"
    script = f"head -c 100000 /dev/zero; head -c 100000 /dev/zero >&2; touch {shlex.quote(str(marker))}; exit 7"
    result = receipt(invoke(config, "ssh-exec", "--key", "unused", "--ip", "fixture", "--script",
                            base64.b64encode(script.encode()).decode()))
    assert marker.exists()
    assert result["exit_code"] == 7
    assert result["stdout_truncated"] and result["stderr_truncated"]
    assert len(base64.b64decode(result["stdout_b64"])) == config["maximum_output_bytes"]
    assert len(base64.b64decode(result["stderr_b64"])) == config["maximum_output_bytes"]
    assert not list(Path(config["spool"]).iterdir())


def test_timeout_is_reported(config):
    result = receipt(invoke(config, "ssh-exec", "--key", "unused", "--ip", "fixture", "--script",
                            base64.encodebytes(b"sleep 10\n").decode(), "--timeout", "0.1s"))
    assert result["timed_out"] and result["exit_code"] == 124


@pytest.mark.parametrize("maximum", [0, 2048, 8192])
def test_fetch_bounds_transfer_before_storage(config, tmp_path, maximum):
    source = tmp_path / "source with ' quotes"
    data = b"a" * 4096
    source.write_bytes(data)
    result = receipt(invoke(config, "ssh-fetch", "--key", "unused", "--ip", "fixture", "--path", str(source),
                            "--maximum-bytes", str(maximum)))
    assert result["size"] == len(data)
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert base64.b64decode(result["content_b64"]) == data[:maximum]
    assert result["truncated"] is (maximum < len(data))
    assert not list(Path(config["spool"]).iterdir())


def test_copy_observes_both_destinations(config, tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"payload")
    for direction in ("to", "from"):
        args = ("check-copy", "--key", "unused", "--ip", "fixture", direction, str(source), str(tmp_path / "destination"))
        assert invoke(config, *args).returncode == 0
        config["minimum_free_gib"] = 10**6
        assert invoke(config, *args).returncode == 75
        config["minimum_free_gib"] = 0


@pytest.mark.parametrize("failure", ["bytes", "inodes", "unknown"])
def test_copy_refuses_low_or_unknown_guest_storage(config, tmp_path, monkeypatch, failure):
    source = tmp_path / "source"
    source.write_bytes(b"payload")
    config["minimum_free_inodes"] = 1

    def remote(*_):
        if failure == "unknown":
            raise guard.NoSpace("unavailable guest observation")
        available = 0 if failure == "bytes" else 10000
        inodes = 0 if failure == "inodes" else 10000
        return (f"Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                f"disk 20000 10000 {available} 50% /\n"
                f"Filesystem Inodes IUsed IFree IUse% Mounted on\n"
                f"disk 20000 10000 {inodes} 50% /\n4096\n1\n").encode()

    monkeypatch.setattr(guard, "remote_read", remote)
    with pytest.raises(guard.NoSpace):
        guard.check_copy(config, argparse.Namespace(direction="to", source=str(source),
                                                   destination="/owned/destination", key="unused", ip="fixture"))


def test_known_growth_budget_before_allocation(config):
    assert invoke(config, "check", "--required-bytes", "1000000000000000").returncode == 75
    assert invoke(config, "check").returncode == 0


@pytest.mark.parametrize("size", ["20G", "90G"])
def test_sparse_image_admits_initial_growth_and_refuses_physical_shortfall(config, tmp_path, monkeypatch, size):
    guard.check(config)
    config.update(minimum_free_gib=10, minimum_free_inodes=4096)
    monkeypatch.setattr(guard.os, "statvfs", lambda _: SimpleNamespace(
        f_bavail=17 * guard.GIB, f_frsize=1, f_files=12997824, f_favail=12339577))
    qemu = tmp_path / "bin/qemu-img"
    qemu.write_text('#!/bin/bash\nsize=${@: -1}; size=${size%G}\n'
                    'printf \'{"required":%s,"fully-allocated":%s}\\n\' '
                    '"${MEASURE_REQUIRED_BYTES:-327680}" "$((size*1073741824+327680))"\n')
    qemu.chmod(0o700)
    guard.check_image(config, tmp_path, size)
    monkeypatch.setenv("MEASURE_REQUIRED_BYTES", str(8 * guard.GIB))
    with pytest.raises(guard.NoSpace):
        guard.check_image(config, tmp_path, size)
    monkeypatch.delenv("MEASURE_REQUIRED_BYTES")
    guard.check_image(config, tmp_path, size)


@pytest.mark.parametrize("measurement", ["{}", "[]", '{"required":true}', '{"required":-1}'])
def test_sparse_image_unknown_measurement_refuses(config, tmp_path, measurement):
    qemu = tmp_path / "bin/qemu-img"
    qemu.write_text("#!/bin/bash\nprintf '%s\\n' " + shlex.quote(measurement) + "\n")
    qemu.chmod(0o700)
    result = invoke(config, "check-image", "--path", str(tmp_path), "--size", "20G")
    assert result.returncode == 75


@pytest.mark.parametrize("guest_free,free_inodes,new_file,admitted", [
    (12 * 1024**2, 1, 1, True),
    (int(5.7 * guard.GIB), 1, 1, True),
    (32 * 1024, 1, 1, False),
    (12 * 1024**2, 0, 1, False),
    (12 * 1024**2, 0, 0, True),
])
def test_guest_copy_budgets_payload_and_metadata_independently(config, tmp_path, monkeypatch,
                                                            guest_free, free_inodes, new_file, admitted):
    guard.check(config)
    config.update(minimum_free_gib=10, minimum_free_inodes=4096)
    monkeypatch.setattr(guard.os, "statvfs", lambda _: SimpleNamespace(
        f_bavail=17 * guard.GIB, f_frsize=1, f_files=12997824, f_favail=12339577))
    source = tmp_path / "payload"
    source.write_bytes(b"p" * 65536)
    observation = (f"Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                   f"disk 20000000 10000 {guest_free // 1024} 50% /data\n"
                   f"Filesystem Inodes IUsed IFree IUse% Mounted on\n"
                   f"disk 20000 10000 {free_inodes} 50% /data\n4096\n{new_file}\n").encode()
    monkeypatch.setattr(guard, "remote_read", lambda *_: observation)
    args = argparse.Namespace(direction="to", source=str(source), destination="/data/payload", key="unused", ip="fixture")
    if admitted:
        guard.check_copy(config, args)
    else:
        with pytest.raises(guard.NoSpace):
            guard.check_copy(config, args)


def test_download_stops_on_new_pressure_and_removes_only_its_stage(config, tmp_path, monkeypatch):
    curl = tmp_path / "bin" / "curl"
    curl.write_text("#!/bin/bash\nhead -c 262144 /dev/zero\n")
    curl.chmod(0o700)
    config["minimum_free_gib"] = 1
    observations = 0
    guard.check({**config, "minimum_free_gib": 0})

    def space(_):
        nonlocal observations
        observations += 1
        available = guard.GIB + (3 * guard.CHUNK if observations <= 2 else guard.CHUNK - 1)
        return SimpleNamespace(f_bavail=available, f_frsize=1, f_files=10000, f_favail=9999)

    monkeypatch.setattr(guard.os, "statvfs", space)
    protected = tmp_path / "retained-input"
    protected.write_bytes(b"keep")
    destination = tmp_path / "image.part"
    with pytest.raises(guard.NoSpace):
        guard.download(config, argparse.Namespace(destination=str(destination), url="fixture"))
    assert observations == 3
    assert protected.read_bytes() == b"keep"
    assert not destination.exists()
    assert not list(Path(config["spool"]).iterdir())
    assert json.loads(Path(config["status_file"]).read_text())["state"] == "LOW_OR_UNKNOWN"


def test_cron_action_reclaims_dead_owner_while_preserving_live_and_retained(config, tmp_path):
    # The dead process leaves a genuine locked-then-published scratch directory.
    # A host scheduler can reclaim it even when no Rundeck command is admitted.
    code = ("import json, os; from pathlib import Path; from scripts.devstack_storage.guard import temporary_directory; "
            f"c=json.loads({json.dumps(json.dumps(config))}); "
            "d=temporary_directory(c).__enter__(); (d/'download').write_bytes(b'x'*8192); os._exit(0)")
    # Keep the context manager alive until _exit, rather than letting reference
    # counting perform its normal cleanup before the process dies.
    code = code.replace("d=temporary_directory(c).__enter__()", "owner=temporary_directory(c); d=owner.__enter__()")
    subprocess.run([sys.executable, "-c", code], check=True)
    spool = Path(config["spool"])
    abandoned = list(spool.iterdir())
    assert len(abandoned) == 1
    retained = spool / "retained-proof"
    retained.mkdir()
    (retained / "input").write_bytes(b"keep")
    with guard.temporary_directory(config) as live:
        (live / "script").write_text("active")
        # This is precisely the command installed into the independent crontab.
        assert invoke(config, "sweep").returncode == 0
        assert not abandoned[0].exists()
        assert (live / "script").read_text() == "active"
        assert (retained / "input").read_bytes() == b"keep"
        status = json.loads(Path(config["status_file"]).read_text())
        assert status["reclaimed_temporary_directories"] == 1


def test_independent_sweep_releases_real_allocated_space_and_recovery_rearms(config, tmp_path):
    guard.check(config)
    reserve = tmp_path / "emergency-space"
    allocated = reserve.stat().st_blocks * 512
    assert allocated >= config["emergency_bytes"]
    normal = dict(config)
    config["minimum_free_gib"] = 10**6
    # No disk fill and no daemon stop: only the observation threshold changes.
    refused = invoke(config, "check")
    assert refused.returncode == 75 and reserve.exists()
    assert invoke(config, "sweep").returncode == 75
    assert not reserve.exists()
    status = json.loads(Path(config["status_file"]).read_text())
    assert status["released_emergency_bytes"] == allocated
    assert status["state"] == "LOW_OR_UNKNOWN"
    assert invoke(config, "check").returncode == 75
    assert not reserve.exists()
    assert invoke(normal, "check").returncode == 0
    assert reserve.stat().st_blocks * 512 >= normal["emergency_bytes"]


def test_released_space_is_not_reused_for_new_admissions(config, tmp_path, monkeypatch):
    floor = guard.GIB
    config["minimum_free_gib"] = 1
    monkeypatch.setattr(guard.os, "statvfs", lambda _: SimpleNamespace(
        f_bavail=floor + config["emergency_bytes"] - 1, f_frsize=1, f_files=10000, f_favail=9999))
    with pytest.raises(guard.NoSpace):
        guard.check(config)
    assert not (tmp_path / "emergency-space").exists()
    assert json.loads(Path(config["status_file"]).read_text())["emergency_state"] == "waiting-for-recovery"


@pytest.mark.parametrize("kind", ["file", "link"])
def test_sweep_preserves_unrecognized_emergency_file(config, tmp_path, kind):
    protected = tmp_path / "protected"
    protected.write_bytes(b"retain")
    reserve = tmp_path / "emergency-space"
    if kind == "file":
        reserve.write_bytes(b"unrecognized")
    else:
        reserve.symlink_to(protected)
    config["minimum_free_gib"] = 10**6
    assert invoke(config, "sweep").returncode == 75
    assert reserve.exists() and protected.read_bytes() == b"retain"


def test_installer_rejects_changed_binding_before_any_write(tmp_path):
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    (jobs / "_common.sh").write_text("operator edit\n")
    bindings = tmp_path / "bindings.json"
    bindings.write_text(json.dumps({"scripts": [{"path": "/jobs/_common.sh", "sha256": "0" * 64}]}))
    state = tmp_path / "state"
    with pytest.raises(ValueError, match="differs from the observed host binding"):
        install.install(argparse.Namespace(bindings=bindings, jobs=jobs, state=state))
    assert not state.exists()
    assert (jobs / "_common.sh").read_text() == "operator edit\n"


@pytest.fixture
def bound_host_jobs(config, tmp_path, monkeypatch):
    if not os.environ.get("DEVSTACK_STORAGE_JOB_SOURCES"):
        pytest.skip("requires the operator-supplied nonsecret actual host job sources and binding receipt")
    sources = Path(os.environ["DEVSTACK_STORAGE_JOB_SOURCES"])
    jobs = tmp_path / "jobs"
    shutil.copytree(sources, jobs)
    harness = tmp_path / "harness"
    pool = tmp_path / "pool"
    pool.mkdir()
    (harness / "ssh").mkdir(parents=True)
    (harness / "ssh/id_ed25519.pub").write_text("fixture public key\n")
    # The cached base and allocator are stand-ins. Useful admission reaches
    # the allocator marker without a real disk allocation or guest boot.
    (pool / "ubuntu-24.04-server-cloudimg-amd64.img").write_text("cached\n")
    binary = tmp_path / "bin"
    # Synthetic host bytes match the supplied receipt. Keep real path failures
    # and inode observations so the existing refusal controls still apply.
    python = binary / "guard-python"
    python.write_text(f"#!{sys.executable}\n"
                      "import os, runpy, sys\nfrom types import SimpleNamespace\n"
                      "original = os.statvfs\n"
                      "def space(path):\n"
                      "    actual = original(path)\n"
                      "    return SimpleNamespace(f_bavail=17606909952, f_frsize=1, "
                      "f_files=actual.f_files, f_favail=actual.f_favail)\n"
                      "os.statvfs = space\n"
                      "script = sys.argv.pop(1); sys.argv[0] = script\n"
                      "runpy.run_path(script, run_name='__main__')\n")
    python.chmod(0o700)
    (binary / "virsh").write_text("#!/bin/bash\nexit 0\n")
    allocation = tmp_path / "allocator-invoked"
    (binary / "qemu-img").write_text(
        '#!/bin/bash\nif [[ $1 = measure ]]; then '
        'printf \'{"required":%s,"fully-allocated":21475164160}\\n\' "${MEASURE_REQUIRED_BYTES:-327680}"; '
        f'else touch {shlex.quote(str(allocation))}; exit 7; fi\n')
    cron_file = tmp_path / "crontab"
    cron_file.write_text("5 0 * * * preserve-existing-entry\n")
    (binary / "crontab").write_text(
        f'#!/bin/bash\nif [[ $1 = -l ]]; then cat {shlex.quote(str(cron_file))}; '
        f'else cat > {shlex.quote(str(cron_file))}; fi\n')
    for executable in ("virsh", "qemu-img", "crontab"):
        (binary / executable).chmod(0o700)
    monkeypatch.setenv("HARNESS_DIR", str(harness))
    monkeypatch.setenv("POOL_DIR", str(pool))
    args = argparse.Namespace(bindings=sources.parent / "host-bindings-14047.json", jobs=jobs,
                              state=harness / "storage", pool=pool, harness=harness, python=python,
                              minimum_free_gib=10, minimum_free_inodes=4096, maximum_output_bytes=1024,
                              emergency_bytes=8192,
                              install_cron=True)
    return args, install.install(args)


def test_bound_host_entry_points_and_crontab(bound_host_jobs, tmp_path, monkeypatch):
    args, installed = bound_host_jobs
    jobs = args.jobs
    sources = Path(os.environ["DEVSTACK_STORAGE_JOB_SOURCES"])
    binary = tmp_path / "bin"
    pool = args.pool
    cron_file = tmp_path / "crontab"
    allocation = tmp_path / "allocator-invoked"
    # A repeat does not replace backups, add another schedule or lose other jobs.
    assert install.install(args) == installed
    assert cron_file.read_text().count("# safeyolo-devstack-storage") == 1
    assert "preserve-existing-entry" in cron_file.read_text()
    for name in install.NAMES:
        subprocess.run(["bash", "-n", str(jobs / name)], check=True)
        assert (args.state / "original-jobs" / name).read_bytes() == (sources / name).read_bytes()
    marker = tmp_path / "entry-child"
    payload = base64.b64encode(f"touch {shlex.quote(str(marker))}; exit 7".encode()).decode()
    configuration = args.state / "config.json"
    healthy = json.loads(configuration.read_text())
    for failure in ("bytes", "inodes", "unknown", "status"):
        low = dict(healthy)
        if failure == "bytes":
            low["minimum_free_gib"] = 10**6
        elif failure == "inodes":
            low["minimum_free_inodes"] = os.statvfs(tmp_path).f_favail + 10000
        elif failure == "unknown":
            low["filesystems"] = [str(tmp_path / "unknown")]
        else:
            low["status_file"] = str(tmp_path / "missing" / "status.json")
        configuration.write_text(json.dumps(low))
        rejected = subprocess.run(["bash", str(jobs / "ssh_exec.sh"), "fixture", payload], capture_output=True)
        assert rejected.returncode == 75 and not marker.exists()
    configuration.write_text(json.dumps(healthy))
    recovered = subprocess.run(["bash", str(jobs / "ssh_exec.sh"), "fixture", payload], capture_output=True, text=True)
    assert receipt(recovered)["exit_code"] == 7 and marker.exists()
    source = tmp_path / "remote-source"
    source.write_bytes(b"p" * 8192)
    fetched = subprocess.run(["bash", str(jobs / "ssh_fetch.sh"), "fixture", str(source), "1024"],
                             capture_output=True, text=True)
    assert len(base64.b64decode(receipt(fetched)["content_b64"])) == 1024
    copied = tmp_path / "scp-invoked"
    (binary / "scp").write_text(f"#!/bin/bash\ntouch {shlex.quote(str(copied))}\n")
    (binary / "scp").chmod(0o700)
    (binary / "ssh").write_text(
        '#!/bin/bash\nif [[ ${@: -1} = *"df -Pk"* ]]; then\n'
        '  [[ ${GUEST_UNKNOWN:-0} = 0 ]] || exit 1\n'
        '  printf \'Filesystem 1024-blocks Used Available Capacity Mounted on\\n'
        'disk 20000000 10000 %s 50%% /data\\n'
        'Filesystem Inodes IUsed IFree IUse%% Mounted on\\n'
        'disk 20000 10000 %s 50%% /data\\n4096\\n1\\n\' '
        '"$GUEST_FREE_KIB" "${GUEST_FREE_INODES:-1}"\n'
        'else exec bash -c "${@: -1}"; fi\n')
    copy_command = f"source {shlex.quote(str(jobs / '_common.sh'))}; harness_scp_to fixture {shlex.quote(str(source))} /data/payload"
    for available in (12 * 1024, int(5.7 * guard.GIB) // 1024):
        monkeypatch.setenv("GUEST_FREE_KIB", str(available))
        copied.unlink(missing_ok=True)
        assert subprocess.run(["bash", "-c", copy_command], capture_output=True).returncode == 0
        assert copied.exists()
    for failure in ("bytes", "inodes", "unknown"):
        copied.unlink(missing_ok=True)
        monkeypatch.setenv("GUEST_FREE_KIB", "1" if failure == "bytes" else "12288")
        monkeypatch.setenv("GUEST_FREE_INODES", "0" if failure == "inodes" else "1")
        monkeypatch.setenv("GUEST_UNKNOWN", "1" if failure == "unknown" else "0")
        assert subprocess.run(["bash", "-c", copy_command], capture_output=True).returncode == 75
        assert not copied.exists()
    for name in ("GUEST_FREE_KIB", "GUEST_FREE_INODES", "GUEST_UNKNOWN"):
        monkeypatch.delenv(name)
    monkeypatch.setenv("MEASURE_REQUIRED_BYTES", "1000000000000000")
    provision = ["bash", str(jobs / "provision.sh"), "--scenario", "fixture", "--flavor", "bare", "--reuse", "--disk", "20"]
    rejected = subprocess.run(provision, capture_output=True)
    assert rejected.returncode == 75 and not allocation.exists()
    assert not (pool / ".guest-lease").exists()
    monkeypatch.delenv("MEASURE_REQUIRED_BYTES")
    for disk in ("20", "90"):
        allocation.unlink(missing_ok=True)
        admitted = subprocess.run([*provision[:-1], disk], capture_output=True)
        assert admitted.returncode == 7 and allocation.exists()
    protected = pool / "sy-protected-retained.qcow2"
    protected.write_bytes(b"retained")
    rejected = subprocess.run(["bash", str(jobs / "provision.sh"), "--scenario", "fixture", "--flavor", "bare",
                               "--clean"], capture_output=True)
    assert rejected.returncode == 64 and protected.read_bytes() == b"retained"
    # An orphan from the deployed temporary-file implementation is removed by
    # the exact installed cron body. There is no Rundeck call in that action.
    orphan_code = ("import json, os; from pathlib import Path; from scripts.devstack_storage.guard import temporary_directory; "
                   f"c=json.loads(Path({str(configuration)!r}).read_text()); owner=temporary_directory(c); "
                   "d=owner.__enter__(); (d/'download').write_bytes(b'p'*8192); os._exit(0)")
    subprocess.run([sys.executable, "-c", orphan_code], check=True)
    assert len(list(Path(healthy["spool"]).iterdir())) == 1
    cron_body = cron_file.read_text().splitlines()[-1].split(" ", 5)[5]
    configuration.write_text(json.dumps({**healthy, "minimum_free_gib": 10**6}))
    assert subprocess.run(["/bin/sh", "-c", cron_body]).returncode == 75
    assert not list(Path(healthy["spool"]).iterdir())
    assert not (args.state / "emergency-space").exists()
    configuration.write_text(json.dumps(healthy))
    subprocess.run(["/bin/sh", "-c", cron_body], check=True)
    assert (args.state / "emergency-space").stat().st_blocks * 512 >= args.emergency_bytes
    assert protected.read_bytes() == b"retained"
    changed = jobs / "_common.sh"
    changed.write_text(changed.read_text() + "# subsequent operator edit\n")
    with pytest.raises(ValueError, match="changed after the bound observation"):
        install.install(args)
    assert changed.read_text().endswith("# subsequent operator edit\n")


@pytest.mark.parametrize("destination_form", ["file-link", "directory-entry-link", "dangling-link"])
def test_bound_guest_copy_follows_destination_symlinks(bound_host_jobs, tmp_path, monkeypatch, destination_form):
    args, _ = bound_host_jobs
    scp = shutil.which("scp")
    sftp = Path("/usr/lib/openssh/sftp-server")
    if scp is None or not sftp.exists():
        pytest.skip("native local transfer requires OpenSSH scp and its SFTP server")
    source = tmp_path / "source/a"
    source.parent.mkdir()
    source.write_bytes(b"x")
    high = tmp_path / "guest-high 'quoted"
    low = tmp_path / "guest-low"
    high.mkdir()
    low.mkdir()
    target = low / source.name
    if destination_form != "dangling-link":
        target.write_bytes(b"original")
    link = high / source.name
    link.symlink_to(Path("..") / low.name / source.name)
    destination = high if destination_form == "directory-entry-link" else link
    binary = tmp_path / "bin"
    # Run the remote observation shell unchanged. Only df synthesizes the
    # two guest filesystems; no actual filesystem is filled.
    (binary / "df").write_text(
        f"#!{sys.executable}\nimport os, sys\nfrom pathlib import Path\n"
        f"low = Path({str(low)!r})\n"
        "path = Path(sys.argv[-1]).resolve()\n"
        "available = os.environ['GUEST_LOW_KIB'] if path.is_relative_to(low) else '12288'\n"
        "print('Filesystem Total Used Available Capacity Mounted')\n"
        "print('guest 20000000 0', available if '-Pk' in sys.argv else '10000', '0% /guest')\n")
    copied = tmp_path / "scp-invoked"
    # The installed harness still invokes scp. Its native local SFTP server
    # follows the link and performs the actual write without SSH or a guest.
    (binary / "scp").write_text(
        f"#!/bin/bash\ntouch {shlex.quote(str(copied))}\n"
        f"exec {shlex.quote(scp)} -D {shlex.quote(str(sftp))} \"$@\"\n")
    for executable in ("df", "scp"):
        (binary / executable).chmod(0o700)
    command = (f"source {shlex.quote(str(args.jobs / '_common.sh'))}; "
               f"harness_scp_to fixture {shlex.quote(str(source))} {shlex.quote(str(destination))}")
    monkeypatch.setenv("GUEST_LOW_KIB", "0")
    refused = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=15)
    assert refused.returncode == 75, refused.stderr
    assert not copied.exists()
    if destination_form == "dangling-link":
        assert not target.exists()
    else:
        assert target.read_bytes() == b"original"
    for available in (12 * 1024, int(5.7 * guard.GIB) // 1024):
        monkeypatch.setenv("GUEST_LOW_KIB", str(available))
        copied.unlink(missing_ok=True)
        admitted = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=15)
        assert admitted.returncode == 0, admitted.stderr
        assert copied.exists() and target.read_bytes() == b"x"
        assert link.is_symlink()
