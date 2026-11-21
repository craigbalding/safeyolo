"""Native recovery controls in owned roots; installed runsc/VZ proof is separate.

Set SAFEYOLO_RETAINED_STATE_HELPER to the candidate Linux guest helper. Install
etckeeper from the trusted guest inventory (or use its extracted package with
ETCKEEPER_CONF_DIR). No test installs into the running environment.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import time
from contextlib import chdir
from pathlib import Path

import pytest

HELPER = os.environ.get("SAFEYOLO_RETAINED_STATE_HELPER")
pytestmark = pytest.mark.skipif(not HELPER or not shutil.which("etckeeper"), reason="candidate helper and etckeeper required")


def run(*args, check=True, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, **kwargs)
    if check and result.returncode:
        raise AssertionError(f"{args}: {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


@pytest.fixture
def guest(tmp_path):
    root, state = tmp_path / "root", tmp_path / "home-state"
    for path in ("etc", "usr/local/etc", "var/lib/dpkg", "var/lib/apt", "var/cache/apt/archives/partial", "var/lib/apt/lists/partial", "var/log/apt", "etc/apt/apt.conf.d"):
        (root / path).mkdir(parents=True, exist_ok=True)
    (root / "var/lib/dpkg/status").write_text("")
    (root / "etc/os-release").write_text('ID=debian\nVERSION_CODENAME=trixie\n')
    (root / "etc/fixture.conf").write_text("base\n")
    baseline = root / "usr/share/safeyolo/guest-base"
    (baseline / "configuration").mkdir(parents=True)
    shutil.copytree(root / "etc", baseline / "configuration/etc")
    (baseline / "configuration/usr/local/etc").mkdir(parents=True)
    (baseline / "packages.tsv").write_text("")
    command = [str(HELPER), "retained-state", "--root", str(root), "--directory", str(state)]
    run(*command, "start")
    return root, state, command


def saved(state):
    return json.loads((state / "state.json").read_text())


def eventually(check):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if result := check():
            return result
        time.sleep(0.05)
    raise AssertionError("capture did not complete")


def test_event_capture_coverage_metadata_and_killed_watcher(guest):
    root, state, command = guest
    with (state / "watch-output").open("w") as log:
        watch = subprocess.Popen([*command, "watch"], stdout=log, stderr=log)
        try:
            eventually(lambda: saved(state).get("watch", {}).get("pid") == watch.pid)
            config = root / "etc/fixture.conf"
            config.write_text("direct edit\n")
            expected = hashlib.sha256(config.read_bytes()).hexdigest()
            eventually(lambda: saved(state)["configuration"].get("/etc/fixture.conf", {}).get("hash") == expected)
            atomic = config.with_suffix(".replacement")
            atomic.write_text("atomic edit\n")
            atomic.replace(config)
            config.chmod(0o600)
            expected = hashlib.sha256(config.read_bytes()).hexdigest()
            eventually(lambda: saved(state)["configuration"]["/etc/fixture.conf"].get("hash") == expected
                       and saved(state)["configuration"]["/etc/fixture.conf"]["mode"] == 0o600)
            outside = root / "opt/example"
            outside.mkdir(parents=True)
            (outside / "settings").write_text("outside /etc\n")
            run(*command, "paths", "add", "/opt/example")
            assert (state / "configuration/opt/example/settings").read_text() == "outside /etc\n"
            assert "0600 './etc/fixture.conf'" in (state / "configuration/.etckeeper").read_text()
            config.unlink()
            eventually(lambda: "/etc/fixture.conf" not in saved(state)["configuration"])
            assert "guest configuration capture" in run(*command, "history").stdout
            before = saved(state)
            # The live watcher has not completed its one-second debounce for
            # this edit. A forced stop can lose precisely this uncommitted work.
            (outside / "settings").write_text("uncommitted before force-stop\n")
            watch.kill()
            watch.wait(timeout=5)
            run(*command, "start")
            assert saved(state)["configuration"] == before["configuration"]
            assert saved(state)["reconcile_required"] is True
            assert saved(state)["coverage"] == before["coverage"]
            assert run(*command, "capture", check=False).returncode
            assert saved(state)["status"] == "needs_attention"
            assert (state / "configuration/opt/example/settings").read_text() == "outside /etc\n"
        finally:
            if watch.poll() is None:
                watch.kill()
                watch.wait(timeout=5)


def test_idle_watcher_does_not_wake_itself_on_recorder_lock_closes(guest):
    _, state, command = guest
    before = saved(state)["last_completed_capture"]
    with (state / "watch-output").open("w") as log:
        watch = subprocess.Popen([*command, "watch"], stdout=log, stderr=log)
        try:
            eventually(lambda: saved(state)["last_completed_capture"] != before)
            time.sleep(0.2)

            def cpu_seconds():
                fields = Path(f"/proc/{watch.pid}/stat").read_text().rsplit(")", 1)[1].split()
                return sum(int(fields[index]) for index in (11, 12)) / os.sysconf("SC_CLK_TCK")

            cpu = cpu_seconds()
            time.sleep(2)
            # The observed feedback loop used most of one CPU while idle.
            # Permit bookkeeping overhead without accepting that busy loop.
            assert cpu_seconds() - cpu < 0.25
            assert watch.poll() is None
        finally:
            watch.kill()
            watch.wait(timeout=5)


def make_deb(directory, version):
    package = directory / f"package-{version}"
    (package / "DEBIAN").mkdir(parents=True)
    (package / "DEBIAN/control").write_text(
        f"Package: sy-retention-fixture\nVersion: {version}\nArchitecture: all\nMaintainer: Test <test@localhost>\nDescription: isolated retained-state fixture\n")
    (package / "usr/share/retention-fixture").mkdir(parents=True)
    (package / "usr/share/retention-fixture/version").write_text(version)
    archive = directory / f"fixture-{version}.deb"
    run("dpkg-deb", "--root-owner-group", "--build", str(package), str(archive))
    return archive


def test_direct_dpkg_selections_and_adopted_constraints(guest, tmp_path):
    root, state, command = guest
    archive = make_deb(tmp_path, "1.0")
    hooks = ["--pre-invoke=" + shlex.join([*command, "dpkg-pre"]),
             "--post-invoke=" + shlex.join([*command, "dpkg-post"]),
             "--status-logger=" + shlex.join([*command, "dpkg-status"])]
    run("dpkg", "--root=" + str(root), "--force-not-root", "--force-script-chrootless", *hooks, "--install", str(archive))
    run(*command, "capture")
    record = saved(state)
    assert record["packages"]["sy-retention-fixture"]["version"] == "1.0"
    assert record["desired_packages"]["sy-retention-fixture"]["action"] == "install"
    assert record["desired_packages"]["sy-retention-fixture"]["requested_archive"]["version"] == "1.0"
    assert any(tx["post_hook_seen"] for tx in record["transactions"].values())
    assert all(tx["outcome"] != "succeeded" for tx in record["transactions"].values())
    with (state / "watch-output").open("w") as log:
        watch = subprocess.Popen([*command, "watch"], stdout=log, stderr=log)
        try:
            eventually(lambda: saved(state).get("watch", {}).get("pid") == watch.pid)
            run("apt-mark", "-o", "Dir::State::status=" + str(root / "var/lib/dpkg/status"), "hold", "sy-retention-fixture")
            eventually(lambda: saved(state)["desired_packages"]["sy-retention-fixture"].get("hold") is True)
        finally:
            watch.kill()
            watch.wait(timeout=5)
    run(*command, "require", "sy-retention-fixture", "ge", "2.0", "debian:trixie", "advisory:test")
    result = run(*command, "restore", check=False)
    assert result.returncode
    assert "hold conflicts" in (state / "state.json").read_text()
    assert saved(state)["requirements"]["sy-retention-fixture"]["version"] == "2.0"
    run(*command, "require", "sy-retention-fixture", "ge", "0.9", "debian:trixie", "advisory:test")
    run(*command, "restore")
    assert saved(state)["restore"]["installs"] == []
    assert (root / "usr/share/retention-fixture/version").read_text() == "1.0"


def test_changed_base_does_not_erase_saved_configuration(guest):
    root, state, command = guest
    (root / "etc/fixture.conf").write_text("local change\n")
    run(*command, "capture")
    before = saved(state)
    (root / "usr/share/safeyolo/guest-base/configuration/etc/new-default").write_text("new secure default\n")
    (root / "etc/fixture.conf").write_text("new base conflicts\n")
    run(*command, "start")
    assert saved(state)["configuration"] == before["configuration"]
    result = run(*command, "restore", check=False)
    assert result.returncode
    assert "/etc/fixture.conf" in saved(state)["restore"]["configuration_conflicts"]
    assert (state / "configuration/etc/fixture.conf").read_text() == "local change\n"
    assert (root / "etc/fixture.conf").read_text() == "new base conflicts\n"
    (root / "etc/fixture.conf").write_text("new base security default\nreviewed local setting\n")
    run(*command, "resolve", "/etc/fixture.conf")
    run(*command, "restore")
    assert (state / "configuration/etc/fixture.conf").read_text() == "new base security default\nreviewed local setting\n"


def test_uncommitted_mirror_does_not_replace_completed_checkpoint(guest):
    root, state, command = guest
    config = root / "etc/fixture.conf"
    config.write_text("completed local setting\n")
    run(*command, "capture")
    before = saved(state)
    assert before["configuration_commit"]
    # These are the observable bytes left by an interrupted mirror update.
    (state / "configuration/etc/fixture.conf").write_text("uncommitted copy\n")
    (state / "configuration/etc/partial-new-file").write_text("incomplete\n")
    config.write_text("base\n")
    run(*command, "start")
    run(*command, "restore")
    assert (state / "configuration/etc/fixture.conf").read_text() == "completed local setting\n"
    assert not (state / "configuration/etc/partial-new-file").exists()
    assert saved(state)["configuration_commit"] == before["configuration_commit"]
    assert "/etc/fixture.conf" in saved(state)["restore"]["configuration_changes"]


@pytest.mark.parametrize("mode", [0o400, 0o440])
def test_configuration_copy_without_timestamp_permission(guest, tmp_path, monkeypatch, mode):
    root, state, command = guest
    tools = tmp_path / "copy-tools"
    tools.mkdir()
    copier = tools / "cp"
    # Model the actual gofer refusal without requiring a protected runtime.
    # Ownership and mode still come from the retained configuration record.
    copier.write_text(
        '#!/bin/sh\nfor option do\n'
        '  case "$option" in --preserve=*timestamps*) echo "timestamps denied" >&2; exit 1;; esac\n'
        'done\nexec ' + shlex.quote(shutil.which("cp")) + ' "$@"\n'
    )
    copier.chmod(0o755)
    monkeypatch.setenv("PATH", str(tools) + os.pathsep + os.environ["PATH"])
    config = root / "etc/private.conf"
    config.write_text("synthetic private configuration\n")
    config.chmod(mode)
    os.utime(config, (1700000000, 1700000000))
    link = root / "etc/private-link"
    link.symlink_to(config.name)
    run(*command, "capture")
    record = saved(state)
    expected = record["configuration"]["/etc/private.conf"]
    for copied in (config, state / "configuration/etc/private.conf"):
        metadata = copied.stat()
        assert hashlib.sha256(copied.read_bytes()).hexdigest() == expected["hash"]
        assert metadata.st_mode & 0o7777 == mode == expected["mode"]
        assert (metadata.st_uid, metadata.st_gid) == (expected["uid"], expected["gid"])
    assert (state / "configuration/etc/private-link").readlink() == Path(config.name)
    assert state.stat().st_mode & 0o7777 == 0o700
    assert (state / "configuration").stat().st_mode & 0o7777 == 0o700
    config.unlink()
    link.unlink()
    run(*command, "restore")
    assert config.read_text() == "synthetic private configuration\n"
    assert config.stat().st_mode & 0o7777 == mode
    assert link.readlink() == Path(config.name)
    before = saved(state)
    copier.write_text('#!/bin/sh\necho "synthetic copy failure" >&2\nexit 23\n')
    (root / "etc/new-setting").write_text("not completed\n")
    result = run(*command, "capture", check=False)
    assert result.returncode
    assert "synthetic copy failure" in result.stderr
    assert saved(state)["last_completed_capture"] == before["last_completed_capture"]
    assert "synthetic copy failure" in saved(state)["capture_error"]


def test_interrupted_dpkg_and_capture_failure_remain_visible(guest, tmp_path):
    import signal
    import socket

    root, state, command = guest
    archive = make_deb(tmp_path, "1.0")
    ready = tmp_path / "pre-invoke-ready"
    pre = shlex.join([*command, "dpkg-pre"]) + "; touch " + shlex.quote(str(ready)) + "; sleep 60"
    with (tmp_path / "dpkg-output").open("w") as log:
        process = subprocess.Popen(["dpkg", "--root=" + str(root), "--force-not-root", "--force-script-chrootless",
                                    "--pre-invoke=" + pre, "--install", str(archive)], stdout=log, stderr=log,
                                   start_new_session=True)
        try:
            eventually(ready.exists)
        finally:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    run(*command, "capture")
    assert any(tx["outcome"] == "interrupted_or_post_hook_absent" for tx in saved(state)["transactions"].values())
    before = saved(state)["last_completed_capture"]
    with socket.socket(socket.AF_UNIX) as unsupported:
        # UNIX sockets are runtime state, not restorable configuration files.
        # The recorder reports this uncovered type rather than claiming capture.
        # The kernel's Unix-socket path limit is independent of pytest's root.
        with chdir(root / "etc"):
            unsupported.bind("runtime.socket")
        assert run(*command, "capture", check=False).returncode
        assert saved(state)["last_completed_capture"] == before
        assert "unsupported configuration file type" in saved(state)["capture_error"]


@pytest.mark.parametrize("package_request", ["archive", "version", "release"])
def test_apt_choices_survive_real_nested_dpkg_hooks(guest, tmp_path, package_request):
    root, state, command = guest
    archive = make_deb(tmp_path, "1.0")
    (root / "usr/bin").mkdir(parents=True)
    for name in ("dpkg-query", "etckeeper"):
        shutil.copy2(shutil.which(name), root / "usr/bin" / name)
    (root / "etc/etckeeper").mkdir()
    (root / "etc/etckeeper/etckeeper.conf").write_text('VCS="git"\n')
    run("bash", "-c", 'source "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh"; install_safeyolo_guest_state "$TEST_ROOTFS"',
        env={**os.environ, "SAFEYOLO_GUEST_SRC_DIR": str(Path(__file__).resolve().parents[1] / "guest"),
             "TEST_ROOTFS": str(root)})
    wrapper = root / "usr/local/lib/safeyolo/guest-state-hook"
    wrapper.write_text(wrapper.read_text().replace("/run/safeyolo/safeyolo-guest", str(HELPER))
                       .replace('retained-state "$@"', shlex.join(command[1:]) + ' "$@"'))
    apt_hook = root / "etc/apt/apt.conf.d/05etckeeper"
    apt_hook.write_text(apt_hook.read_text().replace("/usr/local/lib/safeyolo/guest-state-hook", str(wrapper)))
    assert "AVOID_DAILY_AUTOCOMMITS=1" in (root / "etc/etckeeper/etckeeper.conf").read_text()
    options = ["-o", "Dir=" + str(root),
               "-o", "Dir::State::status=" + str(root / "var/lib/dpkg/status"),
               "-o", "Dir::Etc::sourcelist=-", "-o", "Dir::Etc::sourceparts=-",
               "-o", "Debug::NoLocking=1", "-o", "APT::Sandbox::User=" + str(os.getuid()),
               "-o", "DPkg::Options::=--root=" + str(root), "-o", "DPkg::Options::=--force-not-root",
               "-o", "DPkg::Options::=--force-script-chrootless"]
    config = tmp_path / "apt.conf"
    config.write_text(f'Dir "{root}";\nDir::Etc::parts "{root}/etc/apt/apt.conf.d";\nDir::Etc::main "{root}/etc/apt/apt.conf";\n')
    options += ["-o", "DPkg::Options::=--log=" + str(root / "var/log/dpkg.log")]
    # --root does not redirect dpkg's host configuration lookup. Pass the
    # shipped hook settings explicitly, rebinding only the owned wrapper path.
    dpkg_config = root / "etc/dpkg/dpkg.cfg.d/99safeyolo-guest-state"
    for setting in dpkg_config.read_text().splitlines():
        options += ["-o", "DPkg::Options::=--" + setting.replace("/usr/local/lib/safeyolo/guest-state-hook", str(wrapper))]
    if package_request == "archive":
        operand = str(archive)
    else:
        repository = tmp_path / "repository"
        repository.mkdir()
        shutil.copy2(archive, repository / archive.name)
        (repository / "Packages").write_text(
            run("dpkg-deb", "--field", str(archive)).stdout.rstrip() + "\n"
            + f"Filename: ./{archive.name}\nSize: {archive.stat().st_size}\n"
            + f"SHA256: {hashlib.sha256(archive.read_bytes()).hexdigest()}\n\n")
        (repository / "Release").write_text("Suite: fixture-release\nCodename: fixture-release\n")
        sources = root / "etc/apt/sources.list"
        sources.write_text(f"deb [trusted=yes] file:{repository} ./\n")
        options += ["-o", "Dir::Etc::sourcelist=" + str(sources)]
        run("apt-get", *options, "update", env={**os.environ, "APT_CONFIG": str(config)})
        operand = "sy-retention-fixture" + ("=1.0" if package_request == "version" else "/fixture-release")
    run("apt-get", *options, "-y", "--no-install-recommends", "install", operand,
        env={**os.environ, "APT_CONFIG": str(config)})
    run(*command, "capture")
    record = saved(state)
    plans = [tx["plan"] for tx in record["transactions"].values() if "plan" in tx]
    assert plans and plans[0][0]["package"] == "sy-retention-fixture"
    assert plans[0][0]["version"] == "1.0"
    assert any(tx.get("requested_archives") for tx in record["transactions"].values())
    choice = record["desired_packages"]["sy-retention-fixture"]
    assert choice["requested_archive"]["version"] == "1.0"
    if package_request == "version":
        assert choice["version"] == "1.0"
    elif package_request == "release":
        assert choice["release"] == "fixture-release"
    else:
        assert "version" not in choice and "release" not in choice
    assert (root / "usr/share/retention-fixture/version").read_text() == "1.0"
    # A later direct dpkg invocation deliberately requests an archive, without
    # adopting the earlier APT pin or release as its own requirement.
    hooks = ["--" + setting.replace("/usr/local/lib/safeyolo/guest-state-hook", str(wrapper))
             for setting in dpkg_config.read_text().splitlines()]
    run("dpkg", "--root=" + str(root), "--force-not-root", "--force-script-chrootless", *hooks, "--install", str(archive))
    choice = saved(state)["desired_packages"]["sy-retention-fixture"]
    assert "version" not in choice and "release" not in choice


def test_changed_account_mapping_requires_review(guest):
    root, state, command = guest
    uid, gid = os.getuid(), os.getgid()
    (root / "etc/passwd").write_text(f"old-owner:x:{uid}:{gid}::/:/bin/sh\n")
    (root / "etc/group").write_text(f"old-group:x:{gid}:\n")
    (root / "etc/fixture.conf").write_text("private local setting\n")
    run(*command, "capture")
    (root / "etc/fixture.conf").write_text("base\n")
    (root / "etc/passwd").write_text(f"different-owner:x:{uid}:{gid}::/:/bin/sh\n")
    result = run(*command, "restore", check=False)
    assert result.returncode
    assert "/etc/fixture.conf" in saved(state)["restore"]["configuration_conflicts"]
    assert (root / "etc/fixture.conf").read_text() == "base\n"


def test_unknown_original_baseline_is_explicit(guest):
    root, state, command = guest
    shutil.rmtree(root / "usr/share/safeyolo/guest-base")
    unknown = state.with_name("unknown-baseline-state")
    command = [*command[:-1], str(unknown)]
    run(*command, "start")
    status = json.loads(run(*command, "status").stdout)
    assert status["baseline_known"] is False
    assert status["paths_without_original_baseline"] == ["/etc", "/usr/local/etc"]
    assert saved(unknown)["baseline"] == {}
    (root / "etc/fixture.conf").write_text("different new default\n")
    assert run(*command, "restore", check=False).returncode
    assert (root / "etc/fixture.conf").read_text() == "different new default\n"


def test_removed_coverage_stops_tracking_without_removing_application_files(guest):
    root, state, command = guest
    outside = root / "opt/example"
    outside.mkdir(parents=True)
    (outside / "settings").write_text("application configuration\n")
    run(*command, "paths", "add", "/opt//example/")
    assert "/opt/example" in saved(state)["coverage"]
    run(*command, "paths", "remove", "/opt/example")
    assert "/opt/example" not in saved(state)["coverage"]
    assert "/opt/example/settings" not in saved(state)["configuration"]
    assert not (state / "configuration/opt/example/settings").exists()
    assert (outside / "settings").read_text() == "application configuration\n"


@pytest.mark.parametrize("excluded", ["app/agent_token", "etc/environment", "safeyolo/private"])
def test_configuration_rejects_symlink_parents_but_retains_symlinks(guest, excluded):
    root, state, command = guest
    target = root / excluded
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("synthetic excluded credential\n")
    alias = root / "opt/a"
    alias.parent.mkdir()
    alias.symlink_to(target.parent, target_is_directory=True)
    before = saved(state)
    result = run(*command, "paths", "add", f"/opt/a/{target.name}", check=False)
    assert result.returncode
    assert "configuration parent is a symlink" in result.stderr
    assert saved(state)["coverage"] == before["coverage"]
    assert saved(state)["configuration_commit"] == before["configuration_commit"]
    # The link itself is configuration. Its target's contents are not captured.
    run(*command, "paths", "add", "/opt/a")
    mirror = state / "configuration/opt/a"
    assert mirror.is_symlink()
    assert mirror.readlink() == target.parent
    assert saved(state)["configuration"]["/opt/a"]["kind"] == "symlink"
    assert not any(path.startswith("/opt/a/") for path in saved(state)["configuration"])


@pytest.mark.parametrize("watching", [False, True])
def test_capture_and_watch_report_a_replaced_symlink_parent(guest, watching):
    root, state, command = guest
    outside = root / "opt/example"
    outside.mkdir(parents=True)
    (outside / "settings").write_text("retained application setting\n")
    run(*command, "paths", "add", "/opt/example/settings")
    sensitive = root / "app"
    sensitive.mkdir()
    (sensitive / "settings").write_text("synthetic excluded credential\n")
    with (state / "watch-output").open("w") as log:
        watch = subprocess.Popen([*command, "watch"], stdout=log, stderr=log) if watching else None
        try:
            if watch is not None:
                eventually(lambda: saved(state).get("watch", {}).get("pid") == watch.pid)
                eventually(lambda: saved(state)["status"] == "captured")
            before = saved(state)
            outside.rename(outside.with_name("original"))
            outside.symlink_to(sensitive, target_is_directory=True)
            if watch is not None:
                eventually(lambda: saved(state)["status"] == "needs_attention")
            else:
                assert run(*command, "capture", check=False).returncode
            record = saved(state)
            assert "configuration parent is a symlink" in record["capture_error"]
            assert record["configuration_commit"] == before["configuration_commit"]
            assert (state / "configuration/opt/example/settings").read_text() == "retained application setting\n"
        finally:
            if watch is not None:
                if watch.poll() is None:
                    watch.kill()
                watch.wait(timeout=5)


def test_adopted_requirement_checks_actual_package_and_reuses_newer_base(guest, tmp_path):
    root, state, command = guest
    older = make_deb(tmp_path, "1.0")
    run("dpkg", "--root=" + str(root), "--force-not-root", "--force-script-chrootless", "--install", str(older))
    # Make this package an actual base-provided prerequisite, not a local pin.
    observed = run("dpkg-query", "--admindir=" + str(root / "var/lib/dpkg"), "-W",
                   "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n").stdout
    (root / "usr/share/safeyolo/guest-base/packages.tsv").write_text(observed)
    run(*command, "require", "sy-retention-fixture", "ge", "2.0", "debian:trixie", "advisory:test")
    assert run(*command, "restore", check=False).returncode
    assert saved(state)["restore"]["package_blockers"]
    assert (root / "usr/share/retention-fixture/version").read_text() == "1.0"
    newer = make_deb(tmp_path, "3.0")
    run("dpkg", "--root=" + str(root), "--force-not-root", "--force-script-chrootless", "--install", str(newer))
    run(*command, "restore")
    assert saved(state)["restore"]["installs"] == []
    assert (root / "usr/share/retention-fixture/version").read_text() == "3.0"


def test_image_baseline_excludes_generated_values_and_replaces_old_reference(guest, tmp_path):
    root, _, _ = guest
    baseline = tmp_path / "assembled-baseline"
    for path in ("environment", "hostname", "passwd", "apt/apt.conf.d/99safeyolo-proxy", "ssl/certs/safeyolo.pem"):
        file = root / "etc" / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("generated-per-run-fixture-value\n")
    source = (Path(__file__).resolve().parents[1] / "guest/rootfs/safeyolo-guest-state-base").read_text()
    # Rebind only the selected source/destination roots. Execute the shipped
    # tar exclusions and actual dpkg query instead of duplicating their logic.
    source = source.replace('base=/usr/share/safeyolo/guest-base', 'base="$TEST_BASE"')
    source = source.replace('tar -C / ', 'tar -C "$TEST_ROOT" ')
    script = tmp_path / "capture-image-base"
    script.write_text('dpkg-query() { command dpkg-query "--admindir=$TEST_ROOT/var/lib/dpkg" "$@"; }\n' + source)
    environment = {**os.environ, "TEST_ROOT": str(root), "TEST_BASE": str(baseline)}
    run("bash", str(script), env=environment)
    assert (baseline / "configuration/etc/fixture.conf").read_text() == "base\n"
    assert not any(b"generated-per-run-fixture-value" in path.read_bytes()
                   for path in baseline.rglob("*") if path.is_file())
    (root / "etc/fixture.conf").unlink()
    run("bash", str(script), env=environment)
    assert not (baseline / "configuration/etc/fixture.conf").exists()
