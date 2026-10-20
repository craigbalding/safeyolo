#!/usr/bin/env python3
"""Run owned execution-boundary probes on macOS without changing login policy.

Run outside Seatbelt as a normal test user. Each run owns a fresh directory,
bundle IDs and launchd labels. This is a scoped-process test, not an account
audit or a physical VZ witness. Never run it through the active agent SSH entry.
"""

import argparse
import json
import os
import plistlib
import re
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, timeout=30, **kwargs)


def checked(argv, **kwargs):
    result = run(argv, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{argv}: {result.returncode}: {result.stdout}{result.stderr}")
    return result.stdout


def write_plist(path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(values))


def make_bundle(root, source, canary, identity):
    app = root / "Boundary.app"
    binary = app / "Contents/MacOS/probe"
    binary.parent.mkdir(parents=True)
    checked([
        "/usr/bin/xcrun", "clang", "-Wall", "-Wextra", "-Werror",
        "-Wno-deprecated-declarations", "-O2", "-fobjc-arc",
        "-framework", "Foundation", "-framework", "AppKit",
        "-framework", "ServiceManagement", str(source / "boundary-helper.m"),
        "-o", str(binary),
    ])
    info = {
        "CFBundleIdentifier": identity, "CFBundleExecutable": "probe",
        "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
        "LSUIElement": True, "ProbeMarker": str(root / "marker-main"),
        "ProbeReady": str(root / "event-ready"),
        "ProbeCanary": str(canary),
    }
    write_plist(app / "Contents/Info.plist", info)
    login = app / "Contents/Library/LoginItems/Login.app"
    (login / "Contents/MacOS").mkdir(parents=True)
    shutil.copy2(binary, login / "Contents/MacOS/probe")
    write_plist(login / "Contents/Info.plist", {
        **info, "CFBundleIdentifier": identity + ".login",
        "ProbeMarker": str(root / "marker-login"),
    })
    for kind, directory in (("agent", "LaunchAgents"), ("daemon", "LaunchDaemons")):
        write_plist(app / f"Contents/Library/{directory}/probe-{kind}.plist", {
            "Label": identity + "." + kind, "BundleProgram": "Contents/MacOS/probe",
            "RunAtLoad": True,
        })
    for target in (login, app):
        checked(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(target)])
        checked(["/usr/bin/codesign", "--verify", "--strict", str(target)])
    return app, binary


def service_observation(binary, action, kind, prefix=()):
    result = run([*prefix, str(binary), action, kind])
    if result.returncode:
        raise RuntimeError(f"ServiceManagement helper failed: {result.stdout}{result.stderr}")
    return json.loads(result.stdout)


def service_probes(binary, prefix):
    for kind in ("login", "agent", "daemon"):
        before = service_observation(binary, "status", kind)
        assert before["after"] in (0, 3), before
        observation = service_observation(binary, "register", kind, prefix)
        print(json.dumps(observation), flush=True)
        after = service_observation(binary, "status", kind)
        try:
            assert not observation["registered"] and after["after"] in (0, 3), after
            assert observation["smd_lookup"] == 1100, observation  # BOOTSTRAP_NOT_PRIVILEGED
        finally:
            if after["after"] not in (0, 3):
                print(json.dumps({"cleanup": service_observation(binary, "unregister", kind)}))
                assert service_observation(binary, "status", kind)["after"] in (0, 3)
        # The identical signed bundle must reach registration outside Seatbelt.
        # RequiresApproval (2) is registration even when the API returns false.
        try:
            control = service_observation(binary, "register", kind)
            print(json.dumps({"unconfined_control": control}), flush=True)
            assert control["after"] in (1, 2), control
        finally:
            if service_observation(binary, "status", kind)["after"] in (1, 2):
                print(json.dumps({"cleanup": service_observation(binary, "unregister", kind)}))
            assert service_observation(binary, "status", kind)["after"] in (0, 3)


def require_absent(target):
    result = run(["/bin/launchctl", "print", target])
    assert result.returncode == 113 and "Could not find service" in result.stderr, result


def refusal(argv, **kwargs):
    try:
        result = run(argv, **kwargs)
    except PermissionError as exc:
        print(json.dumps({"command": argv, "errno": exc.errno}), flush=True)
        return
    print(json.dumps({"command": argv, "returncode": result.returncode,
                      "stdout": result.stdout, "stderr": result.stderr}), flush=True)
    assert result.returncode != 0, f"unexpected success: {argv}"


def remove_job(target):
    result = run(["/bin/launchctl", "print", target])
    if result.returncode == 0:
        checked(["/bin/launchctl", "bootout", target])
    require_absent(target)


def marker_result(marker):
    deadline = time.monotonic() + 5
    while not marker.exists():
        assert time.monotonic() < deadline, f"owned helper did not write {marker}"
        time.sleep(0.05)
    return json.loads(marker.read_text())


def launchd_probes(home, binary, prefix, identity, trusted_policy):
    domain = f"gui/{os.getuid()}"
    checked(["/bin/launchctl", "print", domain])
    label, submitted = identity + ".direct", identity + ".submit"
    target, submitted_target = domain + "/" + label, domain + "/" + submitted
    plist = home / "Library/LaunchAgents/owned.plist"
    write_plist(plist, {"Label": label, "ProgramArguments": [str(binary)], "RunAtLoad": False})
    marker = home / "marker-main"
    marker.unlink(missing_ok=True)
    require_absent(target)
    require_absent(submitted_target)
    try:
        refusal([*prefix, "/bin/launchctl", "bootstrap", domain, str(plist)])
        require_absent(target)
        refusal([*prefix, "/bin/launchctl", "submit", "-l", submitted, "--", str(binary)])
        require_absent(submitted_target)
        assert not marker.exists()
        # This deliberately unsafe operator-created consumer is the exposure
        # setup must identify, even though job-creation itself is denied.
        checked(["/bin/launchctl", "bootstrap", domain, str(plist)])
        checked([*prefix, "/bin/launchctl", "kickstart", target])
        control = marker_result(marker)
        assert control["ppid"] == 1 and control["outside_read"] == 1, control
        print(json.dumps({"unsafe_preexisting_consumer": control}), flush=True)
        remove_job(target)
        marker.unlink()
        # Correct that consumer: protected system code attaches the protected
        # profile before reaching the same agent-writable executable.
        write_plist(plist, {"Label": label, "ProgramArguments": [
            "/usr/bin/sandbox-exec", "-f", str(trusted_policy),
            "-D", f"AGENT_HOME={home}", "-D", "TOOLCHAIN_ROOT=/opt/homebrew", str(binary),
        ], "RunAtLoad": False})
        refusal([*prefix, "/bin/sh", "-c", 'printf poison > "$1"', "sh", str(trusted_policy)])
        assert trusted_policy.read_bytes() == (home / "candidate.sb").read_bytes()
        checked(["/bin/launchctl", "bootstrap", domain, str(plist)])
        checked([*prefix, "/bin/launchctl", "kickstart", target])
        corrected = marker_result(marker)
        assert corrected["outside_read"] == 0 and corrected["errno"] in (1, 13), corrected
        print(json.dumps({"corrected_preexisting_consumer": corrected}), flush=True)
    finally:
        remove_job(target)
        remove_job(submitted_target)
    marker.unlink(missing_ok=True)


def scheduler_probes(home, prefix, identity):
    before = run(["/usr/bin/crontab", "-l"], env={**os.environ, "LC_ALL": "C"})
    assert before.returncode == 1 and "no crontab for" in before.stderr, "use a test user with no crontab"
    cron = home / "owned.crontab"
    text = f"0 0 1 1 * /usr/bin/touch {home}/cron-{identity}\n"
    cron.write_text(text)
    try:
        refusal([*prefix, "/usr/bin/crontab", str(cron)])
        after = run(["/usr/bin/crontab", "-l"], env={**os.environ, "LC_ALL": "C"})
        assert after.returncode == 1 and "no crontab for" in after.stderr, after
    finally:
        current = run(["/usr/bin/crontab", "-l"])
        if current.returncode == 0:
            assert current.stdout == text, "crontab changed outside the owned test; preserve it"
            checked(["/usr/bin/crontab", "-r"])
    queue_before = checked(["/usr/bin/atq"])
    command = f"/usr/bin/touch {home}/at-{identity}\n"
    for argv in (["/usr/bin/at", "-t", "209901010000"], ["/usr/bin/batch"]):
        try:
            result = run([*prefix, *argv], input=command)
        except PermissionError as exc:
            result = subprocess.CompletedProcess(argv, 1, "", str(exc))
        print(json.dumps({"command": argv, "returncode": result.returncode,
                          "stdout": result.stdout, "stderr": result.stderr}), flush=True)
        match = re.search(r"job (\d+) at", result.stderr)
        if match:
            job = match[1]
            contents = checked(["/usr/bin/at", "-c", job])
            assert command.strip() in contents, "scheduler job is not the owned probe"
            checked(["/usr/bin/at", "-r", job])
        assert not match and result.returncode != 0, "at/batch accepted a job"
        assert checked(["/usr/bin/atq"]) == queue_before, "queue changed; inspect before cleanup"


def path_probes(home, prefix):
    script = home / "paths.py"
    script.write_text('''import errno, os
from pathlib import Path
home = Path(os.environ["HOME"])
protected = home / "Library/LaunchAgents/owned.plist"
for name, operation in [
    ("create", lambda: (protected.parent / "new.plist").write_text("marker")),
    ("modify", lambda: protected.write_text("changed")),
    ("rename directory", lambda: protected.parent.rename(home / "moved")),
    ("rename Library", lambda: (home / "Library").rename(home / "Library-moved")),
    ("hardlink", lambda: os.link(protected, home / "linked.plist")),
]:
    try:
        operation()
    except OSError as exc:
        assert exc.errno in (errno.EPERM, errno.EACCES), (name, exc)
    else:
        raise AssertionError(name + " was allowed")
(home / ".zshenv").write_text("# ordinary confined startup remains writable\\n")
(home / "Library/ordinary-cache").mkdir()
print("LaunchAgents create/modify/rename/link and Library replacement denied; rc/cache writes work")
''')
    print(checked([*prefix, "/usr/bin/python3", str(script)]).strip(), flush=True)
    # Also check the directory itself when absent, not just files below it.
    shutil.rmtree(home / "Library/LaunchAgents")
    refusal([*prefix, "/bin/mkdir", str(home / "Library/LaunchAgents")])
    assert not (home / "Library/LaunchAgents").exists()


def delegation_probes(home, app, binary, prefix):
    marker = home / "marker-main"
    marker.unlink(missing_ok=True)
    try:
        refusal([*prefix, "/usr/bin/open", "-n", "-a", str(app)])
        direct = json.loads(checked([*prefix, str(binary), "open", str(app)]))
        assert direct["status"] != 0, direct
        print(json.dumps(direct), flush=True)
        receiver = subprocess.Popen([str(binary), "serve"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not (home / "event-ready").exists():
                assert receiver.poll() is None and time.monotonic() < deadline, "owned event receiver failed"
                time.sleep(0.05)
            control = json.loads(checked([str(binary), "appleevent", str(receiver.pid)]))
            print(json.dumps({"unconfined_appleevent_control": control}), flush=True)
            assert control["sent"], control
            appleevent = json.loads(checked([*prefix, str(binary), "appleevent", str(receiver.pid)]))
            print(json.dumps(appleevent), flush=True)
            assert not appleevent["sent"] and appleevent["appleevents_lookup"] == 1100, appleevent
        finally:
            receiver.terminate()
            receiver.communicate(timeout=5)
        assert not marker.exists(), "a delegated process ran"
        checked(["/usr/bin/open", "-n", "-a", str(app)])
        deadline = time.monotonic() + 5
        while not marker.exists():
            assert time.monotonic() < deadline, "unconfined open did not launch helper"
            time.sleep(0.05)
        observation = json.loads(marker.read_text())
        assert observation["outside_read"] == 1 and observation["ppid"] == 1, observation
        print(json.dumps({"unconfined_open_control": observation}), flush=True)
    finally:
        # Unregister only this unique app from the LaunchServices database.
        checked(["/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
                 "-u", str(app)])
    marker.unlink(missing_ok=True)


def workload_probe(home, source, canary, binary, prefix):
    checked([*prefix, str(binary), "mark"])
    marker = json.loads((home / "marker-main").read_text())
    assert marker["outside_read"] == 0 and marker["errno"] in (1, 13), marker
    print(json.dumps({"confined_child": marker}), flush=True)
    probe = home / "probe.py"
    shutil.copyfile(source / "probe.py", probe)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.2)
        print(checked([*prefix, "/usr/bin/python3", str(probe), "--outside-file", str(canary),
                       "--loopback-port", str(listener.getsockname()[1])]).strip(), flush=True)
        try:
            connection, _ = listener.accept()
        except socket.timeout:  # noqa: UP041 -- macOS /usr/bin/python3 can be Python 3.9.
            pass  # The live outside listener must receive no denied connection.
        else:
            connection.close()
            raise AssertionError("outside listener received a connection")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=Path(__file__).with_name("agent-dev.sb"))
    args = parser.parse_args()
    if os.uname().sysname != "Darwin" or os.getuid() == 0:
        parser.error("run outside Seatbelt on macOS as a normal test user")
    source = Path(__file__).resolve().parent
    identity = "org.safeyolo.seatbelt.probe" + uuid.uuid4().hex
    # Retain the directory on failure so an unexpected registration can be
    # inspected and removed through its owner before deleting its executable.
    root = Path(tempfile.mkdtemp(prefix="seatbelt-boundary-", dir=Path.home())).resolve()
    canary = root / "outside-canary"
    canary.write_text(identity)
    home = root / "home"
    (home / "Library/LaunchAgents").mkdir(parents=True)
    (home / "tmp").mkdir()
    app, binary = make_bundle(home, source, canary, identity)
    trusted_policy = root / "trusted.sb"
    shutil.copyfile(args.profile, trusted_policy)
    policy = home / "candidate.sb"
    shutil.copyfile(args.profile, policy)
    prefix = [
        "/usr/bin/env", "-i", f"HOME={home}", f"TMPDIR={home}/tmp/",
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
        "/usr/bin/sandbox-exec", "-f", str(policy),
        "-D", f"AGENT_HOME={home}", "-D", "TOOLCHAIN_ROOT=/opt/homebrew",
    ]
    print(json.dumps({"fixture": str(root), "identity": identity, "uid": os.getuid(),
                      "platform": checked(["/usr/bin/sw_vers"])}), flush=True)
    service_probes(binary, prefix)
    launchd_probes(home, binary, prefix, identity, trusted_policy)
    path_probes(home, prefix)
    scheduler_probes(home, prefix, identity)
    delegation_probes(home, app, binary, prefix)
    workload_probe(home, source, canary, binary, prefix)
    shutil.rmtree(root)
    print(json.dumps({"status": "pass", "fixture_removed": str(root),
                      "scope": "scoped process; account setup and physical VZ are separate"}))


if __name__ == "__main__":
    main()
