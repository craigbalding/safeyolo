#!/usr/bin/env python3
"""One owned Ubuntu public install and normal reentry.

Adapted from the retained observer for issue 239's Ubuntu AMD64 consumer.
Run only on the fresh runner named by --host with its matching --platform.
Python is an observer prerequisite; the product keeps the runner's normal PATH.
The two product commands retain the normal PATH, proxy, CA and shipped harness.
Only result.json may be uploaded. Terminal screens and state hashes stay private.
Use --cleanup-only after an interrupted attempt on this same owned host.
The observer owns its attempted installation; it borrows the runner and its tools.
"""

import argparse
import datetime as dt
import errno
import fcntl
import hashlib
import json
import math
import os
import pty
import re
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness.process_identity import child_exited, process_start_token

SOURCE = "c9ecb66b462c2ba0c499f2322f6cfc5c142012da"
BOOTSTRAP = "45d8853a202c04c9f5f8ca772df410ae8ced1844"
PACKAGES = {
    "linux-amd64": {"machine": "x86_64", "bytes": 190882862,
                    "sha256": "c91e61117e416a8245476e100d20155b7512ac429976457c87a0b2c3e6bec6da"},
    "linux-arm64": {"machine": "aarch64", "bytes": 176869006,
                    "sha256": "eab9b709b3e4c6b536614eeb6b422d12c2b55826149085f78c326b31637922af"},
}
RELEASE = "host-" + SOURCE
DOWNLOAD = ["curl", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
            "--output", "install-safeyolo.sh",
            f"https://raw.githubusercontent.com/craigbalding/safeyolo/{BOOTSTRAP}/install.sh"]
LAUNCH = ["bash", "install-safeyolo.sh", "--release", RELEASE, "--launch", ".",
          "--name", "first", "--harness", "claude", "--launcher", "tmux-window"]
PROBES = [
    ("positive", 'test -n "$HTTP_PROXY" && curl -sS -D /dev/stderr -o /dev/null -w "%{json}" '
     '--proxy "$HTTP_PROXY" -H "X-SafeYolo-Test-Context: run=isolation;agent=bbtest" '
     '--max-time 10 http://httpbin.org/get'),
    ("direct-http", "curl -sS -D /dev/stderr -w '%{json}' --noproxy '*' --connect-timeout 3 --max-time 10 -o /dev/null http://1.1.1.1"),
    ("direct-https", "curl -sS -D /dev/stderr -w '%{json}' --noproxy '*' --connect-timeout 3 --max-time 10 -k -o /dev/null https://8.8.8.8"),
]
PHASE_TEXT = [
    ("host-acquisition", "SafeYolo: acquiring safeyolo-linux-"),
    ("host-verification-unpack", "SafeYolo: verifying and unpacking the host package."),
    ("host-preparation-consent", "SafeYolo needs these host changes:"),
    ("guest-acquisition", "SafeYolo: acquiring and verifying the compatible guest."),
    ("activation", "SafeYolo: activating the verified installation at"),
    ("installed-launch", "SafeYolo: launching the first agent from the installed instance."),
    ("harness-setup", "Preparing the shipped harness setup"),
    ("services-start", "Starting or reusing the installed services"),
    ("sandbox-harness-start", "Starting or resuming claude."),
    ("harness-installed", "SafeYolo: Claude Code is installed; opening the session."),
]
PUBLIC_STATE = ["policy.toml", "certs/mitmproxy-ca-cert.pem", "data/instance_id", "share/guest-selection.json"]
PRIVATE_STATE = ["data/admin_token", "data/agent_token", "certs/mitmproxy-ca.pem",
                 "agents/first/home/.safeyolo-command"]
OPTIONAL_PRIVATE_STATE = ["data/credentials.key", "data/credentials.enc",
                          "agents/first/home/.claude/.credentials.json"]
HOME_MARKER = "SAFEYOLO_ONBOARDING_HOME\n"
MARKER_QUERY = ('p=$(cat /workspace/.onboarding239.pid) && kill -0 "$p" && '
                'printf "pid=%s\\n" "$p" && awk \'{print "start=" $22}\' /proc/"$p"/stat && '
                'printf "heartbeat=" && cat /workspace/.onboarding239.heartbeat')


def stamp():
    return {"at": dt.datetime.now(dt.UTC).isoformat(), "monotonic": time.monotonic()}


def save():
    # This extends the existing observer result; it is not another task/transcript store.
    out.write_text(json.dumps(x, indent=2) + "\n")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def text(path):
    return path.read_text() if path.is_file() else None


def read_json(path):
    return json.loads(path.read_text()) if path.is_file() else None


def capture(dest, key, action):
    # Missing/racing runtime files must not prevent independent workspace/network capture.
    try:
        dest[key] = action()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        dest[key] = {"observation_error": str(error), **stamp()}
    save()
    return dest[key]


def birth(pid):
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    return process_start_token(pid)


def observe(label, args, timeout=20, private_output=False):
    row = {"label": label, "command": list(map(str, args)), **stamp()}
    x["observations"].append(row)
    save()
    try:
        process = subprocess.Popen(row["command"], cwd=project, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=max(0.1, timeout))
        except subprocess.TimeoutExpired:
            # Only this newly created diagnostic process group is terminated.
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=3)
            row["timeout"] = True
        row["exit"] = process.returncode
        if private_output:
            (private / (label + ".stdout")).write_bytes(stdout)
            (private / (label + ".stderr")).write_bytes(stderr)
            row.update(private_output=True, stdout_bytes=len(stdout), stderr_bytes=len(stderr))
        else:
            row.update(stdout=stdout.decode(errors="replace"), stderr=stderr.decode(errors="replace"))
    except (OSError, subprocess.SubprocessError) as error:
        row["observation_error"] = str(error)
    row["ended"] = stamp()
    save()
    return row


def guest(label, code, deadline, private_output=False):
    return observe(label, [cli, "--root", root, "agent", "shell", "first", "-c", code],
                   min(20, max(0.1, deadline - time.monotonic())), private_output=private_output)


def network_probe(phase, kind, code, deadline):
    """Export selected operands; curl output and new proxy log bytes stay private."""
    label = phase + "-" + kind
    logs = {}
    for name in ["events.jsonl", "proxy.log"]:
        path = root / "logs" / name
        try:
            info = path.stat()
            logs[name] = {"offset": info.st_size, "inode": info.st_ino}
        except OSError as error:
            logs[name] = {"errno": error.errno}
    operand = guest(label, code, deadline, private_output=True)
    row = {"kind": kind, "operand": operand, "response": {}, "proxy_logs": logs}
    try:
        metrics = json.loads((private / (label + ".stdout")).read_bytes())
        if not isinstance(metrics, dict):
            raise ValueError("Curl metrics were not an object")
        for key in ["http_code", "http_connect", "num_connects", "size_download", "time_namelookup",
                    "time_connect", "time_pretransfer", "time_starttransfer", "time_total"]:
            value = metrics.get(key)
            if type(value) in (int, float) and math.isfinite(value) and value >= 0:
                row["response"][key] = value
    except (OSError, ValueError) as error:
        row["metrics_error"] = type(error).__name__
    headers = (private / (label + ".stderr")).read_bytes() if operand.get("private_output") else b""
    # Response header claims alone do not establish local enforcement or origin delivery.
    for line in headers.splitlines():
        name, _, value = line.partition(b":")
        value = value.strip()
        if name.lower() == b"x-safeyolo-request-id" and re.fullmatch(rb"req-[0-9a-f]{32}", value):
            row["response"]["request_id"] = value.decode()
        if name.lower() == b"x-blocked-by":
            row["response"]["blocked_by_header_present"] = True
            if value in [b"network-guard", b"credential-guard", b"pattern-scanner", b"test-context", b"admin-shield", b"service-gateway"]:
                row["response"]["blocked_by_header"] = value.decode()
    request_id = row["response"].get("request_id")
    for name, log in logs.items():
        if "offset" not in log:
            continue
        try:
            with (root / "logs" / name).open("rb") as stream:
                info = os.fstat(stream.fileno())
                if info.st_ino != log["inode"] or info.st_size < log["offset"]:
                    log["changed_file"] = True
                    continue
                stream.seek(log["offset"])
                data = stream.read(65537)
            log["truncated"] = len(data) > 65536
            data = data[:65536]
            (private / (label + "-" + name)).write_bytes(data)
            log["bytes"] = len(data)
            log["matches"] = []
            for line in data.splitlines():
                if name == "proxy.log":
                    match = re.match(rb"request (req-[0-9a-f]{32}) (identity reconciliation failed|failed):", line)
                    if match and (not request_id or match[1].decode() == request_id):
                        failure = {"request_id": match[1].decode(),
                            "stage": "identity-reconciliation" if match[2].startswith(b"identity") else "request-failed",
                            "correlation": "request-id" if request_id else "time-window-only"}
                        categories = [term for term in ["dns", "connection refused", "connection reset", "timed out", "tls", "unexpected eof"]
                                      if term.encode() in line.lower()]
                        if categories:
                            failure["error_categories"] = categories
                        log["matches"].append(failure)
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    log["invalid_json_line"] = True
                    continue
                if not isinstance(event, dict):
                    log["invalid_event_shape"] = True
                    continue
                if (event.get("event") != "proxy.request" or event.get("host") != "httpbin.org"
                        or not re.fullmatch(r"req-[0-9a-f]{32}", str(event.get("request_id")))
                        or (request_id and event["request_id"] != request_id)):
                    continue
                selected = {"request_id": event["request_id"],
                            "correlation": "request-id" if request_id else "host-and-time-window-only"}
                if type(event.get("status")) is int and 100 <= event["status"] <= 599:
                    selected["status"] = event["status"]
                if event.get("decision") in ["allow", "deny", "error", "invalid", "admin_port_access"]:
                    selected["decision"] = event["decision"]
                log["matches"].append(selected)
            log["matches_truncated"] = len(log["matches"]) > 16
            log["matches"] = log["matches"][:16]
        except OSError as error:
            log["read_errno"] = error.errno
    row["expected_result"] = (operand.get("exit") == 0 and row["response"].get("http_code") == 200
                              if kind == "positive" else operand.get("exit") in [7, 28] and not operand.get("timeout"))
    return row


def process_read(entry, stage, row):
    """Retry only a denied, fixed /proc read; never run the observer as root."""
    try:
        if stage == "exe":
            return os.readlink(entry / "exe").encode()
        if stage == "fd":
            links = []
            for fd in (entry / "fd").iterdir():
                try:
                    links.append(os.readlink(fd).encode())
                except FileNotFoundError:
                    # A closed descriptor no longer holds its former socket.
                    continue
            return b"\n".join(links)
        return (entry / "cmdline").read_bytes()
    except PermissionError as error:
        failed = {"stage": stage, "errno": error.errno, **stamp()}
        row.setdefault("permission_reads", []).append(failed)
        commands = {"exe": ["/usr/bin/readlink", "--", str(entry / "exe")],
                    "cmdline": ["/usr/bin/cat", "--", str(entry / "cmdline")],
                    "fd": ["/usr/bin/find", str(entry / "fd"), "-mindepth", "1", "-maxdepth", "1", "-printf", "%l\n"]}
        try:
            observed = subprocess.run(["sudo", "-n", *commands[stage]], capture_output=True, timeout=3)
        except (OSError, subprocess.TimeoutExpired) as retry_error:
            failed["sudo_error"] = type(retry_error).__name__
            raise PermissionError(error.errno, "Scoped process reader unavailable", str(entry / stage)) from retry_error
        failed["sudo_exit"] = observed.returncode
        # Output can include unrelated command arguments or open-file paths.
        (private / f"proc-{entry.name}-{stage}.stdout").write_bytes(observed.stdout)
        (private / f"proc-{entry.name}-{stage}.stderr").write_bytes(observed.stderr)
        if observed.returncode:
            raise PermissionError(error.errno, "Scoped process read failed", str(entry / stage)) from error
        return observed.stdout.rstrip(b"\n") if stage == "exe" else observed.stdout


def processes():
    result = []
    unreadable = []
    details = []
    record = read_json(root / "agents/first/runtime.json") or {}
    runtime_births = {record.get(key): record.get(key.replace("_pid", "_token"))
                      for key in ["holder_pid", "backend_pid"] if record.get(key)}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        row = {"pid": pid, "stage": "stat"}
        try:
            owner = entry.stat()
            row.update(uid=owner.st_uid, gid=owner.st_gid, birth=birth(pid))
            expected = runtime_births.get(pid)
            if owner.st_uid != os.getuid() and not (expected and row["birth"] == expected):
                continue
            row["stage"] = "cmdline"
            argv = process_read(entry, "cmdline", row)
            row["argv_root_match"] = str(root).encode() in argv
            row["stage"] = "exe"
            executable = process_read(entry, "exe", row).decode(errors="replace")
            row.update(executable=executable, executable_root_match=executable.startswith(str(root) + "/"),
                       birth_after=birth(pid))
            if not row["birth"] or row["birth_after"] != row["birth"]:
                row["stage"] = "birth-changed-or-unavailable"
                unreadable.append(pid)
            elif row["argv_root_match"] or row["executable_root_match"]:
                result.append({"pid": pid, "birth": row["birth"], "executable": executable,
                               "uid": row["uid"], "gid": row["gid"]})
            row["ownership"] = ("unknown" if pid in unreadable else
                                "owned" if row["argv_root_match"] or row["executable_root_match"] else "unrelated")
        except (FileNotFoundError, ProcessLookupError):
            # /proc races are expected; the saved birth is checked again after stop.
            continue
        except (OSError, subprocess.TimeoutExpired) as error:
            # A stable unreadable process cannot be classified as owned or unrelated.
            if entry.exists():
                unreadable.append(pid)
                row.update(errno=getattr(error, "errno", None), error_type=type(error).__name__,
                           ownership="unknown", birth_after=birth(pid))
        finally:
            if row.get("permission_reads") or pid in unreadable:
                details.append(row)
    x["latest_process_scan"] = {"unreadable_pids": unreadable, "read_details": details, **stamp()}
    if unreadable or details:
        x.setdefault("process_scan_limits", []).append(x["latest_process_scan"])
    return result


def listeners(owned):
    if not isinstance(owned, list):
        raise ValueError("Owned process capture was unavailable; listeners are unverified.")
    inodes = set()
    for process in owned:
        row = {"pid": process["pid"], "birth": process["birth"]}
        entry = Path(f"/proc/{process['pid']}")
        try:
            if birth(process["pid"]) != process["birth"]:
                if entry.exists():
                    raise ValueError(f"Process {process['pid']} listener identity changed or is unavailable")
                continue
            links = process_read(entry, "fd", row)
            if birth(process["pid"]) != process["birth"]:
                if entry.exists():
                    raise ValueError(f"Process {process['pid']} listener identity changed or is unavailable")
                continue
            for link in links.decode().splitlines():
                if link.startswith("socket:["):
                    inodes.add(link[8:-1])
        except (FileNotFoundError, ProcessLookupError):
            # A reaped process cannot retain a listener. Live races stay unknown.
            if birth(process["pid"]) == process["birth"]:
                raise ValueError(f"Live process {process['pid']} listener read raced") from None
            continue
        finally:
            if row.get("permission_reads"):
                x.setdefault("listener_read_details", []).append(row)
                save()
    result = []
    for family in ["tcp", "tcp6", "unix"]:
        for line in Path("/proc/net/" + family).read_text().splitlines()[1:]:
            fields = line.split()
            inode = fields[6] if family == "unix" else fields[9]
            listening = fields[3] == "00010000" if family == "unix" else fields[3] == "0A"
            if inode in inodes and listening:
                result.append({"family": family, "inode": inode,
                               "address": fields[-1] if family == "unix" else fields[1]})
    return result


def live_record():
    record = read_json(root / "agents/first/runtime.json") or {}
    selected = {k: record.get(k) for k in ["name", "agent_id", "run_id", "holder_pid",
                "holder_token", "backend_pid", "backend_token", "linux"]}
    selected["live_births"] = {key: {"observed": birth(record.get(key)),
                              "recorded": record.get(key.replace("_pid", "_token"))}
                              for key in ["holder_pid", "backend_pid"] if record.get(key)}
    selected["process_mappings"] = {}
    for key in ["holder_pid", "backend_pid"]:
        if record.get(key):
            for mapping in ["uid_map", "gid_map"]:
                try:
                    value = Path(f"/proc/{record[key]}/{mapping}").read_text()
                except OSError as error:
                    value = {"observation_error": str(error)}
                selected["process_mappings"][key + "/" + mapping] = value
    return selected


def launch_record():
    record = read_json(root / "agents/first/current-launch.json") or {}
    return {k: record.get(k) for k in ["launch_id", "state", "pid", "process_token",
            "runner_pid", "runner_token", "started_at", "pane_id", "tmux_socket", "tmux_session"]}


def terminal_attachment(phase, launch):
    # Read pane facts only. Never copy terminal contents, argv or launch environments.
    if not launch.get("tmux_socket") or not re.fullmatch(r"%\d+", launch.get("pane_id") or ""):
        return {"unavailable": "No recorded tmux socket/pane", **stamp()}
    return observe(phase + "-terminal-attachment", [root / "bin/tmux", "-S", launch["tmux_socket"],
        "display-message", "-p", "-t", launch["pane_id"],
        "#{@safeyolo_launch_id}\t#{pane_dead}\t#{pane_pid}\t#{pane_current_command}\t#{session_id}\t#{session_attached}\t#{window_active}\t#{pane_active}"])


def pane_screen(phase):
    """Read the recorded visible pane; keep its contents and errors private."""
    launch = launch_record()
    if not launch.get("tmux_socket") or not re.fullmatch(r"%\d+", launch.get("pane_id") or ""):
        return {"unavailable": "No recorded tmux socket/pane", **stamp()}
    command = [str(root / "bin/tmux"), "-S", launch["tmux_socket"]]
    facts = subprocess.run([*command, "display-message", "-p", "-t", launch["pane_id"],
        "#{@safeyolo_launch_id}\t#{pane_dead}\t#{window_active}\t#{pane_active}\t#{session_attached}"],
        capture_output=True, timeout=2)
    values = facts.stdout.decode(errors="replace").strip().split("\t")
    visible = (facts.returncode == 0 and len(values) == 5 and values[:4] == [launch.get("launch_id"), "0", "1", "1"]
               and values[4].isdigit() and int(values[4]) > 0)
    row = {"facts_exit": facts.returncode, "matching_live_visible_pane": visible, **stamp()}
    if visible:
        screen = subprocess.run([*command, "capture-pane", "-p", "-e", "-J", "-t", launch["pane_id"]],
                                capture_output=True, timeout=2)
        (private / (phase + "-pane.screen")).write_bytes(screen.stdout)
        (private / (phase + "-pane.stderr")).write_bytes(screen.stderr)
        row.update(exit=screen.returncode, labels=login_label(screen.stdout) if screen.returncode == 0 else [], ended=stamp())
    return row


def witness(phase, start_marker=False):
    deadline = time.monotonic() + 90
    row = {**stamp()}
    x[phase] = row
    save()
    capture(row, "runtime", live_record)
    row["status"] = observe(phase + "-status", [cli, "--root", root, "agent", "status", "first"])
    capture(row, "launch", launch_record)
    capture(row, "terminal_attachment", lambda: terminal_attachment(phase, row["launch"]))
    capture(row, "processes", processes)
    capture(row, "listeners", lambda: listeners(row.get("processes", [])))
    if start_marker:
        code = ("nohup sh -c 'echo $$ > /workspace/.onboarding239.pid; while :; do "
                "date +%s > /workspace/.onboarding239.heartbeat; sleep 1; done' "
                ">/workspace/.onboarding239.log 2>&1 </dev/null &\n"
                "printf %s " + shlex.quote(HOME_MARKER) + ' > "$HOME/.onboarding239-home"')
        row["marker_start"] = guest(phase + "-marker-start", code, deadline)
        time.sleep(1)
    row["marker"] = guest(phase + "-marker", MARKER_QUERY, deadline)
    row["home_marker"] = guest(phase + "-home", 'cat "$HOME/.onboarding239-home"', deadline)
    row["home_matches"] = row["home_marker"].get("exit") == 0 and row["home_marker"].get("stdout") == HOME_MARKER
    capture(row, "workspace_before", lambda: (project / "onboarding-fixture.txt").read_text())
    addition = "ONBOARDING239_" + phase + "\n"
    row["workspace_guest"] = guest(phase + "-workspace", "cat /workspace/onboarding-fixture.txt && printf %s "
                                  + shlex.quote(addition) + " >> /workspace/onboarding-fixture.txt", deadline)
    capture(row, "workspace_after", lambda: (project / "onboarding-fixture.txt").read_text())
    row["workspace_matches"] = (row["workspace_guest"].get("exit") == 0
        and row["workspace_guest"].get("stdout") == row["workspace_before"]
        and isinstance(row["workspace_before"], str)
        and row["workspace_after"] == row["workspace_before"] + addition)
    row["network"] = []
    for label, code in PROBES:
        # These direct controls execute ONLY in this owned product guest.
        row["network"].append(network_probe(phase, label, code, deadline))
        save()
    capture(row, "guest_selection", lambda: read_json(root / "share/guest-selection.json"))
    state = {}
    # These hashes stay private. A failed read must not erase the other operands.
    for path in PUBLIC_STATE + PRIVATE_STATE + OPTIONAL_PRIVATE_STATE:
        try:
            state[path] = digest(root / path) if (root / path).is_file() else None
        except OSError as error:
            row.setdefault("state_observation_errors", {})[path] = str(error)
    (private / (phase + "-state-hashes.json")).write_text(json.dumps(state))
    row["selected_public_state_present"] = [p for p in PUBLIC_STATE if state.get(p)]
    row["selected_private_state_present"] = [p for p in PRIVATE_STATE + OPTIONAL_PRIVATE_STATE if state.get(p)]
    row["ended"] = stamp()
    save()
    return state


def sample_files(phase):
    observed = stamp()
    sampling = x.setdefault("sampling", {}).setdefault(phase, {"max_gap_seconds": 0})
    previous = sampling.get("last")
    if previous:
        sampling["max_gap_seconds"] = max(sampling["max_gap_seconds"], observed["monotonic"] - previous["monotonic"])
    paths = {"host-archive-verified": archive, "instance-activated": root / "config.toml",
             "installed-guest-selection": root / "share/guest-selection.json"}
    for kind in ["blobs", "trees"]:
        parent = store / kind / "sha256"
        if parent.is_dir():
            for path in parent.iterdir():
                if re.fullmatch(r"[0-9a-f]{64}(?:-.+)?", path.name):
                    paths[kind + "/" + path.name] = path
    for label, path in paths.items():
        key = phase + ":" + label
        if key not in sampled and path.exists():
            sampled.add(key)
            x["phase_observations"].append({"phase": phase, "boundary": label,
                "path": str(path), "size": path.stat().st_size,
                "previous_sample": previous, **observed})
            save()
    sampling["last"] = observed


def terminal_plain(data):
    return re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", data).lower()


def theme_prompt(data):
    # The original cold receipt retained these two display-choice labels.
    match = re.search(rb"(?:choose|select) the text style[^\r\n]*", terminal_plain(data))
    return match.group(0)[:160].decode(errors="replace") if match else None


def login_label(data):
    plain = terminal_plain(data)
    # Shipped startup banners mention sign-in BEFORE the harness is installed.
    plain = b"\n".join(line for line in plain.splitlines()
                       if b"opening the session" not in line and b"first use may download tools" not in line)
    plain = plain.replace(b"sign in if claude asks.", b"")
    return [label for label in ["/login", "sign in"] if label.encode() in plain]


def console_group(pid):
    """Read live members of the owned PTY group while its leader remains waitable."""
    members = []
    if sys.platform == "darwin":
        observed = subprocess.run(["ps", "-axo", "pid=,pgid=,stat="],
                                  check=True, capture_output=True, text=True, timeout=3)
        leader_seen = False
        for line in observed.stdout.splitlines():
            member, group, state = line.split()
            leader_seen |= member == str(pid)
            if group == str(pid) and not state.startswith(("Z", "X")):
                members.append({"pid": int(member), "birth": birth(int(member)), "state": state})
        if not leader_seen:
            raise ChildProcessError(f"Owned console {pid} was not observed before reaping")
        return members
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            # A process that disappeared cannot hold the group's listener open.
            continue
        if fields[2] == str(pid) and fields[0] not in {"Z", "X"}:
            members.append({"pid": int(entry.name), "birth": birth(int(entry.name)), "state": fields[0]})
    return members


def stop_console_group(pid, row):
    shutdown = {"pgid": pid, "verified": False, "started": stamp()}
    row["console_group_shutdown"] = shutdown
    save()
    # pty.fork created this session/group. Keep its direct child unreaped so
    # its PID and group ID cannot be reused while the group is signalled.
    limit = time.monotonic() + 3
    remaining = console_group(pid)
    if remaining:
        row["observer_terminated_viewer"] = stamp()
        os.killpg(pid, signal.SIGTERM)
    while remaining and time.monotonic() < limit - 1:
        time.sleep(0.05)
        remaining = console_group(pid)
    if remaining:
        shutdown["sigkill"] = stamp()
        os.killpg(pid, signal.SIGKILL)
        while remaining and time.monotonic() < limit:
            time.sleep(0.05)
            remaining = console_group(pid)
    shutdown.update(remaining=remaining, verified=not remaining, ended=stamp())
    save()


def entered(phase, seconds):
    row = {"command": LAUNCH, "phase": phase, **stamp()}
    row["post_return_diagnostics"] = [["command", "-v", "safeyolo"], ["safeyolo", "--version"]]
    x["product_commands"].append(row)
    save()
    # Post-q discovery runs in the same terminal and inherited shell PATH.
    script = (shlex.join(LAUNCH) + '\nresult=$?\nprintf "\\nSY239_COMMAND_EXIT=%s\\n" "$result"\n'
              'printf "SY239_DISCOVERY_BEGIN\\n"\ncommand -v safeyolo\nprintf "SY239_DISCOVERY_EXIT=%s\\n" "$?"\n'
              'printf "SY239_VERSION_BEGIN\\n"\nsafeyolo --version\nprintf "SY239_VERSION_EXIT=%s\\n" "$?"\nexit "$result"\n')
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(project)
        os.environ["TERM"] = "xterm-256color"
        os.execvpe("bash", ["bash", "-c", script], os.environ)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
    row["console_pid"] = pid
    row["console_reaped"] = False
    deadline = time.monotonic() + seconds
    pending = b""
    status = None
    detached = False
    captured = False
    next_pane_read = 0
    terminal_open = True
    completed = set()
    states = None
    try:
        with (private / (phase + ".terminal")).open("wb") as log:
            while True:
                sample_files(phase)
                if select.select([fd] if terminal_open else [], [], [], 0.25)[0]:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        # Linux PTYs report EIO when the last slave closes.
                        chunk = b""
                    if chunk:
                        log.write(chunk)
                        log.flush()
                        pending = (pending + chunk)[-60000:]
                    else:
                        terminal_open = False
                        deadline = min(deadline, time.monotonic() + 3)
                for label, phrase in PHASE_TEXT:
                    if label not in completed and phrase.encode() in pending:
                        x["phase_observations"].append({"phase": phase, "boundary": label, **stamp()})
                        completed.add(label)
                        save()
                for label, prompt, answer in [
                    ("host", "Allow these host changes? [y/N]", "y\n"),
                    ("setup", "Run this setup and share this workspace? [y/N]", "y\n"),
                    ("auth", "Copy this selected host authentication and settings? [y/N]", "n\n"),
                ]:
                    if terminal_open and label not in completed and prompt.encode() in pending:
                        seen = stamp()
                        os.write(fd, answer.encode())
                        x["interactions"].append({"phase": phase, "prompt": prompt,
                                                  "answer": answer.strip(), "seen": seen, "sent": stamp()})
                        completed.add(label)
                        pending = b""
                        save()
                theme = theme_prompt(pending)
                if terminal_open and phase == "cold" and "sandbox-harness-start" in completed and "theme" not in completed and theme:
                    seen = stamp()
                    os.write(fd, b"\r")
                    x["interactions"].append({"phase": phase, "kind": "guest display choice",
                        "prompt": theme, "answer": "Enter (default theme)", "seen": seen, "sent": stamp()})
                    completed.add("theme")
                    pending = b""
                    save()
                labels = login_label(pending)
                label_source = "host-terminal-output"
                if terminal_open and not captured and not labels and time.monotonic() >= next_pane_read:
                    # Reentry need not emit the old prompt again. Read the current
                    # visible screen, without treating wrapper text or liveness as readiness.
                    capture(row, "pane_screen", lambda: pane_screen(phase))
                    next_pane_read = time.monotonic() + 1
                    labels = row["pane_screen"].get("labels", [])
                    label_source = "attached-pane-screen"
                expired = time.monotonic() >= deadline
                if terminal_open and not captured and (labels or expired):
                    if labels:
                        row["signed_out_label"] = {"labels": labels, "source": label_source, **stamp()}
                    else:
                        row["readiness_unclassified_at_deadline"] = stamp()
                    save()
                    started = time.monotonic()
                    captured = True
                    states = witness("before-return" if phase == "cold" else "after-reentry", phase == "cold")
                    row["capture_seconds"] = time.monotonic() - started
                    # Capture precedes detach even for an unclassified UI.
                    os.write(fd, b"\x02d")
                    detached = True
                    row["viewer_detach"] = stamp()
                    pending = b""
                    deadline = time.monotonic() + 30
                    save()
                if terminal_open and detached and b"SafeYolo host> " in pending and "q" not in completed:
                    os.write(fd, b"q\n")
                    row["ordinary_q"] = stamp()
                    completed.add("q")
                    pending = b""
                    save()
                for key in ["COMMAND", "DISCOVERY", "VERSION"]:
                    match = re.search(rb"SY239_" + key.encode() + rb"_EXIT=(\d+)", pending)
                    if match:
                        row[key.lower() + "_exit"] = int(match.group(1))
                for key in ["DISCOVERY", "VERSION"]:
                    match = re.search(rb"SY239_" + key.encode() + rb"_BEGIN\r?\n(.*?)SY239_" + key.encode() + rb"_EXIT=", pending, re.S)
                    if match:
                        row[key.lower() + "_stdout"] = match.group(1).decode(errors="replace").strip()[:2048]
                # The shell can exit while its final discovery/version bytes remain queued.
                if child_exited(pid) and (not terminal_open or not select.select([fd], [], [], 0)[0]):
                    break
                if time.monotonic() >= deadline:
                    break
    finally:
        # Viewer EOF or any classification error must still leave reached live operands.
        if not captured:
            try:
                states = witness("before-return" if phase == "cold" else "after-reentry", phase == "cold")
            except Exception as error:
                # Preserve the error but always reap this owned viewer below.
                row["final_capture_error"] = repr(error)
                save()
        try:
            if not child_exited(pid) or not row.get("ordinary_q") or console_group(pid):
                stop_console_group(pid, row)
        finally:
            waited, code = os.waitpid(pid, os.WNOHANG)
            if waited:
                status = code
                row["console_reaped"] = True
            os.close(fd)
            row.update(exit_code=os.waitstatus_to_exitcode(status) if status is not None else None, ended=stamp())
            save()
    return row, states


def inventory():
    tools = ["bash", "curl", "tar", "sha256sum", "shasum", "git", "python3", "uv", "cargo",
             "rustc", "gcc", "make", "sudo", "newuidmap", "newgidmap", "getfacl", "setfacl", "runsc", "nats-server", "claude",
             "mise", "node", "npm", "tmux", "docker", "oras", "apt-get"]
    return {"hostname": os.uname().nodename, "machine": list(os.uname()), "uid": os.getuid(),
            "gid": os.getgid(), "groups": os.getgroups(), "PATH": os.environ.get("PATH"),
            "os_release": text(Path("/etc/os-release")), "tools": {p: shutil.which(p) for p in tools},
            "subuid": text(Path("/etc/subuid")), "subgid": text(Path("/etc/subgid")),
            "kvm_present": Path("/dev/kvm").exists(), "kvm_user_rw": os.access("/dev/kvm", os.R_OK | os.W_OK),
            "userns": text(Path("/proc/sys/kernel/unprivileged_userns_clone")),
            "apparmor_userns": text(Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")),
            "auth_present": {p: (Path.home() / p).exists() for p in [".claude.json", ".claude/.credentials.json"]},
            "vendor_cache_present": {p: (Path.home() / p).exists() for p in [".local/share/claude", ".cache/claude", ".local/bin/claude"]},
            "cache_present": {str(p): p.exists() for p in [root, archive.parent, store,
                Path.home() / ".local/share/mise", Path.home() / ".cache/mise", Path.home() / ".local/share/safeyolo/tools"]},
            "credential_env_names": [p for p in ["GH_TOKEN", "GITHUB_TOKEN", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"] if os.environ.get(p)],
            "proxy_ca_env_present": {p: bool(os.environ.get(p)) for p in ["HTTP_PROXY", "HTTPS_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"]}}


def cleanup():
    deadline = time.monotonic() + 120
    capture(x, "pre_cleanup_processes", processes)
    capture(x, "pre_cleanup_listeners", lambda: listeners(x.get("pre_cleanup_processes", [])))
    x["cleanup"] = []
    if cli.is_file():
        for label, args in [("stop-first", ["agent", "stop", "first"]), ("stop-instance", ["stop"]),
                            ("stop-coord", ["coord", "stop"]), ("final-agent", ["agent", "status", "first"]),
                            ("final-proxy", ["status"]), ("final-coord", ["coord", "status"])]:
            x["cleanup"].append(observe(label, [cli, "--root", root, *args], min(25, max(0.1, deadline - time.monotonic()))))
    capture(x, "remaining_owned_processes", processes)
    capture(x, "remaining_owned_listeners", lambda: listeners(x.get("remaining_owned_processes", [])))
    tracked = {}
    before_stop = x.get("pre_cleanup_processes", [])
    for process in before_stop if isinstance(before_stop, list) else []:
        tracked[process["birth"]] = process["pid"]
    for row in list(x.values()):
        if isinstance(row, dict) and isinstance(row.get("processes"), list):
            for process in row["processes"]:
                tracked[process["birth"]] = process["pid"]
    x["tracked_births_still_live"] = {saved: pid for saved, pid in tracked.items() if saved and birth(pid) == saved}
    x["cleanup_verified"] = (isinstance(before_stop, list) and not x["tracked_births_still_live"] and x.get("remaining_owned_processes") == []
        and not x.get("latest_process_scan", {}).get("unreadable_pids")
        and all(row.get("console_reaped", True) and row.get("console_group_shutdown", {}).get("verified", True)
                for row in x.get("product_commands", []))
        and x.get("remaining_owned_listeners") == [] and bool(x["cleanup"])
        and all(row.get("exit") == 0 and not row.get("timeout") for row in x["cleanup"]))
    save()


def main():
    global root, project, private, cli, out, archive, store, x, sampled
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="exact newly allocated owned hostname")
    parser.add_argument("--platform", required=True, choices=PACKAGES)
    parser.add_argument("--observation-dir", type=Path, help="fresh private observer directory outside the checkout")
    parser.add_argument("--observer-source", default="unknown", help="workflow checkout commit; separate from product identities")
    parser.add_argument("--cleanup-only", action="store_true", help="stop and inspect this observer's recorded attempt")
    args = parser.parse_args()
    if os.uname().nodename != args.host or args.host == "sy-1050-c9-cold-428968871" or os.geteuid() == 0:
        raise SystemExit("Use only the named fresh host as its ordinary user; the retained fixture is excluded.")
    root = Path.home() / ".safeyolo"
    private = args.observation_dir or Path.home() / "239-onboarding-observation"
    project = Path.home() / "239-onboarding-project"
    cli = root / "bin/safeyolo"
    package = PACKAGES[args.platform]
    archive = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "safeyolo/host-packages" / RELEASE / f"safeyolo-{args.platform}-production.tar.gz"
    store = Path.home() / ".local/share/safeyolo/guests"
    os.umask(0o077)
    out = private / "result.json"
    if args.cleanup_only:
        x = read_json(out) or {}
        if not (x.get("owns_product_attempt") and x.get("platform") == args.platform
                and x.get("baseline", {}).get("hostname") == args.host
                and x.get("baseline", {}).get("uid") == os.getuid()
                and x.get("fixture_preparation", {}).get("project") == str(project)):
            raise SystemExit("No matching owned attempt; existing runner state was preserved.")
        if x.get("cleanup_verified"):
            return 0
        cleanup()
        x["cleanup_rechecked"] = stamp()
        save()
        return 0 if x.get("cleanup_verified") else 1
    private.mkdir(mode=0o700)
    x = {"started": stamp(), "purpose": "Public Ubuntu install, normal q and warm repeat",
         "observation_outcome": "partial",
         "platform": args.platform, "expected_host_package": package,
         "native_source": SOURCE, "bootstrap_source": BOOTSTRAP, "observer_parent": "operator6542/6732",
         "observer_source": args.observer_source,
         "ownership": {"runner": "borrowed; no host shutdown or tool/cache removal",
                       "product_root": str(root), "agent": "first", "project": str(project), "private_observer": str(private)},
         "product_commands": [], "interactions": [], "observations": [], "phase_observations": [],
         "limits": ["Signed-out endpoint only; no model task, login or authentication copy",
                    "File/terminal boundaries are sampled; combined phases and provider/download waits remain bounds",
                    "Terminal screens and state hashes must remain private; only selected-state equality and presence are exported",
                    "Guest-home proof covers the saved command and a guest-written marker, not every changing home file",
                    "No other platform, OCI >2GiB, independent-update or Mac cleanup proof"]}
    sampled = set()
    x["baseline"] = inventory()
    save()
    overrides = [p for p in os.environ if p.startswith("SAFEYOLO_")]
    prior_product = any(p.exists() or p.is_symlink() for p in
                        [root, archive.parent, store, Path.home() / ".local/share/safeyolo/tools"])
    prior_vendor = any(x["baseline"][key][p] for key in ["auth_present", "vendor_cache_present"] for p in x["baseline"][key])
    if prior_product or prior_vendor or overrides or x["baseline"]["credential_env_names"] or os.uname().machine != package["machine"]:
        x["baseline_unavailable"] = {"reason": "Existing product/authentication inputs, overrides or wrong architecture; all preserved", "override_names": overrides}
        save()
        return 2
    project.mkdir(mode=0o755)
    (project / "onboarding-fixture.txt").write_text("SAFEYOLO_ONBOARDING_FIXTURE\n")
    x["fixture_preparation"] = {"project": str(project), "file": "onboarding-fixture.txt", **stamp()}
    x["owns_product_attempt"] = True
    save()
    try:
        observe("baseline-sudo-noninteractive", ["sudo", "-n", "true"], 5)
        started = time.monotonic()
        first = observe("bootstrap-download", DOWNLOAD, 60)
        x["product_commands"].append(first)
        save()
        if first.get("exit") != 0:
            return 1
        x["bootstrap_sha256"] = digest(project / "install-safeyolo.sh")
        cold, state_before = entered("cold", max(1, 900 - (time.monotonic() - started)))
        x["timings"] = {"bootstrap_seconds": first["ended"]["monotonic"] - first["monotonic"],
                        "cold_readiness_seconds": (cold["signed_out_label"]["monotonic"] - first["monotonic"])
                        if cold.get("signed_out_label") else None}
        capture(x, "after_q_runtime", live_record)
        capture(x, "after_q_processes", processes)
        guest("after-q-marker", MARKER_QUERY, time.monotonic() + 15)
        if archive.is_file():
            x["host_archive"] = {"path": str(archive), "bytes": archive.stat().st_size,
                "sha256": digest(archive)}
            x["host_archive"]["matches_assigned_bytes"] = (x["host_archive"]["bytes"] == package["bytes"] and x["host_archive"]["sha256"] == package["sha256"])
        capture(x, "package_info", lambda: text(root / "package-info"))
        observe("native-version", [cli, "--version"])
        observe("native-help", [cli, "--help"])
        observe("proxy-version", [root / "bin/safeyolo-proxy", "--version"])
        observe("installed-runsc-version", [root / "libexec/runsc", "--version"])
        guest("harness-version", "command -v claude; claude --version", time.monotonic() + 20)
        save()
        # A failed/terminated first entry is not silently retried as a warm success.
        if cold.get("ordinary_q") and cold.get("exit_code") == 0 and not cold.get("observer_terminated_viewer"):
            warm, state_after = entered("warm", 180)
            x["timings"]["warm_readiness_seconds"] = (warm["signed_out_label"]["monotonic"] - warm["monotonic"]
                if warm.get("signed_out_label") else None)
            x["timings"]["observer_gap_before_warm_seconds"] = warm["monotonic"] - cold["ended"]["monotonic"]
            x["selected_public_state_equality"] = {p: bool(state_before.get(p)) and state_before.get(p) == state_after.get(p) for p in PUBLIC_STATE}
            x["selected_private_state_equality"] = {p: (p in state_before and p in state_after
                and (bool(state_before[p]) or p in OPTIONAL_PRIVATE_STATE) and state_before[p] == state_after[p])
                for p in PRIVATE_STATE + OPTIONAL_PRIVATE_STATE}
            a, b = x["before-return"], x["after-reentry"]
            x["same_runtime_record"] = a.get("runtime") == b.get("runtime")
            x["same_marker"] = (a.get("marker", {}).get("exit") == b.get("marker", {}).get("exit") == 0
                and a["marker"]["stdout"].split("heartbeat=")[0] == b["marker"]["stdout"].split("heartbeat=")[0])
            x["marker_heartbeat_changed"] = bool(x["same_marker"] and a["marker"]["stdout"] != b["marker"]["stdout"])
            x["live_births_match"] = all(len(r.get("runtime", {}).get("live_births", {})) == 2
                and all(pair["observed"] and pair["observed"] == pair["recorded"]
                        for pair in r["runtime"]["live_births"].values()) for r in [a, b])
            x["warm_returned_normally"] = bool(warm.get("ordinary_q") and warm.get("exit_code") == 0 and not warm.get("observer_terminated_viewer"))
            complete = (cold.get("signed_out_label") and warm.get("signed_out_label")
                and x.get("host_archive", {}).get("matches_assigned_bytes")
                and isinstance(x.get("package_info"), str)
                and f"source_commit={SOURCE}" in x["package_info"] and "profile=production" in x["package_info"]
                and f"platform={args.platform}" in x["package_info"]
                and x["warm_returned_normally"] and x["same_runtime_record"] and x["same_marker"]
                and x["marker_heartbeat_changed"] and x["live_births_match"]
                and all(r.get("discovery_exit") == r.get("version_exit") == 0 for r in [cold, warm])
                and all(x["selected_public_state_equality"].values())
                and all(x["selected_private_state_equality"].values())
                and all(r.get("home_matches") and r.get("workspace_matches") and len(r.get("network", [])) == 3
                        and all(n["expected_result"] for n in r["network"]) for r in [a, b]))
            if complete:
                x["observation_outcome"] = "captured; independent assessment required"
            if not warm.get("signed_out_label"):
                x["warm_display_limit"] = "Unclassified display; no warm harness-readiness time is claimed. Live operands and normal return are separate."
        else:
            x["warm_not_run"] = "First entry did not return normally; preserve reached result without retry."
    except Exception as error:
        # This observer boundary records an unexpected error and still performs owned cleanup.
        x["observer_error"] = repr(error)
        save()
        return 1
    finally:
        try:
            cleanup()
        finally:
            x["ended"] = stamp()
            save()
    return 0 if x["observation_outcome"] != "partial" and x.get("cleanup_verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
