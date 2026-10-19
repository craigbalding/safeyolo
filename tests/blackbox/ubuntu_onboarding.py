#!/usr/bin/env python3
"""One owned Ubuntu public install and normal reentry.

Adapted from the retained observer for issue 239's Ubuntu AMD64 consumer.
Run only on the fresh runner named by --host with its matching --platform.
Python is an observer prerequisite; the product keeps the runner's normal PATH.
The two product commands retain the normal PATH, proxy, CA and shipped harness.
Only result.json may be uploaded. Terminal screens and state hashes stay private.
Use --cleanup-only after an interrupted attempt on this same owned host.
The observer owns its attempted installation; it borrows the runner and its tools.
The default endpoint is signed out. --connected adds one foreground first task
and live return, with --preparation supplying actual prior accounting operands.
In connected mode, Ctrl-] triggers the fixed task once; other input stays in the
normal product terminal. The observer never signs in or retries a task.
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
import tty
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
CONNECTED_SOURCE = "c5ce76019b6c997e282ab05cea0212b492e945d2"
CONNECTED_PACKAGE = {"machine": "x86_64", "bytes": 191260514,
                     "sha256": "811a20c1fa75d081504b9bfa3a7766bb3c2df6e55f4740742243ad24bc217538"}
TASK = ('Create /workspace/index.html as a complete HTML page with the heading '
        '"Hello from SafeYolo". Use no external dependencies.')
CONNECTED_PROSE = ("Start in an empty workspace on Ubuntu 24.04 AMD64 with curl and bash. "
    "Use an ordinary account. Review the requested host changes and workspace access before consenting. "
    "If you already use Claude, you can consent to copy its selected host authentication. "
    "Ctrl-b then d opens SafeYolo's host controls. Use a to inspect pending requests and their scope before approving. "
    "Press Enter to return. After the first task, detach and use q to keep the session. "
    "Repeat the second command to return to it.")
SIGNED_OUT_PROSE = ("Use an ordinary account on a fresh Ubuntu 24.04 host with curl and bash. "
    "Review the host changes and workspace access before consenting. "
    "This observation declines authentication copy and stops at the sign-in screen. "
    "Ctrl-b then d opens the host controls. Use q to keep the session. "
    "Repeat the second command to return to it.")
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


def record_reading(phase, kind, data=None):
    """Count the presented text, retaining account screens only in private files."""
    if data is None:
        # Read the full recorded output, rather than the bounded prompt-search
        # buffer, so progress output cannot hide earlier consent prose.
        offsets = x.setdefault("reading_offsets", {})
        with (private / (phase + ".terminal")).open("rb") as stream:
            stream.seek(offsets.get(phase, 0))
            data = stream.read()
            offsets[phase] = stream.tell()
    plain = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", data).decode(errors="replace")
    # The reading budget excludes commands and the fixed task, including a
    # wrapped echo of the task in the attached terminal.
    for excluded in [TASK, shlex.join(DOWNLOAD), shlex.join(LAUNCH)]:
        plain = re.sub(r"\s+".join(map(re.escape, excluded.split())), "", plain)
    rows = x.setdefault("required_reading", [])
    name = f"reading-{len(rows)}.txt"
    (private / name).write_text(plain)
    rows.append({"phase": phase, "kind": kind, "words": len(plain.split()),
                 "private_file": name, "count_method": "whitespace-separated displayed tokens", **stamp()})
    save()


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


def observe(label, args, timeout=20, private_output=False, role="observer"):
    row = {"label": label, "role": role, "command": list(map(str, args)), **stamp()}
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
            row["recorded_runtime_birth_match"] = bool(expected and row["birth"] == expected)
            if owner.st_uid != os.getuid() and not row["recorded_runtime_birth_match"]:
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
            elif row["argv_root_match"] or row["executable_root_match"] or row["recorded_runtime_birth_match"]:
                result.append({"pid": pid, "birth": row["birth"], "executable": executable,
                               "uid": row["uid"], "gid": row["gid"]})
            row["ownership"] = ("unknown" if pid in unreadable else
                                "owned" if row["argv_root_match"] or row["executable_root_match"] or row["recorded_runtime_birth_match"] else "unrelated")
        except (FileNotFoundError, ProcessLookupError) as error:
            # A missing file does not prove that a recorded runtime birth exited.
            if row.get("recorded_runtime_birth_match") and birth(pid) == row["birth"]:
                unreadable.append(pid)
                row.update(errno=error.errno, ownership="unknown", birth_after=birth(pid))
            continue
        except (OSError, subprocess.TimeoutExpired) as error:
            # A stable unreadable process cannot be classified as owned or unrelated.
            if entry.exists():
                unreadable.append(pid)
                row.update(errno=getattr(error, "errno", None), error_type=type(error).__name__,
                           ownership="unknown", birth_after=birth(pid))
        finally:
            if row.get("permission_reads") or row.get("recorded_runtime_birth_match") or pid in unreadable:
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
    counts = x.setdefault("observer_tmux_commands", {})
    counts["display-message"] = counts.get("display-message", 0) + 1
    facts = subprocess.run([*command, "display-message", "-p", "-t", launch["pane_id"],
        "#{@safeyolo_launch_id}\t#{pane_dead}\t#{window_active}\t#{pane_active}\t#{session_attached}"],
        capture_output=True, timeout=2)
    values = facts.stdout.decode(errors="replace").strip().split("\t")
    visible = (facts.returncode == 0 and len(values) == 5 and values[:4] == [launch.get("launch_id"), "0", "1", "1"]
               and values[4].isdigit() and int(values[4]) > 0)
    row = {"facts_exit": facts.returncode, "matching_live_visible_pane": visible,
           "selection": launch, "facts": values, **stamp()}
    if visible:
        counts["capture-pane"] = counts.get("capture-pane", 0) + 1
        screen = subprocess.run([*command, "capture-pane", "-p", "-e", "-J", "-t", launch["pane_id"]],
                                capture_output=True, timeout=2)
        (private / (phase + "-pane.screen")).write_bytes(screen.stdout)
        (private / (phase + "-pane.stderr")).write_bytes(screen.stderr)
        row.update(exit=screen.returncode, labels=login_label(screen.stdout) if screen.returncode == 0 else [], ended=stamp())
    return row


def conversation_offsets():
    return {str(p): p.stat().st_size for p in (root / "agents/first/home/.claude/projects").glob("*/*.jsonl")}


def task_records(records, host_content):
    """Project the reached Claude JSONL format without exporting message contents."""
    users, writes, results, errors = [], [], [], []
    active = False
    for index, event in enumerate(records):
        message = event.get("message", {})
        content = message.get("content", [])
        blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content
        texts = [b.get("text", "") for b in blocks if b.get("type") == "text"]
        if event.get("type") == "user" and texts and not event.get("isMeta"):
            exact = texts == [TASK]
            users.append({"uuid": event.get("uuid"), "timestamp": event.get("timestamp"), "exact_task": exact})
            active |= exact
        if not active:
            continue
        for label in ["Login expired", "API Error: 401", "API Error: 428"]:
            if any(label in value for value in texts) and label not in errors:
                errors.append(label)
        for block in blocks:
            if event.get("type") == "assistant" and block.get("type") == "tool_use" and block.get("name") == "Write":
                operand = block.get("input", {})
                writes.append({"id": block.get("id"), "timestamp": event.get("timestamp"), "event_index": index,
                    "target_matches": operand.get("file_path") == "/workspace/index.html",
                    "content_matches_host": host_content is not None and operand.get("content") == host_content})
            if event.get("type") == "user" and block.get("type") == "tool_result":
                results.append({"tool_use_id": block.get("tool_use_id"), "timestamp": event.get("timestamp"), "event_index": index,
                                "is_error": block.get("is_error", False)})
    matched = [w["id"] for w in writes if w["id"] and w["target_matches"] and w["content_matches_host"]
               and any(r["tool_use_id"] == w["id"] and r["is_error"] is False
                       and w["event_index"] < r["event_index"] for r in results)]
    return {"users": users, "writes": writes, "tool_results": results, "errors": errors,
            "matching_write_result_ids": matched,
            "successful_task": len(users) == 1 and users[0]["exact_task"] and bool(matched)}


def task_observation(offsets):
    file = project / "index.html"
    content = file.read_text() if file.is_file() else None
    conversations = []
    for path in (root / "agents/first/home/.claude/projects").glob("*/*.jsonl"):
        with path.open("rb") as stream:
            stream.seek(offsets.get(str(path), 0))
            data = stream.read()
        # An in-progress final line is not a complete canonical event yet.
        lines = data.splitlines(keepends=True)
        records = [json.loads(line) for line in lines if line.endswith(b"\n")]
        if any(record.get("type") == "user" and
               (record.get("message", {}).get("content") == TASK or
                record.get("message", {}).get("content") == [{"type": "text", "text": TASK}]) for record in records):
            conversations.append({"file": str(path.relative_to(root)), **task_records(records, content)})
    complete = (len(conversations) == 1 and conversations[0]["successful_task"] and content is not None
                and bool(re.search(r"<h1\b[^>]*>\s*Hello from SafeYolo\s*</h1>", content, re.I))
                and "</html>" in content.lower())
    return {"conversations": conversations, "file_present": content is not None,
            "file_bytes": file.stat().st_size if content is not None else None,
            "successful_task": complete, **stamp()}


class ConnectedJourney:
    """One foreground task and one live return through the existing launch driver."""

    def __init__(self, phase, row):
        self.phase, self.row = phase, row
        self.input = b""
        self.screen = b""
        self.pane = {}
        self.sent = False
        self.decision_seen = None
        self.first_key = None
        baseline = private / "conversation-offsets.json"
        if phase == "cold":
            self.offsets = conversation_offsets()
            baseline.write_text(json.dumps(self.offsets))
        else:
            self.offsets = read_json(baseline)

    def poll(self):
        self.pane = pane_screen(self.phase)
        self.row["pane_screen"] = self.pane
        if not self.pane.get("matching_live_visible_pane") or self.pane.get("exit") != 0:
            return False
        self.screen = (private / (self.phase + "-pane.screen")).read_bytes()
        plain = terminal_plain(self.screen)
        task = task_observation(self.offsets)
        if task["file_present"] and "host_file_first_seen" not in self.row:
            self.row["host_file_first_seen"] = {"previous_sample": self.row.get("last_task_sample"), **stamp()}
        if any(c["users"] for c in task["conversations"]) and "canonical_submission_first_seen" not in self.row:
            self.row["canonical_submission_first_seen"] = stamp()
        self.row["last_task_sample"] = stamp()
        self.row["task_observation"] = task
        if b"login expired" in plain or (self.sent and b"api error: 401" in plain):
            self.row["connected_failure"] = "Observed provider authentication failure; no task or login retry."
            return True
        if self.phase == "cold" and self.sent and time.monotonic() - self.row["task_input"]["enter_attempted"]["monotonic"] > 20:
            if not any(c["users"] for c in task["conversations"]):
                self.row["connected_failure"] = "Enter was sent, but canonical submission was not observed; no retransmission."
                return True
        if self.input_ready() and task["successful_task"]:
            if b"index.html" in plain and b"hello from safeyolo" in plain:
                self.row["connected_ready"] = stamp()
                return True
        return False

    def input_ready(self):
        plain = terminal_plain(self.screen)
        # This identifies an input display, not working provider authentication.
        return (self.pane.get("matching_live_visible_pane") and "❯".encode() in plain
                and not login_label(self.screen) and b"esc to interrupt" not in plain)

    def submit(self):
        if self.phase != "cold" or self.sent or self.row.get("task_input"):
            raise ValueError("This journey permits one task transmission and no warm task.")
        self.poll()
        if not self.input_ready():
            raise ValueError("Task input requires the selected live, active, attached input pane.")
        selection = self.pane["selection"]
        command = [str(root / "bin/tmux"), "-S", selection["tmux_socket"]]
        task = {"text": TASK, "selection": selection, "facts_before_input": self.pane["facts"],
                "literal_attempted": stamp(), "literal_transmissions": None}
        self.row["task_input"] = task
        x.setdefault("observer_tmux_commands", {}).setdefault("send-keys", 0)
        x["observer_tmux_commands"]["send-keys"] += 1
        save()  # Save intent before either uncertain external input effect.
        subprocess.run([*command, "send-keys", "-t", selection["pane_id"], "-l", TASK], check=True, timeout=3)
        task["literal_transmissions"] = 1
        time.sleep(0.3)
        checked = pane_screen(self.phase + "-input")
        screen = (private / (self.phase + "-input-pane.screen")).read_bytes() if checked.get("exit") == 0 else b""
        # Claude can insert explicit newlines and indentation even with tmux -J.
        # Fold display whitespace only; canonical saved tasks still match TASK exactly.
        plain = b" ".join(terminal_plain(screen).split())
        task.update(input_readback=checked, input_visible=TASK.lower().encode() in plain)
        save()
        if not checked.get("matching_live_visible_pane") or checked["selection"] != selection or not task["input_visible"]:
            raise ValueError("Literal input readback failed; Enter was not sent and input will not be repeated.")
        task["enter_attempted"] = stamp()
        x["observer_tmux_commands"]["send-keys"] += 1
        save()
        subprocess.run([*command, "send-keys", "-t", selection["pane_id"], "Enter"], check=True, timeout=3)
        self.sent = True
        task["enter_sent"] = stamp()
        save()

    def forward(self, fd, data, pending):
        # tmux asks the outer terminal for colours, attributes and cursor
        # position. Forward its replies without counting them as human choices.
        keys = re.sub(rb"\x1b\](?:10|11);[^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-9;?=>]*[cR]|\x1bP>\|.*?\x1b\\", b"", data)
        if not keys:
            os.write(fd, data)
            return
        if b"\x1d" in keys:
            if keys != b"\x1d" or keys != data:
                raise ValueError("Send the observer task trigger alone; mixed input was preserved without forwarding.")
            self.submit()
            return
        if not self.input:
            self.decision_seen = self.row.get("terminal_output_last_seen")
            self.first_key = stamp()
            current = pane_screen(self.phase + "-decision")
            screen = ((private / (self.phase + "-decision-pane.screen")).read_bytes()
                      if current.get("exit") == 0 else None)
            if screen is None and not (private / (self.phase + ".terminal")).is_file():
                screen = pending
            record_reading(self.phase, "foreground decision screen", screen)
        self.input += keys
        if b"\r" in data or b"\n" in data or b"\x02d" in self.input:
            answer = self.input.strip(b"\r\n")
            known = {b"": "Enter", b"a": "a", b"q": "q", b"approve": "approve", b"reject": "reject",
                     b"\x02d": "Ctrl-b d", b"\x1b[B": "Down, Enter", b"\x1b[A": "Up, Enter"}
            public = known.get(answer, "request number" if answer.isdigit() else "private/unclassified input")
            interaction = {"phase": self.phase, "kind": "foreground operator input", "answer": public,
                "bytes": len(self.input), "seen": self.decision_seen, "first_key": self.first_key, "sent": stamp(),
                "classification_complete": public != "private/unclassified input"}
            if public in {"approve", "reject"}:
                plain = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", pending)
                views = re.findall(rb"Request: ([^\r\n]+)\r?\nStatus: ([^\r\n]+)\r?\nSafeYolo effect: ([^\r\n]+)", plain)
                if views:
                    identifier, status, effect = views[-1]
                    interaction["displayed_approval"] = {"request_id": identifier.decode(), "status": status.decode(), "effect": effect.decode()}
                else:
                    interaction["classification_complete"] = False
            x["interactions"].append(interaction)
            self.input = b""
            save()
        os.write(fd, data)


def witness(phase, start_marker=False, connected=False):
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
    if connected:
        capture(row, "task", lambda: task_observation(read_json(private / "conversation-offsets.json")))
        return snapshot_state(phase, row, connected=True)
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
    return snapshot_state(phase, row)


def snapshot_state(phase, row, connected=False):
    capture(row, "guest_selection", lambda: read_json(root / "share/guest-selection.json"))
    state = {}
    # These hashes stay private. A failed read must not erase the other operands.
    paths = PUBLIC_STATE + PRIVATE_STATE + OPTIONAL_PRIVATE_STATE
    if connected:
        paths += ["agents/first/home/.claude.json", "agents/first/home/.claude/settings.json"]
    for path in paths:
        try:
            state[path] = digest(root / path) if (root / path).is_file() else None
        except OSError as error:
            row.setdefault("state_observation_errors", {})[path] = str(error)
    if connected:
        for path in [".claude.json", ".claude/.credentials.json"]:
            source = Path.home() / path
            key = "host-state/" + path
            try:
                state[key] = digest(source) if source.is_file() else None
            except OSError as error:
                row.setdefault("state_observation_errors", {})[key] = str(error)
    (private / (phase + "-state-hashes.json")).write_text(json.dumps(state))
    row["selected_public_state_present"] = [p for p in PUBLIC_STATE if state.get(p)]
    row["selected_private_state_present"] = [p for p in state if p not in PUBLIC_STATE and state.get(p)]
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


def record_launch_result(row, output):
    """Save fixed diagnostic categories before runtime capture or owned cleanup."""
    result = {"command_exit": row.get("command_exit"), "failure_phase": "unknown",
              "error_category": "unknown", "launch_id": None, **stamp()}
    boundaries = [r["boundary"] for r in x["phase_observations"]
                  if r["phase"] == row["phase"] and r["boundary"] in dict(PHASE_TEXT)]
    result["last_observed_phase"] = boundaries[-1] if boundaries else "unknown"
    # Inspect only launch output, before the same-terminal diagnostic commands.
    # Never export an error excerpt, even for a recognized product prefix.
    plain = terminal_plain(output[-60000:]).split(b"sy239_command_exit=", 1)[0]
    phases = {"shipped harness setup": "harness-setup", "host setup": "host-setup",
              "services": "services-start", "proxy readiness": "proxy-readiness",
              "coord readiness": "coord-readiness", "sandbox/harness startup": "sandbox-harness-start",
              "terminal attachment": "terminal-attachment", "harness session": "harness-session",
              "approvals": "approvals", "sandbox/harness retry": "sandbox-harness-retry"}
    if row.get("command_exit") not in (None, 0):
        matches = re.findall(rb"(?:^|[\r\n])(?:safeyolo: )?first-agent ([^:\r\n]{1,80}) failed: ([^\r\n]*)", plain)
        if matches and matches[-1][0].decode(errors="replace") in phases:
            result["failure_phase"] = phases[matches[-1][0].decode()]
            for message, error_category in [
                (b"coding-agent observation timed out", "coding-agent-observation-timeout"),
                (b"coding-agent observation failed", "coding-agent-observation-failed"),
                (b"coding-agent observation is unverified", "coding-agent-observation-unverified"),
            ]:
                if matches[-1][1].startswith(message + b". saved agent state is retained."):
                    result["error_category"] = error_category
    try:
        launch = launch_record()
    except (OSError, ValueError):
        # A missing/corrupt identity remains unknown; do not lose the diagnosis
        # or prevent disposal, and do not export exception text from private state.
        result["identity_status"] = "unreadable"
    else:
        launch_id = launch.get("launch_id")
        if isinstance(launch_id, str) and re.fullmatch(r"launch-[0-9a-f]{32}", launch_id):
            result.update(launch_id=launch_id, identity_status="recorded")
        else:
            result["identity_status"] = "unavailable"
    row["launch_result"] = result
    save()


def entered(phase, seconds, connected=False, operator_fd=None):
    row = {"command": LAUNCH, "role": "product", "phase": phase, **stamp()}
    row["post_return_diagnostics"] = [["command", "-v", "safeyolo"], ["safeyolo", "--version"]]
    x["product_commands"].append(row)
    save()
    # Post-q discovery runs in the same terminal and inherited shell PATH.
    script = (shlex.join(LAUNCH) + '\nresult=$?\nprintf "\\nSY239_COMMAND_EXIT=%s\\n" "$result"\n'
              'printf "SY239_DISCOVERY_BEGIN\\n"\ncommand -v safeyolo\nprintf "SY239_DISCOVERY_EXIT=%s\\n" "$?"\n'
              'printf "SY239_VERSION_BEGIN\\n"\nsafeyolo --version\nprintf "SY239_VERSION_EXIT=%s\\n" "$?"\nexit "$result"\n')
    journey = ConnectedJourney(phase, row) if connected else None
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
    old_terminal = None
    connected_done = False
    try:
        if connected and operator_fd is None:
            operator_fd = sys.stdin.fileno()
            old_terminal = termios.tcgetattr(operator_fd)
            tty.setraw(operator_fd)
        with (private / (phase + ".terminal")).open("wb") as log:
            while True:
                sample_files(phase)
                ready = select.select(([fd] if terminal_open else []) + ([operator_fd] if connected else []), [], [], 0.25)[0]
                if connected and operator_fd in ready:
                    data = os.read(operator_fd, 1024)
                    if not data:
                        raise EOFError("Foreground operator input closed; preserve the reached journey without retry.")
                    journey.forward(fd, data, pending)
                if fd in ready:
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
                        if connected:
                            os.write(sys.stdout.fileno(), chunk)
                            row["terminal_output_last_seen"] = stamp()
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
                    ("auth", "Copy this selected host authentication and settings? [y/N]", "y\n" if connected else "n\n"),
                ]:
                    if terminal_open and label not in completed and prompt.encode() in pending:
                        seen = stamp()
                        record_reading(phase, label + " consent")
                        os.write(fd, answer.encode())
                        x["interactions"].append({"phase": phase, "prompt": prompt,
                                                  "answer": answer.strip(), "seen": seen, "sent": stamp()})
                        completed.add(label)
                        pending = b""
                        save()
                theme = theme_prompt(pending)
                if terminal_open and phase == "cold" and "sandbox-harness-start" in completed and "theme" not in completed and theme:
                    seen = stamp()
                    record_reading(phase, "guest display choice")
                    os.write(fd, b"\r")
                    x["interactions"].append({"phase": phase, "kind": "guest display choice",
                        "prompt": theme, "answer": "Enter (default theme)", "seen": seen, "sent": stamp()})
                    completed.add("theme")
                    pending = b""
                    save()
                labels = login_label(pending) if not connected else []
                label_source = "host-terminal-output"
                if connected and terminal_open and not captured and time.monotonic() >= next_pane_read:
                    connected_done = journey.poll()
                    next_pane_read = time.monotonic() + 0.5
                if not connected and terminal_open and not captured and not labels and time.monotonic() >= next_pane_read:
                    # Reentry need not emit the old prompt again. Read the current
                    # visible screen, without treating wrapper text or liveness as readiness.
                    capture(row, "pane_screen", lambda: pane_screen(phase))
                    next_pane_read = time.monotonic() + 1
                    labels = row["pane_screen"].get("labels", [])
                    label_source = "attached-pane-screen"
                expired = time.monotonic() >= deadline
                if terminal_open and not captured and (labels or connected_done or expired):
                    if labels:
                        row["signed_out_label"] = {"labels": labels, "source": label_source, **stamp()}
                    elif not row.get("connected_ready"):
                        row["readiness_unclassified_at_deadline"] = stamp()
                    save()
                    started = time.monotonic()
                    captured = True
                    states = witness("before-return" if phase == "cold" else "after-reentry", phase == "cold" and not connected,
                                     **({"connected": True} if connected else {}))
                    row["capture_seconds"] = time.monotonic() - started
                    # Capture precedes detach even for an unclassified UI.
                    os.write(fd, b"\x02d")
                    detached = True
                    row["viewer_detach"] = stamp()
                    x["interactions"].append({"phase": phase, "kind": "return to host", "answer": "Ctrl-b d", "sent": stamp()})
                    pending = b""
                    deadline = time.monotonic() + 30
                    save()
                if terminal_open and detached and b"SafeYolo host> " in pending and "q" not in completed:
                    record_reading(phase, "host return controls")
                    os.write(fd, b"q\n")
                    row["ordinary_q"] = stamp()
                    x["interactions"].append({"phase": phase, "kind": "keep session and exit", "answer": "q", "sent": stamp()})
                    completed.add("q")
                    pending = b""
                    save()
                for key in ["COMMAND", "DISCOVERY", "VERSION"]:
                    match = re.search(rb"SY239_" + key.encode() + rb"_EXIT=(\d+)", pending)
                    if match:
                        row[key.lower() + "_exit"] = int(match.group(1))
                        if key == "COMMAND" and "launch_result" not in row:
                            record_launch_result(row, pending)
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
        if "launch_result" not in row:
            # An interrupted viewer or an absent exit marker has no classified
            # product failure. Retain explicit unknowns before cleanup starts.
            record_launch_result(row, pending)
        if journey and journey.input:
            row["unfinished_foreground_input"] = {"bytes": len(journey.input), "seen": journey.decision_seen,
                                                   "first_key": journey.first_key, **stamp()}
        if old_terminal is not None:
            termios.tcsetattr(operator_fd, termios.TCSADRAIN, old_terminal)
        # Viewer EOF or any classification error must still leave reached live operands.
        if not captured:
            try:
                states = witness("before-return" if phase == "cold" else "after-reentry", phase == "cold" and not connected,
                                 **({"connected": True} if connected else {}))
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


def preparation_accounting(path):
    """Read nonsecret observations of preparation already owned by the operator."""
    if path is None:
        raise ValueError("Connected observation needs --preparation with actual prior commands, times and reading; no cold run started.")
    data = read_json(path)
    if not isinstance(data, dict) or data.get("required_user_commands_complete") is not True:
        raise ValueError("Required user preparation is unknown; resolve it before a cold attempt.")
    if data.get("required_user_reading_complete") is not True or not isinstance(data.get("required_reading"), list):
        raise ValueError("Required preparation reading is unknown; include its actual prose or an explicit empty list.")
    commands = data.get("commands")
    if not isinstance(commands, list):
        raise ValueError("Preparation commands must be recorded, including an explicit empty list when none were needed.")
    for command in commands:
        if (not isinstance(command, dict) or command.get("role") not in {"required-user", "fixture", "observer"}
                or not isinstance(command.get("command"), list) or not command["command"]
                or not all(isinstance(value, str) for value in command["command"])):
            raise ValueError("Each preparation command needs its actual command operands and required-user, fixture or observer role.")
        if not command.get("reason"):
            raise ValueError("Each preparation classification needs its normal-user or fixture reason.")
        for key in ["started_at", "ended_at"]:
            if command.get(key) is not None:
                if not isinstance(command[key], str) or dt.datetime.fromisoformat(command[key]).utcoffset() is None:
                    raise ValueError("Preparation timestamps need an explicit UTC offset.")
    decisions = data.get("decisions")
    if not isinstance(decisions, list):
        raise ValueError("Preparation decisions must be recorded; use an explicit empty list when none were needed.")
    for decision in decisions:
        if (not isinstance(decision, dict) or decision.get("role") not in {"required-user", "fixture", "observer"}
                or not isinstance(decision.get("description"), str) or not decision["description"]):
            raise ValueError("Each preparation decision needs its role and nonsecret description.")
        for key in ["seen_at", "answered_at"]:
            if decision.get(key) is not None:
                if not isinstance(decision[key], str) or dt.datetime.fromisoformat(decision[key]).utcoffset() is None:
                    raise ValueError("Preparation timestamps need an explicit UTC offset.")
    for reading in data["required_reading"]:
        if not isinstance(reading, dict) or not isinstance(reading.get("text"), str):
            raise ValueError("Preparation reading must contain its actual text.")
        if reading.get("seen_at") is not None:
            if not isinstance(reading["seen_at"], str) or dt.datetime.fromisoformat(reading["seen_at"]).utcoffset() is None:
                raise ValueError("Preparation timestamps need an explicit UTC offset.")
    # Account for transport in the fixture category only when the recorded
    # caller supports that distinction. Operator7950 supplies the actual source.
    x["preparation"] = data
    save()
    return data


def signed_out_accounting():
    """Keep counts and measured intervals without claiming a first task."""
    cold = [row for row in x["product_commands"] if row.get("phase") != "warm"]
    warm = [row for row in x["product_commands"] if row.get("phase") == "warm"]
    x["counts"] = {"cold_product_commands": len(cold), "warm_product_commands": len(warm),
        "product_interactions": len(x["interactions"]),
        "material_decisions": sum(bool(row.get("prompt")) for row in x["interactions"]),
        "required_reading_words": sum(row["words"] for row in x.get("required_reading", [])),
        "canonical_task_submissions": 0,
        "observer_diagnostic_commands": sum(row.get("role") == "observer" for row in x["observations"]),
        "observer_tmux_commands": x.get("observer_tmux_commands", {}),
        "reading_method": "Displayed instructions and terminal text; command echoes excluded. Repeated text counts again.",
        "limits": "Signed-out endpoint only. No human reading duration or complete first-task command count is claimed."}
    timings = x.setdefault("timings", {})
    timings.update(phase_boundaries=x["phase_observations"],
        automated_interaction_intervals=[row for row in x["interactions"] if row.get("seen")],
        observer_intervals=[{"label": row["label"], "started": {key: row[key] for key in ["at", "monotonic"]},
                             "ended": row.get("ended")} for row in x["observations"] if row.get("role") == "observer"],
        wait_limit="Phase observations are sampled bounds. Automated responses do not measure human reading or provider-only waits.")
    save()


def connected_accounting():
    preparation = x["preparation"]
    commands = preparation["commands"]
    cold = [row for row in x["product_commands"] if row.get("phase") != "warm"]
    warm = [row for row in x["product_commands"] if row.get("phase") == "warm"]
    required = [row for row in commands if row["role"] == "required-user"]
    readings = x.get("required_reading", [])
    decisions = preparation["decisions"]
    transmissions = [row["task_input"]["literal_transmissions"] for row in cold if row.get("task_input")]
    x["counts"] = {"cold_product_commands": len(cold), "warm_product_commands": len(warm),
        "required_user_preparation_commands": len(required), "total_required_user_commands_to_first_task": len(required) + len(cold),
        "fixture_preparation_commands": sum(row["role"] == "fixture" for row in commands),
        "observer_preparation_commands": sum(row["role"] == "observer" for row in commands),
        "observer_diagnostic_commands": sum(row.get("role") == "observer" for row in x["observations"]),
        "observer_tmux_commands": x.get("observer_tmux_commands", {}),
        "required_user_preparation_decisions": sum(row["role"] == "required-user" for row in decisions),
        "fixture_preparation_decisions": sum(row["role"] == "fixture" for row in decisions),
        "observer_preparation_decisions": sum(row["role"] == "observer" for row in decisions),
        "product_interactions": len(x["interactions"]),
        "literal_task_attempts": len(transmissions),
        "literal_task_transmissions": sum(transmissions) if all(value is not None for value in transmissions) else None,
        "canonical_task_submissions": sum(len(conversation["users"]) for conversation in
            (cold[-1].get("task_observation", {}).get("conversations", []) if cold else [])),
        "material_decisions": (sum(row["role"] == "required-user" for row in decisions)
            + sum(bool(row.get("prompt")) or row.get("kind") == "guest display choice" or row.get("answer") in
            ["approve", "reject", "Down, Enter", "Up, Enter", "request number"] for row in x["interactions"])),
        "required_reading_words": sum(row["words"] for row in readings),
        "reading_method": "Presented normal-path prose, whole decision screens and recorded terminal output before consent/host-control input. Output and repeated text count again. Known task/command echoes are excluded. This is a conservative displayed-token count, not measured human reading effort.",
        "interaction_classification_complete": (all(row.get("classification_complete", True) for row in x["interactions"])
            and not any(row.get("unfinished_foreground_input") for row in cold + warm))}
    first = cold[0]["monotonic"] if cold else None
    launch = next((row for row in cold if row.get("phase") == "cold"), {})
    returned = warm[0] if warm else {}
    start_at = x["started"]["at"]
    required_starts = ([row.get("started_at") for row in required]
        + [row.get("seen_at") for row in decisions if row["role"] == "required-user"]
        + [row.get("seen_at") for row in preparation["required_reading"]])
    total_start = min([start_at, *[value for value in required_starts if value]], key=dt.datetime.fromisoformat)
    ready = launch.get("connected_ready", {})
    warm_ready = returned.get("connected_ready", {})
    def elapsed(a, b):
        return (dt.datetime.fromisoformat(b) - dt.datetime.fromisoformat(a)).total_seconds() if a and b else None
    x["timings"] = {"total_started_at": total_start,
        "required_preparation_start_known": all(required_starts),
        "cold_total_to_first_task_seconds": elapsed(total_start, ready.get("at")) if all(required_starts) else None,
        "cold_product_to_first_task_seconds": ready.get("monotonic", first) - first if first and ready else None,
        "cold_product_to_input_seconds": (launch["task_input"]["enter_sent"]["monotonic"] - first
            if first and launch.get("task_input", {}).get("enter_sent") else None),
        "canonical_submission_first_seen": launch.get("canonical_submission_first_seen"),
        "host_file_first_seen": launch.get("host_file_first_seen"),
        "warm_readiness_seconds": warm_ready["monotonic"] - returned["monotonic"] if warm_ready else None,
        "human_decision_intervals": [{"phase": row["phase"], "seen": row["seen"], "first_key": row["first_key"], "sent": row["sent"]}
            for row in x["interactions"] if row.get("seen") and row.get("kind") == "foreground operator input"],
        "preparation_decision_intervals": decisions,
        "automated_consent_intervals": [{"phase": row["phase"], "seen": row["seen"], "sent": row["sent"]}
            for row in x["interactions"] if row.get("seen") and row.get("kind") != "foreground operator input"],
        "observer_intervals": [{"label": row["label"], "started": {key: row[key] for key in ["at", "monotonic"]},
                               "ended": row.get("ended")} for row in x["observations"] if row.get("role") == "observer"],
        "phase_boundaries": x["phase_observations"],
        "provider_request_intervals": provider_intervals(),
        "limits": ["Phase boundaries and screen readiness are sampled, not exact product start/completion times.",
                   "Foreground decision intervals start at the last observed terminal output before the first key; prompt appearance and active reading effort remain unknown.",
                   "Overlapping observer, download and provider work must not be added or subtracted as disjoint time.",
                   "Provider request durations include proxy/transport time; missing request/response operands stay unknown.",
                   "Host and guest phase intervals combine download, verification and extraction; their individual wait totals are unknown.",
                   "Unattributed time remains unknown; no historical wait attribution is reconstructed."],
        "target_15_seconds": "unmet; no operator target disposition is inferred"}
    save()


def provider_intervals():
    requests = {}
    intervals = []
    path = root / "logs/events.jsonl"
    if not path.is_file():
        return {"unavailable": "No reached product event log"}
    for line in path.read_bytes().splitlines(keepends=True):
        if not line.endswith(b"\n"):
            continue
        event = json.loads(line)
        if event.get("host") not in {"api.anthropic.com", "mcp-proxy.anthropic.com"} or not event.get("request_id"):
            continue
        identifier = event["request_id"]
        if event.get("event") == "traffic.request":
            requests[identifier] = event.get("ts")
        elif event.get("event") == "traffic.response":
            milliseconds = event.get("details", {}).get("ms")
            intervals.append({"request_id": identifier, "host": event["host"], "started_at": requests.pop(identifier, None),
                "ended_at": event.get("ts"), "recorded_duration_ms": milliseconds,
                "status": event.get("details", {}).get("status")})
    return {"responses": intervals, "requests_without_response": requests,
            "scope": "Reached requests in this new single-agent instance; no provider-only or disjoint-wait total."}


def connected_run(args, package):
    record_reading("cold", "normal-path instructions", CONNECTED_PROSE.encode())
    for row in x["preparation"].get("required_reading", []):
        record_reading("cold", "required preparation prose", row["text"].encode())
    print(CONNECTED_PROSE, flush=True)
    print("Observer: use the foreground product controls. At the input display, after pending approvals, press Ctrl-] once to send the fixed task. "
          "The observer checks the input, sends Enter once, then observes the file and one live return. Do not type another task.", flush=True)
    first = observe("bootstrap-download", DOWNLOAD, 60, role="product")
    x["product_commands"].append(first)
    save()
    if first.get("exit") != 0:
        return
    x["bootstrap_sha256"] = digest(project / "install-safeyolo.sh")
    cold, before = entered("cold", 900, connected=True)
    capture(x, "after_q_runtime", live_record)
    if archive.is_file():
        x["host_archive"] = {"bytes": archive.stat().st_size, "sha256": digest(archive)}
        x["host_archive"]["matches_assigned_bytes"] = (x["host_archive"]["bytes"] == package["bytes"]
            and x["host_archive"]["sha256"] == package["sha256"])
    capture(x, "package_info", lambda: text(root / "package-info"))
    if not (cold.get("connected_ready") and cold.get("ordinary_q") and cold.get("exit_code") == 0
            and not cold.get("observer_terminated_viewer")):
        x["warm_not_run"] = "First task/normal return was not established; no task, login or install retry."
        return
    file_before = digest(project / "index.html")
    warm, after = entered("warm", 180, connected=True)
    a, b = x["before-return"], x["after-reentry"]
    x["selected_state_equality"] = {path: {"present_before": bool(before.get(path)), "present_after": bool(after.get(path)),
        "equal": path in before and path in after and before[path] == after[path]} for path in before.keys() | after.keys()}
    x["same_runtime_record"] = a.get("runtime") == b.get("runtime")
    x["same_launch"] = a.get("launch") == b.get("launch")
    x["same_conversation"] = (a.get("task", {}).get("conversations") == b.get("task", {}).get("conversations"))
    x["host_file_unchanged"] = file_before == digest(project / "index.html")
    x["live_births_match"] = all(len(r.get("runtime", {}).get("live_births", {})) == 2
        and all(pair["observed"] and pair["observed"] == pair["recorded"]
                for pair in r["runtime"]["live_births"].values()) for r in [a, b])
    if (warm.get("connected_ready") and warm.get("ordinary_q") and warm.get("exit_code") == 0
            and not warm.get("observer_terminated_viewer") and x["same_runtime_record"] and x["same_launch"]
            and x["same_conversation"] and x["host_file_unchanged"] and x["live_births_match"]
            and x.get("host_archive", {}).get("matches_assigned_bytes")
            and isinstance(x["package_info"], str) and f"source_commit={CONNECTED_SOURCE}" in x["package_info"]
            and "profile=production" in x["package_info"] and f"platform={args.platform}" in x["package_info"]
            and all(before.get(path) and after.get(path) for path in PUBLIC_STATE + PRIVATE_STATE
                    + ["agents/first/home/.claude/.credentials.json"])
            # Usage metadata and renewed vendor tokens can change during a
            # normal return. Report those comparisons without requiring whole
            # vendor files to remain identical.
            and all(x["selected_state_equality"][path]["equal"] for path in PUBLIC_STATE + PRIVATE_STATE)
            and all(row.get("discovery_exit") == row.get("version_exit") == 0 for row in [cold, warm])):
        x["observation_outcome"] = "captured; independent assessment required"


def main():
    global root, project, private, cli, out, archive, store, x, sampled, LAUNCH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="exact newly allocated owned hostname")
    parser.add_argument("--platform", required=True, choices=PACKAGES)
    parser.add_argument("--observation-dir", type=Path, help="fresh private observer directory outside the checkout")
    parser.add_argument("--observer-source", default="unknown", help="workflow checkout commit; separate from product identities")
    parser.add_argument("--cleanup-only", action="store_true", help="stop and inspect this observer's recorded attempt")
    parser.add_argument("--connected", action="store_true", help="foreground AMD64 first task and live return using existing consented host authentication")
    parser.add_argument("--preparation", type=Path, help="nonsecret actual preparation commands/times/reading; required with --connected")
    args = parser.parse_args()
    if os.uname().nodename != args.host or args.host == "sy-1050-c9-cold-428968871" or os.geteuid() == 0:
        raise SystemExit("Use only the named fresh host as its ordinary user; the retained fixture is excluded.")
    root = Path.home() / ".safeyolo"
    private = args.observation_dir or Path.home() / "239-onboarding-observation"
    project = Path.home() / "239-onboarding-project"
    cli = root / "bin/safeyolo"
    if args.connected and args.platform != "linux-amd64":
        raise SystemExit("The connected operator witness is bound to Ubuntu AMD64; signed-out platform use is unchanged.")
    package = CONNECTED_PACKAGE if args.connected else PACKAGES[args.platform]
    source = CONNECTED_SOURCE if args.connected else SOURCE
    LAUNCH = ["bash", "install-safeyolo.sh", "--release", "host-" + source, "--launch", ".",
              "--name", "first", "--harness", "claude", "--launcher", "tmux-window"]
    archive = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "safeyolo/host-packages" / ("host-" + source) / f"safeyolo-{args.platform}-production.tar.gz"
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
         "native_source": source, "bootstrap_source": BOOTSTRAP, "observer_parent": "operator6542/6732",
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
    if args.connected:
        x["purpose"] = "Connected public first task and normal live return"
        x["observer_parent"] = "TASK7946/operator7950"
        x["limits"] = ["One authorized existing-host-authentication Ubuntu AMD64 witness; no new sign-in or other platform claim.",
            "Only selected policy, CA/token, guest, authentication, configuration and task state comparisons; no whole-home/cache equality.",
            "Only captured process births/listeners are covered by owned cleanup; historical missing captures stay unknown.",
            "Terminal screens, canonical history contents and state hashes stay private.",
            "Source readiness is not product acceptance. The 15-second target stays unmet."]
    x["baseline"] = inventory()
    save()
    overrides = [p for p in os.environ if p.startswith("SAFEYOLO_")]
    prior_product = any(p.exists() or p.is_symlink() for p in
                        [root, archive.parent, store, Path.home() / ".local/share/safeyolo/tools"])
    prior_vendor = any(x["baseline"][key][p] for key in (["vendor_cache_present"] if args.connected else ["auth_present", "vendor_cache_present"]) for p in x["baseline"][key])
    if prior_product or prior_vendor or overrides or x["baseline"]["credential_env_names"] or os.uname().machine != package["machine"]:
        x["baseline_unavailable"] = {"reason": "Existing product/authentication inputs, overrides or wrong architecture; all preserved", "override_names": overrides}
        save()
        return 2
    if args.connected and (not sys.stdin.isatty() or not sys.stdout.isatty()
                          or not all(x["baseline"]["auth_present"].values())):
        x["baseline_unavailable"] = "Connected witness needs a foreground terminal and the existing account in normal host locations; no login was attempted."
        save()
        return 2
    if args.connected:
        try:
            preparation_accounting(args.preparation)
        except (OSError, ValueError) as error:
            x["preparation_unavailable"] = str(error)
            save()
            return 2
    project.mkdir(mode=0o755)
    if not args.connected:
        (project / "onboarding-fixture.txt").write_text("SAFEYOLO_ONBOARDING_FIXTURE\n")
    x["fixture_preparation"] = {"project": str(project), "file": None if args.connected else "onboarding-fixture.txt", **stamp()}
    x["owns_product_attempt"] = True
    save()
    if args.connected:
        try:
            connected_run(args, package)
        except Exception as error:
            # Retain the first failure; cleanup never resubmits input or signs in.
            x["observer_error"] = repr(error)
        finally:
            try:
                cleanup()
                connected_accounting()
                if not x["counts"]["interaction_classification_complete"]:
                    x["observation_outcome"] = "partial"
            finally:
                x["ended"] = stamp()
                save()
        return 0 if x["observation_outcome"] != "partial" and x.get("cleanup_verified") else 1
    try:
        observe("baseline-sudo-noninteractive", ["sudo", "-n", "true"], 5)
        record_reading("cold", "signed-out observation instructions", SIGNED_OUT_PROSE.encode())
        print(SIGNED_OUT_PROSE, flush=True)
        started = time.monotonic()
        first = observe("bootstrap-download", DOWNLOAD, 60, role="product")
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
            for phase in ["cold", "warm"]:
                if (private / (phase + ".terminal")).is_file():
                    record_reading(phase, "remaining terminal output")
            signed_out_accounting()
            x["ended"] = stamp()
            save()
    return 0 if x["observation_outcome"] != "partial" and x.get("cleanup_verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
