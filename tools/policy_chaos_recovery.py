"""Native proxy process-death and guarded disposable-VM recovery helpers."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import select
import socket
import stat
import sys
import tempfile
import threading
import time
import tomllib
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from tests.proxy_migration.harness import launch_proxy, read_events, request
from tests.proxy_migration.scenarios import origin_server

TARGET = "revoked.invalid"
CONTROL = "permitted.invalid"
BLOCKED = "blocked.invalid"
POLICY = '''# C6 operator context survives the revocation
version = "2.0"
description = "native crash recovery fixture"
budget = 1000
[hosts]
"*" = { egress = "deny" }
"permitted.invalid" = { egress = "allow" }
"blocked.invalid" = { egress = "deny" }
[agents.alice.hosts]
"revoked.invalid" = { egress = "allow" }
'''
CHECKPOINTS = {
    "before-rename": ("commit", "rename"),
    "after-rename-before-directory-sync": ("commit", "directory_sync"),
    "after-acknowledged-response": None,
}
ADMISSIBLE_VERSIONS = {
    "before-rename": ["old"],
    "after-rename-before-directory-sync": ["old", "new"],
    "after-acknowledged-response": ["new"],
}
SENTINEL = ".safeyolo-chaos-disposable"
MANIFEST = "recovery-manifest.json"
VM_INPUT_LIMIT = 1024 * 1024  # Each outside-VM protocol input is at most 1 MiB.


def checked_run_id(run_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", run_id):
        raise ValueError("run ID must be 8-64 letters, digits, underscores or dashes")
    return run_id


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def policy_version(policy: bytes, old: bytes, new: bytes) -> str | None:
    if policy == old:
        return "old"
    if policy == new:
        return "new"
    return None


def assert_policy_document(data: bytes, *, revoked: bool) -> None:
    document = tomllib.loads(data.decode())
    expected_hosts = {
        "*": {"egress": "deny"},
        CONTROL: {"egress": "allow"},
        BLOCKED: {"egress": "deny"},
    }
    expected = {
        "version": "2.0", "description": "native crash recovery fixture", "budget": 1000,
        "hosts": expected_hosts,
        "agents": {"alice": {"hosts": {TARGET: {"egress": "deny" if revoked else "allow"}}}},
    }
    if document != expected or "# C6 operator context survives the revocation" not in data.decode():
        raise ValueError("policy document differs from the scoped C6 fixture")


class PolicyCheckpoint:
    """Pause one transaction at an actual debug-build native writer checkpoint."""

    def __init__(self, run_id: str, checkpoint: str):
        self.run_id = run_id
        self.checkpoint = checkpoint
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.events: list[dict] = []
        self.errors: list[Exception] = []
        self.transaction: str | None = None
        self.selected_event: dict | None = None

    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sy-native-cut-", dir="/tmp")
        self.path = Path(self.temporary.name) / "checkpoint.sock"
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        self.listener.listen(1)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=5)
        self.listener.close()
        self.temporary.cleanup()
        if self.thread.is_alive():
            raise AssertionError("native checkpoint listener did not stop")
        if self.errors:
            raise AssertionError(f"native checkpoint listener failed: {self.errors}")

    def environment(self) -> dict[str, str]:
        return {
            "SAFEYOLO_TEST_POLICY_STAGE_SOCKET": str(self.path),
            "SAFEYOLO_TEST_POLICY_RUN_ID": self.run_id,
        }

    def record_stage(self, event: dict) -> bool:
        if event.get("run") != self.run_id:
            raise AssertionError("checkpoint run identity changed")
        self.events.append(event)
        if event["kind"] == "mutation" and \
                (event["phase"], event["stage"]) == ("transaction", "begin"):
            if self.transaction is not None:
                raise AssertionError("unexpected second mutation")
            if not isinstance(event.get("transaction"), str) or not event["transaction"]:
                raise AssertionError("native transaction identity is missing")
            self.transaction = event["transaction"]
        selected = (
            event["kind"] == "mutation"
            and self.transaction is not None
            and event["transaction"] == self.transaction
            and (event["phase"], event["stage"]) == CHECKPOINTS[self.checkpoint]
        )
        if selected:
            if self.selected_event is not None:
                raise AssertionError("checkpoint repeated")
            self.selected_event = event
        return selected

    def _serve(self):
        try:
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(130)
                    with connection.makefile("rb") as incoming:
                        for line in incoming:
                            event = json.loads(line)
                            if self.record_stage(event):
                                self.ready.set()
                                self.stop.wait(120)
                                return  # Do not authorize the native writer past the checkpoint.
                            connection.sendall(b"c")
        except Exception as error:
            self.errors.append(error)


@contextmanager
def native_proxy(directory: Path, origin, *, initial: str | None, admin: bool = True,
                 runtime_directory: Path | None = None):
    from safeyolo.api import AdminAPI

    runtime = runtime_directory or directory
    runtime.mkdir(parents=True, exist_ok=True)
    token_file = runtime / "operator-token"
    if admin:
        token_file.write_text("native-chaos-operator\n")
    with launch_proxy(
        "rust", directory, initial,
        parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
        network_guard_enabled=True, network_guard_block=True,
        admin_port=0 if admin else None,
        admin_api_token_file=token_file if admin else None,
        runtime_directory=runtime_directory,
    ) as proxy:
        if admin:
            marker = json.loads(proxy.readiness_file.read_text())
            api = AdminAPI(
                base_url=f"http://127.0.0.1:{marker['admin_port']}",
                token=token_file.read_text().strip(), timeout=15,
            )
        else:
            api = None
        yield proxy, api


def observe_effects(proxy, origin, *, revoked: bool) -> dict[str, int]:
    expected = {
        "alice-target": 403 if revoked else 200,
        "bob-target": 403,
        "alice-control": 200,
        "alice-blocked": 403,
    }
    actual = {}
    for label, agent, host in (
        ("alice-target", "alice", TARGET),
        ("bob-target", "bob", TARGET),
        ("alice-control", "alice", CONTROL),
        ("alice-blocked", "alice", BLOCKED),
    ):
        before = origin.accepts
        status, _, body = request(proxy.paths[agent], f"http://{host}:8123/c6")
        actual[label] = status
        assert status == expected[label], (label, status, body)
        assert origin.accepts == before + int(status == 200), label
    return actual


def policy_residue(directory: Path) -> list[Path]:
    return sorted(directory.glob(".policy-*.toml"))


def success_audit(directory: Path) -> list[dict]:
    return [event for event in read_events(directory / "audit.jsonl")
            if event.get("event") == "admin.host_denied"]


def linux_filesystem_type(path: Path) -> str:
    """Return the longest matching Linux mount for a resolved path."""
    matches = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        source, separator, details = line.partition(" - ")
        if not separator:
            continue
        mount = Path(source.split()[4].replace("\\040", " "))
        if path == mount or mount in path.parents:
            matches.append((len(mount.parts), details.split()[0]))
    if not matches:
        raise ValueError(f"cannot identify filesystem for {path}")
    return max(matches)[1]


def safe_vm_paths(config_dir: Path, state_dir: Path, confirmed: bool) -> tuple[Path, Path, Path]:
    if not confirmed or os.environ.get("SAFEYOLO_CHAOS_DISPOSABLE_VM") != "1":
        raise ValueError("VM fault mode requires --confirm-disposable-vm and SAFEYOLO_CHAOS_DISPOSABLE_VM=1")
    config = config_dir.expanduser().resolve()
    state = state_dir.expanduser().resolve()
    home = Path.home().resolve()
    repo = Path(__file__).resolve().parents[1]
    if config in {Path("/"), home, repo} or state in {Path("/"), home, repo}:
        raise ValueError("refusing unsafe VM config/state root")
    if repo in config.parents or repo in state.parents:
        raise ValueError("VM fault paths must be outside the source checkout")
    if config == state or config in state.parents or state in config.parents:
        raise ValueError("VM config and state directories must be separate")
    sentinel = config / SENTINEL
    if not config.is_dir() or not sentinel.is_file() or sentinel.is_symlink():
        raise ValueError(f"missing or unsafe disposable VM sentinel: {sentinel}")
    policy = config / "policy.toml"
    if not policy.is_file() or policy.is_symlink() or policy.resolve().parent != config:
        raise ValueError(f"missing or unsafe policy path: {policy}")
    state.mkdir(parents=True, exist_ok=True)
    if linux_filesystem_type(config) in {"tmpfs", "ramfs"} or \
            linux_filesystem_type(state) in {"tmpfs", "ramfs"}:
        raise ValueError("VM policy and recovery manifest must be on disk-backed filesystems")
    return policy, config, state


def read_vm_input(path: Path) -> bytes:
    """Read a bounded regular protocol file without following links or blocking on FIFOs."""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        details = os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode):
            raise ValueError(f"VM protocol input is not a regular file: {path}")
        if details.st_size > VM_INPUT_LIMIT:
            raise ValueError(f"VM protocol input exceeds 1 MiB: {path}")
        raw = stream.read(VM_INPUT_LIMIT + 1)
    if len(raw) > VM_INPUT_LIMIT:
        raise ValueError(f"VM protocol input exceeds 1 MiB: {path}")
    return raw


def parse_vm_json(raw: bytes | str):
    try:
        return json.loads(raw)
    except RecursionError as error:
        raise ValueError("VM protocol JSON is too deeply nested") from error


def read_manifest(path: Path) -> tuple[dict, str]:
    raw = read_vm_input(path)
    manifest = parse_vm_json(raw)
    if not isinstance(manifest, dict) or type(manifest.get("version")) is not int or \
            manifest["version"] != 1 or \
            type(manifest.get("checkpoint")) is not str or \
            manifest["checkpoint"] not in CHECKPOINTS:
        raise ValueError("invalid native recovery manifest")
    for key in ("run_id", "config_dir", "policy_path", "binary", "binary_sha256",
                "old_b64", "new_b64", "old_sha256", "new_sha256"):
        if not isinstance(manifest.get(key), str) or not manifest[key]:
            raise ValueError(f"native recovery manifest lacks {key}")
    checked_run_id(manifest["run_id"])
    if manifest.get("expected_versions") != ADMISSIBLE_VERSIONS[manifest["checkpoint"]]:
        raise ValueError("native recovery manifest has invalid expected versions")
    for version in ("old", "new"):
        try:
            contents = base64.b64decode(manifest[f"{version}_b64"], validate=True)
        except ValueError as error:
            raise ValueError(f"invalid {version} policy in recovery manifest") from error
        if digest(contents) != manifest[f"{version}_sha256"]:
            raise ValueError(f"{version} policy hash mismatch in recovery manifest")
        assert_policy_document(contents, revoked=version == "new")
    return manifest, digest(raw)


def read_checkpoint_observation(observation: Path) -> tuple[dict, dict]:
    lines = [parse_vm_json(line) for line in read_vm_input(observation).decode().splitlines()
             if line.strip()]
    if not all(isinstance(line, dict) for line in lines):
        raise ValueError("checkpoint observation contains a non-object line")
    prepared = [line for line in lines if line.get("status") == "PREPARED"]
    ready = [line for line in lines if line.get("status") == "READY_FOR_POWER_CUT"]
    if len(prepared) != 1 or len(ready) != 1:
        raise ValueError("missing or repeated prepared/ready observation")
    return prepared[0], ready[0]


def validate_ready(manifest: dict, manifest_hash: str, observation: Path) -> dict:
    prepared, event = read_checkpoint_observation(observation)
    expected = {"run_id": manifest["run_id"], "checkpoint": manifest["checkpoint"],
                "manifest_sha256": manifest_hash}
    if any(prepared.get(key) != value or event.get(key) != value
           for key, value in expected.items()):
        raise ValueError("stale or mismatched VM checkpoint observation")
    if type(event.get("proxy_pid")) is not int or event["proxy_pid"] <= 0:
        raise ValueError("ready observation has no proxy process identity")
    if not isinstance(event.get("transaction"), str) or not event["transaction"]:
        raise ValueError("ready observation has no native transaction identity")
    stage = CHECKPOINTS[manifest["checkpoint"]]
    if stage is None:
        if ((event.get("phase"), event.get("stage")) != ("response", "acknowledged")
                or event.get("operation_result") != "denied"):
            raise ValueError("acknowledged checkpoint lacks successful Admin response")
    elif (event.get("phase"), event.get("stage")) != stage:
        raise ValueError("ready observation names the wrong native checkpoint")
    if type(event.get("success_audit_count")) is not int or event["success_audit_count"] < 0:
        raise ValueError("ready observation lacks the pre-cut audit count")
    if stage is not None and event["success_audit_count"] != 0:
        raise ValueError("success audit appeared before the paused Admin response")
    return event


def wait_for_arm(run_id: str, checkpoint: str, manifest_hash: str) -> None:
    readable, _, _ = select.select([sys.stdin], [], [], 300)
    if not readable:
        raise ValueError("controller did not arm the prestaged manifest")
    if sys.stdin.readline().strip() != f"ARM {run_id} {checkpoint} {manifest_hash}":
        raise ValueError("controller arm did not match this run and checkpoint")


def vm_fixture_manifest(directory: Path, state_dir: Path, binary: Path,
                        run_id: str, checkpoint: str) -> dict:
    old = (directory / "policy.toml").read_bytes()
    assert_policy_document(old, revoked=False)
    with tempfile.TemporaryDirectory(prefix="sy-native-reference-", dir=state_dir) as scratch:
        reference = Path(scratch)
        with origin_server() as origin:
            with native_proxy(reference, origin, initial=old.decode()) as (proxy, api):
                observe_effects(proxy, origin, revoked=False)
                result = api.deny_host(TARGET, agent="alice")
                if result.get("status") != "denied":
                    raise ValueError("reference native revoke was not acknowledged")
                new = (reference / "policy.toml").read_bytes()
            with native_proxy(reference, origin, initial=None, admin=False) as (fresh, _):
                observe_effects(fresh, origin, revoked=True)
    assert_policy_document(new, revoked=True)
    return {
        "version": 1, "run_id": run_id, "checkpoint": checkpoint,
        "policy_path": str(directory / "policy.toml"), "config_dir": str(directory),
        "binary": str(binary), "binary_sha256": file_digest(binary),
        "old_sha256": digest(old), "new_sha256": digest(new),
        "old_b64": base64.b64encode(old).decode(),
        "new_b64": base64.b64encode(new).decode(),
        "operation": {"admin": "deny_host", "host": TARGET, "agent": "alice"},
        "expected_versions": ADMISSIBLE_VERSIONS[checkpoint],
        "vm_storage_contract": "record filesystem and VM disk/cache configuration in the cut record",
    }


def write_manifest(path: Path, manifest: dict) -> str:
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return digest(raw)


def vm_runtime_base(config: Path, path: Path) -> Path:
    runtime = path.expanduser().resolve()
    if (not runtime.is_dir() or os.stat(runtime).st_dev == os.stat(config).st_dev
            or linux_filesystem_type(runtime) not in {"tmpfs", "ramfs"}):
        raise ValueError("VM runtime directory must be a separate writable tmpfs or ramfs")
    return runtime


def observe_vm_checkpoint(args, controller: PolicyCheckpoint, policy: Path,
                          manifest: dict, result) -> dict:
    if args.checkpoint == "after-acknowledged-response":
        response = result.result(timeout=30)
        if response.get("status") != "denied":
            raise ValueError("native Admin did not acknowledge the durable revoke")
        if controller.transaction is None or not any(
            item["phase"] == "commit" and item["stage"] == "directory_sync"
            for item in controller.events
        ):
            raise ValueError("selected proxy did not report a complete native transaction")
        if policy.read_bytes() != base64.b64decode(manifest["new_b64"]):
            raise ValueError("acknowledged native policy differs from prestaged new version")
        return {"phase": "response", "stage": "acknowledged",
                "transaction": controller.transaction, "operation_result": "denied"}
    if not controller.ready.wait(30):
        raise ValueError(f"native checkpoint was not reached: {controller.events}")
    if result.done():
        raise ValueError("Admin responded before the selected native checkpoint")
    expected = base64.b64decode(manifest[
        "old_b64" if args.checkpoint == "before-rename" else "new_b64"
    ])
    if policy.read_bytes() != expected:
        raise ValueError("visible policy does not match the selected native checkpoint")
    if controller.selected_event is None:
        raise ValueError("native checkpoint lost its selected event")
    return controller.selected_event


def prepare_vm_cut(args) -> int:
    from concurrent.futures import ThreadPoolExecutor
    from unittest.mock import patch

    policy, config, state = safe_vm_paths(args.config_dir, args.state_dir,
                                          args.confirm_disposable_vm)
    runtime_base = vm_runtime_base(config, args.runtime_dir)
    binary = args.binary.expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError(f"selected native proxy is not executable: {binary}")
    run_id = checked_run_id(args.run_id or os.urandom(16).hex())
    if policy.read_bytes() != POLICY.encode():
        raise ValueError("VM policy must contain the documented untouched C6 fixture")
    run_dir = state / run_id
    run_dir.mkdir(exist_ok=False)
    with patch.dict(os.environ, {"SAFEYOLO_RUST_PROXY": str(binary)}):
        manifest = vm_fixture_manifest(config, state, binary, run_id, args.checkpoint)
    old = base64.b64decode(manifest["old_b64"])
    manifest_path = run_dir / MANIFEST
    manifest_hash = write_manifest(manifest_path, manifest)
    with tempfile.TemporaryDirectory(prefix="sy-native-vm-runtime-", dir=runtime_base) as runtime_name, \
         PolicyCheckpoint(run_id, args.checkpoint) as controller, \
         patch.dict(os.environ, {**controller.environment(), "SAFEYOLO_RUST_PROXY": str(binary)}), \
         origin_server() as origin:
        runtime = Path(runtime_name)
        with native_proxy(config, origin, initial=None, runtime_directory=runtime) as (proxy, api):
            if policy.read_bytes() != old:
                raise ValueError("native startup changed the policy before the cut")
            observe_effects(proxy, origin, revoked=False)
            print(json.dumps({"status": "PREPARED", "run_id": run_id,
                              "checkpoint": args.checkpoint, "manifest_sha256": manifest_hash,
                              "manifest": str(manifest_path)}), flush=True)
            wait_for_arm(run_id, args.checkpoint, manifest_hash)
            with ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(api.deny_host, TARGET, agent="alice")
                event = observe_vm_checkpoint(args, controller, policy, manifest, result)
                ready = {"status": "READY_FOR_POWER_CUT", "run_id": run_id,
                         "checkpoint": args.checkpoint, "manifest_sha256": manifest_hash,
                         "proxy_pid": proxy.process.pid,
                         "transaction": event["transaction"],
                         "phase": event["phase"], "stage": event["stage"],
                         "success_audit_count": len(success_audit(runtime))}
                if args.checkpoint == "after-acknowledged-response":
                    ready["operation_result"] = "denied"
                print(json.dumps(ready), flush=True)  # No target-filesystem write after ready.
                time.sleep(120)  # The outside controller must cut this disposable VM.
                raise ValueError("VM cut was not observed before the bounded ready window expired")


def ready_vm_cut(args) -> int:
    manifest, manifest_hash = read_manifest(args.manifest)
    event = validate_ready(manifest, manifest_hash, args.observation)
    print(json.dumps({"status": "CONFIRMED_READY_FOR_POWER_CUT", "run_id": event["run_id"],
                      "checkpoint": event["checkpoint"],
                      "manifest_sha256": manifest_hash, "transaction": event["transaction"]}))
    return 0


def assess_surviving_policy(manifest: dict, config: Path,
                            visible: bytes) -> tuple[str | None, list[Path], list[str]]:
    old = base64.b64decode(manifest["old_b64"])
    new = base64.b64decode(manifest["new_b64"])
    version = policy_version(visible, old, new)
    problems = []
    if version is None:
        problems.append("policy is neither the complete old nor the complete new file")
    elif version not in manifest["expected_versions"]:
        problems.append(f"{version} policy is not admissible at {manifest['checkpoint']}")
    try:
        assert_policy_document(visible, revoked=version == "new")
    except (ValueError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        problems.append(f"surviving policy is invalid or unexpected: {error}")
    residue = policy_residue(config)
    for path in residue:
        if path.read_bytes() != new:
            problems.append(f"unexpected temporary policy residue: {path}")
    if manifest["checkpoint"] == "before-rename" and len(residue) > 1:
        problems.append("more than one temporary policy remains before rename")
    if manifest["checkpoint"] != "before-rename" and residue:
        problems.append("temporary policy remains after rename")
    return version, residue, problems


def observe_fresh_recovery(config: Path, policy: Path, manifest: dict,
                           runtime_dir: Path, version: str) -> tuple[dict | None, list[str]]:
    binary = Path(manifest["binary"])
    if file_digest(binary) != manifest["binary_sha256"]:
        raise ValueError("recovery binary differs from the prestaged native proxy")
    runtime_base = vm_runtime_base(config, runtime_dir)
    problems = []
    effects = None
    with tempfile.TemporaryDirectory(prefix="sy-native-vm-recover-", dir=runtime_base) as runtime_name, \
         origin_server() as origin, \
         patch.dict(os.environ, {"SAFEYOLO_RUST_PROXY": str(binary)}):
        before = policy.read_bytes()
        try:
            with native_proxy(config, origin, initial=None, admin=False,
                              runtime_directory=Path(runtime_name)) as (fresh, _):
                effects = observe_effects(fresh, origin, revoked=version == "new")
        except (AssertionError, OSError, ValueError, http.client.HTTPException) as error:
            problems.append(f"fresh Rust could not enforce surviving policy: {error}")
        if policy.read_bytes() != before:
            problems.append("fresh startup rewrote the surviving policy")
    return effects, problems


def recover_vm_cut(args) -> int:
    policy, config, state = safe_vm_paths(args.config_dir, args.state_dir,
                                          args.confirm_disposable_vm)
    run_id = checked_run_id(args.run_id)
    run_dir = state / run_id
    if not run_dir.is_dir() or run_dir.is_symlink() or run_dir.resolve().parent != state:
        raise ValueError("missing or unsafe recovery run directory")
    manifest_path = run_dir / MANIFEST
    if manifest_path.is_symlink() or manifest_path.resolve().parent != run_dir:
        raise ValueError("unsafe recovery manifest path")
    manifest, manifest_hash = read_manifest(manifest_path)
    if manifest["run_id"] != run_id or manifest["config_dir"] != str(config) or \
            manifest["policy_path"] != str(policy):
        raise ValueError("recovery manifest does not name this run and policy")
    ready = validate_ready(manifest, manifest_hash, args.observation)
    cut = parse_vm_json(read_vm_input(args.cut_record))
    if not isinstance(cut, dict):
        raise ValueError("outside-VM cut record must be a JSON object")
    if any(cut.get(key) != value for key, value in (
        ("run_id", args.run_id), ("checkpoint", manifest["checkpoint"]),
        ("manifest_sha256", manifest_hash), ("transaction", ready["transaction"]),
        ("target", "vm"),
    )) or not all(cut.get(key) for key in ("vm_id", "mechanism", "filesystem", "storage", "stopped_at", "restarted_at")):
        raise ValueError("missing or mismatched outside-VM abrupt-stop record")
    if cut.get("abrupt_vm_stop") is not True:
        raise ValueError("outside-VM cut record does not confirm an abrupt VM stop")
    visible = policy.read_bytes()
    version, residue, problems = assess_surviving_policy(manifest, config, visible)
    effects = None
    if version is not None:
        effects, fresh_problems = observe_fresh_recovery(
            config, policy, manifest, args.runtime_dir, version,
        )
        problems.extend(fresh_problems)
    report = {
        "status": "FINDING" if problems else "PASS",
        "mode": "declared-disposable-vm-recovery", "run_id": args.run_id,
        "checkpoint": manifest["checkpoint"], "manifest_sha256": manifest_hash,
        "cut_record": cut, "visible_version": version,
        "visible_sha256": digest(visible), "expected_versions": manifest["expected_versions"],
        "fresh_effects": effects,
        "pre_cut_success_audit_count": ready["success_audit_count"],
        "temporary_residue": [str(path) for path in residue],
        "problems": problems,
        "physical_power_loss_claimed": False,
        "in_flight_exactly_once_claimed": False,
        "vm_stop_verified_by_tool": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "report": str(args.output),
                      "visible_version": version}))
    return int(bool(problems))
