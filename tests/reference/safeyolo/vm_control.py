"""Bounded client for the private, host-only VM helper control socket."""

from __future__ import annotations

import json
import os
import socket
import tempfile
import time
from pathlib import Path

from .config import get_data_dir
from .sockets import _AGENT_NAME_RE


class VMControlError(RuntimeError):
    """The helper control operation failed or could not be verified."""


def socket_path(name: str) -> Path:
    if _AGENT_NAME_RE.fullmatch(name) is None:
        raise VMControlError(f"invalid agent name: {name!r}")
    return get_data_dir() / "vm-control" / f"{name}.sock"


def remaining(deadline: float) -> float:
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise VMControlError("VM control deadline expired")
    return seconds


def request(name: str, operation: str, *, timeout: float = 3.0, **parameters) -> dict:
    """One request with an overall deadline and a bounded response."""
    path = socket_path(name)
    deadline = time.monotonic() + timeout
    encoded = json.dumps({**parameters, "operation": operation}).encode() + b"\n"
    if len(encoded) > 65536:
        raise VMControlError("VM control request exceeds 64 KiB")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(remaining(deadline))
            sock.connect(str(path))
            sock.settimeout(remaining(deadline))
            sock.sendall(encoded)
            raw = bytearray()
            while b"\n" not in raw:
                sock.settimeout(remaining(deadline))
                chunk = sock.recv(16384)
                if not chunk:
                    raise VMControlError("helper closed the control socket before a response")
                raw.extend(chunk)
                if len(raw) > 2 * 1024 * 1024:
                    raise VMControlError("VM control response exceeds 2 MiB")
    except OSError as error:
        raise VMControlError(f"VM control unavailable at {path}: {error}") from error
    return _decode_response(raw, operation)


def _decode_response(raw: bytearray, operation: str) -> dict:
    try:
        response = json.loads(raw.partition(b"\n")[0])
    except (ValueError, UnicodeError) as error:
        raise VMControlError("helper returned invalid control JSON") from error
    if not isinstance(response, dict):
        raise VMControlError("helper returned a non-object control response")
    if type(response.get("schema_version")) is not int or response["schema_version"] != 1:
        raise VMControlError("helper returned an unsupported control schema")
    if (not isinstance(response.get("instance"), str) or not response["instance"]
            or len(response["instance"]) > 128 or not response["instance"].isprintable()):
        raise VMControlError("helper did not identify its process instance")
    if response.get("ok") is not True:
        raise VMControlError(f"helper refused {operation}: {str(response.get('error', 'unknown error'))[:1024]}")
    return response


def read_status(name: str, *, timeout: float = 3.0) -> dict:
    value = request(name, "status", timeout=timeout)
    helper, vm = value.get("helper"), value.get("vm")
    if not isinstance(helper, dict) or not isinstance(vm, dict):
        raise VMControlError("helper returned invalid runtime identity")
    _validate_identity(helper)
    if not isinstance(vm.get("state"), str) or not vm["state"].isprintable():
        raise VMControlError("helper returned invalid VM state")
    for field in ("pid", "active", "relay_fd_count"):
        if type(value.get(field)) is not int or value[field] < 0:
            raise VMControlError(f"helper returned invalid counter: {field}")
    if value.get("health") not in {"responsive", "relay_executor_not_progressing"}:
        raise VMControlError("helper returned unknown relay health")
    for field in ("counts_by_kind", "counts_by_phase"):
        if not isinstance(value.get(field), dict):
            raise VMControlError("helper returned invalid relay counts")
    return value


def _validate_identity(helper: dict) -> None:
    from .vm import VMError
    from .vm_identity import parse_vm_helper_identity

    try:
        parse_vm_helper_identity(helper)
    except VMError as error:
        raise VMControlError(str(error)) from error


def list_relays(name: str, *, timeout: float = 3.0) -> tuple[str, list[dict]]:
    """Read all pages within one deadline, rejecting process changes or loops."""
    deadline = time.monotonic() + timeout
    instance = None
    after = 0
    records = []
    while True:
        response = request(name, "relays", after=after, limit=256, timeout=remaining(deadline))
        if instance is not None and response["instance"] != instance:
            raise VMControlError("helper instance changed while listing relays; retry")
        instance = response["instance"]
        page = response.get("relays")
        if not isinstance(page, list):
            raise VMControlError("helper returned invalid relay records")
        for record in page:
            if not isinstance(record, dict) or type(record.get("id")) is not int or record["id"] <= after:
                raise VMControlError("helper returned invalid relay IDs")
            if record.get("kind") not in {"proxy", "shell"} or not isinstance(record.get("phase"), str):
                raise VMControlError("helper returned invalid relay kind or phase")
            after = record["id"]
        records.extend(page)
        next_after = response.get("next_after")
        if next_after is None:
            return instance, records
        if not page or type(next_after) is not int or next_after != after:
            raise VMControlError("helper returned a non-progressing relay cursor")


def cancel_relays(name: str, instance: str, ids: list[int], *, reason: str, timeout: float = 3.0) -> dict:
    """Request exact IDs and observe their removal before reporting closure."""
    deadline = time.monotonic() + timeout
    queued: set[int] = set()
    actions = []
    for offset in range(0, len(ids), 256):
        batch = ids[offset:offset + 256]
        try:
            response = request(name, "cancel", instance=instance, ids=batch, reason=reason, timeout=remaining(deadline))
        except VMControlError as error:
            raise VMControlError(
                f"{error}; {len(queued)} earlier cancellations were acknowledged. "
                "The latest request and closure are unverified; inspect the relay list and cancellation audit."
            ) from error
        if response["instance"] != instance:
            raise VMControlError("helper instance changed while cancelling relays")
        accepted = response.get("queued_ids")
        if not isinstance(accepted, list) or any(type(item) is not int or item not in batch for item in accepted):
            raise VMControlError("helper returned invalid cancellation acknowledgement")
        queued.update(accepted)
        actions.append(response.get("action_id"))
    try:
        while queued:
            current_instance, active = list_relays(name, timeout=remaining(deadline))
            if current_instance != instance:
                raise VMControlError("helper restarted before relay closure could be verified")
            if not queued.intersection(record["id"] for record in active):
                break
            time.sleep(min(0.05, remaining(deadline)))
    except VMControlError as error:
        raise VMControlError(
            f"{error}; {len(queued)} cancellations were queued but closure is unverified. "
            f"Run safeyolo agent vm relays {name} and inspect the cancellation audit."
        ) from error
    return {"instance": instance, "closed_ids": sorted(queued), "action_ids": actions}


def write_dump(name: str, output: Path | None = None) -> Path:
    """Save a bounded helper dump as a private atomic replacement."""
    path = output or socket_path(name).with_suffix(".hang.json")
    data = request(name, "dump")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".vm-dump-", dir=path.parent) as folder:
            temporary = Path(folder) / "dump.json"
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(data, stream, indent=2)
                stream.write("\n")
            os.replace(temporary, path)
    except OSError as error:
        raise VMControlError(f"cannot write VM dump: {error}") from error
    return path
