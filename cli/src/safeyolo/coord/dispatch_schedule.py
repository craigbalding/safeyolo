"""One-shot, operator-authored Dispatch production delivery."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from . import api
from .identity import coord_data_dir

LEDGER_VERSION = 1
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_TASKS = 4096
WEEKDAYS = {
    "monday": 0,
    "tuesday": 1,
    "wednesday": 2,
    "thursday": 3,
    "friday": 4,
    "saturday": 5,
    "sunday": 6,
}


class DispatchScheduleError(RuntimeError):
    """The durable Dispatch schedule state is invalid or conflicts."""


@dataclass(frozen=True)
class DeliveryResult:
    task_key: str
    status: str
    sequence: int


def default_ledger_path() -> Path:
    return coord_data_dir() / "dispatch-schedule.json"


def _previous_month(day: date) -> tuple[date, date]:
    end = day - timedelta(days=1)
    return end.replace(day=1), end


def render_task(
    run_date: date,
    *,
    weekly_on: str,
    publication_mode: str = "manual",
) -> tuple[str, str]:
    """Return the stable task key and one complete Relay TASK body."""
    weekday = WEEKDAYS.get(weekly_on)
    if weekday is None:
        raise ValueError(f"weekly_on must be one of {', '.join(WEEKDAYS)}")
    if publication_mode not in {"manual", "automatic"}:
        raise ValueError("publication_mode must be 'manual' or 'automatic'")
    key = f"dispatch-production/{run_date.isoformat()}"
    periods = [f"daily {run_date.isoformat()}"]
    if run_date.weekday() == weekday:
        weekly_end = run_date - timedelta(days=1)
        weekly_start = weekly_end - timedelta(days=6)
        iso = weekly_start.isocalendar()
        periods.append(
            f"weekly {iso.year}-W{iso.week:02d} ({weekly_start.isoformat()} through "
            f"{weekly_end.isoformat()})"
        )
    if run_date.day == 1:
        monthly_start, monthly_end = _previous_month(run_date)
        periods.append(
            f"monthly {monthly_start:%Y-%m} ({monthly_start.isoformat()} through "
            f"{monthly_end.isoformat()})"
        )

    requested = "; ".join(periods)
    publication = (
        "When content exists, generate deterministic repository Markdown, create one "
        "publication branch and PR limited to the documented site paths, and present the "
        "existing `dispatch-publication` request with publish/revise/defer. Do not merge "
        "or publish before the operator chooses publish."
        if publication_mode == "manual"
        else (
            "The operator explicitly selected automatic publication for this schedule. "
            "When content exists, generate deterministic repository Markdown and use the "
            "same fixed publication paths and CI-to-Pages lane without a publication PR "
            "or `dispatch-publication` decision. Do not broaden Relay's repository authority."
        )
    )
    body = (
        f"TASK relay Produce SafeYolo Dispatch content for {requested}.\n\n"
        f"Schedule key: `{key}`. This is one idempotent content-production task; "
        f"a scheduler retry with the same key is not new work. The configured weekly "
        f"boundary is {weekly_on}, and publication mode is {publication_mode}.\n\n"
        "Follow the repository Dispatch generation contract. Give the operator the "
        "short pre-draft account required by that contract before writing substantive "
        "copy. It is valid to produce nothing when there is no substantive material; "
        "in that case, report completion without creating an artifact or publication PR.\n\n"
        f"{publication} Publication is a separate, "
        "idempotent side lane: delay, revision, CI, build, or Pages trouble must not hold "
        "an issue delivery claim or occupy Forge or Lens."
    )
    return key, body


class DispatchScheduleLedger:
    """Small locked JSON outbox; records stable envelopes before publication."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_ledger_path()
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    @contextmanager
    def locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        with os.fdopen(fd, "r+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise DispatchScheduleError("Dispatch schedule ledger has duplicate JSON keys")
            result[key] = value
        return result

    def read_unlocked(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        try:
            if self.path.stat().st_size > MAX_LEDGER_BYTES:
                raise DispatchScheduleError("Dispatch schedule ledger exceeds its size bound")
            document = json.loads(
                self.path.read_text(encoding="utf-8"),
                object_pairs_hook=self._pairs,
            )
        except DispatchScheduleError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise DispatchScheduleError("Dispatch schedule ledger is unreadable") from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"tasks", "version"}
            or document["version"] != LEDGER_VERSION
            or not isinstance(document["tasks"], dict)
            or len(document["tasks"]) > MAX_TASKS
        ):
            raise DispatchScheduleError("Dispatch schedule ledger root is invalid")
        records: dict[str, dict[str, Any]] = {}
        for task_key, record in document["tasks"].items():
            if (
                not isinstance(task_key, str)
                or not isinstance(record, dict)
                or set(record) != {
                    "body_sha256",
                    "prepared",
                    "room",
                    "sequence",
                    "status",
                }
                or record["status"] not in {"pending", "delivered"}
                or not isinstance(record["room"], str)
                or not isinstance(record["body_sha256"], str)
                or (
                    record["sequence"] is not None
                    and (type(record["sequence"]) is not int or record["sequence"] <= 0)
                )
                or (record["status"] == "pending" and record["sequence"] is not None)
                or (record["status"] == "delivered" and record["sequence"] is None)
            ):
                raise DispatchScheduleError("Dispatch schedule ledger contains an invalid record")
            records[task_key] = record
        return records

    def write_unlocked(self, records: dict[str, dict[str, Any]]) -> None:
        if len(records) > MAX_TASKS:
            raise DispatchScheduleError(f"Dispatch schedule supports at most {MAX_TASKS} tasks")
        payload = json.dumps(
            {"tasks": {key: records[key] for key in sorted(records)}, "version": LEDGER_VERSION},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ) + "\n"
        if len(payload.encode("ascii")) > MAX_LEDGER_BYTES:
            raise DispatchScheduleError("Dispatch schedule ledger exceeds its size bound")
        fd, temporary = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            suffix=".tmp",
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise


async def deliver_task(
    room: str,
    run_date: date,
    *,
    weekly_on: str = "monday",
    publication_mode: str = "manual",
    ledger: DispatchScheduleLedger | None = None,
) -> DeliveryResult:
    """Prepare, reconcile, and deliver exactly one operator-authored task."""
    task_key, body = render_task(
        run_date,
        weekly_on=weekly_on,
        publication_mode=publication_mode,
    )
    body_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
    state = ledger or DispatchScheduleLedger()
    with state.locked():
        records = state.read_unlocked()
        record = records.get(task_key)
        if record is None:
            if len(records) >= MAX_TASKS:
                raise DispatchScheduleError(f"Dispatch schedule supports at most {MAX_TASKS} tasks")
            prepared = await api.prepare_operator_message(
                room,
                body,
                declared_content_type="text/markdown",
                notify=["relay"],
            )
            record = {
                "body_sha256": body_sha256,
                "prepared": prepared,
                "room": room,
                "sequence": None,
                "status": "pending",
            }
            records[task_key] = record
            state.write_unlocked(records)
        elif record["room"] != room or record["body_sha256"] != body_sha256:
            raise DispatchScheduleError(
                f"{task_key} is already bound to different room or schedule settings"
            )
        prepared_body = (
            record["prepared"].get("envelope", {}).get("body")
            if isinstance(record["prepared"], dict)
            else None
        )
        if (
            not isinstance(prepared_body, str)
            or hashlib.sha256(prepared_body.encode("utf-8")).hexdigest() != body_sha256
        ):
            raise DispatchScheduleError(f"{task_key} has corrupt prepared message content")

        if record["status"] == "delivered":
            return DeliveryResult(task_key, "already-delivered", int(record["sequence"]))

        found = await api.find_prepared_operator_message(room, record["prepared"])
        status = "reconciled"
        if found is None:
            result = await api.publish_prepared_operator_message(room, record["prepared"])
            sequence = int(result["sequence"])
            status = "delivered"
        else:
            sequence = int(found["sequence"])
        record["status"] = "delivered"
        record["sequence"] = sequence
        state.write_unlocked(records)
        return DeliveryResult(task_key, status, sequence)
