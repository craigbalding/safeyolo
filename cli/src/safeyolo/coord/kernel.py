"""Generic transactional mutation and optimistic-revision primitives."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Mapping
from typing import Any, TypeVar

from . import store

T = TypeVar("T")

LOCAL_OPERATOR_KIND = "operator"
LOCAL_OPERATOR_ID = "operator"
MAX_OPERATION_ID_BYTES = 256
MAX_OUTCOME_BYTES = 64 * 1024


class OperationConflictError(ValueError):
    """An operation ID was reused with different canonical input."""


class DeterministicMutationError(RuntimeError):
    """A stable domain/concurrency outcome that consumes an operation ID."""

    code = "domain_conflict"

    def __init__(self, message: str, *, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.details = dict(details or {})


class RevisionConflictError(DeterministicMutationError):
    code = "revision_conflict"

    def __init__(self, expected_revision: int, actual_revision: int):
        super().__init__(
            f"expected revision {expected_revision}, current revision is {actual_revision}",
            details={
                "expected_revision": expected_revision,
                "actual_revision": actual_revision,
            },
        )


def next_revision(*, expected_revision: int, actual_revision: int) -> int:
    """Check optimistic concurrency and return the one legal next revision."""
    if expected_revision < 0:
        raise ValueError("expected_revision must be non-negative")
    if actual_revision != expected_revision:
        raise RevisionConflictError(expected_revision, actual_revision)
    return actual_revision + 1


def apply_revisioned_change(
    *,
    expected_revision: int,
    actual_revision: int,
    write_projection: Callable[[int], None],
    append_history: Callable[[int], None],
) -> int:
    """Apply one projection + append-only history change at one revision.

    The surrounding ``execute_mutation`` transaction supplies atomicity. Typed
    feature stores supply their own projection/history tables and callbacks;
    the kernel deliberately does not invent a generic domain-object schema.
    """
    revision = next_revision(
        expected_revision=expected_revision,
        actual_revision=actual_revision,
    )
    write_projection(revision)
    append_history(revision)
    return revision


def canonical_request_hash(request: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        request,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_operation_id(operation_id: str) -> None:
    if not isinstance(operation_id, str) or not operation_id:
        raise ValueError("operation_id must be a non-empty string")
    try:
        size = len(operation_id.encode("utf-8"))
    except UnicodeError as exc:
        raise ValueError("operation_id must be valid UTF-8") from exc
    if size > MAX_OPERATION_ID_BYTES:
        raise ValueError(
            f"operation_id exceeds {MAX_OPERATION_ID_BYTES} UTF-8 bytes"
        )


def _encode_outcome(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    if len(encoded.encode("utf-8")) > MAX_OUTCOME_BYTES:
        raise ValueError(f"mutation outcome exceeds {MAX_OUTCOME_BYTES} UTF-8 bytes")
    return encoded


def _raise_recorded_error(payload: dict[str, Any]) -> None:
    if payload.get("code") == RevisionConflictError.code:
        details = payload.get("details", {})
        raise RevisionConflictError(
            int(details["expected_revision"]),
            int(details["actual_revision"]),
        )
    raise DeterministicMutationError(
        payload.get("message", "recorded deterministic mutation rejection"),
        details=payload.get("details", {}),
    )


def _conflict_event_id(operation_type: str, operation_id: str) -> str:
    material = (
        f"{LOCAL_OPERATOR_KIND}\0{LOCAL_OPERATOR_ID}\0"
        f"{operation_type}\0{operation_id}\0input-conflict"
    ).encode()
    return f"evt-{hashlib.sha256(material).hexdigest()[:32]}"


def execute_mutation(
    *,
    operation_id: str,
    operation_type: str,
    request: Mapping[str, Any],
    mutate: Callable[[sqlite3.Connection], T],
) -> T:
    """Run one local-operator mutation with idempotent outcome replay."""
    _validate_operation_id(operation_id)
    if not operation_type.startswith("coord."):
        raise ValueError("operation_type must use the coord.* namespace")
    request_hash = canonical_request_hash(request)
    recorded_error: dict[str, Any] | None = None
    result: T | None = None
    conflict: OperationConflictError | None = None

    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT request_hash, outcome_kind, outcome_json
               FROM coord_operations
               WHERE principal_kind = ? AND principal_id = ?
                 AND operation_type = ? AND operation_id = ?""",
            (
                LOCAL_OPERATOR_KIND,
                LOCAL_OPERATOR_ID,
                operation_type,
                operation_id,
            ),
        ).fetchone()
        if row is not None:
            if row["request_hash"] != request_hash:
                from .outbox import enqueue_coord_event

                enqueue_coord_event(
                    conn,
                    "coord.operation_conflict",
                    {
                        "actor": LOCAL_OPERATOR_ID,
                        "operation_id": operation_id,
                        "operation_type": operation_type,
                        "request_hash": request_hash,
                    },
                    event_id=_conflict_event_id(operation_type, operation_id),
                )
                conn.execute("COMMIT")
                conflict = OperationConflictError(
                    f"operation_id {operation_id!r} was already used with different input"
                )
            else:
                payload = json.loads(row["outcome_json"])
                conn.execute("COMMIT")
                if row["outcome_kind"] == "error":
                    recorded_error = payload
                else:
                    result = payload
        else:
            try:
                conn.execute("SAVEPOINT coord_mutation")
                result = mutate(conn)
                outcome_json = _encode_outcome(result)
                conn.execute("RELEASE coord_mutation")
                conn.execute(
                    """INSERT INTO coord_operations
                       (principal_kind, principal_id, operation_type,
                        operation_id, request_hash, outcome_kind,
                        outcome_json, created_at)
                       VALUES (?, ?, ?, ?, ?, 'success', ?, ?)""",
                    (
                        LOCAL_OPERATOR_KIND,
                        LOCAL_OPERATOR_ID,
                        operation_type,
                        operation_id,
                        request_hash,
                        outcome_json,
                        store.now_ms(),
                    ),
                )
                conn.execute("COMMIT")
            except DeterministicMutationError as exc:
                conn.execute("ROLLBACK TO coord_mutation")
                conn.execute("RELEASE coord_mutation")
                payload = {
                    "code": exc.code,
                    "message": str(exc),
                    "details": exc.details,
                }
                conn.execute(
                    """INSERT INTO coord_operations
                       (principal_kind, principal_id, operation_type,
                        operation_id, request_hash, outcome_kind,
                        outcome_json, created_at)
                       VALUES (?, ?, ?, ?, ?, 'error', ?, ?)""",
                    (
                        LOCAL_OPERATOR_KIND,
                        LOCAL_OPERATOR_ID,
                        operation_type,
                        operation_id,
                        request_hash,
                        _encode_outcome(payload),
                        store.now_ms(),
                    ),
                )
                conn.execute("COMMIT")
                recorded_error = payload
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    # Projection failure never changes the already-committed mutation result.
    from .outbox import project_pending

    project_pending()
    if conflict is not None:
        raise conflict
    if recorded_error is not None:
        _raise_recorded_error(recorded_error)
    return result  # type: ignore[return-value]
