"""Plumb: host-mediated agent-to-agent collaboration — the service module.

This is a plain, process-level singleton (`get_plumb_service()`), NOT a
mitmproxy addon. It owns all mailbox state; the two ingress surfaces route to
it:

  - AgentAPI (`_safeyolo.proxy.internal`, agent bearer token, service-discovery
    attribution) routes /plumb/* here for agents.
  - AdminAPI (host admin token, port `admin_port`) routes /admin/plumb/* here
    for the operator, marshalling every call onto mitmproxy's event loop via
    asyncio.run_coroutine_threadsafe so admin-thread calls never race the
    loop-owned state (asyncio.Condition waiters).

Design invariants:
  * Sender identity is ALWAYS the attributed agent passed in by AgentAPI,
    never anything from the request body.
  * Authorization to send = membership in an operator-approved, unexpired
    conversation grant. Approval is the policy gate (a future `plumb:send`
    PDP action can layer rate/budget on top — see _future_policy_hook).
  * Agent-authored strings (topic/note/body) are untrusted: sanitized before
    they ever reach an operator-facing field, and delivered to other agents
    as data, never as instructions.
  * All in-memory mutation happens on the mitmproxy event loop; SQLite
    write-through runs off the loop via asyncio.to_thread and is guarded by
    its own lock.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from safeyolo.core.audit_schema import (
    ApprovalRequest,
    Decision,
    EventKind,
    Severity,
)
from safeyolo.core.utils import sanitize_for_log, write_event

# RFC1123 label — the canonical agent-name pattern used across the codebase
# (mitm_addons/unix_listener.py, commands/agent.py, sockets.py). Participant
# names become approval targets, grant principals, and operator-rendered text,
# so they must be validated against exactly this.
_AGENT_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# --- defaults/backpressure ---
DEFAULT_MAX_MESSAGE_BYTES = 1_048_576
DEFAULT_MESSAGE_PAGE_LIMIT = 200
# Default participant cap (incl. requester). NOT a hard architectural limit —
# operators override via config.yaml [plumb].max_participants. Over-limit
# requests are rejected, never truncated.
DEFAULT_MAX_PARTICIPANTS = 8
MAX_CONCURRENT_WAITERS = 64          # parked long-polls (one task each)
DEFAULT_TTL_SECONDS = 3600
LONGPOLL_MAX_WAIT = 30               # cap client-requested ?wait=
UNTRUSTED_FIELD_DISPLAY_MAXLEN = 500

log = logging.getLogger("safeyolo.plumb")


# =============================================================================
# Content scanning — explicit opt-in
# =============================================================================
# The `*.internal` domain policy sets {"bypass": ["pattern_scanner"]}, so plumb
# bodies would silently skip secret detection if we relied on the addon path.
# We scan here directly against the builtin "secrets" set instead.

def _load_secret_rules():
    try:
        from safeyolo.detection.patterns import (
            load_builtin_set,
            load_patterns_from_config,
        )

        rules = load_patterns_from_config(load_builtin_set("secrets"))
        if not rules:
            log.warning("plumb: secret-scan ruleset is empty — message scanning is a no-op")
        return rules
    except Exception as exc:
        # Don't silently disable a security control. Surface it loudly so an
        # operator sees scanning is off; the caller still enforces membership
        # + bounds, but secret detection won't fire until this is fixed.
        log.error("plumb: FAILED to load secret-scan rules (%s: %s) — "
                  "message secret-scanning DISABLED", type(exc).__name__, exc)
        return []


def _scan(text: str, rules) -> tuple[list[str], bool]:
    """Return (detected_class_names, should_block) for a message body."""
    detected: list[str] = []
    should_block = False
    for rule in rules:
        target = getattr(rule, "target", "both")
        if target not in ("request", "both"):
            continue
        try:
            if rule.matches(text):
                detected.append(rule.name)
                if getattr(rule, "should_block", False):
                    should_block = True
        except Exception:
            continue
    return detected, should_block


# =============================================================================
# SQLite write-through — mirrors storage/flow_store.py (WAL + lock, thread-safe)
# =============================================================================

_CREATE_GRANTS = """
CREATE TABLE IF NOT EXISTS plumb_grants (
    conversation_id TEXT PRIMARY KEY,
    participants_json TEXT NOT NULL,
    topic TEXT,
    requested_by TEXT,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    closed INTEGER NOT NULL DEFAULT 0
);
"""
_CREATE_PENDING = """
CREATE TABLE IF NOT EXISTS plumb_pending (
    request_id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    participants_json TEXT NOT NULL,
    topic TEXT,
    note TEXT,
    ttl_seconds INTEGER NOT NULL,
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
);
"""
_CREATE_MESSAGES = """
CREATE TABLE IF NOT EXISTS plumb_messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    from_agent TEXT NOT NULL,
    created_at REAL NOT NULL,
    body TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
"""
_CREATE_MSG_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_plumb_messages_conv "
    "ON plumb_messages (conversation_id, created_at);"
)


class PlumbStore:
    """Durable backing store for plumb state.

    Message history is append-only and SQLite-backed. PlumbService owns live
    grant/pending state and waiter notifications, but it does not treat an
    in-memory message list as the authoritative chat log.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute(_CREATE_GRANTS)
        self._conn.execute(_CREATE_PENDING)
        self._conn.execute(_CREATE_MESSAGES)
        self._conn.execute(_CREATE_MSG_INDEX)
        self._conn.commit()

    def load(self) -> tuple[dict, dict]:
        """Rehydrate pending requests and active grants after a restart/rebind."""
        convos: dict[str, dict] = {}
        pending: dict[str, dict] = {}
        if self._conn is None:
            return pending, convos
        with self._lock:
            for row in self._conn.execute("SELECT * FROM plumb_grants WHERE closed=0"):
                convos[row["conversation_id"]] = {
                    "conversation_id": row["conversation_id"],
                    "participants": json.loads(row["participants_json"]),
                    "topic": row["topic"] or "",
                    "requested_by": row["requested_by"] or "",
                    "created_at": row["created_at"],
                    "expires_at": row["expires_at"],
                }
            for row in self._conn.execute("SELECT * FROM plumb_pending WHERE status='pending'"):
                pending[row["request_id"]] = {
                    "request_id": row["request_id"],
                    "requester": row["requester"],
                    "participants": json.loads(row["participants_json"]),
                    "topic": row["topic"] or "",
                    "note": row["note"] or "",
                    "ttl_seconds": row["ttl_seconds"],
                    "created_at": row["created_at"],
                    "status": row["status"],
                }
        return pending, convos

    # write-through methods — all called via asyncio.to_thread from the loop
    def put_pending(self, req: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO plumb_pending "
                "(request_id, requester, participants_json, topic, note, ttl_seconds, created_at, status) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (req["request_id"], req["requester"], json.dumps(req["participants"]),
                 req["topic"], req["note"], req["ttl_seconds"], req["created_at"], req["status"]),
            )
            self._conn.commit()

    def set_pending_status(self, request_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE plumb_pending SET status=? WHERE request_id=?", (status, request_id))
            self._conn.commit()

    def put_conv(self, grant: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO plumb_grants "
                "(conversation_id, participants_json, topic, requested_by, created_at, expires_at, closed) "
                "VALUES (?,?,?,?,?,?,0)",
                (grant["conversation_id"], json.dumps(grant["participants"]), grant["topic"],
                 grant["requested_by"], grant["created_at"], grant["expires_at"]),
            )
            self._conn.commit()

    def close_conv(self, conversation_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE plumb_grants SET closed=1 WHERE conversation_id=?", (conversation_id,))
            self._conn.commit()

    def append_message(self, msg: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO plumb_messages "
                "(id, conversation_id, from_agent, created_at, body, metadata_json) "
                "VALUES (?,?,?,?,?,?)",
                (msg["id"], msg["conversation_id"], msg["from_agent"], msg["created_at"],
                 msg["body"], json.dumps(msg["metadata"])),
            )
            self._conn.commit()

    def list_messages(self, conversation_id: str, after: str | None = None,
                      limit: int = DEFAULT_MESSAGE_PAGE_LIMIT) -> dict:
        """Return one durable chat-message page for a conversation.

        Unknown cursors return from the beginning rather than failing or hiding
        history. The response is still bounded by `limit`.
        """
        if self._conn is None:
            return {"messages": [], "has_more": False, "next_after": after}
        with self._lock:
            after_rowid = None
            if after:
                row = self._conn.execute(
                    "SELECT rowid FROM plumb_messages "
                    "WHERE conversation_id=? AND id=?",
                    (conversation_id, after),
                ).fetchone()
                if row is not None:
                    after_rowid = row["rowid"]

            if after_rowid is None:
                cursor = self._conn.execute(
                    "SELECT rowid, * FROM plumb_messages "
                    "WHERE conversation_id=? ORDER BY rowid ASC LIMIT ?",
                    (conversation_id, limit + 1),
                )
            else:
                cursor = self._conn.execute(
                    "SELECT rowid, * FROM plumb_messages "
                    "WHERE conversation_id=? AND rowid>? ORDER BY rowid ASC LIMIT ?",
                    (conversation_id, after_rowid, limit + 1),
                )
            rows = list(cursor)
            has_more = len(rows) > limit
            rows = rows[:limit]
            messages = [
                {
                    "id": row["id"],
                    "conversation_id": row["conversation_id"],
                    "from_agent": row["from_agent"],
                    "created_at": row["created_at"],
                    "body": row["body"],
                    "metadata": json.loads(row["metadata_json"]),
                }
                for row in rows
            ]
            return {
                "messages": messages,
                "has_more": has_more,
                "next_after": messages[-1]["id"] if messages else after,
            }


# =============================================================================
# The service
# =============================================================================

class PlumbService:
    def __init__(
        self,
        data_dir: str | None = None,
        max_participants: int | None = None,
        max_message_bytes: int | None = None,
        message_page_limit: int | None = None,
        default_ttl_seconds: int | None = None,
    ):
        base = data_dir or os.environ.get("SAFEYOLO_DATA_DIR", "/safeyolo/data")
        self._store = PlumbStore(os.path.join(base, "plumb", "plumb.db"))
        self._store.init_db()
        self._pending, self._convos = self._store.load()
        self._conds: dict[str, asyncio.Condition] = {}
        self._waiters = 0
        self._rules = _load_secret_rules()
        self._max_participants = max(2, int(max_participants or DEFAULT_MAX_PARTICIPANTS))
        self._max_message_bytes = _coerce_nonnegative_int(
            max_message_bytes, DEFAULT_MAX_MESSAGE_BYTES
        )
        self._message_page_limit = max(
            1, int(message_page_limit or DEFAULT_MESSAGE_PAGE_LIMIT)
        )
        self._default_ttl_seconds = max(
            1, int(default_ttl_seconds or DEFAULT_TTL_SECONDS)
        )

    # ---- ids (secrets is fine here — normal app code, not a workflow sandbox)
    @staticmethod
    def _new_id(prefix: str) -> str:
        return f"{prefix}_{secrets.token_hex(6)}"

    def _cond_for(self, conv_id: str) -> asyncio.Condition:
        # created lazily on the loop thread (where post/read run)
        cond = self._conds.get(conv_id)
        if cond is None:
            cond = asyncio.Condition()
            self._conds[conv_id] = cond
        return cond

    def _is_member(self, conv_id: str, agent: str) -> bool:
        g = self._convos.get(conv_id)
        return bool(g and agent in g["participants"] and g["expires_at"] > time.time())

    @staticmethod
    def _clean(text: Any) -> str:
        """Neutralize control characters in stored agent-authored prose.

        Length is not capped here. Watch/UI rendering can truncate for display,
        but the approval record should preserve the operator-visible context.
        """
        return sanitize_for_log(str(text or ""), max_len=None).strip()

    def _ttl_or_default(self, value: Any) -> int:
        try:
            ttl = int(value)
        except (TypeError, ValueError):
            return self._default_ttl_seconds
        return ttl if ttl > 0 else self._default_ttl_seconds

    def _page_limit(self, value: Any) -> int:
        try:
            requested = int(value)
        except (TypeError, ValueError):
            requested = self._message_page_limit
        if requested <= 0:
            requested = self._message_page_limit
        return max(1, min(requested, self._message_page_limit))

    # ---------------------------------------------------------------- agent API
    async def request_chat(self, requester: str, participants: list[str],
                           topic: str, note: str, ttl_seconds: int) -> dict:
        """Agent asks to talk to others. Emits an operator approval; returns
        pending. Runs on the loop (called from AgentAPI's async hook)."""
        # Validate & normalize participants BEFORE they become approval targets,
        # grant principals, or operator-facing text. Never silently drop names
        # (the old sort+truncate could even drop the requester); reject instead.
        targets = {str(p) for p in (participants or [])} - {requester}
        if not targets:
            return {"status": 400, "error": "no participants to chat with"}
        names = {requester, *targets}
        invalid = sorted(n for n in names if not _AGENT_NAME_RE.match(n))
        if invalid:
            return {"status": 400, "error": f"invalid participant name(s): {', '.join(invalid)}"}
        if len(names) > self._max_participants:
            return {"status": 400,
                    "error": f"too many participants (max {self._max_participants})"}
        members = sorted(names)          # requester guaranteed present

        topic_c = self._clean(topic)
        note_c = self._clean(note)
        ttl = self._ttl_or_default(ttl_seconds)

        req = {
            "request_id": self._new_id("req"),
            "requester": requester,
            "participants": members,
            "topic": topic_c,
            "note": note_c,
            "ttl_seconds": ttl,
            "created_at": time.time(),
            "status": "pending",
        }
        self._pending[req["request_id"]] = req
        await asyncio.to_thread(self._store.put_pending, req)

        target_names = [p for p in members if p != requester]
        write_event(
            "plumb.requested",
            kind=EventKind.PLUMB,
            severity=Severity.CRITICAL,
            summary=f"{sanitize_for_log(requester)} requests a chat with {sanitize_for_log(', '.join(target_names))}",
            decision=Decision.REQUIRE_APPROVAL,
            agent=requester,
            addon="plumb",
            approval=ApprovalRequest(
                required=True,
                approval_type="plumb",
                key=req["request_id"],           # dedup identity
                target=",".join(members),
                # scope_hint carries BOTH trusted (system-derived) and untrusted
                # (agent prose) — watch renders them in separate, labeled blocks.
                scope_hint={
                    "requester": requester,           # trusted: attributed
                    "participants": members,          # trusted: attributed
                    "ttl_seconds": ttl,               # trusted
                    "topic": topic_c,                 # untrusted: agent prose (sanitized)
                    "note": note_c,                   # untrusted: agent prose (sanitized)
                },
            ),
        )
        return {"status": 202, "state": "pending",
                "request_id": req["request_id"], "participants": members}

    def list_conversations(self, agent: str) -> list[dict]:
        now = time.time()
        return [
            {k: g[k] for k in ("conversation_id", "participants", "topic", "expires_at")}
            for g in self._convos.values()
            if agent in g["participants"] and g["expires_at"] > now
        ]

    async def post_message(self, agent: str, conv_id: str, body: str,
                           references: list | None = None) -> dict:
        """Enqueue a message from `agent` (attributed) into a conversation."""
        if not self._is_member(conv_id, agent):
            return {"error": "not a participant", "status": 403}
        raw = body.encode("utf-8", errors="replace")
        if self._max_message_bytes and len(raw) > self._max_message_bytes:
            return {"error": "message too large", "status": 413}

        detected, should_block = _scan(body, self._rules)
        if should_block:
            write_event(
                "plumb.message_blocked",
                kind=EventKind.PLUMB, severity=Severity.CRITICAL,
                summary=f"{sanitize_for_log(agent)} -> {conv_id}: blocked (secret detected)",
                decision=Decision.DENY, agent=agent, addon="plumb",
                details={"detected_classes": detected},
            )
            return {"error": "message blocked: credential/secret detected",
                    "detected_classes": detected, "status": 403}

        msg = {
            "id": self._new_id("msg"),
            "conversation_id": conv_id,
            "from_agent": agent,                         # attribution, never body
            "created_at": time.time(),
            "body": body,
            "metadata": {
                "size_bytes": len(raw),
                "detected_classes": detected,
                "references": references or [],
            },
        }
        await asyncio.to_thread(self._store.append_message, msg)   # off the loop

        cond = self._cond_for(conv_id)
        async with cond:
            cond.notify_all()

        write_event(
            "plumb.message_flagged" if detected else "plumb.message_allowed",
            kind=EventKind.PLUMB,
            severity=Severity.HIGH if detected else Severity.LOW,
            summary=f"{sanitize_for_log(agent)} -> {conv_id} ({len(raw)}B)",
            decision=Decision.ALLOW, agent=agent, addon="plumb",
            details={"detected_classes": detected},
        )
        return {"id": msg["id"], "detected_classes": detected, "status": 200}

    async def read_messages(self, agent: str, conv_id: str,
                            after: str | None, wait: int,
                            limit: int | None = None) -> dict:
        """Long-poll receive. Never blocks the loop — parks on an
        asyncio.Condition with a timeout."""
        if not self._is_member(conv_id, agent):
            return {"error": "not a participant", "status": 403}
        wait = max(0, min(int(wait or 0), LONGPOLL_MAX_WAIT))
        page_limit = self._page_limit(limit)

        async def snapshot() -> dict:
            page = await asyncio.to_thread(
                self._store.list_messages, conv_id, after, page_limit
            )
            page["limit"] = page_limit
            page["status"] = 200
            return page

        cond = self._cond_for(conv_id)
        async with cond:
            fresh = await snapshot()
            if fresh["messages"] or wait == 0:
                return fresh
            if self._waiters >= MAX_CONCURRENT_WAITERS:
                return {
                    "messages": [],
                    "has_more": False,
                    "next_after": after,
                    "limit": page_limit,
                    "status": 200,
                }       # shed load, don't park

            self._waiters += 1
            try:
                try:
                    await asyncio.wait_for(cond.wait(), timeout=wait)
                except TimeoutError:
                    # Long-poll timeout is a normal empty-read outcome.
                    pass
                return await snapshot()   # 200 [] on timeout
            finally:
                self._waiters -= 1

    async def leave(self, agent: str, conv_id: str) -> dict:
        g = self._convos.get(conv_id)
        if not g or agent not in g["participants"]:
            return {"error": "not a participant", "status": 403}
        g["participants"] = [p for p in g["participants"] if p != agent]
        await asyncio.to_thread(self._store.put_conv, g)
        if len(g["participants"]) <= 1:
            await self._close(conv_id, reason="last participant left")
        return {"status": 200, "left": conv_id}

    # ---------------------------------------------------------------- admin API
    # These are async so AdminAPI can marshal them onto the loop via
    # run_coroutine_threadsafe — keeping all state mutation on the loop thread.
    async def list_pending(self) -> dict:
        # Only genuinely-pending requests; resolved ones keep their record for
        # audit/dedup but must not resurface as awaiting approval.
        return {"pending": [r for r in self._pending.values() if r["status"] == "pending"]}

    async def approve_request(self, request_id: str,
                              operator_ttl: int | None = None) -> dict:
        req = self._pending.get(request_id)
        if not req or req["status"] != "pending":
            return {"error": "unknown or already-resolved request", "status": 404}
        req["status"] = "approved"
        await asyncio.to_thread(self._store.set_pending_status, request_id, "approved")

        ttl = self._ttl_or_default(operator_ttl) if operator_ttl is not None else req["ttl_seconds"]
        grant = {
            "conversation_id": self._new_id("conv"),
            "participants": list(req["participants"]),
            "topic": req["topic"],
            "requested_by": req["requester"],
            "created_at": time.time(),
            "expires_at": time.time() + ttl,
        }
        self._convos[grant["conversation_id"]] = grant
        await asyncio.to_thread(self._store.put_conv, grant)

        write_event(
            "plumb.approved", kind=EventKind.PLUMB, severity=Severity.MEDIUM,
            summary=f"chat approved: {sanitize_for_log(','.join(grant['participants']))}",
            decision=Decision.ALLOW, agent=req["requester"], addon="plumb",
            details={"conversation_id": grant["conversation_id"],
                     "participants": grant["participants"], "request_id": request_id},
        )
        write_event(
            "plumb.conversation_created", kind=EventKind.PLUMB, severity=Severity.LOW,
            summary=f"conversation {grant['conversation_id']} created",
            decision=Decision.ALLOW, addon="plumb",
            details={"participants": grant["participants"]},
        )
        return {"status": 200, **grant}

    async def deny_request(self, request_id: str) -> dict:
        req = self._pending.get(request_id)
        if not req or req["status"] != "pending":
            return {"error": "unknown or already-resolved request", "status": 404}
        req["status"] = "denied"
        await asyncio.to_thread(self._store.set_pending_status, request_id, "denied")
        write_event(
            "plumb.denied", kind=EventKind.PLUMB, severity=Severity.MEDIUM,
            summary=f"chat denied: {sanitize_for_log(request_id)}",
            decision=Decision.DENY, agent=req["requester"], addon="plumb",
            # participants included so watch can reconstruct key:target on restart
            details={"request_id": request_id, "participants": req["participants"]},
        )
        return {"status": 200, "denied": request_id}

    async def close_conversation(self, conv_id: str) -> dict:
        if conv_id not in self._convos:
            return {"error": "unknown conversation", "status": 404}
        await self._close(conv_id, reason="operator closed")
        return {"status": 200, "closed": conv_id}

    async def admin_list_conversations(self) -> dict:
        return {"conversations": list(self._convos.values())}

    # ------------------------------------------------------------------ helpers
    async def _close(self, conv_id: str, reason: str) -> None:
        self._convos.pop(conv_id, None)
        await asyncio.to_thread(self._store.close_conv, conv_id)
        write_event(
            "plumb.conversation_closed", kind=EventKind.PLUMB, severity=Severity.LOW,
            summary=f"conversation {conv_id} closed: {reason}",
            decision=Decision.LOG, addon="plumb",
            details={"conversation_id": conv_id, "reason": reason},
        )

    def _future_policy_hook(self, agent: str, conv_id: str) -> None:
        """Seam for a future `plumb:send` PDP action (rate/budget per agent).
        Authorization today is grant membership + TTL (operator-approved)."""
        return None


# =============================================================================
# Process-level singleton — same idiom as get_service_registry/get_policy_client
# =============================================================================

_service: PlumbService | None = None
_service_lock = threading.Lock()


def get_plumb_service() -> PlumbService:
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                settings = _configured_plumb_settings()
                _service = PlumbService(**settings)
    return _service


def _coerce_nonnegative_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default


def _coerce_positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _configured_plumb_settings() -> dict[str, int]:
    """Read [plumb] settings from config.yaml, falling back to defaults.

    Never raise — a bad/missing config must not disable plumb.
    """
    try:
        from safeyolo.config import load_config

        cfg = load_config().get("plumb", {})
    except Exception:
        cfg = {}
    return {
        "max_participants": _coerce_positive_int(
            cfg.get("max_participants"), DEFAULT_MAX_PARTICIPANTS
        ),
        "max_message_bytes": _coerce_nonnegative_int(
            cfg.get("max_message_bytes"), DEFAULT_MAX_MESSAGE_BYTES
        ),
        "message_page_limit": _coerce_positive_int(
            cfg.get("message_page_limit"), DEFAULT_MESSAGE_PAGE_LIMIT
        ),
        "default_ttl_seconds": _coerce_positive_int(
            cfg.get("default_ttl_seconds"), DEFAULT_TTL_SECONDS
        ),
    }


def _configured_max_participants() -> int:
    """Read [plumb].max_participants from config.yaml, falling back to the
    default. Never raise — a bad/missing config must not disable plumb."""
    return _configured_plumb_settings()["max_participants"]
