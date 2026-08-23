"""Opt-in per-request execution tracing for the SafeYolo addon pipeline.

Answers the diagnostic question `/explain` cannot: which parts of the
pipeline actually executed for a given request? See issue #213 for the
motivation — missing audit events are ambiguous, missing trace steps
are explicit (`state=not_loaded` at read time).

Contract with the rest of the codebase:

- Callers use `record_step(flow, addon=..., hook=..., state=..., ...)`.
- The call is a no-op unless `flow.metadata.get("trace") is True`, so
  every request path pays only a single dict lookup when tracing is off.
- Any exception raised inside recording is swallowed here; addon
  enforcement is never disturbed by a trace-instrumentation bug.
- Nothing here writes to disk. Store is in-memory, bounded, TTL'd.

Reads happen via `TraceStore.get(request_id, agent_id)` and must be
scoped to the originating agent. The store deliberately returns None
both for unknown ids and for wrong-agent lookups, so an outside caller
cannot distinguish the two.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mitmproxy import http

_log = logging.getLogger("safeyolo.trace")


# =============================================================================
# Configuration (env-tunable)
# =============================================================================

def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


TRACE_TTL_S = _int_env("SAFEYOLO_TRACE_TTL_S", 300)
TRACE_GLOBAL_MAX = _int_env("SAFEYOLO_TRACE_GLOBAL_MAX", 1000)
TRACE_PER_AGENT_MAX = _int_env("SAFEYOLO_TRACE_PER_AGENT_MAX", 200)
TRACE_STEPS_MAX = _int_env("SAFEYOLO_TRACE_STEPS_MAX", 128)
TRACE_DETAILS_MAX_BYTES = _int_env("SAFEYOLO_TRACE_DETAILS_MAX_BYTES", 4096)


# =============================================================================
# Expected-addon registry
# =============================================================================
# The addons a normal outbound request should traverse. `TraceStore.get`
# emits `state=not_loaded` for any expected addon that never appeared in
# the recorded steps. Modules add themselves at import time by calling
# `register_expected_addon`; this keeps the "what should run" list beside
# the code that would run it rather than in a distant list.

_expected_addons: list[str] = []
_expected_lock = threading.Lock()


def register_expected_addon(name: str) -> None:
    """Declare an addon whose absence from a trace is diagnostic evidence.

    Safe to call more than once with the same name; duplicates are ignored.
    Ordering is insertion order (matches the mitmproxy addon load order in
    practice, which is what we compare against).
    """
    with _expected_lock:
        if name not in _expected_addons:
            _expected_addons.append(name)


def expected_addons() -> list[str]:
    with _expected_lock:
        return list(_expected_addons)


# =============================================================================
# Data model
# =============================================================================

# States a step can be in. Values chosen to match the vocabulary in issue #213
# so agent-side reasoning can enum-match rather than string-compare on drift.
STATE_EVALUATED = "evaluated"
STATE_BYPASSED = "bypassed"
STATE_ERROR = "error"
STATE_NOT_LOADED = "not_loaded"  # synthesised at read time, never recorded

# Canonical bypass/error reasons. Kept centrally so the skill DAG can branch on
# a stable, code-enforced vocabulary rather than free-form strings. Per-addon
# outcome constants live at the top of each addon module.
REASON_PRIOR_RESPONSE = "prior_response"      # an earlier addon already responded
REASON_POLICY_DISABLED = "policy_disabled"    # PDP said the addon is off for scope
REASON_ADDON_DISABLED = "addon_disabled"      # mitmproxy option disables the addon globally


@dataclass
class Step:
    """One instrumented step in the pipeline for a single request.

    Fields deliberately narrow — trace never carries request/response
    bodies, credential values, or authorization headers. `details` is
    for small non-secret categorical facts (match counts, decision
    strings) and is size-capped at serialise time.
    """
    addon: str
    hook: str  # "request" | "response"
    state: str  # STATE_EVALUATED | STATE_BYPASSED | STATE_ERROR
    outcome: str | None = None
    reason: str | None = None
    duration_us: int | None = None
    details: dict[str, Any] | None = None
    ts: float = field(default_factory=time.time)


@dataclass
class TraceRecord:
    request_id: str
    agent_id: str | None
    created_at: float = field(default_factory=time.time)
    steps: list[Step] = field(default_factory=list)
    truncated: bool = False  # step count exceeded TRACE_STEPS_MAX


# =============================================================================
# Store
# =============================================================================

class TraceStore:
    """In-memory, bounded, TTL'd store of per-request execution traces.

    Not persisted anywhere: this is short-lived diagnostic state whose
    only consumer is the originating agent (via /trace) and doctor.
    """

    def __init__(
        self,
        ttl_s: float = TRACE_TTL_S,
        global_max: int = TRACE_GLOBAL_MAX,
        per_agent_max: int = TRACE_PER_AGENT_MAX,
        steps_max: int = TRACE_STEPS_MAX,
        details_max_bytes: int = TRACE_DETAILS_MAX_BYTES,
    ) -> None:
        self._ttl_s = ttl_s
        self._global_max = global_max
        self._per_agent_max = per_agent_max
        self._steps_max = steps_max
        self._details_max_bytes = details_max_bytes
        # OrderedDict gives us O(1) LRU: move_to_end on write, popitem(last=False)
        # on eviction. Insertion order is refreshed on every append so the LRU
        # answers "least-recently-appended-to" — the natural notion here.
        self._records: OrderedDict[str, TraceRecord] = OrderedDict()
        self._by_agent: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    # -- write side --------------------------------------------------------

    def _ensure_record(self, request_id: str, agent_id: str | None) -> TraceRecord:
        record = self._records.get(request_id)
        if record is None:
            record = TraceRecord(request_id=request_id, agent_id=agent_id)
            self._records[request_id] = record
            if agent_id:
                self._by_agent.setdefault(agent_id, []).append(request_id)
            self._enforce_caps(agent_id)
        else:
            # First writer wins on agent_id; later writers cannot claim a
            # trace they don't own even by racing. If agent_id was unknown
            # at creation, later fill it in (service-discovery may resolve
            # after the first step).
            if record.agent_id is None and agent_id:
                record.agent_id = agent_id
                self._by_agent.setdefault(agent_id, []).append(request_id)
            self._records.move_to_end(request_id)
        return record

    def append_step(
        self,
        request_id: str,
        agent_id: str | None,
        step: Step,
    ) -> None:
        with self._lock:
            self._expire_locked()
            record = self._ensure_record(request_id, agent_id)
            if len(record.steps) >= self._steps_max:
                record.truncated = True
                return
            record.steps.append(step)

    # -- read side ---------------------------------------------------------

    def get(self, request_id: str, agent_id: str | None) -> TraceRecord | None:
        """Return a trace only when `agent_id` owns it.

        Missing record and wrong-agent record return the same None so
        callers cannot use existence-of-id as an oracle.
        """
        with self._lock:
            self._expire_locked()
            record = self._records.get(request_id)
            if record is None:
                return None
            # None agent_id is not a wildcard: unresolved caller identity
            # must not read anyone's trace.
            if not agent_id or record.agent_id != agent_id:
                return None
            return record

    # -- housekeeping -----------------------------------------------------

    def _expire_locked(self) -> None:
        now = time.time()
        cutoff = now - self._ttl_s
        # OrderedDict is insertion-ordered; oldest is at the front. Records
        # get move_to_end on every append, so we can stop at the first live
        # one only for lookups by created_at. Because we care about
        # last-activity, not created_at, iterate from the front and drop
        # while their newest-step time (== record's move_to_end position)
        # is stale. Simpler: check both created_at and any step's ts.
        stale: list[str] = []
        for rid, rec in self._records.items():
            last = rec.steps[-1].ts if rec.steps else rec.created_at
            if last < cutoff:
                stale.append(rid)
            else:
                # Nothing older follows: rely on move_to_end keeping
                # active records toward the back.
                break
        for rid in stale:
            self._drop_locked(rid)

    def _enforce_caps(self, agent_id: str | None) -> None:
        # Per-agent cap first — a single agent can't monopolise the store.
        if agent_id:
            agent_ids = self._by_agent.get(agent_id, [])
            while len(agent_ids) > self._per_agent_max:
                oldest = agent_ids[0]
                self._drop_locked(oldest)
                # _drop_locked mutates agent_ids too; refresh reference in
                # case the list object was replaced by cleanup.
                agent_ids = self._by_agent.get(agent_id, [])
        # Global cap: LRU eviction from the front of the OrderedDict.
        while len(self._records) > self._global_max:
            oldest_rid, _ = next(iter(self._records.items()))
            self._drop_locked(oldest_rid)

    def _drop_locked(self, request_id: str) -> None:
        rec = self._records.pop(request_id, None)
        if rec is None:
            return
        if rec.agent_id:
            agent_ids = self._by_agent.get(rec.agent_id)
            if agent_ids:
                try:
                    agent_ids.remove(request_id)
                except ValueError:
                    pass
                if not agent_ids:
                    self._by_agent.pop(rec.agent_id, None)

    # -- serialisation helper (used by /trace) ----------------------------

    def serialise(self, record: TraceRecord) -> dict[str, Any]:
        """Build the wire payload for `/trace`, including `not_loaded` diff."""
        observed = {step.addon for step in record.steps}
        not_loaded = [name for name in expected_addons() if name not in observed]
        return {
            "request_id": record.request_id,
            "agent_id": record.agent_id,
            "created_at": record.created_at,
            "truncated": record.truncated,
            "steps": [self._safe_step_dict(step) for step in record.steps],
            "not_loaded": [
                {"addon": name, "state": STATE_NOT_LOADED}
                for name in not_loaded
            ],
        }

    def _safe_step_dict(self, step: Step) -> dict[str, Any]:
        payload = asdict(step)
        payload.pop("ts", None)
        details = payload.get("details")
        if details is not None:
            payload["details"] = self._cap_details(details)
        # Drop keys whose value is None to keep the wire payload compact
        # without hiding the semantic distinction between "no reason" and
        # "reason: ..." — both are keys the caller cares about only when
        # present.
        return {k: v for k, v in payload.items() if v is not None}

    def _cap_details(self, details: dict[str, Any]) -> dict[str, Any]:
        """Enforce the per-step details byte cap and drop nested structures."""
        cleaned: dict[str, Any] = {}
        for key, value in details.items():
            if isinstance(value, (str, int, bool)) or value is None:
                cleaned[key] = value
            else:
                # Anything else (dict, list, object) is coerced to a short str.
                # This prevents accidental inclusion of request/response
                # bodies or header dumps that a caller passed by reference.
                cleaned[key] = f"<{type(value).__name__}>"
        try:
            if len(json.dumps(cleaned)) > self._details_max_bytes:
                cleaned = {"_truncated": True}
        except (TypeError, ValueError):
            cleaned = {"_truncated": True}
        return cleaned


# =============================================================================
# Module-level singleton
# =============================================================================

_store: TraceStore | None = None
_store_lock = threading.Lock()


def get_store() -> TraceStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = TraceStore()
    return _store


def reset_store_for_tests() -> None:
    """Drop the singleton so a test can construct a fresh one via `get_store`."""
    global _store
    with _store_lock:
        _store = None


# =============================================================================
# Convenience API (call-site facing)
# =============================================================================

def is_traced(flow: http.HTTPFlow) -> bool:
    try:
        return bool(flow.metadata.get("trace"))
    except Exception:  # pragma: no cover - defensive
        return False


def record_step(
    flow: http.HTTPFlow,
    *,
    addon: str,
    hook: str,
    state: str,
    outcome: str | None = None,
    reason: str | None = None,
    duration_us: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Record one pipeline step. No-op unless the flow opted into tracing.

    Never raises. Trace-instrumentation failure must not weaken enforcement.
    """
    try:
        if not is_traced(flow):
            return
        request_id = flow.metadata.get("request_id")
        if not request_id:
            return
        agent_id = flow.metadata.get("agent")
        step = Step(
            addon=addon,
            hook=hook,
            state=state,
            outcome=outcome,
            reason=reason,
            duration_us=duration_us,
            details=details,
        )
        get_store().append_step(request_id, agent_id, step)
    except Exception as exc:  # noqa: BLE001 — enforcement must never regress
        _log.warning("trace record_step failed: %s: %s", type(exc).__name__, exc)


# =============================================================================
# Hook decorator — strictly observational: timing + error capture, nothing else
# =============================================================================
# Explicit per-hook wrapper rather than __init_subclass__ magic: keeps this
# security-relevant instrumentation visible at each participating addon (issue
# #213 review). Compatible with any addon that exposes a `name` attribute; not
# tied to SecurityAddon so `service-gateway` can use it too.
#
# Invariant (#213 review, second pass): a traced request MUST execute the
# exact same addon logic as an untraced one. The decorator does not decide
# whether the addon body runs, does not preempt short-circuits, and does not
# reinterpret decisions. It may:
#   - start a monotonic timer whose delta feeds `duration_us`,
#   - observe raised exceptions, record `state=error, reason=<ExcType>` and
#     re-raise so enforcement sees identical exception behaviour.
# It may NOT:
#   - skip calling the wrapped function under any condition,
#   - mutate flow.request / flow.response / flow.metadata beyond the private
#     timer key it sets and removes,
#   - emit `bypassed/*` on the addon's behalf (the addon owns its own
#     short-circuit decisions and their trace evidence).

def _hook_start_key(addon_name: str, hook: str) -> str:
    return f"_trace_hook_start:{addon_name}:{hook}"


def _elapsed_us_from(flow: http.HTTPFlow, addon_name: str, hook: str) -> int | None:
    """Compute microseconds elapsed since `trace_addon_hook` started this hook.

    Returns None if the timer wasn't started (untraced flow, or the addon
    wasn't decorated) so callers can distinguish "measured" from "unavailable"
    in the trace payload. Defensive against Mock/duck-typed flow.metadata:
    a non-int `start` reads as "no timer" rather than raising.
    """
    try:
        start = flow.metadata.get(_hook_start_key(addon_name, hook))
    except Exception:  # pragma: no cover - defensive
        return None
    if not isinstance(start, int):
        return None
    return (time.perf_counter_ns() - start) // 1000


def trace_addon_hook(hook: str) -> Callable:
    """Observational decorator for an addon's `request` or `response` method.

    See the invariant block above. This wrapper only:
      1. starts a monotonic timer that the addon's own `_trace_evaluated` /
         `_trace_bypassed` calls read to fill `duration_us`, and
      2. catches exceptions to emit `state=error, reason=<ExceptionType>,
         duration_us=<measured>` before re-raising so enforcement sees the
         identical exception.

    The wrapped function is ALWAYS called for a traced flow — the decorator
    does not decide whether the hook body runs. Addons that short-circuit
    (e.g. `if flow.response: return` or `if self.is_bypassed(flow): return`)
    are responsible for emitting their own `bypassed/*` trace evidence.
    """
    if hook not in ("request", "response"):
        raise ValueError(f"trace_addon_hook: unsupported hook {hook!r}")

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(self, flow, *args, **kwargs):
            if not is_traced(flow):
                return fn(self, flow, *args, **kwargs)

            addon_name = getattr(self, "name", type(self).__name__)
            key = _hook_start_key(addon_name, hook)
            flow.metadata[key] = time.perf_counter_ns()
            try:
                return fn(self, flow, *args, **kwargs)
            except BaseException as exc:
                # Compute duration BEFORE record_step so the trace step reflects
                # how long the failed hook ran.
                elapsed = _elapsed_us_from(flow, addon_name, hook)
                try:
                    record_step(
                        flow,
                        addon=addon_name,
                        hook=hook,
                        state=STATE_ERROR,
                        reason=type(exc).__name__,
                        duration_us=elapsed,
                    )
                except Exception as inner:  # noqa: BLE001
                    _log.warning(
                        "trace_addon_hook error emit failed: %s: %s",
                        type(inner).__name__, inner,
                    )
                raise
            finally:
                # Clean up the private timer key so it doesn't leak into other
                # hooks or into serialisation surfaces that inspect
                # flow.metadata. The delete is the only mutation this wrapper
                # makes to flow.metadata visible to production code.
                flow.metadata.pop(key, None)
        return wrapper
    return decorator


# =============================================================================
# Module-level convenience for addons that aren't SecurityAddon subclasses
# =============================================================================
# service-gateway needs to record trace without inheriting base.py plumbing.

def trace_evaluated(
    flow: http.HTTPFlow,
    *,
    addon: str,
    hook: str = "request",
    outcome: str,
    duration_us: int | None = None,
    **details: Any,
) -> None:
    """Standalone `state=evaluated` emitter for non-SecurityAddon participants."""
    if duration_us is None:
        duration_us = _elapsed_us_from(flow, addon, hook)
    record_step(
        flow,
        addon=addon,
        hook=hook,
        state=STATE_EVALUATED,
        outcome=outcome,
        duration_us=duration_us,
        details=details or None,
    )


def trace_bypassed(
    flow: http.HTTPFlow,
    *,
    addon: str,
    hook: str = "request",
    reason: str,
) -> None:
    """Standalone `state=bypassed` emitter for non-SecurityAddon participants."""
    record_step(
        flow,
        addon=addon,
        hook=hook,
        state=STATE_BYPASSED,
        reason=reason,
    )


# No mitmproxy addon here — this module is pure infrastructure, imported
# by base.py and agent_api.py. Explicit empty list keeps `-s trace.py`
# from doing anything surprising.
addons: list = []
