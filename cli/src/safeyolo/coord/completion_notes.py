"""Optional structured candidate trailer for canonical coord completions.

The ordinary leading delivery state remains the wire-compatible contract.
Candidate notes are an optional, tightly delimited JSON suffix.  Trusted
provenance is never part of that JSON: it is attached here from the canonical
coord envelope returned by ``read_room``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal

TRAILER_START = "<<<SAFEYOLO_COMPLETION_NOTES_V1>>>"
TRAILER_END = "<<<END_SAFEYOLO_COMPLETION_NOTES_V1>>>"
_RESERVED_MARKER_PREFIX = "<<<SAFEYOLO_COMPLETION_NOTES_"

MAX_TRAILER_BYTES = 32 * 1024
MAX_CANDIDATES = 8
MAX_EVIDENCE = 8
MAX_SUMMARY_BYTES = 512
MAX_TEXT_BYTES = 2 * 1024
MAX_SNIPPET_BYTES = 4 * 1024
MAX_EVIDENCE_REF_BYTES = 512

_TRAILER_RE = re.compile(
    rf"\n\n{re.escape(TRAILER_START)}\n(?P<payload>[^\r\n]*)\n"
    rf"{re.escape(TRAILER_END)}\Z"
)
_DELIVERY_STATE_RE = re.compile(r"^(?P<state>DONE|READY|CHANGES_REQUIRED|BLOCKED|FAILED)(?:[ \t]|$)")
_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_MSG_ID_RE = re.compile(r"^msg-[0-9a-f]{32}$")


class DeliveryState(StrEnum):
    DONE = "DONE"
    READY = "READY"
    CHANGES_REQUIRED = "CHANGES_REQUIRED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class CandidateType(StrEnum):
    DISPATCH = "DISPATCH_CANDIDATE"
    FACTORY = "FACTORY_CANDIDATE"


class AttributionCategory(StrEnum):
    LENS_REVIEW_FINDING = "lens_review_finding"
    FORGE_IMPLEMENTATION_DISCOVERY = "forge_implementation_discovery"
    PREEXISTING_BUG_EXPOSED_BY_TESTING = "preexisting_bug_exposed_by_testing"
    INFRASTRUCTURE_ENVIRONMENT_PROBLEM = "infrastructure_environment_problem"
    FACTORY_PROCESS_OBSERVATION = "factory_process_observation"


class EvidenceKind(StrEnum):
    ISSUE = "issue"
    PR = "pr"
    COMMIT = "commit"
    HEAD = "head"
    TREE = "tree"
    TEST = "test"
    RUNTIME = "runtime"
    COORD = "coord"
    DOCUMENT = "document"


@dataclass(frozen=True)
class EvidenceRef:
    kind: EvidenceKind
    ref: str

    def to_wire(self) -> dict[str, str]:
        return {"kind": self.kind.value, "ref": self.ref}


@dataclass(frozen=True)
class CandidateDraft:
    candidate_type: CandidateType
    attribution: AttributionCategory
    summary: str
    kind: str | None = None
    interest: str | None = None
    why_interesting: str | None = None
    evidence: tuple[EvidenceRef, ...] = ()
    snippet: str | None = None
    outcome: str | None = None
    area: str | None = None
    problem: str | None = None
    impact: str | None = None
    suggestion: str | None = None
    confidence: str | None = None

    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": self.candidate_type.value,
            "attribution": self.attribution.value,
            "summary": self.summary,
        }
        for field in (
            "kind",
            "interest",
            "why_interesting",
            "snippet",
            "outcome",
            "area",
            "problem",
            "impact",
            "suggestion",
            "confidence",
        ):
            value = getattr(self, field)
            if value is not None:
                result[field] = value
        if self.evidence:
            result["evidence"] = [item.to_wire() for item in self.evidence]
        return result


@dataclass(frozen=True)
class EnvelopeProvenance:
    msg_id: str
    coord_sequence: int
    sent_at: int
    sender_kind: str
    sender_agent_id: str | None
    sender_agent_name: str | None
    origin_instance_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "msg_id": self.msg_id,
            "coord_sequence": self.coord_sequence,
            "sent_at": self.sent_at,
            "sender_kind": self.sender_kind,
            "sender_agent_id": self.sender_agent_id,
            "sender_agent_name": self.sender_agent_name,
            "origin_instance_id": self.origin_instance_id,
        }


@dataclass(frozen=True)
class ParsedCandidate:
    candidate_type: CandidateType
    attribution: AttributionCategory
    summary: str
    provenance: EnvelopeProvenance
    kind: str | None = None
    interest: str | None = None
    why_interesting: str | None = None
    evidence: tuple[EvidenceRef, ...] = ()
    snippet: str | None = None
    outcome: str | None = None
    area: str | None = None
    problem: str | None = None
    impact: str | None = None
    suggestion: str | None = None
    confidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = CandidateDraft(
            candidate_type=self.candidate_type,
            attribution=self.attribution,
            summary=self.summary,
            kind=self.kind,
            interest=self.interest,
            why_interesting=self.why_interesting,
            evidence=self.evidence,
            snippet=self.snippet,
            outcome=self.outcome,
            area=self.area,
            problem=self.problem,
            impact=self.impact,
            suggestion=self.suggestion,
            confidence=self.confidence,
        ).to_wire()
        result["provenance"] = self.provenance.to_dict()
        return result


@dataclass(frozen=True)
class CompletionParseResult:
    delivery_state: DeliveryState | None
    delivery_body: str
    trailer_status: Literal["absent", "valid", "invalid"]
    candidates: tuple[ParsedCandidate, ...]
    error: str | None = None


_CANDIDATE_KEYS = frozenset(
    {
        "type",
        "attribution",
        "summary",
        "kind",
        "interest",
        "why_interesting",
        "evidence",
        "snippet",
        "outcome",
        "area",
        "problem",
        "impact",
        "suggestion",
        "confidence",
    }
)
_RESERVED_PROVENANCE_KEYS = frozenset(
    {
        "provenance",
        "msg_id",
        "coord_sequence",
        "sequence",
        "sent_at",
        "sender_kind",
        "sender_agent_id",
        "sender_agent_name",
        "origin_instance_id",
        "discovered_by",
        "author",
    }
)
_OPTIONAL_TEXT_FIELDS = (
    "why_interesting",
    "outcome",
    "area",
    "problem",
    "impact",
    "suggestion",
)


class _TrailerValidationError(ValueError):
    pass


def _text(value: Any, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise _TrailerValidationError(f"{field} must be a string")
    if not value.strip():
        raise _TrailerValidationError(f"{field} must be non-empty")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise _TrailerValidationError(f"{field} must be valid UTF-8") from exc
    if len(encoded) > maximum:
        raise _TrailerValidationError(f"{field} exceeds {maximum} UTF-8 bytes")
    if any(ord(ch) < 0x20 and ch not in {"\n", "\t"} for ch in value):
        raise _TrailerValidationError(f"{field} contains disallowed controls")
    return value


def _token(value: Any, field: str) -> str:
    result = _text(value, field, maximum=64)
    if not _TOKEN_RE.fullmatch(result):
        raise _TrailerValidationError(f"{field} must be a lowercase token")
    return result


def _decode_json(payload: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _TrailerValidationError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise _TrailerValidationError(f"non-finite JSON number {value!r} is not allowed")

    try:
        return json.loads(
            payload,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise _TrailerValidationError("trailer payload is not valid JSON") from exc


def _validate_evidence(value: Any, index: int) -> tuple[EvidenceRef, ...]:
    if not isinstance(value, list):
        raise _TrailerValidationError(f"candidates[{index}].evidence must be a list")
    if len(value) > MAX_EVIDENCE:
        raise _TrailerValidationError(f"candidates[{index}].evidence exceeds {MAX_EVIDENCE} entries")
    result: list[EvidenceRef] = []
    for evidence_index, item in enumerate(value):
        field = f"candidates[{index}].evidence[{evidence_index}]"
        if not isinstance(item, dict) or set(item) != {"kind", "ref"}:
            raise _TrailerValidationError(f"{field} must contain exactly kind and ref")
        try:
            kind = EvidenceKind(item["kind"])
        except (TypeError, ValueError) as exc:
            raise _TrailerValidationError(f"{field}.kind is unknown") from exc
        ref = _text(item["ref"], f"{field}.ref", maximum=MAX_EVIDENCE_REF_BYTES)
        result.append(EvidenceRef(kind=kind, ref=ref))
    return tuple(result)


def _validate_candidate(
    value: Any,
    index: int,
    provenance: EnvelopeProvenance,
) -> ParsedCandidate:
    if not isinstance(value, dict):
        raise _TrailerValidationError(f"candidates[{index}] must be an object")
    keys = set(value)
    spoofed = (
        keys & _RESERVED_PROVENANCE_KEYS
    )  # DOC: docs/coord-completion-notes.md, cli/src/safeyolo/agent_context/skills/safeyolo/references/completion-notes.md
    if spoofed:
        raise _TrailerValidationError(f"candidates[{index}] contains reserved provenance: {', '.join(sorted(spoofed))}")
    unknown = keys - _CANDIDATE_KEYS
    if unknown:
        raise _TrailerValidationError(f"candidates[{index}] contains unknown fields: {', '.join(sorted(unknown))}")
    missing = {"type", "attribution", "summary"} - keys
    if missing:
        raise _TrailerValidationError(f"candidates[{index}] missing fields: {', '.join(sorted(missing))}")
    try:
        candidate_type = CandidateType(value["type"])
    except (TypeError, ValueError) as exc:
        raise _TrailerValidationError(f"candidates[{index}].type is unknown") from exc
    try:
        attribution = AttributionCategory(value["attribution"])
    except (TypeError, ValueError) as exc:
        raise _TrailerValidationError(f"candidates[{index}].attribution is unknown") from exc
    summary = _text(value["summary"], f"candidates[{index}].summary", maximum=MAX_SUMMARY_BYTES)
    optional: dict[str, str | None] = {}
    for field in _OPTIONAL_TEXT_FIELDS:
        optional[field] = (
            _text(value[field], f"candidates[{index}].{field}", maximum=MAX_TEXT_BYTES) if field in value else None
        )
    snippet = (
        _text(
            value["snippet"],
            f"candidates[{index}].snippet",
            maximum=MAX_SNIPPET_BYTES,
        )
        if "snippet" in value
        else None
    )
    kind = _token(value["kind"], f"candidates[{index}].kind") if "kind" in value else None
    interest = _token(value["interest"], f"candidates[{index}].interest") if "interest" in value else None
    confidence = _token(value["confidence"], f"candidates[{index}].confidence") if "confidence" in value else None
    return ParsedCandidate(
        candidate_type=candidate_type,
        attribution=attribution,
        summary=summary,
        provenance=provenance,
        kind=kind,
        interest=interest,
        why_interesting=optional["why_interesting"],
        evidence=(_validate_evidence(value["evidence"], index) if "evidence" in value else ()),
        snippet=snippet,
        outcome=optional["outcome"],
        area=optional["area"],
        problem=optional["problem"],
        impact=optional["impact"],
        suggestion=optional["suggestion"],
        confidence=confidence,
    )


def _provenance(envelope: Mapping[str, Any]) -> EnvelopeProvenance:
    msg_id = envelope.get("msg_id")
    sequence = envelope.get("sequence")
    sent_at = envelope.get("sent_at")
    sender_kind = envelope.get("sender_kind")
    sender_agent_id = envelope.get("sender_agent_id")
    sender_agent_name = envelope.get("sender_agent_name")
    origin_instance_id = envelope.get("origin_instance_id")
    if not isinstance(msg_id, str) or not _MSG_ID_RE.fullmatch(msg_id):
        raise ValueError("canonical envelope has invalid msg_id")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise ValueError("canonical envelope has invalid sequence")
    if isinstance(sent_at, bool) or not isinstance(sent_at, int) or sent_at < 0:
        raise ValueError("canonical envelope has invalid sent_at")
    if sender_kind not in {"agent", "operator"}:
        raise ValueError("canonical envelope has invalid sender_kind")
    if sender_kind == "agent":
        if not isinstance(sender_agent_id, str) or not sender_agent_id:
            raise ValueError("canonical agent envelope has invalid sender_agent_id")
        if sender_agent_name is not None and not isinstance(sender_agent_name, str):
            raise ValueError("canonical agent envelope has invalid sender_agent_name")
    elif sender_agent_id is not None or sender_agent_name is not None:
        raise ValueError("canonical operator envelope must not carry agent identity")
    if not isinstance(origin_instance_id, str) or not origin_instance_id.startswith("sy-"):
        raise ValueError("canonical envelope has invalid origin_instance_id")
    return EnvelopeProvenance(
        msg_id=msg_id,
        coord_sequence=sequence,
        sent_at=sent_at,
        sender_kind=sender_kind,
        sender_agent_id=sender_agent_id,
        sender_agent_name=sender_agent_name,
        origin_instance_id=origin_instance_id,
    )


def _delivery_state(body: str) -> DeliveryState | None:
    first_line = body.split("\n", 1)[0]
    match = _DELIVERY_STATE_RE.match(first_line)
    return DeliveryState(match.group("state")) if match is not None else None


def render_completion_trailer(candidates: Sequence[CandidateDraft]) -> str:
    """Return no bytes for zero notes; otherwise one canonical trailer."""

    if not candidates:
        return ""
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"completion trailer supports at most {MAX_CANDIDATES} candidates")
    # Round-trip through the same strict validator using synthetic canonical
    # provenance. This keeps authored helpers and ingestion on one schema.
    wire = {"candidates": [candidate.to_wire() for candidate in candidates]}
    payload = json.dumps(wire, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(payload.encode("utf-8")) > MAX_TRAILER_BYTES:
        raise ValueError(f"completion trailer exceeds {MAX_TRAILER_BYTES} UTF-8 bytes")
    synthetic = EnvelopeProvenance(
        msg_id="msg-" + "0" * 32,
        coord_sequence=1,
        sent_at=0,
        sender_kind="agent",
        sender_agent_id="validation",
        sender_agent_name=None,
        origin_instance_id="sy-validation",
    )
    for index, value in enumerate(wire["candidates"]):
        try:
            _validate_candidate(value, index, synthetic)
        except _TrailerValidationError as exc:
            raise ValueError(str(exc)) from exc
    return f"{TRAILER_START}\n{payload}\n{TRAILER_END}"


def append_completion_notes(  # DOC: docs/coord-completion-notes.md, cli/src/safeyolo/agent_context/skills/safeyolo/references/completion-notes.md
    body: str, candidates: Sequence[CandidateDraft]
) -> str:
    """Append notes without changing a zero-candidate completion body."""

    trailer = render_completion_trailer(candidates)
    return body if not trailer else f"{body}\n\n{trailer}"


def parse_completion_envelope(  # DOC: docs/coord-completion-notes.md, cli/src/safeyolo/agent_context/skills/safeyolo/references/completion-notes.md
    envelope: Mapping[str, Any],
) -> CompletionParseResult:
    """Parse candidate notes and attach only canonical envelope provenance.

    Malformed/unknown/reserved trailers produce no trusted candidates. The
    ordinary leading delivery state remains independently available.
    """

    provenance = _provenance(envelope)
    body = envelope.get("body")
    content_type = envelope.get("content_type")
    if not isinstance(body, str):
        raise ValueError("canonical envelope has invalid body")
    if content_type not in {"text/plain", "text/markdown"}:
        raise ValueError("canonical envelope has invalid content_type")
    state = _delivery_state(body)
    match = _TRAILER_RE.search(body)
    has_reserved_marker = _RESERVED_MARKER_PREFIX in body or TRAILER_END in body
    if match is None:
        return CompletionParseResult(
            delivery_state=state,
            delivery_body=body,
            trailer_status="invalid" if has_reserved_marker else "absent",
            candidates=(),
            error="malformed or unknown completion-notes trailer" if has_reserved_marker else None,
        )
    delivery_body = body[: match.start()]
    if _RESERVED_MARKER_PREFIX in delivery_body or TRAILER_END in delivery_body:
        return CompletionParseResult(
            delivery_state=state,
            delivery_body=body,
            trailer_status="invalid",
            candidates=(),
            error="multiple or embedded completion-notes markers",
        )
    if _delivery_state(delivery_body) is None:
        return CompletionParseResult(
            delivery_state=state,
            delivery_body=body,
            trailer_status="invalid",
            candidates=(),
            error="completion-notes trailer requires a terminal leading delivery state",
        )
    payload = match.group("payload")
    try:
        payload_size = len(payload.encode("utf-8"))
    except UnicodeError:
        payload_size = MAX_TRAILER_BYTES + 1
    if payload_size > MAX_TRAILER_BYTES:
        return CompletionParseResult(
            delivery_state=state,
            delivery_body=body,
            trailer_status="invalid",
            candidates=(),
            error=f"completion-notes trailer exceeds {MAX_TRAILER_BYTES} UTF-8 bytes",
        )
    try:
        document = _decode_json(payload)
        if not isinstance(document, dict) or set(document) != {"candidates"}:
            raise _TrailerValidationError("trailer root must contain exactly candidates")
        values = document["candidates"]
        if not isinstance(values, list):
            raise _TrailerValidationError("candidates must be a list")
        if not values:
            raise _TrailerValidationError("empty candidate trailer must be omitted")
        if len(values) > MAX_CANDIDATES:
            raise _TrailerValidationError(f"candidates exceeds {MAX_CANDIDATES} entries")
        candidates = tuple(_validate_candidate(value, index, provenance) for index, value in enumerate(values))
    except (UnicodeError, _TrailerValidationError) as exc:
        return CompletionParseResult(
            delivery_state=state,
            delivery_body=body,
            trailer_status="invalid",
            candidates=(),
            error=str(exc),
        )
    return CompletionParseResult(
        delivery_state=_delivery_state(delivery_body),
        delivery_body=delivery_body,
        trailer_status="valid",
        candidates=candidates,
    )
