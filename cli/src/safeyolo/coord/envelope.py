"""Message envelope for the coord plane.

Shape matches #371 final spec. All fields SafeYolo-generated except `body` and
`content_type` (agent-declared, SafeYolo-validated). Trust class is
receiver-derived and NOT on the wire.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SenderKind = Literal["agent", "operator"]

ALLOWED_CONTENT_TYPES = frozenset({"text/plain", "text/markdown"})

# Persisted NATS-only routing metadata. It is deliberately not a field on
# ``Envelope`` so ordinary room history retains the exact agent-visible shape.
INTERNAL_ATTENTION_HEADER = "SafeYolo-Coord-Attention"


@dataclass(frozen=True)
class Envelope:
    msg_id: str
    sent_at: int  # milliseconds since epoch
    sender_kind: SenderKind
    sender_agent_id: str | None  # None when sender_kind == "operator"
    # `sender_agent_name`: display metadata per #22, SafeYolo-generated.
    # Persisted at send time as a SNAPSHOT — if the agent is later
    # removed or renamed, this field still shows what it was called
    # WHEN THE MESSAGE WAS SENT. That's intentional: history should
    # answer "who produced this message" at the time it was produced.
    # `/api/coord/rooms/<name>/members` shows CURRENT names by contrast,
    # so a rename intentionally produces divergence between old messages
    # and the current roster.
    # NULL on an agent row means "agent no longer resolvable to a name"
    # (per bob's #23 backfill; legacy rows are filled on bootstrap).
    # NULL on an operator row is definitional (operators have no
    # registry name in v0; sender_kind='operator' disambiguates).
    sender_agent_name: str | None
    origin_instance_id: str
    content_type: str
    body: str

    def to_dict(self) -> dict:
        return {
            "msg_id": self.msg_id,
            "sent_at": self.sent_at,
            "sender_kind": self.sender_kind,
            "sender_agent_id": self.sender_agent_id,
            "sender_agent_name": self.sender_agent_name,
            "origin_instance_id": self.origin_instance_id,
            "content_type": self.content_type,
            "body": self.body,
        }


def validate_content_type(declared) -> str:
    # Type-check FIRST — an unhashable value (dict, list) blows up in the
    # `in frozenset(...)` check as TypeError, which would reach the addon's
    # generic 500 boundary. That was a caller-error being reported as an
    # internal error. Codex finding, post-patch.
    if not isinstance(declared, str):
        raise ValueError("content_type must be a string")
    if declared not in ALLOWED_CONTENT_TYPES:
        raise ValueError(
            f"content_type {declared!r} not in allowed set {sorted(ALLOWED_CONTENT_TYPES)}"
        )
    return declared
