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


@dataclass(frozen=True)
class Envelope:
    msg_id: str
    sent_at: int  # milliseconds since epoch
    sender_kind: SenderKind
    sender_agent_id: str | None  # None when sender_kind == "operator"
    origin_instance_id: str
    content_type: str
    body: str

    def to_dict(self) -> dict:
        return {
            "msg_id": self.msg_id,
            "sent_at": self.sent_at,
            "sender_kind": self.sender_kind,
            "sender_agent_id": self.sender_agent_id,
            "origin_instance_id": self.origin_instance_id,
            "content_type": self.content_type,
            "body": self.body,
        }


def validate_content_type(declared: str) -> str:
    if declared not in ALLOWED_CONTENT_TYPES:
        raise ValueError(
            f"content_type {declared!r} not in allowed set {sorted(ALLOWED_CONTENT_TYPES)}"
        )
    return declared
