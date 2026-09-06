"""Platform-neutral view models for Command Centre."""

from __future__ import annotations

from dataclasses import dataclass

from safeyolo.core.audit_stream import approval_dedup_key


@dataclass(frozen=True)
class ApprovalItem:
    """One unresolved SafeYolo approval request."""

    event: dict

    @property
    def key(self) -> str:
        return approval_dedup_key(self.event)

    @property
    def approval_type(self) -> str:
        return str(self.event.get("approval", {}).get("approval_type", "unknown"))

    @property
    def agent(self) -> str:
        return str(self.event.get("agent") or "Unknown agent")

    @property
    def target(self) -> str:
        approval = self.event.get("approval", {})
        return str(approval.get("target") or self.event.get("host") or "Unknown target")

    @property
    def title(self) -> str:
        return f"{self.agent}: {self.approval_type} → {self.target}"

    @property
    def summary(self) -> str:
        return str(self.event.get("summary") or "Approval requested")

    @property
    def detail_rows(self) -> tuple[tuple[str, str], ...]:
        rows = [
            ("Agent", self.agent),
            ("Action", self.approval_type.replace("_", " ").title()),
            ("Target", self.target),
        ]
        details = self.event.get("details", {})
        for key in ("service", "method", "path", "reason"):
            if value := details.get(key):
                rows.append((key.title(), str(value)))
        return tuple(rows)


def approval_items(events: list[dict]) -> list[ApprovalItem]:
    """Convert pending event dictionaries to stable oldest-first view models."""
    return [ApprovalItem(event) for event in events]
