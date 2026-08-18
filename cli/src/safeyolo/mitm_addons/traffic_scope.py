"""Pinned SafeYolo traffic scope layered over mitmproxy's user filter."""

from __future__ import annotations

import re

from mitmproxy import ctx, exceptions, flowfilter


def _metadata_filter(key: str, value: str) -> str:
    pattern = re.escape(f"{key}: {value}").replace('"', r"\"")
    return f'~meta "^{pattern}$"'


class TrafficScope:
    name = "traffic-scope"

    def __init__(self) -> None:
        self.agent: str | None = None
        self.unattributed = False
        self.test_id: str | None = None
        self.intent: str | None = None
        self.role: str | None = None
        self.expect: str | None = None
        self.user_filter = ""
        self._effective_filter = ""
        self._applying = False

    def running(self) -> None:
        self.user_filter = ctx.options.view_filter or ""
        self._apply()

    def configure(self, updates) -> None:
        if "view_filter" not in updates or self._applying:
            return
        incoming = ctx.options.view_filter or ""
        if incoming == self._effective_filter:
            return
        self.user_filter = incoming
        self._apply()

    def _scope_parts(self) -> list[str]:
        parts: list[str] = []
        if self.unattributed:
            parts.append("!(~meta ^agent:)")
        elif self.agent is not None:
            parts.append(_metadata_filter("agent", self.agent))
        for key, value in (
            ("test_id", self.test_id),
            ("test_intent", self.intent),
            ("test_role", self.role),
            ("test_expect", self.expect),
        ):
            if value is not None:
                parts.append(_metadata_filter(key, value))
        return parts

    def effective_filter(self) -> str:
        parts = self._scope_parts()
        if self.user_filter.strip():
            parts.append(f"({self.user_filter.strip()})")
        return " & ".join(parts)

    def _apply(self) -> None:
        effective = self.effective_filter()
        if effective:
            try:
                flowfilter.parse(effective)
            except ValueError as exc:
                raise exceptions.OptionsError(str(exc)) from exc
        self._effective_filter = effective
        if ctx.options.view_filter != effective:
            self._applying = True
            try:
                ctx.options.update(view_filter=effective)
            finally:
                self._applying = False

    def set_scope(
        self,
        *,
        agent: str | None = None,
        unattributed: bool = False,
        test_id: str | None = None,
        intent: str | None = None,
        role: str | None = None,
        expect: str | None = None,
    ) -> dict:
        if unattributed and agent is not None:
            raise ValueError("agent and unattributed are mutually exclusive")
        for name, value in (
            ("agent", agent),
            ("test_id", test_id),
            ("intent", intent),
            ("role", role),
            ("expect", expect),
        ):
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{name} must be a non-empty string or null")
        self.agent = agent
        self.unattributed = unattributed
        self.test_id = test_id
        self.intent = intent
        self.role = role
        self.expect = expect
        self._apply()
        return self.get_stats()

    def get_stats(self) -> dict:
        return {
            "agent": self.agent,
            "unattributed": self.unattributed,
            "test_id": self.test_id,
            "intent": self.intent,
            "role": self.role,
            "expect": self.expect,
            "user_filter": self.user_filter,
            "effective_filter": self.effective_filter(),
        }

    def facet_values(self) -> dict[str, list[dict[str, int | str]]]:
        """Return selector counts from the canonical retained flow store."""
        view = getattr(getattr(ctx, "master", None), "view", None)
        flows = list(view.resolve("@all")) if view is not None else []
        dimensions = (
            ("agent", None),
            ("test_id", "agent"),
            ("test_intent", "test_id"),
            ("test_role", "test_id"),
            ("test_expect", "test_id"),
        )
        result: dict[str, list[dict[str, int | str]]] = {}
        for key, _parent in dimensions:
            counts: dict[str, int] = {}
            for flow in flows:
                metadata = getattr(flow, "metadata", {})
                if self.agent is not None and key != "agent" and metadata.get("agent") != self.agent:
                    continue
                if self.test_id is not None and key not in {"agent", "test_id"}:
                    if metadata.get("test_id") != self.test_id:
                        continue
                value = metadata.get(key)
                if value is not None:
                    text = str(value)
                    counts[text] = counts.get(text, 0) + 1
            result[key] = [
                {"value": value, "count": count}
                for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            ]
        return result


addons = [TrafficScope()]
