"""Pinned SafeYolo traffic scope layered over mitmproxy's user filter."""

from __future__ import annotations

import re
import time
from collections.abc import Sequence

from mitmproxy import command, command_lexer, ctx, exceptions, flowfilter, types
from mitmproxy.tools.console import signals as console_signals


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
        self._test_choices: dict[str, dict[str, str | None]] = {}

    def running(self) -> None:
        self.user_filter = ctx.options.view_filter or ""
        self._apply()

    def configure(self, updates) -> None:
        if "view_filter" not in updates or self._applying:
            return
        incoming = ctx.options.view_filter or ""
        if incoming == self._effective_filter:
            return
        incoming = self._user_filter_from_effective(incoming)
        previous = self.user_filter
        self.user_filter = incoming
        try:
            self._apply()
        except exceptions.OptionsError:
            # An invalid edit belongs to the option transaction, not to our
            # durable scope state. Keep the last valid user filter so agent
            # shortcuts can replace the rejected option and recover.
            self.user_filter = previous
            raise

    def _user_filter_from_effective(self, value: str) -> str:
        """Remove our generated scope wrapper from an externally edited filter."""
        scope = " & ".join(self._scope_parts())
        prefix = f"{scope} & ("
        while scope and value.startswith(prefix) and value.endswith(")"):
            value = value[len(prefix) : -1]
        return "" if value == scope else value

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

    @command.command("safeyolo.traffic.filter.edit")
    def edit_user_filter(self) -> None:
        """Edit only the viewer filter, leaving pinned evidence scope intact."""
        command_text = "safeyolo.traffic.filter.set " + command_lexer.quote(
            self.user_filter
        )
        console_signals.status_prompt_command.send(
            partial=command_text,
            cursor=len(command_text) - 1,
        )

    @command.command("safeyolo.traffic.filter.set")
    def set_user_filter(self, value: str) -> None:
        """Set the viewer filter beneath the pinned SafeYolo scope."""
        previous = self.user_filter
        self.user_filter = value
        try:
            self._apply()
        except exceptions.OptionsError:
            self.user_filter = previous
            raise

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

    def _all_flows(self) -> list:
        view = getattr(getattr(ctx, "master", None), "view", None)
        return list(view.resolve("@all")) if view is not None else []

    def observed_agents(self) -> list[str]:
        """Return running and observed agents without depending on visible flows."""
        agents: set[str] = set()
        master = getattr(ctx, "master", None)
        discovery = master.addons.get("service-discovery") if master is not None else None
        if discovery is not None:
            agents.update(discovery.get_agents().get("agents", {}))
        for flow in self._all_flows():
            value = getattr(flow, "metadata", {}).get("agent")
            if value:
                agents.add(str(value))
        return sorted(agents)

    @command.command("safeyolo.traffic.agent.options")
    def agent_options(self) -> Sequence[str]:
        """List running or observed agents for the native chooser."""
        return self.observed_agents()

    @command.command("safeyolo.traffic.agent.set")
    @command.argument("agent", type=types.Choice("safeyolo.traffic.agent.options"))
    def select_agent(self, agent: str) -> None:
        """Pin traffic to an agent and clear the prior test context."""
        self.set_scope(agent=agent)

    @command.command("safeyolo.traffic.agent.next")
    def next_agent(self) -> None:
        """Cycle to the next running or observed agent."""
        self._cycle_agent(1)

    @command.command("safeyolo.traffic.agent.prev")
    def previous_agent(self) -> None:
        """Cycle to the previous running or observed agent."""
        self._cycle_agent(-1)

    def _cycle_agent(self, offset: int) -> None:
        agents = self.observed_agents()
        if not agents:
            return
        try:
            index = agents.index(self.agent) + offset
        except ValueError:
            index = 0 if offset > 0 else -1
        self.select_agent(agents[index % len(agents)])

    @command.command("safeyolo.traffic.agent.all")
    def all_agents(self) -> None:
        """Show attributed traffic from all agents."""
        self.set_scope()

    @command.command("safeyolo.traffic.agent.unattributed")
    def unattributed_only(self) -> None:
        """Show traffic with no agent attribution."""
        self.set_scope(unattributed=True)

    @staticmethod
    def _flow_timestamp(flow) -> float:
        values = (
            getattr(getattr(flow, "response", None), "timestamp_end", None),
            getattr(getattr(flow, "request", None), "timestamp_start", None),
            getattr(flow, "timestamp_created", None),
        )
        return max((float(value) for value in values if value is not None), default=0.0)

    @staticmethod
    def _age_label(age: float) -> str:
        if age < 60:
            return f"{int(age)}s ago"
        if age < 3600:
            return f"{int(age // 60)}m ago"
        if age < 86400:
            return f"{int(age // 3600)}h ago"
        return f"{int(age // 86400)}d ago"

    @command.command("safeyolo.traffic.test.options")
    def test_options(self) -> Sequence[str]:
        """List observed test contexts with count and recency."""
        grouped: dict[tuple[str, str | None, str | None, str | None], tuple[int, float]] = {}
        for flow in self._all_flows():
            metadata = getattr(flow, "metadata", {})
            if self.agent is not None and metadata.get("agent") != self.agent:
                continue
            if self.unattributed and metadata.get("agent") is not None:
                continue
            test_id = metadata.get("test_id")
            if test_id is None:
                continue
            key = (
                str(test_id),
                str(metadata["test_intent"]) if metadata.get("test_intent") is not None else None,
                str(metadata["test_role"]) if metadata.get("test_role") is not None else None,
                str(metadata["test_expect"]) if metadata.get("test_expect") is not None else None,
            )
            count, latest = grouped.get(key, (0, 0.0))
            grouped[key] = (count + 1, max(latest, self._flow_timestamp(flow)))

        self._test_choices = {}
        now = time.time()
        ordered = sorted(grouped.items(), key=lambda item: (-item[1][1], item[0]))
        for (test_id, intent, role, expect), (count, latest) in ordered:
            detail = " · ".join(value for value in (intent, role, expect) if value)
            label = f"{test_id}{' · ' + detail if detail else ''} · {count} flow{'s' if count != 1 else ''} · {self._age_label(max(0, now - latest))}"
            self._test_choices[label] = {
                "test_id": test_id,
                "intent": intent,
                "role": role,
                "expect": expect,
            }
        return list(self._test_choices)

    @command.command("safeyolo.traffic.test.set")
    @command.argument("choice", type=types.Choice("safeyolo.traffic.test.options"))
    def select_test(self, choice: str) -> None:
        """Pin an observed test context while retaining the agent scope."""
        selected = self._test_choices.get(choice)
        if selected is None:
            self.test_options()
            selected = self._test_choices.get(choice)
        if selected is None:
            raise exceptions.CommandError(f"unknown test context: {choice}")
        self.set_scope(
            agent=self.agent,
            unattributed=self.unattributed,
            **selected,
        )

    @command.command("safeyolo.traffic.test.clear")
    def clear_test(self) -> None:
        """Clear test dimensions while retaining the agent scope."""
        self.set_scope(agent=self.agent, unattributed=self.unattributed)

    @command.command("safeyolo.traffic.scope.clear")
    def clear_scope(self) -> None:
        """Clear every SafeYolo scope while retaining the user's filter."""
        self.set_scope()


addons = [TrafficScope()]
