"""Policy host management commands."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Optional

import tomlkit
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from ..config import get_config_dir

console = Console()

host_app = typer.Typer(
    name="host",
    help="Manage host entries in policy.",
    no_args_is_help=True,
)

# ---------------------------------------------------------------------------
# TOML helpers (no addons/ imports — CLI-local)
# ---------------------------------------------------------------------------

DURATIONS = {
    "1h": timedelta(hours=1),
    "8h": timedelta(hours=8),
    "1d": timedelta(days=1),
    "7d": timedelta(days=7),
}


def _parse_expires(value: str) -> datetime:
    """Parse duration shorthand (1h/8h/1d/7d) or ISO datetime."""
    if value in DURATIONS:
        return datetime.now(UTC) + DURATIONS[value]
    return datetime.fromisoformat(value)


def _load_toml() -> tuple[tomlkit.TOMLDocument, Path]:
    """Load policy.toml, return (doc, path)."""
    path = get_config_dir() / "policy.toml"
    if not path.exists():
        console.print("[red]Error:[/red] policy.toml not found. Run [bold]safeyolo init[/bold].")
        raise typer.Exit(1)
    return tomlkit.parse(path.read_text()), path


def _save_toml(doc: tomlkit.TOMLDocument, path: Path) -> None:
    """Compatibility helper for read-only callers; commands mutate under lock."""
    from safeyolo.policy.toml_roundtrip import save_roundtrip

    save_roundtrip(path, doc)


def _locked_mutate(mutate_fn):
    """Apply one CLI read-modify-write operation under the shared lock."""
    path = get_config_dir() / "policy.toml"
    if not path.exists():
        console.print("[red]Error:[/red] policy.toml not found. Run [bold]safeyolo init[/bold].")
        raise typer.Exit(1)
    from safeyolo.policy.toml_roundtrip import locked_policy_mutate

    try:
        return locked_policy_mutate(path, mutate_fn)
    except (OSError, ValueError, tomlkit.exceptions.TOMLKitError) as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(1) from exc


def _validate_rate(doc, rate: int | None, *, require_global: bool = False) -> int | None:
    """Validate a CLI host rate against the latest policy-wide budget."""
    budget = doc.get("budget")
    if budget is not None and (
        not isinstance(budget, int) or isinstance(budget, bool) or budget < 1
    ):
        raise ValueError("global network budget must be a positive integer")
    if budget is not None:
        budget = int(budget)
    if require_global and budget is None:
        raise ValueError("no global budget is configured; pass --rate or configure budget")
    if rate is not None and (type(rate) is not int or rate < 1):
        raise ValueError("--rate must be a positive integer")
    if rate is not None and budget is not None and rate > budget:
        raise ValueError(
            f"--rate {rate} exceeds global budget {budget} requests/minute"
        )
    return budget


def _get_hosts_table(doc: tomlkit.TOMLDocument, agent: str | None = None):
    """Get or create the hosts table (proxy-wide or agent-scoped)."""
    if agent:
        agents = doc.get("agents")
        if agents is None:
            agents = tomlkit.table()
            doc.add("agents", agents)
        agent_section = agents.get(agent)
        if agent_section is None:
            agent_section = tomlkit.table()
            agents.add(agent, agent_section)
        hosts = agent_section.get("hosts")
        if hosts is None:
            hosts = tomlkit.table()
            agent_section.add("hosts", hosts)
        return hosts
    else:
        hosts = doc.get("hosts")
        if hosts is None:
            hosts = tomlkit.table()
            doc.add("hosts", hosts)
        return hosts


def _scope_label(agent: str | None) -> str:
    if agent:
        return f" [dim](agent: {escape(agent)})[/dim]"
    return ""


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@host_app.command("add")
def host_add(  # DOC: docs/CONFIGURATION.md
    host: str = typer.Argument(..., help="Host pattern (e.g., api.stripe.com)"),
    rate: Optional[int] = typer.Option(None, "--rate", "-r", help="Rate limit (requests/min)"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent name (agent-scoped entry)"),
    expires: Optional[str] = typer.Option(None, "--expires", "-e", help="Expiry duration (1h/8h/1d/7d) or ISO datetime"),
) -> None:
    """Add or update a host entry in policy.

    Examples:
        safeyolo policy host add api.stripe.com --rate 600
        safeyolo policy host add api.stripe.com --rate 600 --agent boris
        safeyolo policy host add temp-api.com --rate 100 --expires 1d
    """
    def mutate(doc):
        budget = _validate_rate(doc, rate, require_global=rate is None)
        hosts = _get_hosts_table(doc, agent)
        config = tomlkit.inline_table()
        config.append("egress", "allow")
        if rate is not None:
            config.append("rate", rate)
        if expires is not None:
            config.append("expires", _parse_expires(expires))

        if host in hosts:
            existing = hosts[host]
            if isinstance(existing, (dict, tomlkit.items.InlineTable, tomlkit.items.Table)):
                existing["egress"] = "allow"
                if rate is None:
                    existing.pop("rate", None)
                else:
                    existing["rate"] = rate
                if expires is not None:
                    existing["expires"] = _parse_expires(expires)
            else:
                hosts[host] = config
        else:
            hosts[host] = config
        return budget

    budget = _locked_mutate(mutate)
    if rate is None:
        rate_label = f"global budget ({budget:,} req/min)"
    elif budget is None:
        rate_label = f"{rate:,} req/min; global budget not configured"
    else:
        rate_label = f"{rate:,} req/min; global budget {budget:,} req/min"
    console.print(
        f"[green]Added host:[/green] {escape(host)}{_scope_label(agent)} "
        f"[dim](rate: {rate_label})[/dim]"
    )


@host_app.command("remove")
def host_remove(
    host: str = typer.Argument(..., help="Host pattern to remove"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent name (agent-scoped entry)"),
) -> None:
    """Remove a host entry from policy.

    Examples:
        safeyolo policy host remove api.stripe.com
        safeyolo policy host remove api.stripe.com --agent boris
    """
    def mutate(doc):
        hosts = _get_hosts_table(doc, agent)
        if host not in hosts:
            return False
        del hosts[host]
        return True

    if not _locked_mutate(mutate):
        console.print(f"[yellow]Not found:[/yellow] {escape(host)}{_scope_label(agent)}")
        raise typer.Exit(1)
    console.print(f"[green]Removed host:[/green] {escape(host)}{_scope_label(agent)}")


@host_app.command("deny")
def host_deny(
    host: str = typer.Argument(..., help="Host pattern to deny"),
    expires: Optional[str] = typer.Option("1d", "--expires", "-e", help="Expiry (1h/8h/1d/7d/ISO datetime, default: 1d)"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent name (agent-scoped entry)"),
) -> None:
    """Deny egress to a host.

    Writes an entry with egress = "deny". Defaults to 1d expiry to
    prevent the policy accumulating denied hosts over time.

    Examples:
        safeyolo policy host deny sketchy.io
        safeyolo policy host deny sketchy.io --expires 7d
        safeyolo policy host deny sketchy.io --expires 7d --agent boris
    """
    def mutate(doc):
        hosts = _get_hosts_table(doc, agent)
        existing = hosts.get(host)
        if isinstance(existing, dict):
            existing["egress"] = "deny"
            if expires is not None:
                existing["expires"] = _parse_expires(expires)
        else:
            config = tomlkit.inline_table()
            config.append("egress", "deny")
            if expires is not None:
                config.append("expires", _parse_expires(expires))
            hosts[host] = config

    _locked_mutate(mutate)

    dur = expires or "permanent"
    console.print(f"[red]Denied host:[/red] {escape(host)} [dim](expires {dur})[/dim]{_scope_label(agent)}")


@host_app.command("add-list")
def host_add_list(
    name: str = typer.Argument(..., help="List name (from [lists] section)"),
    rate: Optional[int] = typer.Option(None, "--rate", "-r", help="Rate limit (requests/min)"),
    egress: Optional[str] = typer.Option(None, "--egress", help="Egress posture: allow, deny, prompt"),
) -> None:
    """Apply a named list as a host entry.

    Writes "$name" = { config } to [hosts], referencing a list from [lists].

    Examples:
        safeyolo policy host add-list known_bad --egress deny
        safeyolo policy host add-list package_registries --rate 1200
    """
    if egress is not None and egress not in ("allow", "deny", "prompt"):
        console.print(f"[red]Error:[/red] Invalid egress '{escape(egress)}'. Use: allow, deny, prompt")
        raise typer.Exit(1)

    def mutate(doc):
        lists = doc.get("lists", {})
        if name not in lists:
            raise ValueError(
                f"List '${name}' not found in [lists]. Add it first with: "
                f"safeyolo policy list add {name} <path>"
            )
        _validate_rate(doc, rate, require_global=egress == "allow" and rate is None)
        hosts = doc.get("hosts")
        if hosts is None:
            hosts = tomlkit.table()
            doc.add("hosts", hosts)
        config = tomlkit.inline_table()
        if egress is not None:
            config.append("egress", egress)
        if rate is not None:
            config.append("rate", rate)
        hosts[f"${name}"] = config
        return dict(config)

    saved_config = _locked_mutate(mutate)
    console.print(
        f"[green]Added list reference:[/green] "
        f"${escape(name)} = {escape(str(saved_config))}"
    )


@host_app.command("list")
def host_list(
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent name (show agent-scoped entries)"),
) -> None:
    """List host entries in policy.

    Examples:
        safeyolo policy host list
        safeyolo policy host list --agent boris
    """
    doc, _path = _load_toml()

    if agent:
        agents = doc.get("agents", {})
        agent_section = agents.get(agent, {})
        hosts = agent_section.get("hosts", {}) if isinstance(agent_section, dict) else {}
        title = f"Hosts for agent: {agent}"
    else:
        hosts = doc.get("hosts", {})
        title = "Proxy-wide hosts"

    if not hosts:
        console.print(f"[dim]No host entries{_scope_label(agent)}[/dim]")
        return

    table = Table(title=title)
    table.add_column("Host", style="bold")
    table.add_column("Rate")
    table.add_column("Allow")
    table.add_column("Egress")
    table.add_column("Bypass")
    table.add_column("Expires")

    for host_key, config in hosts.items():
        if not isinstance(config, dict):
            table.add_row(host_key, "", "", "", "", "")
            continue
        rate = str(config.get("rate", config.get("rate_limit", "")))
        allow = ", ".join(config.get("allow", config.get("credentials", [])))
        egress = str(config.get("egress", ""))
        bypass = ", ".join(config.get("bypass", []))
        expires_val = str(config.get("expires", ""))
        table.add_row(host_key, rate, allow, egress, bypass, expires_val)

    console.print(table)


@host_app.command("bypass")
def host_bypass(
    host: str = typer.Argument(..., help="Host pattern"),
    addon: str = typer.Argument(..., help="Addon to bypass (e.g., circuit_breaker, pattern_scanner)"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent name (agent-scoped entry)"),
) -> None:
    """Add an addon bypass for a host.

    Examples:
        safeyolo policy host bypass api.stripe.com circuit_breaker
        safeyolo policy host bypass api.stripe.com pattern_scanner --agent boris
    """
    def mutate(doc):
        hosts = _get_hosts_table(doc, agent)
        if host in hosts:
            existing = hosts[host]
            if isinstance(existing, (dict, tomlkit.items.InlineTable, tomlkit.items.Table)):
                bypass_list = existing.get("bypass", [])
                if isinstance(bypass_list, list):
                    if addon not in bypass_list:
                        bypass_list.append(addon)
                        existing["bypass"] = bypass_list
                else:
                    existing["bypass"] = [addon]
            else:
                config = tomlkit.inline_table()
                config.append("bypass", [addon])
                hosts[host] = config
        else:
            config = tomlkit.inline_table()
            config.append("bypass", [addon])
            hosts[host] = config

    _locked_mutate(mutate)
    console.print(f"[green]Bypass added:[/green] {escape(host)} \u2192 {escape(addon)}{_scope_label(agent)}")
