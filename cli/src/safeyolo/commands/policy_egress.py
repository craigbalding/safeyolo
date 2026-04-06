"""Policy egress posture commands."""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape

from .policy_host import _load_toml, _save_toml

console = Console()

egress_app = typer.Typer(
    name="egress",
    help="Manage egress posture.",
    no_args_is_help=True,
)


@egress_app.command("set")
def egress_set(
    posture: str = typer.Argument(..., help="Egress posture: allow, prompt, or deny"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent name (set agent-level posture)"),
) -> None:
    """Set the default egress posture.

    Without --agent: sets the proxy-wide wildcard egress field.
    With --agent: sets the agent-level egress field.

    Examples:
        safeyolo policy egress set prompt
        safeyolo policy egress set deny --agent boris
    """
    if posture not in ("allow", "prompt", "deny"):
        console.print(f"[red]Error:[/red] Invalid posture '{escape(posture)}'. Use: allow, prompt, deny")
        raise typer.Exit(1)

    doc, path = _load_toml()

    if agent:
        # Agent-level egress
        import tomlkit

        agents = doc.get("agents")
        if agents is None:
            agents = tomlkit.table()
            doc.add("agents", agents)
        agent_section = agents.get(agent)
        if agent_section is None:
            agent_section = tomlkit.table()
            agents.add(agent, agent_section)
        agent_section["egress"] = posture
        label = f"Agent [bold]{escape(agent)}[/bold]"
    else:
        # Proxy-wide: update wildcard "*" entry, creating it if needed
        if "hosts" not in doc:
            doc.add("hosts", tomlkit.table())
        hosts = doc["hosts"]
        if "*" not in hosts:
            it = tomlkit.inline_table()
            it.append("egress", posture)
            hosts["*"] = it
        else:
            wildcard = hosts["*"]
            if isinstance(wildcard, dict):
                wildcard["egress"] = posture
            else:
                console.print("[red]Error:[/red] Wildcard '*' entry is not a table")
                raise typer.Exit(1)
        label = "Proxy-wide"

    _save_toml(doc, path)

    color = {"allow": "green", "prompt": "yellow", "deny": "red"}[posture]
    console.print(f"{label} egress posture: [{color}]{posture}[/{color}]")


@egress_app.command("show")
def egress_show(
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent name"),
) -> None:
    """Show the current egress posture.

    Examples:
        safeyolo policy egress show
        safeyolo policy egress show --agent boris
    """
    doc, _path = _load_toml()

    # Proxy-wide posture
    hosts = doc.get("hosts", {})
    wildcard = hosts.get("*", {})
    if "*" not in hosts:
        # No wildcard = network-guard blocks everything = effective deny
        proxy_egress = "deny"
    elif isinstance(wildcard, dict):
        proxy_egress = wildcard.get("egress", "allow")
    else:
        proxy_egress = "allow"

    if agent:
        agents = doc.get("agents", {})
        agent_section = agents.get(agent, {})
        agent_egress = agent_section.get("egress") if isinstance(agent_section, dict) else None

        if agent_egress:
            color = {"allow": "green", "prompt": "yellow", "deny": "red"}.get(agent_egress, "white")
            console.print(f"Agent [bold]{escape(agent)}[/bold] egress: [{color}]{agent_egress}[/{color}]")
        else:
            color = {"allow": "green", "prompt": "yellow", "deny": "red"}.get(proxy_egress, "white")
            console.print(
                f"Agent [bold]{escape(agent)}[/bold] egress: [dim]inherits proxy-wide[/dim] "
                f"([{color}]{proxy_egress}[/{color}])"
            )
    else:
        color = {"allow": "green", "prompt": "yellow", "deny": "red"}.get(proxy_egress, "white")
        console.print(f"Proxy-wide egress: [{color}]{proxy_egress}[/{color}]")
