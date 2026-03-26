"""Policy inspection commands — load, merge, and display the merged policy."""

from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.syntax import Syntax

console = Console()

policy_app = typer.Typer(
    name="policy",
    help="Inspect merged policy configuration.",
    no_args_is_help=True,
)


def _load_policy_yaml(config_dir: Path) -> tuple[dict, Path]:
    """Load policy.yaml from config dir. Returns (dict, path)."""
    policy_path = config_dir / "policy.yaml"
    if not policy_path.exists():
        console.print(f"[red]Error:[/red] {policy_path} not found")
        console.print("Run [bold]safeyolo init[/bold] to create a policy.")
        raise typer.Exit(1)

    with open(policy_path) as f:
        raw = yaml.safe_load(f) or {}
    return raw, policy_path


def _merge_siblings(raw: dict, policy_path: Path) -> dict:
    """Merge sibling addons.yaml and agents.yaml into the policy dict.

    Replicates PolicyLoader._merge_addons() and _merge_agents():
    - addons.yaml keys are defaults (policy.yaml overrides)
    - addons key gets deep-merged (addons.yaml defaults, policy.yaml overrides)
    - agents.yaml provides the 'agents' key if not already present
    """
    parent = policy_path.parent

    # Merge addons.yaml
    addons_path = parent / "addons.yaml"
    if addons_path.exists():
        with open(addons_path) as f:
            addons_raw = yaml.safe_load(f) or {}
        for key, value in addons_raw.items():
            if key not in raw:
                raw[key] = value
            elif key == "addons" and isinstance(raw[key], dict) and isinstance(value, dict):
                merged = dict(value)
                merged.update(raw[key])
                raw[key] = merged

    # Merge agents.yaml (runtime state supplements policy.yaml agent config)
    agents_path = parent / "agents.yaml"
    if agents_path.exists():
        with open(agents_path) as f:
            agents_raw = yaml.safe_load(f) or {}
        if "agents" not in raw:
            raw["agents"] = agents_raw
        else:
            for agent_name, agent_data in agents_raw.items():
                if not isinstance(agent_data, dict):
                    continue
                if agent_name not in raw["agents"]:
                    raw["agents"][agent_name] = agent_data
                elif isinstance(raw["agents"][agent_name], dict):
                    merged = dict(agent_data)
                    merged.update(raw["agents"][agent_name])
                    raw["agents"][agent_name] = merged

    return raw


def _fetch_compiled_policy() -> dict:
    """Fetch the compiled policy from the running proxy's PDP.

    Uses the admin API to get the live policy — this is the single source
    of truth, not a local recompilation.
    """
    from ..api import AdminAPI, APIError

    try:
        api = AdminAPI()
        data = api._request("GET", "/admin/policy/baseline")
        return data.get("baseline", data)
    except APIError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print("Is SafeYolo running? Try [bold]safeyolo status[/bold]")
        raise typer.Exit(1)


@policy_app.command()
def show(
    compiled: bool = typer.Option(False, "--compiled", help="Show compiled IAM format"),
    section: str | None = typer.Option(
        None, "--section", "-s", help="Show only this section (e.g. hosts, agents, credentials)"
    ),
) -> None:
    """Show the merged policy (policy.yaml + addons.yaml + agents.yaml).

    By default shows the merged host-centric YAML that operators write.
    Use --compiled to see the IAM format the PDP evaluates.

    Examples:

        safeyolo policy show
        safeyolo policy show --compiled
        safeyolo policy show --section hosts
        safeyolo policy show --compiled --section permissions
    """
    from ..config import get_config_dir

    config_dir = get_config_dir()
    raw, policy_path = _load_policy_yaml(config_dir)
    result = _merge_siblings(raw, policy_path)

    if compiled:
        result = _fetch_compiled_policy()
        console.print("[dim]# Compiled IAM format (live from PDP)[/dim]")
    else:
        console.print("[dim]# Merged from: policy.yaml + addons.yaml + agents.yaml[/dim]")

    if section:
        if section not in result:
            available = ", ".join(sorted(result.keys()))
            console.print(f"[red]Error:[/red] Section '{escape(section)}' not found")
            console.print(f"Available: {available}")
            raise typer.Exit(1)
        result = {section: result[section]}

    yaml_text = yaml.dump(result, default_flow_style=False, sort_keys=False)
    console.print(Syntax(yaml_text, "yaml"))

    # Show resolved agent authorizations (non-compiled view, full or agents section)
    if not compiled and (not section or section == "agents"):
        _show_agent_authorizations(result)


def _show_agent_authorizations(result: dict) -> None:
    """Show resolved agent authorizations with route details.

    Loads service definitions and resolves capability routes + contract bindings
    to show the operator exactly what each agent can access.
    """
    agents = result.get("agents", {})
    if not agents or not isinstance(agents, dict):
        return

    # Load service definitions from builtin + user directories
    from ._service_discovery import _load_service_files

    service_defs = {svc["name"]: svc for svc in _load_service_files()}
    if not service_defs:
        return

    console.print()
    console.print("[bold]Agents:[/bold]")

    for agent_name, agent_data in agents.items():
        if not isinstance(agent_data, dict):
            continue
        services = agent_data.get("services", {})
        if not isinstance(services, dict):
            continue
        contract_bindings = agent_data.get("contract_bindings", [])

        for service_name, svc_config in services.items():
            if isinstance(svc_config, str):
                capability_name = svc_config
            elif isinstance(svc_config, dict):
                capability_name = svc_config.get("capability", svc_config.get("role", ""))
            else:
                continue

            console.print(f"  [cyan]{escape(agent_name)}[/cyan] → [green]{escape(service_name)}[/green]")

            svc_def = service_defs.get(service_name)
            if not svc_def:
                console.print(f"    {escape(capability_name)} [dim](service definition not found)[/dim]")
                continue

            capabilities = svc_def.get("capabilities", {})
            cap_def = capabilities.get(capability_name)
            if not cap_def:
                console.print(f"    {escape(capability_name)} [dim](capability not found)[/dim]")
                continue

            has_contract = isinstance(cap_def, dict) and "contract" in cap_def

            if not has_contract:
                # No contract — show raw routes
                console.print(f"    [bold]{escape(capability_name)}[/bold] [dim](no contract):[/dim]")
                routes = cap_def.get("routes", []) if isinstance(cap_def, dict) else []
                for route in routes:
                    methods = route.get("methods", ["*"])
                    path = route.get("path", "?")
                    method_str = ",".join(methods)
                    console.print(f"      {method_str:8s} {path:40s} [green]allow[/green]")
            else:
                # Has contract — find binding
                binding = _find_binding(contract_bindings, service_name, capability_name)
                if binding is None:
                    console.print(f"    [bold]{escape(capability_name)}[/bold] [dim](unbound — no permissions)[/dim]")
                else:
                    bv = binding.get("bound_values", {})
                    bv_str = ", ".join(f"{k}={v}" for k, v in bv.items())
                    console.print(f"    [bold]{escape(capability_name)}[/bold] [dim](bound: {escape(bv_str)}):[/dim]")
                    for op_name in binding.get("grantable_operations", []):
                        op = _find_op_in_contract(cap_def["contract"], op_name)
                        if op:
                            req = op.get("request", op)  # ops nest under request:
                            resolved = _resolve_op_path(req, bv)
                            method = req.get("method", "?").upper()
                            console.print(
                                f"      {escape(op_name):20s} {method:8s} {escape(resolved):30s} [green]allow[/green]"
                            )

    console.print()


def _find_binding(bindings: list, service: str, capability: str) -> dict | None:
    """Find a contract binding for a service/capability."""
    for b in bindings:
        if b.get("service") == service and b.get("capability") == capability:
            return b
    return None


def _find_op_in_contract(contract: dict, op_name: str) -> dict | None:
    """Find an operation by name in a contract definition."""
    for op in contract.get("operations", []):
        if op.get("name") == op_name:
            return op
    return None


def _resolve_op_path(op: dict, bound_values: dict) -> str:
    """Resolve path template parameters using bound values."""
    path = op.get("path", "?")
    for param_name, constraint in op.get("path_params", {}).items():
        placeholder = f"{{{param_name}}}"
        if placeholder in path and isinstance(constraint, dict):
            var_name = constraint.get("equals_var")
            if var_name and var_name in bound_values:
                path = path.replace(placeholder, str(bound_values[var_name]))
    return path
