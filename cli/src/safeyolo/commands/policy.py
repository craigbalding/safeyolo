"""Policy inspection commands — load, merge, and display the merged policy."""

import sys
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

    # Merge agents.yaml
    agents_path = parent / "agents.yaml"
    if agents_path.exists():
        with open(agents_path) as f:
            agents_raw = yaml.safe_load(f) or {}
        if "agents" not in raw:
            raw["agents"] = agents_raw

    return raw


def _compile(raw: dict) -> dict:
    """Import and call compile_policy from addons/policy_compiler.py.

    policy_compiler imports utils which imports mitmproxy (not available
    in the CLI environment). We stub utils with just sanitize_for_log
    before importing.
    """
    import types

    addons_dir = Path(__file__).parent.parent.parent.parent.parent / "addons"

    # Stub the utils module so policy_compiler can import without mitmproxy
    stub = types.ModuleType("utils")
    stub.sanitize_for_log = lambda s: s  # type: ignore[attr-defined]
    prev_utils = sys.modules.get("utils")
    prev_compiler = sys.modules.pop("policy_compiler", None)
    sys.modules["utils"] = stub
    sys.path.insert(0, str(addons_dir))
    try:
        from policy_compiler import compile_policy

        return compile_policy(raw)
    finally:
        sys.path.pop(0)
        # Restore previous state
        if prev_utils is not None:
            sys.modules["utils"] = prev_utils
        else:
            sys.modules.pop("utils", None)
        if prev_compiler is not None:
            sys.modules["policy_compiler"] = prev_compiler


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
        result = _compile(result)
        console.print("[dim]# Compiled IAM format (as evaluated by PDP)[/dim]")
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
