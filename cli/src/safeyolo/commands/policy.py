"""Policy inspection and management commands."""

from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.syntax import Syntax

from .policy_egress import egress_app
from .policy_host import host_app
from .policy_list import list_app

console = Console()

policy_app = typer.Typer(
    name="policy",
    help="Inspect and manage policy configuration.",
    no_args_is_help=True,
)

# Register subcommand groups
policy_app.add_typer(host_app, name="host")
policy_app.add_typer(egress_app, name="egress")
policy_app.add_typer(list_app, name="list")


def _find_policy_path(config_dir: Path) -> Path | None:
    """Find policy file: prefer .toml, fall back to .yaml."""
    toml_path = config_dir / "policy.toml"
    if toml_path.exists():
        return toml_path
    yaml_path = config_dir / "policy.yaml"
    if yaml_path.exists():
        return yaml_path
    return None


def _load_policy_file(config_dir: Path) -> tuple[dict, Path]:
    """Load policy file from config dir. Returns (dict, path).

    Checks for policy.toml first, falls back to policy.yaml.
    """
    policy_path = _find_policy_path(config_dir)
    if not policy_path:
        console.print(f"[red]Error:[/red] Policy file not found in {config_dir}")
        console.print("Run [bold]safeyolo init[/bold] to create a policy.")
        raise typer.Exit(1)

    if policy_path.suffix == ".toml":
        import tomlkit

        raw = tomlkit.parse(policy_path.read_text())
        # Normalize TOML field names to internal format for merge/compile
        addons_dir = Path(__file__).parent.parent.parent.parent.parent / "addons"
        import sys

        prev_normalizer = sys.modules.pop("toml_normalize", None)
        sys.path.insert(0, str(addons_dir))
        try:
            from toml_normalize import normalize

            plain = raw.unwrap()
            internal = normalize(plain)
        finally:
            sys.path.pop(0)
            if prev_normalizer is not None:
                sys.modules["toml_normalize"] = prev_normalizer
            else:
                sys.modules.pop("toml_normalize", None)
        return internal, policy_path
    else:
        with open(policy_path) as f:
            raw = yaml.safe_load(f) or {}
        return raw, policy_path


def _merge_siblings(raw: dict, policy_path: Path) -> dict:
    """Merge sibling addons.yaml into the policy dict.

    Replicates PolicyLoader._merge_addons():
    - addons.yaml keys are defaults (policy.toml overrides)
    - addons key gets deep-merged (addons.yaml defaults, policy.toml overrides)
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

    return raw


def _fetch_compiled_policy(raw: dict, policy_path: Path) -> dict:
    """Fetch the compiled policy from the running proxy's PDP.

    Tries the admin API first (live policy = single source of truth).
    Falls back to local compilation if proxy isn't running.
    """
    from ..api import AdminAPI, APIError

    try:
        api = AdminAPI()
        data = api._request("GET", "/admin/policy/baseline")
        return data.get("baseline", data)
    except APIError:
        # Proxy not running — fall back to local compilation
        return _compile_locally(raw, policy_path)


def _compile_locally(raw: dict, policy_path: Path) -> dict:
    """Compile policy locally (fallback when proxy isn't running)."""
    import sys
    import types

    addons_dir = Path(__file__).parent.parent.parent.parent.parent / "addons"

    stub = types.ModuleType("utils")
    stub.sanitize_for_log = lambda s: s  # type: ignore[attr-defined]
    prev_utils = sys.modules.get("utils")
    prev_compiler = sys.modules.pop("policy_compiler", None)
    prev_service_loader = sys.modules.pop("service_loader", None)
    sys.modules["utils"] = stub
    sys.path.insert(0, str(addons_dir))
    try:
        from policy_compiler import compile_policy

        return compile_policy(raw)
    finally:
        sys.path.pop(0)
        if prev_utils is not None:
            sys.modules["utils"] = prev_utils
        else:
            sys.modules.pop("utils", None)
        if prev_compiler is not None:
            sys.modules["policy_compiler"] = prev_compiler
        if prev_service_loader is not None:
            sys.modules["service_loader"] = prev_service_loader
        else:
            sys.modules.pop("service_loader", None)


@policy_app.command()
def show(
    compiled: bool = typer.Option(False, "--compiled", help="Show compiled IAM format"),
    section: str | None = typer.Option(
        None, "--section", "-s", help="Show only this section (e.g. hosts, agents, credentials)"
    ),
) -> None:
    """Show the merged policy (policy + addons.yaml).

    By default shows the merged host-centric format that operators write.
    Use --compiled to see the IAM format the PDP evaluates.

    Examples:

        safeyolo policy show
        safeyolo policy show --compiled
        safeyolo policy show --section hosts
        safeyolo policy show --compiled --section permissions
    """
    from ..config import get_config_dir

    config_dir = get_config_dir()
    raw, policy_path = _load_policy_file(config_dir)
    result = _merge_siblings(raw, policy_path)

    if compiled:
        result = _fetch_compiled_policy(result, policy_path)
        console.print("[dim]# Compiled IAM format (as evaluated by PDP)[/dim]")
    else:
        sources = f"{policy_path.name} + addons.yaml"
        console.print(f"[dim]# Merged from: {sources}[/dim]")

    if section:
        if section not in result:
            available = ", ".join(sorted(result.keys()))
            console.print(f"[red]Error:[/red] Section '{escape(section)}' not found")
            console.print(f"Available: {available}")
            raise typer.Exit(1)
        result = {section: result[section]}

    # Use TOML syntax highlighting for TOML files
    syntax_lang = "toml" if policy_path.suffix == ".toml" else "yaml"
    yaml_text = yaml.dump(result, default_flow_style=False, sort_keys=False)
    console.print(Syntax(yaml_text, syntax_lang))

    # Show resolved agent authorizations (non-compiled view, full or agents section)
    if not compiled and (not section or section == "agents"):
        _show_agent_authorizations(result)


@policy_app.command()
def migrate(
    dry_run: bool = typer.Option(False, "--dry-run", help="Print to stdout instead of writing"),
    keep: bool = typer.Option(False, "--keep", help="Keep policy.yaml (don't rename to .bak)"),
) -> None:
    """Migrate policy.yaml to policy.toml.

    Converts the YAML policy to TOML format with idiomatic field names.
    Comments are migrated on a best-effort basis.

    Examples:

        safeyolo policy migrate --dry-run
        safeyolo policy migrate
        safeyolo policy migrate --keep
    """
    import sys

    from ..config import get_config_dir

    config_dir = get_config_dir()
    yaml_path = config_dir / "policy.yaml"
    toml_path = config_dir / "policy.toml"

    if not yaml_path.exists():
        console.print(f"[red]Error:[/red] {yaml_path} not found")
        raise typer.Exit(1)

    if toml_path.exists() and not dry_run:
        console.print(f"[red]Error:[/red] {toml_path} already exists")
        console.print("Remove it first or use --dry-run to preview.")
        raise typer.Exit(1)

    # Load YAML
    with open(yaml_path) as f:
        raw = yaml.safe_load(f) or {}

    # Convert to TOML field names
    addons_dir = Path(__file__).parent.parent.parent.parent.parent / "addons"
    prev_normalizer = sys.modules.pop("toml_normalize", None)
    sys.path.insert(0, str(addons_dir))
    try:
        from toml_normalize import denormalize

        toml_data = denormalize(raw)
    finally:
        sys.path.pop(0)
        if prev_normalizer is not None:
            sys.modules["toml_normalize"] = prev_normalizer
        else:
            sys.modules.pop("toml_normalize", None)

    # Build TOML document with proper structure
    import tomlkit

    doc = _build_toml_document(toml_data)
    content = tomlkit.dumps(doc)

    if dry_run:
        console.print(Syntax(content, "toml"))
        return

    toml_path.write_text(content)
    console.print(f"  [green]Created[/green] {toml_path}")

    if not keep:
        bak_path = yaml_path.with_suffix(".yaml.bak")
        yaml_path.rename(bak_path)
        console.print(f"  [dim]Renamed[/dim] {yaml_path} → {bak_path}")

    console.print("[green]Migration complete.[/green]")


def _build_toml_document(data: dict):
    """Build a well-structured TOMLDocument from denormalized data."""
    import tomlkit

    doc = tomlkit.document()

    # Top-level scalars and arrays (must come before any [table] headers in TOML)
    if "version" in data:
        doc.add("version", data["version"])
    if "description" in data:
        doc.add("description", data["description"])
    if "budget" in data:
        doc.add("budget", data["budget"])

    # Top-level arrays (before table sections)
    for key in ("required", "scan_patterns"):
        if key in data:
            doc.add(tomlkit.nl())
            doc.add(key, data[key])

    # [hosts] section with inline tables
    if "hosts" in data:
        doc.add(tomlkit.nl())
        hosts_table = tomlkit.table()
        for host, config in data["hosts"].items():
            if isinstance(config, dict):
                it = tomlkit.inline_table()
                for k, v in config.items():
                    it.append(k, v)
                hosts_table.add(host, it)
            else:
                hosts_table.add(host, config)
        doc.add("hosts", hosts_table)

    # [credential.X] sub-tables
    if "credential" in data:
        doc.add(tomlkit.nl())
        for cred_name, cred_config in data["credential"].items():
            key = f"credential.{cred_name}"
            tbl = tomlkit.table()
            if isinstance(cred_config, dict):
                for k, v in cred_config.items():
                    tbl.add(k, v)
            doc.add(key, tbl)

    # [[risk]] array of tables
    if "risk" in data:
        doc.add(tomlkit.nl())
        aot = tomlkit.aot()
        for rule in data["risk"]:
            tbl = tomlkit.table()
            if isinstance(rule, dict):
                for k, v in rule.items():
                    tbl.add(k, v)
            aot.append(tbl)
        doc.add("risk", aot)

    # Remaining keys as-is
    for key in ("addons", "clients", "gateway", "services", "agents"):
        if key in data:
            doc.add(tomlkit.nl())
            doc.add(key, data[key])

    return doc


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
