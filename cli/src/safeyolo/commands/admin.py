"""Administrative commands for SafeYolo."""

import httpx
import typer
from rich.console import Console
from rich.table import Table

from ..api import APIError, get_api
from ..config import (
    find_config_dir,
    get_admin_token,
    get_certs_dir,
    get_config_path,
    get_rules_path,
    load_config,
)
from ..docker import check_docker, get_container_status

console = Console()


def check() -> None:
    """Verify SafeYolo setup is working correctly.

    Checks configuration, Docker, container, API, and HTTPS inspection.

    Examples:

        safeyolo check
    """
    all_ok = True
    proxy_running = False

    console.print("\n[bold]SafeYolo Health Check[/bold]\n")

    # 1. Check config directory
    config_dir = find_config_dir()
    if config_dir:
        console.print(f"  [green]✓[/green]  Config directory: {config_dir}")
    else:
        console.print("  [red]✗[/red]  Config directory not found")
        console.print("        Run: [bold]safeyolo init[/bold]")
        all_ok = False

    # 2. Check config file
    if config_dir:
        config_path = get_config_path()
        if config_path.exists():
            console.print(f"  [green]✓[/green]  Config file: {config_path.name}")
        else:
            console.print("  [red]✗[/red]  Config file missing")
            all_ok = False

    # 3. Check rules file
    if config_dir:
        rules_path = get_rules_path()
        if rules_path.exists():
            console.print(f"  [green]✓[/green]  Rules file: {rules_path.name}")
        else:
            console.print("  [dim]–[/dim]  Rules file missing (using defaults)")

    # 4. Check admin token
    token = get_admin_token()
    if token:
        console.print("  [green]✓[/green]  Admin token configured")
    else:
        console.print("  [dim]–[/dim]  Admin token not set")

    # 5. Check Docker
    if check_docker():
        console.print("  [green]✓[/green]  Docker available")
    else:
        console.print("  [red]✗[/red]  Docker not available")
        all_ok = False

    # 6. Check container status
    status = get_container_status()
    if status:
        state = status.get("State", {})
        if state.get("Running"):
            console.print("  [green]✓[/green]  Container running")
            proxy_running = True
        else:
            console.print("  [yellow]![/yellow]  Container not running")
            console.print("        Run: [bold]safeyolo start[/bold]")
    else:
        console.print("  [dim]–[/dim]  Container not created yet")

    # 7. Check API connectivity
    if proxy_running:
        try:
            api = get_api()
            health = api.health()
            if health.get("status") == "healthy":
                console.print("  [green]✓[/green]  Admin API responding")
            else:
                console.print(f"  [yellow]![/yellow]  Admin API unhealthy: {health}")
        except APIError as e:
            console.print(f"  [red]✗[/red]  Admin API error: {e}")
            all_ok = False
        except Exception as e:
            console.print(f"  [red]✗[/red]  Admin API unreachable: {e}")
            all_ok = False

    # 8. Check CA certificate
    ca_cert_exists = False
    if config_dir:
        certs_dir = get_certs_dir()
        ca_cert = certs_dir / "mitmproxy-ca-cert.pem"
        if ca_cert.exists():
            console.print("  [green]✓[/green]  CA certificate exists")
            ca_cert_exists = True
        else:
            console.print("  [dim]–[/dim]  CA certificate (generated on first run)")

    # 9. Check proxy reachability
    if proxy_running:
        config = load_config()
        proxy_port = config.get("proxy", {}).get("port", 8080)
        proxy_url = f"http://localhost:{proxy_port}"

        try:
            # Simple HTTP request through proxy to verify it's working
            resp = httpx.get(
                "http://httpbin.org/get",
                proxy=proxy_url,
                timeout=10.0,
            )
            if resp.status_code == 200:
                console.print("  [green]✓[/green]  Proxy reachable (HTTP)")
            else:
                console.print(f"  [yellow]![/yellow]  Proxy returned {resp.status_code}")
        except Exception as e:
            console.print(f"  [red]✗[/red]  Proxy unreachable: {type(e).__name__}")
            all_ok = False

    # 10. Check HTTPS inspection
    if proxy_running and ca_cert_exists:
        config = load_config()
        proxy_port = config.get("proxy", {}).get("port", 8080)
        proxy_url = f"http://localhost:{proxy_port}"

        try:
            # HTTPS request through proxy - verify using safeyolo CA cert
            resp = httpx.get(
                "https://httpbin.org/get",
                proxy=proxy_url,
                timeout=10.0,
                verify=str(ca_cert),
            )
            if resp.status_code == 200:
                console.print("  [green]✓[/green]  HTTPS inspection working")
            else:
                console.print(f"  [yellow]![/yellow]  HTTPS returned {resp.status_code}")
        except httpx.ConnectError:
            console.print("  [red]✗[/red]  HTTPS inspection failed")
            console.print("        The proxy can intercept HTTPS but your system may")
            console.print("        not trust the CA certificate yet.")
            console.print("        Run: [bold]safeyolo cert install[/bold]")
            all_ok = False
        except Exception as e:
            console.print(f"  [red]✗[/red]  HTTPS test failed: {type(e).__name__}")
            all_ok = False

    # Summary
    console.print()
    if all_ok:
        console.print("[green]All checks passed![/green]")
        if proxy_running:
            console.print("\nSafeYolo is ready. Configure your agent:")
            config = load_config()
            proxy_port = config.get("proxy", {}).get("port", 8080)
            console.print(f"  export HTTP_PROXY=http://localhost:{proxy_port}")
            console.print(f"  export HTTPS_PROXY=http://localhost:{proxy_port}")
    else:
        console.print("[yellow]Some issues found. See above for details.[/yellow]")
        raise typer.Exit(1)


def mode(
    addon: str = typer.Argument(
        None,
        help="Addon name (credential-guard, rate-limiter, etc.)",
    ),
    new_mode: str = typer.Argument(
        None,
        help="New mode: 'warn' or 'block'",
    ),
) -> None:
    """View or change addon modes.

    Without arguments, shows current modes for all addons.
    With addon name, shows mode for that addon.
    With addon and mode, sets the new mode.

    Examples:

        safeyolo mode                           # Show all modes
        safeyolo mode credential-guard          # Show specific addon
        safeyolo mode credential-guard warn     # Set to warn mode
        safeyolo mode credential-guard block    # Set to block mode
    """
    try:
        api = get_api()
    except Exception as e:
        console.print(f"[red]Error:[/red] Cannot connect to API: {e}")
        console.print("Is SafeYolo running? Try: [bold]safeyolo start[/bold]")
        raise typer.Exit(1)

    # No arguments - show all modes
    if addon is None:
        try:
            result = api.get_modes()
            modes = result.get("modes", {})

            if not modes:
                console.print("[dim]No switchable addons found[/dim]")
                return

            table = Table(title="Addon Modes")
            table.add_column("Addon", style="bold")
            table.add_column("Mode")

            for name, mode_val in modes.items():
                style = "green" if mode_val == "block" else "yellow"
                table.add_row(name, f"[{style}]{mode_val}[/{style}]")

            console.print(table)

        except APIError as e:
            console.print(f"[red]API Error:[/red] {e}")
            raise typer.Exit(1)
        return

    # Just addon name - show that addon's mode
    if new_mode is None:
        try:
            result = api.get_modes()
            modes = result.get("modes", {})

            if addon in modes:
                mode_val = modes[addon]
                style = "green" if mode_val == "block" else "yellow"
                console.print(f"{addon}: [{style}]{mode_val}[/{style}]")
            else:
                console.print(f"[red]Unknown addon:[/red] {addon}")
                console.print(f"[dim]Available: {', '.join(modes.keys())}[/dim]")
                raise typer.Exit(1)

        except APIError as e:
            console.print(f"[red]API Error:[/red] {e}")
            raise typer.Exit(1)
        return

    # Both addon and mode - set the mode
    if new_mode not in ("warn", "block"):
        console.print(f"[red]Invalid mode:[/red] {new_mode}")
        console.print("Mode must be 'warn' or 'block'")
        raise typer.Exit(1)

    try:
        result = api.set_mode(addon, new_mode)
        status = result.get("status", "")

        if status == "updated":
            style = "green" if new_mode == "block" else "yellow"
            console.print(f"[green]Updated[/green] {addon} -> [{style}]{new_mode}[/{style}]")
        else:
            console.print(f"Result: {result}")

    except APIError as e:
        if e.status_code == 404:
            console.print(f"[red]Unknown addon:[/red] {addon}")
            # Try to get available addons
            try:
                modes_result = api.get_modes()
                available = list(modes_result.get("modes", {}).keys())
                if available:
                    console.print(f"[dim]Available: {', '.join(available)}[/dim]")
            except Exception:
                pass  # Best-effort hint, ok to fail silently
        else:
            console.print(f"[red]API Error:[/red] {e}")
        raise typer.Exit(1)


def policies(
    project: str = typer.Argument(
        None,
        help="Project ID to show policy for",
    ),
) -> None:
    """View credential approval policies.

    Without arguments, lists all policies.
    With project name, shows that project's policy details.

    Examples:

        safeyolo policies           # List all policies
        safeyolo policies default   # Show default policy
    """
    try:
        api = get_api()
    except Exception as e:
        console.print(f"[red]Error:[/red] Cannot connect to API: {e}")
        raise typer.Exit(1)

    if project is None:
        # List all policies
        try:
            result = api.list_policies()
            policy_list = result.get("policies", [])
            policy_dir = result.get("policy_dir", "")

            if not policy_list:
                console.print("[dim]No policies found[/dim]")
                console.print(f"[dim]Policy directory: {policy_dir}[/dim]")
                return

            console.print(f"[bold]Policies[/bold] ({policy_dir})\n")
            for name in policy_list:
                console.print(f"  - {name}")

        except APIError as e:
            console.print(f"[red]API Error:[/red] {e}")
            raise typer.Exit(1)
    else:
        # Show specific policy
        try:
            result = api.get_policy(project)
            policy = result.get("policy", {})

            if not policy:
                console.print(f"[dim]No policy found for '{project}'[/dim]")
                return

            approved = policy.get("approved", [])
            console.print(f"[bold]Policy: {project}[/bold]\n")
            console.print(f"Approved credentials: {len(approved)}\n")

            if approved:
                table = Table(show_header=True)
                table.add_column("HMAC", style="dim", max_width=20)
                table.add_column("Hosts")
                table.add_column("Paths", style="dim")
                table.add_column("Added", style="dim")

                for rule in approved:
                    hmac = rule.get("token_hmac", "")[:16] + "..."
                    hosts = ", ".join(rule.get("hosts", []))
                    paths = ", ".join(rule.get("paths", ["/**"]))
                    added = rule.get("added", "")[:10] if rule.get("added") else ""
                    table.add_row(hmac, hosts, paths, added)

                console.print(table)

        except APIError as e:
            console.print(f"[red]API Error:[/red] {e}")
            raise typer.Exit(1)


def test(
    url: str = typer.Argument(
        "https://api.anthropic.com/v1/messages",
        help="URL to test through the proxy",
    ),
    method: str = typer.Option(
        "GET",
        "--method", "-X",
        help="HTTP method to use",
    ),
    header: list[str] = typer.Option(
        [],
        "--header", "-H",
        help="Add header (can be repeated)",
    ),
    show_headers: bool = typer.Option(
        False,
        "--headers", "-i",
        help="Show response headers",
    ),
) -> None:
    """Test a request through the SafeYolo proxy.

    Makes an HTTP request through the proxy to verify connectivity and
    see how SafeYolo handles it. Useful for testing credential detection.

    Examples:

        safeyolo test                                    # Test default URL
        safeyolo test https://api.openai.com/v1/models  # Test OpenAI
        safeyolo test https://httpbin.org/get           # Test plain HTTP
        safeyolo test -H "Authorization: Bearer sk-test..." https://api.openai.com/v1/models
    """
    # Get proxy config
    config = load_config()
    proxy_port = config.get("proxy", {}).get("port", 8080)
    proxy_url = f"http://localhost:{proxy_port}"

    console.print("[bold]Testing request through proxy[/bold]\n")
    console.print(f"  Proxy: {proxy_url}")
    console.print(f"  URL: {url}")
    console.print(f"  Method: {method}")

    # Parse headers
    headers = {}
    for h in header:
        if ":" in h:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()

    if headers:
        console.print(f"  Headers: {len(headers)}")
    console.print()

    # Make request through proxy using safeyolo CA cert
    certs_dir = get_certs_dir()
    ca_cert = certs_dir / "mitmproxy-ca-cert.pem"
    if not ca_cert.exists():
        console.print("[red]CA certificate not found. Start SafeYolo first.[/red]")
        raise typer.Exit(1)

    try:
        with httpx.Client(proxy=proxy_url, timeout=30.0, verify=str(ca_cert)) as client:
            response = client.request(method, url, headers=headers)

        # Show result
        status_style = "green" if response.status_code < 400 else "red"
        console.print(f"[{status_style}]{response.status_code} {response.reason_phrase}[/{status_style}]")

        # Check for SafeYolo block
        blocked_by = response.headers.get("X-Blocked-By")
        if blocked_by:
            console.print(f"\n[yellow]Blocked by:[/yellow] {blocked_by}")

            # Try to parse JSON body for details
            try:
                body = response.json()
                if "error" in body:
                    console.print(f"[yellow]Error:[/yellow] {body.get('error')}")
                if "type" in body:
                    console.print(f"[yellow]Type:[/yellow] {body.get('type')}")
                if "credential_type" in body:
                    console.print(f"[yellow]Credential:[/yellow] {body.get('credential_type')}")
                if "reflection" in body:
                    console.print(f"\n[dim]{body.get('reflection')}[/dim]")
            except Exception:
                pass  # JSON parsing failed, skip body display

        # Show headers if requested
        if show_headers:
            console.print("\n[bold]Response Headers:[/bold]")
            for key, value in response.headers.items():
                console.print(f"  {key}: {value}")

        # Show body preview for small responses
        if not blocked_by and response.status_code < 400:
            content_type = response.headers.get("content-type", "")
            if "json" in content_type:
                try:
                    body = response.json()
                    preview = str(body)[:200]
                    if len(str(body)) > 200:
                        preview += "..."
                    console.print(f"\n[dim]{preview}[/dim]")
                except Exception:
                    pass  # JSON parsing failed, skip preview

    except httpx.ProxyError as e:
        console.print(f"[red]Proxy error:[/red] {e}")
        console.print("\nIs SafeYolo running? Try: [bold]safeyolo start[/bold]")
        raise typer.Exit(1)
    except httpx.ConnectError as e:
        console.print(f"[red]Connection error:[/red] {e}")
        console.print("\nIs SafeYolo running? Try: [bold]safeyolo start[/bold]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {type(e).__name__}: {e}")
        raise typer.Exit(1)
