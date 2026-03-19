"""Demo command - guided tour of SafeYolo security features."""

import secrets
import string
import time

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..config import load_config

console = Console()


def _generate_demo_key(prefix: str, min_suffix_len: int) -> str:
    """Generate a random demo credential that matches detection patterns."""
    charset = string.ascii_letters + string.digits + "_"
    suffix = "".join(secrets.choice(charset) for _ in range(min_suffix_len))
    return f"{prefix}{suffix}"


def _get_demo_anthropic_key() -> str:
    """Generate random Anthropic-pattern key (sk-ant-api + 90 chars)."""
    return _generate_demo_key("sk-ant-api03-demo_", 90)


def _get_demo_openai_key() -> str:
    """Generate random OpenAI-pattern key."""
    return _generate_demo_key("sk-proj-demo_", 50)


def _get_proxy_url() -> str:
    """Get proxy URL from config."""
    config = load_config()
    port = config.get("proxy", {}).get("port", 8080)
    return f"http://localhost:{port}"


def _make_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict, str]:
    """Make request through proxy, return (status, headers, body)."""
    proxy_url = _get_proxy_url()

    with httpx.Client(proxy=proxy_url, timeout=timeout) as client:
        resp = client.request(method, url, headers=headers or {})
        return resp.status_code, dict(resp.headers), resp.text[:500]


def _wait_for_enter(message: str = "Press Enter to continue...") -> None:
    """Wait for user to press Enter."""
    console.input(f"\n[dim]{message}[/dim]")


def _show_step(step: int, total: int, title: str, description: str) -> None:
    """Display a step header."""
    console.print()
    console.print(Panel(
        f"[bold]{title}[/bold]\n\n{description}",
        title=f"[cyan]Step {step}/{total}[/cyan]",
        border_style="cyan",
    ))


def _show_request(method: str, url: str, headers: dict[str, str] | None = None) -> None:
    """Display request details."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    table.add_row("Method", method)
    table.add_row("URL", url)
    if headers:
        for k, v in headers.items():
            # Truncate long values
            display_v = v[:40] + "..." if len(v) > 40 else v
            table.add_row(f"Header: {k}", display_v)

    console.print(table)


def _show_result(status: int, expected: str, upstream_ok: bool = False) -> None:
    """Display result with expected outcome.

    Args:
        status: HTTP status code
        expected: Expected outcome description
        upstream_ok: If True, 4xx errors from upstream APIs count as "allowed through"
    """
    if status < 400:
        style = "green"
        outcome = "ALLOWED"
    elif status == 428:
        style = "yellow"
        outcome = "REQUIRES APPROVAL"
    elif status == 429:
        style = "red"
        outcome = "RATE LIMITED"
    elif upstream_ok and status in (400, 401, 403):
        # Upstream API rejected (bad key, etc.) but SafeYolo allowed it through
        style = "green"
        outcome = "ALLOWED (upstream rejected)"
    else:
        style = "red"
        outcome = "BLOCKED"

    console.print(f"\n  Result: [{style}]{status} {outcome}[/{style}]")
    console.print(f"  Expected: [dim]{expected}[/dim]")


def demo(
    auto: bool = typer.Option(
        False,
        "--auto",
        help="Run without pauses (for CI/testing)",
    ),
    delay: float = typer.Option(
        1.0,
        "--delay",
        help="Delay between steps in auto mode (seconds)",
    ),
) -> None:
    """Guided tour of SafeYolo security features.

    Run this command while 'safeyolo watch' is running in another terminal
    to see how SafeYolo handles different security scenarios.

    The demo walks through:

    1. Plain requests (no credentials) - always allowed
    2. Pre-approved credentials - allowed by baseline policy
    3. Credential leakage attempts - blocked, requires approval
    4. Approval flow - approve in watch, request succeeds
    5. Rate limiting - too many requests get throttled

    Examples:

        # In terminal 1:
        safeyolo watch

        # In terminal 2:
        safeyolo demo
    """
    console.print(Panel(
        "[bold]SafeYolo Security Demo[/bold]\n\n"
        "This guided tour demonstrates SafeYolo's security features.\n\n"
        "[yellow]Recommended:[/yellow] Run [bold]safeyolo watch[/bold] in another terminal\n"
        "to see approval prompts and observe cause-and-effect.",
        border_style="blue",
    ))

    if not auto:
        _wait_for_enter("Press Enter to start the demo...")
    else:
        time.sleep(delay)

    total_steps = 6

    # Generate random demo credentials for this run
    demo_anthropic_key = _get_demo_anthropic_key()
    demo_anthropic_key_alt = _get_demo_anthropic_key()  # Different key for step 5

    # Step 1: Plain request
    _show_step(1, total_steps,
        "Plain Request (No Credentials)",
        "Requests without sensitive credentials pass through normally.\n"
        "SafeYolo only intervenes when it detects credential patterns."
    )
    _show_request("GET", "https://httpbin.org/get")

    if not auto:
        _wait_for_enter("Press Enter to send request...")

    status, _, _ = _make_request("GET", "https://httpbin.org/get")
    _show_result(status, "ALLOWED - no credentials detected")

    if not auto:
        _wait_for_enter()
    else:
        time.sleep(delay)

    # Step 2: Pre-approved credential
    _show_step(2, total_steps,
        "Pre-Approved Credential",
        "The baseline policy pre-approves certain credential+destination pairs.\n"
        "Anthropic keys to api.anthropic.com are allowed by default."
    )
    _show_request(
        "POST",
        "https://api.anthropic.com/v1/messages",
        {"Authorization": f"Bearer {demo_anthropic_key}"}
    )

    if not auto:
        _wait_for_enter("Press Enter to send request...")

    status, _, body = _make_request(
        "POST",
        "https://api.anthropic.com/v1/messages",
        {"Authorization": f"Bearer {demo_anthropic_key}",
         "Content-Type": "application/json"},
    )
    # Will get 400/401 from Anthropic (invalid key) but that means it passed through
    _show_result(status, "ALLOWED - baseline permits anthropic keys to api.anthropic.com", upstream_ok=True)

    if not auto:
        _wait_for_enter()
    else:
        time.sleep(delay)

    # Step 3: Credential leakage attempt
    _show_step(3, total_steps,
        "Credential Leakage Attempt",
        "When a credential is sent to an [bold]unexpected destination[/bold],\n"
        "SafeYolo blocks the request and requires operator approval.\n\n"
        "[yellow]Watch your 'safeyolo watch' terminal for the approval prompt![/yellow]"
    )
    _show_request(
        "GET",
        "https://httpbin.org/headers",
        {"Authorization": f"Bearer {demo_anthropic_key}"}
    )

    if not auto:
        _wait_for_enter("Press Enter to send request (will be blocked)...")

    status, _, body = _make_request(
        "GET",
        "https://httpbin.org/headers",
        {"Authorization": f"Bearer {demo_anthropic_key}"},
    )
    _show_result(status, "BLOCKED 428 - credential leakage detected")

    if status == 428:
        console.print("\n  [green]✓[/green] SafeYolo blocked the credential leakage!")
        console.print("  [dim]Check 'safeyolo watch' - you should see an approval prompt.[/dim]")

    if not auto:
        _wait_for_enter()
    else:
        time.sleep(delay)

    # Step 4: Approval flow
    _show_step(4, total_steps,
        "Approval Flow",
        "Now [bold]approve[/bold] the credential in 'safeyolo watch' (press 'a').\n"
        "Then we'll retry the same request - it should be allowed.\n\n"
        "[yellow]Go to your watch terminal and approve the pending request.[/yellow]"
    )

    if not auto:
        _wait_for_enter("Press Enter AFTER approving in watch...")
    else:
        console.print("[dim]Auto mode: skipping approval step[/dim]")
        time.sleep(delay)

    console.print("\nRetrying the same request...")
    _show_request(
        "GET",
        "https://httpbin.org/headers",
        {"Authorization": f"Bearer {demo_anthropic_key}"}
    )

    status, _, body = _make_request(
        "GET",
        "https://httpbin.org/headers",
        {"Authorization": f"Bearer {demo_anthropic_key}"},
    )

    if status == 200:
        _show_result(status, "ALLOWED - approval persisted!")
        console.print("\n  [green]✓[/green] The approval worked! Credential now allowed to this destination.")
    elif status == 428:
        _show_result(status, "Should be ALLOWED if you approved")
        console.print("\n  [yellow]![/yellow] Still blocked - did you approve in watch?")
        console.print("  [dim]You can re-run 'safeyolo demo' to try again.[/dim]")
    else:
        _show_result(status, f"Unexpected status {status}")

    if not auto:
        _wait_for_enter()
    else:
        time.sleep(delay)

    # Step 5: Different credential (still blocked)
    _show_step(5, total_steps,
        "Different Credential (New Fingerprint)",
        "Approvals are per-credential-fingerprint, not per-type.\n"
        "A [bold]different[/bold] Anthropic key to the same destination is still blocked."
    )
    _show_request(
        "GET",
        "https://httpbin.org/headers",
        {"Authorization": f"Bearer {demo_anthropic_key_alt}"}
    )

    if not auto:
        _wait_for_enter("Press Enter to send request...")

    status, _, _ = _make_request(
        "GET",
        "https://httpbin.org/headers",
        {"Authorization": f"Bearer {demo_anthropic_key_alt}"},
    )
    _show_result(status, "BLOCKED 428 - different credential, needs separate approval")

    if status == 428:
        console.print("\n  [green]✓[/green] Correct! Each credential must be approved individually.")

    if not auto:
        _wait_for_enter()
    else:
        time.sleep(delay)

    # Step 6: Summary
    _show_step(6, total_steps,
        "Demo Complete!",
        "You've seen SafeYolo's core security features:\n\n"
        "  • [green]Allow[/green] - Plain requests and pre-approved credentials pass through\n"
        "  • [yellow]Block[/yellow] - Credential leakage attempts require approval\n"
        "  • [cyan]Approve[/cyan] - Operators can approve credentials for specific destinations\n"
        "  • [dim]Per-fingerprint[/dim] - Each unique credential needs separate approval"
    )

    console.print("\n[bold]Next steps:[/bold]")
    console.print("  • Edit ~/.safeyolo/policy.yaml to customize your policy")
    console.print("  • Run 'safeyolo watch' during development to monitor traffic")
    console.print("  • See 'safeyolo --help' for all commands")
    console.print()
