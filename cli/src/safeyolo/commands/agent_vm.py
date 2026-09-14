"""Host-only macOS VM inspection and explicit relay cancellation."""

import json
from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .. import vm_control
from ..vm_identity import parse_vm_helper_identity

vm_app = typer.Typer(help="Inspect a macOS VM helper and recover individual relay connections.", no_args_is_help=True)
console = Console()


def _failed(error: Exception, *, as_json: bool = False) -> NoReturn:
    if as_json:
        typer.echo(json.dumps({"ok": False, "error": str(error)}), err=True)
    else:
        console.print(f"[red]{escape(str(error))}[/red]")
    raise typer.Exit(1)


@vm_app.command()
def status(
    name: str = typer.Argument(..., help="Agent instance name"),
    as_json: bool = typer.Option(False, "--json", help="Print the structured helper status"),
) -> None:
    """Show running build identity, VM state, relay counts and executor health."""
    try:
        value = vm_control.read_status(name)
        if as_json:
            typer.echo(json.dumps(value, indent=2))
            return
        helper, vm = parse_vm_helper_identity(value["helper"]), value["vm"]
        console.print(
            f"PID {value['pid']} · VM {escape(vm['state'])} · "
            f"{escape(helper.summary)}"
        )
        if helper.warning:
            console.print(f"[yellow]{escape(helper.warning)}[/yellow]")
        console.print(
            f"Relays {value['active']} · FDs {value['relay_fd_count']} · "
            f"health {escape(value['health'])} · instance {escape(value['instance'])}"
        )
        console.print(f"By type: {value['counts_by_kind']} · By phase: {value['counts_by_phase']}")
    except vm_control.VMControlError as error:
        _failed(error, as_json=as_json)


@vm_app.command()
def relays(
    name: str = typer.Argument(..., help="Agent instance name"),
    as_json: bool = typer.Option(False, "--json", help="Print structured relay records"),
) -> None:
    """List active and pending relays from the independent helper control channel."""
    try:
        instance, records = vm_control.list_relays(name)
    except vm_control.VMControlError as error:
        _failed(error, as_json=as_json)
    if as_json:
        typer.echo(json.dumps({"instance": instance, "relays": records}, indent=2))
        return
    table = Table("ID", "Type", "Phase", "Bytes in", "Bytes out", "Buffered in/out")
    for record in records:
        table.add_row(str(record["id"]), record["kind"], escape(record["phase"]),
                      str(record.get("bytes_in", 0)), str(record.get("bytes_out", 0)),
                      f"{record.get('buffered_in', 0)}/{record.get('buffered_out', 0)}")
    console.print(table)
    console.print(f"{len(records)} relays · instance {escape(instance)}")


@vm_app.command()
def cancel(  # noqa: PLR0913 - Typer binds the operator's independent command options.
    name: str = typer.Argument(..., help="Agent instance name"),
    flow_ids: list[int] | None = typer.Argument(None, help="Explicit flow IDs to terminate"),
    all_flows: bool = typer.Option(False, "--all", help="Select all current relays of --kind"),
    kind: str | None = typer.Option(None, "--kind", help="Bulk selection: proxy or shell"),
    dry_run: bool = typer.Option(False, "--dry-run", help="List the selected connections without cancelling"),
    reason: str = typer.Option("operator request", "--reason", help="Reason recorded in the private cancellation audit"),
    as_json: bool = typer.Option(False, "--json", help="Print selected/closed IDs as JSON"),
) -> None:
    """Terminate selected network or shell connections without stopping the VM.

    List relays first, or use --dry-run. Bulk cancellation requires --all and
    --kind, and targets the IDs present in that snapshot, not future connections.
    """
    if all_flows:
        if flow_ids or kind not in {"proxy", "shell"}:
            raise typer.BadParameter("--all requires --kind proxy|shell and no explicit flow IDs")
    elif not flow_ids or kind is not None or any(value <= 0 for value in flow_ids):
        raise typer.BadParameter("provide positive flow IDs, or --all --kind proxy|shell")
    try:
        instance, records = vm_control.list_relays(name)
        if not all_flows:
            missing = set(flow_ids or []) - {record["id"] for record in records}
            if missing:
                raise vm_control.VMControlError(f"Flow IDs are not active: {sorted(missing)}; list relays again")
        selected = [record["id"] for record in records if record["kind"] == kind] if all_flows else list(dict.fromkeys(flow_ids or []))
        if dry_run:
            result = {"instance": instance, "selected_ids": selected, "dry_run": True}
        else:
            result = vm_control.cancel_relays(name, instance, selected, reason=reason)
        if as_json:
            typer.echo(json.dumps(result, indent=2))
        elif dry_run:
            console.print(f"Would terminate {len(selected)} connections: {selected}")
        else:
            console.print(f"Closed {len(result['closed_ids'])} connections: {result['closed_ids']}")
    except vm_control.VMControlError as error:
        _failed(error, as_json=as_json)


@vm_app.command()
def dump(
    name: str = typer.Argument(..., help="Agent instance name"),
    output: Path | None = typer.Option(None, "--output", help="JSON artifact path; default is the agent's private VM control directory"),
) -> None:
    """Write a bounded hang dump without using shell/proxy relays or a debugger."""
    try:
        path = vm_control.write_dump(name, output)
        console.print(f"VM hang dump: {escape(str(path))}")
    except vm_control.VMControlError as error:
        _failed(error)
