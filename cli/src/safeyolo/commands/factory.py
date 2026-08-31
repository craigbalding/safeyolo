"""CLI commands for explicit supervised factory contracts."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from ..agents_store import load_agent, mutate_agent
from ..config import find_config_dir
from ..factory_contract import (
    FactoryContract,
    FactoryContractError,
    load_active_snapshot,
    load_factory_file,
    store_snapshot,
)
from .agent import (
    _check_project_ownership,
    _resolve_host_script_path,
    _run_agent,
    _run_host_script_for_agent,
)

console = Console()
factory_app = typer.Typer(
    name="factory",
    help="Check, approve, and run supervised coord factories.",
    no_args_is_help=True,
)


def _load_file_or_exit(path: Path) -> FactoryContract:
    try:
        return load_factory_file(path)
    except FactoryContractError as exc:
        console.print(f"[red]Invalid factory contract:[/red] {exc}")
        raise typer.Exit(1) from exc


def _print_contract(contract: FactoryContract) -> None:
    console.print(f"factory={contract.name} schema=safeyolo.factory/v1 room={contract.room}")
    for role in contract.roles:
        console.print(
            f"role={role.name} agent={role.agent} contract={role.contract} "
            f"source={role.contract_source} bytes={role.contract_bytes} "
            f"sha256={role.contract_sha256}"
        )
    console.print(
        f"operator_input=operator to={contract.operator_input.destination} "
        f"types={','.join(contract.operator_input.types)}"
    )
    for handoff in contract.handoffs:
        responses = ",".join(handoff.responses)
        console.print(f"handoff={handoff.request} from={handoff.source} to={handoff.destination} responses={responses}")


@factory_app.command("check")
def check_factory(
    file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
) -> None:
    """Resolve and explain a factory file without changing host state."""
    contract = _load_file_or_exit(file)
    _print_contract(contract)
    console.print("[green]Factory contract is valid.[/green]")


@factory_app.command("apply")
def apply_factory(
    file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    yes: bool = typer.Option(False, "--yes", "-y", help="Approve this exact resolved snapshot without prompting."),
) -> None:
    """Approve and store an immutable host-side factory snapshot."""
    if find_config_dir() is None:
        console.print("[red]No SafeYolo configuration found.[/red]")
        raise typer.Exit(1)
    contract = _load_file_or_exit(file)
    _print_contract(contract)
    if not yes and not typer.confirm("Approve and activate this exact factory snapshot?"):
        console.print("Factory snapshot was not applied.")
        raise typer.Exit(1)
    try:
        identifier, path = store_snapshot(contract)
    except (FactoryContractError, OSError) as exc:
        console.print(f"[red]Could not store factory snapshot:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Applied factory {contract.name} snapshot={identifier}[/green]")
    console.print(f"snapshot_path={path}")


@factory_app.command("run")
def run_factory(name: str = typer.Argument(..., help="Applied factory name")) -> None:
    """Configure and start all existing supervised agents in a snapshot."""
    try:
        identifier, snapshot_path, payload = load_active_snapshot(name)
        _print_snapshot(identifier, snapshot_path, payload)
        _run_snapshot(snapshot_path, payload)
    except FactoryContractError as exc:
        console.print(f"[red]Cannot run factory:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Started factory {name} snapshot={identifier}[/green]")


def _print_snapshot(identifier: str, snapshot_path: Path, payload: dict[str, Any]) -> None:
    console.print(
        f"factory={payload['name']} schema={payload['schema']} room={payload['room']} "
        f"snapshot={identifier} snapshot_path={snapshot_path}"
    )
    for role_name, role in payload["roles"].items():
        console.print(
            f"role={role_name} agent={role['agent']} contract={role['contract']} "
            f"bytes={role['contract_bytes']} sha256={role['contract_sha256']}"
        )
    operator_input = payload["operator_input"]
    console.print(
        f"operator_input=operator to={operator_input['to']} "
        f"types={','.join(operator_input['types'])}"
    )


def _run_snapshot(snapshot_path: Path, payload: dict[str, Any]) -> None:
    roles = payload["roles"]
    configured: list[tuple[str, str, dict[str, Any]]] = []
    host_script = _resolve_host_script_path("@codex-coord")
    assert host_script is not None
    for role_name, role in roles.items():
        agent_name = role["agent"]
        metadata = load_agent(agent_name)
        if not metadata:
            raise FactoryContractError(f"role {role_name!r} requires existing agent {agent_name!r}; create it first")
        folder = metadata.get("folder")
        if not isinstance(folder, str):
            raise FactoryContractError(f"agent {agent_name!r} has no configured folder")
        folder_path = Path(folder).expanduser().resolve()
        if not folder_path.is_dir():
            raise FactoryContractError(f"agent {agent_name!r} folder does not exist: {folder_path}")
        _check_project_ownership(folder_path, False)
        configured.append((role_name, agent_name, metadata))

    # Configure every existing agent from the same immutable snapshot before
    # booting any of them. There is no live reload; another apply+run is needed
    # to move the factory to a different snapshot.
    for role_name, agent_name, metadata in configured:
        with _factory_environment(snapshot_path, role_name):
            _run_host_script_for_agent(
                name=agent_name,
                host_script_path=host_script,
                folder_str=str(Path(metadata["folder"]).expanduser().resolve()),
            )

        def persist_host_script(current: dict[str, Any]) -> None:
            current["host_script"] = str(host_script)

        try:
            mutate_agent(agent_name, persist_host_script)
        except KeyError as exc:
            raise FactoryContractError(f"agent {agent_name!r} was removed during factory setup") from exc

    for _role_name, agent_name, _metadata in configured:
        exit_code = _run_agent(
            agent_name,
            yolo=True,
            detach=True,
            no_snapshot=True,
        )
        if exit_code != 0:
            raise FactoryContractError(f"agent {agent_name!r} failed to start (exit {exit_code})")


@contextmanager
def _factory_environment(snapshot_path: Path, role_name: str) -> Iterator[None]:
    values = {
        "SAFEYOLO_CODEX_FACTORY_SNAPSHOT": str(snapshot_path),
        "SAFEYOLO_CODEX_FACTORY_ROLE": role_name,
    }
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
