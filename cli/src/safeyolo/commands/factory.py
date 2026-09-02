"""CLI commands for explicit supervised factory contracts."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from ..agents_store import get_or_mint_agent_id, load_agent, mutate_agent
from ..config import find_config_dir
from ..coord import api as coord_api
from ..coord import nats_runtime as coord_nats
from ..coord.identity import new_operation_id
from ..factory_contract import (
    FactoryContract,
    FactoryContractError,
    load_active_snapshot,
    load_factory_file,
    store_snapshot,
)
from ..factory_doctor import inspect_factory
from .agent import (
    _check_project_ownership,
    _resolve_host_script_path,
    _run_agent,
    _run_host_script_for_agent,
)

console = Console()
factory_app = typer.Typer(
    name="factory",
    help="Check, approve, run, and diagnose supervised coord factories.",
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
    _print_contract_explanation(contract)


def _print_contract_explanation(  # DOC: docs/factories.md, docs/factories/backlog-coordinator.md
    contract: FactoryContract,
) -> None:
    roles = {role.name: role for role in contract.roles}
    operator_role = roles[contract.operator_input.destination]
    console.print("\n[bold]Authority and routing[/bold]")
    console.print(
        "Approval creates an immutable snapshot. The snapshot binds this "
        "routing graph and the exact UTF-8 bytes of every role contract."
    )
    console.print(
        "The role lines above identify each authoritative contract source path "
        "and SHA-256. Inspect those files directly; SafeYolo does not summarize "
        "or interpret their text."
    )
    console.print(
        f"The canonical operator edge reaches role={operator_role.name} "
        f"agent={operator_role.agent} through the admitted inputs "
        f"{','.join(contract.operator_input.types)}."
    )
    console.print(
        "The admitted input words are not workflow definitions. Their meanings "
        f"come from the bound role contract source={operator_role.contract_source} "
        f"sha256={operator_role.contract_sha256}."
    )
    for handoff in contract.handoffs:
        source = roles[handoff.source]
        destination = roles[handoff.destination]
        console.print(
            f"The role={source.name} agent={source.agent} can send "
            f"request={handoff.request} to role={destination.name} "
            f"agent={destination.agent}; declared responses are "
            f"{','.join(handoff.responses)}."
        )
    console.print(
        f"The canonical trusted brief for room={contract.room} is separate live "
        "operator state. It is not part of the immutable snapshot."
    )
    console.print(
        "This static check does not inspect live room state, grants, brief "
        "revision, or worker health."
    )
    console.print(
        "Static admission of a control word does not select work or prove live "
        "eligibility or readiness."
    )
    console.print(
        "Read the bound role contract and live brief to determine whether "
        "standing intake can delegate or explicit issue selection is required."
    )
    console.print(
        "An absent brief is not a static contract error. A bound role contract "
        "can intentionally use explicit selection only."
    )
    console.print(f"Inspect the live brief: safeyolo coord brief show {contract.room}")
    console.print(
        "Set the live brief: "
        f"safeyolo coord brief set {contract.room} --file BRIEF.md "
        "--expected-revision REVISION"
    )
    console.print(f"Inspect live readiness: safeyolo factory doctor {contract.name}")


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


@factory_app.command("doctor")
def doctor_factory(name: str = typer.Argument(..., help="Applied factory name")) -> None:
    """Inspect an active supervised factory without changing it."""
    report = inspect_factory(name)
    for item in report.checks:
        line = f"{item.status} component={item.component} {item.detail}"
        if item.recovery is not None:
            line += f" recovery={item.recovery}"
        console.print(line)
    counts = {
        status: sum(item.status == status for item in report.checks)
        for status in ("PASS", "WARN", "FAIL")
    }
    console.print(
        f"SUMMARY factory={name} status={report.status} "
        f"pass={counts['PASS']} warn={counts['WARN']} fail={counts['FAIL']}"
    )
    if report.status == "FAIL":
        raise typer.Exit(1)


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

    try:
        coord_nats.start_server(ready_timeout=10.0)
        coord_api.bootstrap()
        _ensure_agent_rooms(agent_name for _role_name, agent_name, _metadata in configured)
    except Exception as exc:
        raise FactoryContractError(f"coord runtime failed to start: {exc}") from exc

    for _role_name, agent_name, _metadata in configured:
        exit_code = _run_agent(
            agent_name,
            yolo=True,
            detach=True,
            run_command_detached=True,
            no_snapshot=True,
        )
        if exit_code != 0:
            raise FactoryContractError(f"agent {agent_name!r} failed to start (exit {exit_code})")


def _ensure_agent_rooms(agent_names: Iterator[str]) -> None:
    existing = {room["name"] for room in coord_api.list_rooms()}
    for agent_name in agent_names:
        room_name = f"{agent_name}-agent"
        if room_name not in existing:
            asyncio.run(coord_api.create_room(room_name))
            existing.add(room_name)
        coord_api.grant(
            room_name,
            "agent",
            get_or_mint_agent_id(agent_name),
            operation_id=new_operation_id(),
        )
        coord_api.grant(
            room_name,
            "operator",
            "operator",
            operation_id=new_operation_id(),
        )


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
