"""Authoritative service-source contract for retained protocol fixtures."""

from __future__ import annotations

from pathlib import Path

import yaml

from safeyolo.core.service_discovery import _load_service_files
from safeyolo.core.service_loader import ServiceDefinition, ServiceRegistry
from safeyolo.core.service_paths import (
    builtin_services_dir,
    resolve_service_directories,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILTIN_NAMES = {"gmail", "minifuse", "slack"}


def _assert_gmail_uses_omitted_header_default(services_dir: Path) -> None:
    raw = yaml.safe_load((services_dir / "gmail.yaml").read_text(encoding="utf-8"))
    operations = raw["capabilities"]["read_messages"]["contract"]["operations"]
    assert all(
        "allow_headers" not in operation["request"]["transport"]
        for operation in operations
    )

    service = ServiceDefinition.from_dict(raw)
    parsed = service.capabilities["read_messages"].contract.operations
    assert all(operation.transport.allow_headers is None for operation in parsed)


def _write_service(path: Path, name: str, description: str) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "name": name,
                "description": description,
            }
        ),
        encoding="utf-8",
    )


def test_source_checkout_uses_packaged_builtin_directory() -> None:
    builtin = builtin_services_dir()

    assert builtin == REPO_ROOT / "cli" / "src" / "safeyolo" / "services"
    assert {path.stem for path in builtin.glob("*.yaml")} == BUILTIN_NAMES
    _assert_gmail_uses_omitted_header_default(builtin)


def test_default_contract_uses_config_override_and_builtin_then_user(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "config"))

    directories = resolve_service_directories()

    assert directories.builtin == builtin_services_dir()
    assert directories.user == (tmp_path / "config" / "services").resolve()
    assert directories.precedence == (directories.builtin, directories.user)


def test_cli_and_registry_expose_identical_effective_documents(
    monkeypatch,
    tmp_path: Path,
) -> None:
    builtin = tmp_path / "builtin"
    user = tmp_path / "user"
    builtin.mkdir()
    user.mkdir()
    _write_service(builtin / "shared.yaml", "shared", "builtin")
    _write_service(builtin / "builtin-only.yaml", "builtin-only", "builtin")
    _write_service(user / "shared.yaml", "shared", "user override")
    _write_service(user / "user-only.yaml", "user-only", "user")
    monkeypatch.setattr(
        "safeyolo.core.service_discovery._get_services_dirs",
        lambda: [builtin, user],
    )

    cli_documents = {item["name"]: item for item in _load_service_files()}
    registry = ServiceRegistry(user, builtin_dir=builtin, require_builtin=True)
    registry.load(strict=True)
    runtime_documents = {
        service.name: service.to_dict() for service in registry.list_services()
    }

    assert cli_documents == runtime_documents
    assert set(cli_documents) == {"shared", "builtin-only", "user-only"}
    assert cli_documents["shared"]["description"] == "user override"


# Native bundle service staging is checked in tests/test_host_packages.py.
