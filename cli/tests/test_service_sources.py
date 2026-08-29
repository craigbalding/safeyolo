"""Authoritative service-source contract across source and wheel layouts."""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import yaml

from safeyolo.commands._service_discovery import _load_service_files
from safeyolo.core.service_loader import ServiceRegistry
from safeyolo.core.service_paths import (
    builtin_services_dir,
    resolve_service_directories,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILTIN_NAMES = {"gmail", "minifuse", "slack"}


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
        "safeyolo.commands._service_discovery._get_services_dirs",
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


def test_built_wheel_contains_curated_services_in_runtime_package(
    tmp_path: Path,
) -> None:
    output = tmp_path / "dist"
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(output)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(output.glob("*.whl"))

    installed = tmp_path / "installed"
    with zipfile.ZipFile(wheel) as archive:
        packaged = {
            Path(name).stem
            for name in archive.namelist()
            if name.startswith("safeyolo/services/") and name.endswith(".yaml")
        }
        archive.extractall(installed)

    assert packaged == BUILTIN_NAMES
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import sys; sys.path.insert(0, sys.argv[1]); "
                "from safeyolo.core.service_paths import builtin_services_dir; "
                "print(builtin_services_dir())"
            ),
            str(installed),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert Path(result.stdout.strip()) == installed / "safeyolo" / "services"
