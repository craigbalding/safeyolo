"""Shared service definition loading for CLI commands."""

from pathlib import Path

from safeyolo.core.service_loader import ServiceRegistry, ServiceRegistryError
from safeyolo.core.service_paths import resolve_service_directories


class ServiceDiscoveryError(RuntimeError):
    """CLI-facing service source or schema failure."""


def _get_services_dirs() -> list[Path]:
    """Get the authoritative builtin then user service directories."""
    return list(resolve_service_directories().precedence)


def _load_service_files() -> list[dict]:
    """Load all service definition YAML files.

    User directory takes priority over builtins (same name → user wins).
    """
    builtin_dir, user_dir = _get_services_dirs()
    registry = ServiceRegistry(
        user_dir,
        builtin_dir=builtin_dir,
        require_builtin=True,
    )
    try:
        registry.load(strict=True)
    except ServiceRegistryError as error:
        raise ServiceDiscoveryError(str(error)) from error
    return [service.to_dict() for service in registry.list_services()]


def find_service(name: str) -> dict | None:
    """Find a single service definition by name. Returns None if not found."""
    for svc in _load_service_files():
        if svc["name"] == name:
            return svc
    return None
