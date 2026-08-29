"""Authoritative locations and precedence for service definitions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ServiceDirectories:
    """The two service sources, ordered from lowest to highest precedence."""

    builtin: Path
    user: Path

    @property
    def precedence(self) -> tuple[Path, Path]:
        """Return builtin first and user second so user definitions override."""
        return (self.builtin, self.user)


def builtin_services_dir() -> Path:
    """Return the curated service directory shipped inside the package."""
    return Path(__file__).resolve().parents[1] / "services"


def resolve_service_directories(
    user_dir: Path | str | None = None,
    builtin_dir: Path | str | None = None,
) -> ServiceDirectories:
    """Resolve the one service-source contract used by CLI and traffic paths."""
    if user_dir is None:
        from safeyolo.config import _get_config_dir_path

        user = _get_config_dir_path() / "services"
    else:
        user = Path(user_dir)

    builtin = Path(builtin_dir) if builtin_dir is not None else builtin_services_dir()
    return ServiceDirectories(
        builtin=builtin.expanduser().resolve(),
        user=user.expanduser().resolve(),
    )
