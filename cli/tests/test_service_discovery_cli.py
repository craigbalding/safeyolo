"""Tests for service definition file loading.

Contract for _load_service_files():
- Uses the same strict ServiceRegistry parser as the running gateway.
- User dir entries override builtin entries with the same 'name' value.
- Malformed, incomplete, and duplicate definitions fail discovery loudly.
- The packaged builtin source is required; the user directory is optional.
- Returns validated raw schema documents for CLI rendering.
"""

import pytest
import yaml

from safeyolo.commands._service_discovery import (
    ServiceDiscoveryError,
    _load_service_files,
)


def _service(name: str, **values) -> dict:
    return {"schema_version": 1, "name": name, **values}


class TestLoadServiceFilesBuiltinOnly:
    """Loading when only builtin dir has services."""

    def test_loads_single_builtin_service(self, tmp_path, monkeypatch):
        builtin = tmp_path / "builtin"
        builtin.mkdir()
        user = tmp_path / "user"  # Does not exist

        svc = _service("redis", description="Redis cache")
        (builtin / "redis.yaml").write_text(yaml.dump(svc))

        monkeypatch.setattr(
            "safeyolo.commands._service_discovery._get_services_dirs",
            lambda: [builtin, user],
        )

        result = _load_service_files()
        assert len(result) == 1
        assert result[0]["name"] == "redis"
        assert result[0]["description"] == "Redis cache"


class TestLoadServiceFilesUserOverride:
    """User dir overrides builtin with the same service name."""

    def test_user_file_overrides_builtin_with_same_name(self, tmp_path, monkeypatch):
        builtin = tmp_path / "builtin"
        builtin.mkdir()
        user = tmp_path / "user"
        user.mkdir()

        builtin_svc = _service("slack", description="Builtin slack")
        user_svc = _service("slack", description="Custom slack")
        (builtin / "slack.yaml").write_text(yaml.dump(builtin_svc))
        (user / "slack.yaml").write_text(yaml.dump(user_svc))

        monkeypatch.setattr(
            "safeyolo.commands._service_discovery._get_services_dirs",
            lambda: [builtin, user],
        )

        result = _load_service_files()
        assert len(result) == 1
        assert result[0]["description"] == "Custom slack"


class TestLoadServiceFilesBothContribute:
    """Both dirs contribute different services."""

    def test_different_services_from_each_dir(self, tmp_path, monkeypatch):
        builtin = tmp_path / "builtin"
        builtin.mkdir()
        user = tmp_path / "user"
        user.mkdir()

        (builtin / "redis.yaml").write_text(yaml.dump(_service("redis")))
        (user / "postgres.yaml").write_text(yaml.dump(_service("postgres")))

        monkeypatch.setattr(
            "safeyolo.commands._service_discovery._get_services_dirs",
            lambda: [builtin, user],
        )

        result = _load_service_files()
        names = {s["name"] for s in result}
        assert names == {"redis", "postgres"}


class TestLoadServiceFilesInvalidFails:
    """CLI discovery refuses definitions the running registry cannot load."""

    def test_malformed_yaml_names_offending_file(self, tmp_path, monkeypatch):
        builtin = tmp_path / "builtin"
        builtin.mkdir()
        user = tmp_path / "user"  # Not created

        (builtin / "bad.yaml").write_text(": : : not valid yaml {{{}}")
        (builtin / "good.yaml").write_text(yaml.dump(_service("good-svc")))

        monkeypatch.setattr(
            "safeyolo.commands._service_discovery._get_services_dirs",
            lambda: [builtin, user],
        )

        with pytest.raises(ServiceDiscoveryError, match="bad.yaml"):
            _load_service_files()

    def test_file_without_name_key_fails(self, tmp_path, monkeypatch):
        builtin = tmp_path / "builtin"
        builtin.mkdir()
        user = tmp_path / "user"  # Not created

        (builtin / "noname.yaml").write_text(
            yaml.dump({"schema_version": 1, "description": "no name field"})
        )
        (builtin / "valid.yaml").write_text(yaml.dump(_service("valid-svc")))

        monkeypatch.setattr(
            "safeyolo.commands._service_discovery._get_services_dirs",
            lambda: [builtin, user],
        )

        with pytest.raises(ServiceDiscoveryError, match="noname.yaml"):
            _load_service_files()


class TestLoadServiceFilesEmptyDirs:
    """Empty sources are valid, but the packaged source must exist."""

    def test_empty_directories_return_empty_list(self, tmp_path, monkeypatch):
        builtin = tmp_path / "builtin"
        builtin.mkdir()
        user = tmp_path / "user"
        user.mkdir()

        monkeypatch.setattr(
            "safeyolo.commands._service_discovery._get_services_dirs",
            lambda: [builtin, user],
        )

        result = _load_service_files()
        assert result == []

    def test_missing_builtin_directory_fails(self, tmp_path, monkeypatch):
        builtin = tmp_path / "missing-builtin"
        user = tmp_path / "user"
        user.mkdir()

        monkeypatch.setattr(
            "safeyolo.commands._service_discovery._get_services_dirs",
            lambda: [builtin, user],
        )

        with pytest.raises(ServiceDiscoveryError, match="packaged builtin"):
            _load_service_files()
