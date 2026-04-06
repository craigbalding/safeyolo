"""Tests for service definition file loading.

Contract for _load_service_files():
- Scans builtin_dir then user_dir for *.yaml files, sorted alphabetically per dir.
- Each file must be valid YAML, a dict, and contain a 'name' key to be accepted.
- User dir entries override builtin entries with the same 'name' value.
- Malformed YAML files are silently skipped (OSError or yaml.YAMLError).
- Files missing the 'name' key are silently skipped.
- Non-existent directories are silently skipped.
- Returns a list of dicts (the raw parsed YAML content).
"""

import yaml

from safeyolo.commands._service_discovery import _load_service_files


class TestLoadServiceFilesBuiltinOnly:
    """Loading when only builtin dir has services."""

    def test_loads_single_builtin_service(self, tmp_path, monkeypatch):
        builtin = tmp_path / "builtin"
        builtin.mkdir()
        user = tmp_path / "user"  # Does not exist

        svc = {"name": "redis", "description": "Redis cache"}
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

        builtin_svc = {"name": "slack", "description": "Builtin slack"}
        user_svc = {"name": "slack", "description": "Custom slack"}
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

        (builtin / "redis.yaml").write_text(yaml.dump({"name": "redis"}))
        (user / "postgres.yaml").write_text(yaml.dump({"name": "postgres"}))

        monkeypatch.setattr(
            "safeyolo.commands._service_discovery._get_services_dirs",
            lambda: [builtin, user],
        )

        result = _load_service_files()
        names = {s["name"] for s in result}
        assert names == {"redis", "postgres"}


class TestLoadServiceFilesMalformedSkipped:
    """Malformed YAML and missing keys are skipped gracefully."""

    def test_malformed_yaml_skipped_other_services_loaded(self, tmp_path, monkeypatch):
        builtin = tmp_path / "builtin"
        builtin.mkdir()
        user = tmp_path / "user"  # Not created

        (builtin / "bad.yaml").write_text(": : : not valid yaml {{{}}")
        (builtin / "good.yaml").write_text(yaml.dump({"name": "good-svc", "port": 8080}))

        monkeypatch.setattr(
            "safeyolo.commands._service_discovery._get_services_dirs",
            lambda: [builtin, user],
        )

        result = _load_service_files()
        assert len(result) == 1
        assert result[0]["name"] == "good-svc"

    def test_file_without_name_key_skipped(self, tmp_path, monkeypatch):
        builtin = tmp_path / "builtin"
        builtin.mkdir()
        user = tmp_path / "user"  # Not created

        (builtin / "noname.yaml").write_text(yaml.dump({"description": "no name field"}))
        (builtin / "valid.yaml").write_text(yaml.dump({"name": "valid-svc"}))

        monkeypatch.setattr(
            "safeyolo.commands._service_discovery._get_services_dirs",
            lambda: [builtin, user],
        )

        result = _load_service_files()
        assert len(result) == 1
        assert result[0]["name"] == "valid-svc"


class TestLoadServiceFilesEmptyDirs:
    """Empty or non-existent directories."""

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
