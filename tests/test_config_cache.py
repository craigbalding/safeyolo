"""Tests for addons/config_cache.py — cached sensor_config.

Mocks `pdp.get_policy_client` and `pdp.is_policy_client_configured`
rather than the underlying PDP so these tests run without policy
files on disk.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

_ADDONS_DIR = Path(__file__).resolve().parent.parent / "addons"
sys.path.insert(0, str(_ADDONS_DIR))

from config_cache import _ConfigCache  # noqa: E402


def _client_with_hash(hash_value: str, rules=None, patterns=None):
    """Make a stub PolicyClient-alike whose get_sensor_config returns
    the given hash + optional rule/pattern lists."""
    client = MagicMock()
    client.get_sensor_config.return_value = {
        "credential_rules": rules or [],
        "scan_patterns": patterns or [],
        "policy_hash": hash_value,
    }
    return client


class TestGet:
    def test_first_call_populates_cache(self):
        client = _client_with_hash("abc")
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            result = cache.get()

        assert result["policy_hash"] == "abc"
        client.get_sensor_config.assert_called_once()

    def test_subsequent_calls_hit_cache(self):
        """The slow path fires once; follow-ups are lock-free reads."""
        client = _client_with_hash("abc")
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            cache.get()
            cache.get()
            cache.get()

        assert client.get_sensor_config.call_count == 1

    def test_invalidate_forces_refetch(self):
        client = _client_with_hash("abc")
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            cache.get()
            cache.invalidate()
            cache.get()

        assert client.get_sensor_config.call_count == 2

    def test_returns_empty_when_policy_client_not_configured(self):
        """Startup race — PDP not up yet — must return {} silently."""
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client") as gpc, \
             mock.patch("pdp.is_policy_client_configured", return_value=False):
            result = cache.get()

        assert result == {}
        gpc.assert_not_called()

    def test_fetch_error_returns_empty_and_logs(self, caplog):
        client = MagicMock()
        client.get_sensor_config.side_effect = KeyError("boom")
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            result = cache.get()

        assert result == {}
        assert "config_cache fetch failed" in caplog.text


class TestReloadCallback:
    def test_registers_callback_on_first_fetch(self):
        client = _client_with_hash("abc")
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            cache.get()

        client.add_reload_callback.assert_called_once_with(cache.invalidate)

    def test_registration_idempotent(self):
        """Cache must not stack callbacks every time it refreshes."""
        client = _client_with_hash("abc")
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            cache.get()
            cache.invalidate()
            cache.get()
            cache.invalidate()
            cache.get()

        assert client.add_reload_callback.call_count == 1

    def test_skips_registration_for_http_client(self):
        """HTTPClient has no add_reload_callback; we must not crash."""
        client = MagicMock(spec=["get_sensor_config"])  # no add_reload_callback
        client.get_sensor_config.return_value = {"policy_hash": "x"}
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            result = cache.get()

        assert result["policy_hash"] == "x"


class TestAccessors:
    def test_convenience_getters(self):
        rules = [{"name": "openai"}]
        patterns = [{"name": "ssn"}]
        client = _client_with_hash("abc", rules=rules, patterns=patterns)
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            assert cache.credential_rules() == rules
            assert cache.scan_patterns() == patterns
            assert cache.policy_hash() == "abc"

    def test_addon_section_returns_subsection(self):
        client = MagicMock()
        client.get_sensor_config.return_value = {
            "policy_hash": "abc",
            "addons": {
                "credential_guard": {"detection_level": "strict"},
                "flow_store": {"db_path": "/tmp/flows.db"},
            },
        }
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            assert cache.addon_section("credential_guard") == {"detection_level": "strict"}
            assert cache.addon_section("missing") == {}


class TestTTLFallback:
    """HTTP-client path: no reload signal, TTL-bound staleness."""

    def test_no_ttl_for_local_client(self):
        """LocalPolicyClient registers a callback — TTL stays None."""
        client = _client_with_hash("abc")  # MagicMock has add_reload_callback
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            cache.get()

        assert cache._ttl_s is None

    def test_ttl_set_for_http_client(self):
        """HTTPClient shape (no add_reload_callback) → TTL fallback."""
        client = MagicMock(spec=["get_sensor_config"])
        client.get_sensor_config.return_value = {"policy_hash": "x"}
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            cache.get()

        assert cache._ttl_s is not None
        assert cache._ttl_s > 0

    def test_ttl_env_override(self, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_CONFIG_CACHE_TTL_S", "7")
        client = MagicMock(spec=["get_sensor_config"])
        client.get_sensor_config.return_value = {"policy_hash": "x"}
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            cache.get()

        assert cache._ttl_s == 7.0

    def test_ttl_env_garbage_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_CONFIG_CACHE_TTL_S", "not-a-number")
        client = MagicMock(spec=["get_sensor_config"])
        client.get_sensor_config.return_value = {"policy_hash": "x"}
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            cache.get()

        assert cache._ttl_s == 30.0  # _DEFAULT_HTTP_TTL_S

    def test_ttl_expiry_triggers_refetch(self):
        client = MagicMock(spec=["get_sensor_config"])
        client.get_sensor_config.return_value = {"policy_hash": "fresh"}
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            cache.get()
            assert client.get_sensor_config.call_count == 1

            # Force expiry by rewinding _fetched_at past the TTL.
            cache._fetched_at -= cache._ttl_s + 1.0
            cache.get()

        assert client.get_sensor_config.call_count == 2

    def test_within_ttl_still_caches(self):
        client = MagicMock(spec=["get_sensor_config"])
        client.get_sensor_config.return_value = {"policy_hash": "fresh"}
        cache = _ConfigCache()

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            cache.get()
            # Well within the 30 s TTL.
            cache.get()
            cache.get()

        assert client.get_sensor_config.call_count == 1


class TestConcurrency:
    def test_concurrent_gets_do_not_crash(self):
        """Multiple threads calling get() during initial fetch is safe."""
        client = _client_with_hash("abc")
        cache = _ConfigCache()
        errors: list = []

        def worker():
            try:
                for _ in range(50):
                    cache.get()
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        with mock.patch("pdp.get_policy_client", return_value=client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert errors == []
        # Fetch may have happened multiple times under race (acceptable —
        # same policy_hash ends up cached), but certainly not hundreds.
        # Put a loose upper bound to catch a regression to "fetch-per-get".
        assert client.get_sensor_config.call_count <= 20
