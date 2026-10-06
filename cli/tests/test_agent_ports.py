"""Tests for agent port mapping features."""


import pytest
import typer

from safeyolo.commands.agent import _parse_port, _parse_user_default_args


class TestParsePort:
    """Unit tests for _parse_port()."""

    def test_valid_two_part(self):
        """Two-part spec normalizes to 127.0.0.1 bind."""
        assert _parse_port("6080:6080") == "127.0.0.1:6080:6080"

    def test_valid_two_part_different_ports(self):
        """Different host and container ports."""
        assert _parse_port("8888:3000") == "127.0.0.1:8888:3000"

    def test_valid_three_part_localhost(self):
        """Three-part with 127.0.0.1 passes through."""
        assert _parse_port("127.0.0.1:6080:6080") == "127.0.0.1:6080:6080"

    def test_reject_non_localhost_bind(self):
        """Rejects non-localhost bind address."""
        with pytest.raises(typer.Exit):
            _parse_port("0.0.0.0:6080:6080")

    def test_reject_one_part(self):
        """Rejects single port (no colon)."""
        with pytest.raises(typer.Exit):
            _parse_port("6080")

    def test_reject_four_part(self):
        """Rejects too many colons."""
        with pytest.raises(typer.Exit):
            _parse_port("127.0.0.1:6080:6080:tcp")

    def test_reject_non_integer_host(self):
        """Rejects non-integer host port."""
        with pytest.raises(typer.Exit):
            _parse_port("abc:6080")

    def test_reject_non_integer_container(self):
        """Rejects non-integer container port."""
        with pytest.raises(typer.Exit):
            _parse_port("6080:abc")

    def test_reject_port_zero(self):
        """Rejects port 0."""
        with pytest.raises(typer.Exit):
            _parse_port("0:6080")

    def test_reject_port_over_65535(self):
        """Rejects port > 65535."""
        with pytest.raises(typer.Exit):
            _parse_port("6080:65536")

    def test_reject_reserved_container_port_8080(self):
        """Rejects reserved container port 8080 (proxy)."""
        with pytest.raises(typer.Exit):
            _parse_port("8080:8080")

    def test_reject_reserved_container_port_9090(self):
        """Rejects reserved container port 9090 (admin)."""
        with pytest.raises(typer.Exit):
            _parse_port("9090:9090")

    def test_allow_reserved_as_host_port(self):
        """Reserved ports are fine as host port (only container is checked)."""
        assert _parse_port("8080:3000") == "127.0.0.1:8080:3000"
        assert _parse_port("9090:3000") == "127.0.0.1:9090:3000"


# ---------------------------------------------------------------------------


class TestParseUserDefaultArgs:
    def test_none_returns_none(self):
        assert _parse_user_default_args(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_user_default_args("") is None

    def test_simple_args(self):
        assert _parse_user_default_args("--model opus --verbose") == ["--model", "opus", "--verbose"]

    def test_quoted_args(self):
        assert _parse_user_default_args('--prompt "hello world"') == ["--prompt", "hello world"]

    def test_single_arg(self):
        assert _parse_user_default_args("--verbose") == ["--verbose"]
