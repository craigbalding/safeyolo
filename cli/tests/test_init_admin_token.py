"""Regression tests for #338 — `init --force` must not invalidate an
admin_token that a running proxy still holds in memory.

Prior behaviour: `_generate_admin_token()` unconditionally wrote a fresh
`secrets.token_urlsafe(32)` to `data/admin_token`. If a mitmproxy was
already running when `init --force` fired, it kept the old token in
memory and rejected every subsequent CLI mode-sync PUT with 401. The
first place operators saw the 401 was mid-`agent add`, as an unstyled
JSON error block between the "Agent added!" panel and the "Starting
agent..." line.
"""

from unittest.mock import patch


def test_regenerates_when_no_token_file(tmp_config_dir):
    from safeyolo.commands.init import _generate_admin_token

    token_path = tmp_config_dir / "data" / "admin_token"
    token_path.unlink(missing_ok=True)

    with patch("safeyolo.proxy.is_proxy_running", return_value=False):
        token, preserved = _generate_admin_token(tmp_config_dir)

    assert preserved is False
    assert token, "expected a non-empty token"
    assert token_path.read_text() == token


def test_regenerates_when_proxy_not_running(tmp_config_dir):
    """If nothing else holds the old token, rotate freely."""
    from safeyolo.commands.init import _generate_admin_token

    token_path = tmp_config_dir / "data" / "admin_token"
    token_path.write_text("stale-token-from-a-previous-run")

    with patch("safeyolo.proxy.is_proxy_running", return_value=False):
        token, preserved = _generate_admin_token(tmp_config_dir)

    assert preserved is False
    assert token != "stale-token-from-a-previous-run"
    assert token_path.read_text() == token


def test_preserves_when_proxy_running_and_token_exists(tmp_config_dir):
    """The load-bearing case: a live proxy holds this token in memory."""
    from safeyolo.commands.init import _generate_admin_token

    live_token = "the-token-mitmproxy-currently-holds-in-memory"
    token_path = tmp_config_dir / "data" / "admin_token"
    token_path.write_text(live_token)

    with patch("safeyolo.proxy.is_proxy_running", return_value=True):
        token, preserved = _generate_admin_token(tmp_config_dir)

    assert preserved is True
    assert token == live_token
    assert token_path.read_text() == live_token


def test_regenerates_when_running_but_token_file_missing(tmp_config_dir):
    """Exceptional case: file was deleted while proxy runs. Can't preserve
    what we don't have; write a fresh token. The operator will have to
    restart the proxy to recover, but that state was already broken."""
    from safeyolo.commands.init import _generate_admin_token

    token_path = tmp_config_dir / "data" / "admin_token"
    token_path.unlink(missing_ok=True)

    with patch("safeyolo.proxy.is_proxy_running", return_value=True):
        token, preserved = _generate_admin_token(tmp_config_dir)

    assert preserved is False
    assert token
    assert token_path.read_text() == token


def test_init_force_prints_preserved_marker(tmp_config_dir):
    """The init flow surfaces the preservation instead of silently swapping."""
    from typer.testing import CliRunner

    from safeyolo.cli import app

    live_token = "token-live-proxy-holds"
    (tmp_config_dir / "data" / "admin_token").write_text(live_token)

    with patch("safeyolo.proxy.is_proxy_running", return_value=True):
        with patch("safeyolo.commands.init.check_guest_images", return_value=True):
            runner = CliRunner()
            result = runner.invoke(app, ["init", "--force", "--no-interactive"])

    assert result.exit_code == 0, result.output
    assert "Preserved" in result.output
    assert "admin token" in result.output
    assert (tmp_config_dir / "data" / "admin_token").read_text() == live_token


def test_init_fresh_prints_created_marker(tmp_config_dir):
    """First-run path: no proxy, no token — original "Created" wording."""
    from typer.testing import CliRunner

    from safeyolo.cli import app

    # Remove the fixture-seeded token so this really is the fresh path.
    (tmp_config_dir / "data" / "admin_token").unlink(missing_ok=True)

    with patch("safeyolo.proxy.is_proxy_running", return_value=False):
        with patch("safeyolo.commands.init.check_guest_images", return_value=True):
            runner = CliRunner()
            result = runner.invoke(app, ["init", "--force", "--no-interactive"])

    assert result.exit_code == 0, result.output
    assert "Created" in result.output
    assert (tmp_config_dir / "data" / "admin_token").exists()
