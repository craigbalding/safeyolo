"""Static regression checks for the real nested-Linux acceptance lane."""

from pathlib import Path

LANE = Path(__file__).parent / "nested-linux" / "acceptance.sh"


def test_nested_linux_rust_starts_use_only_rust_compatible_flags() -> None:
    """Every nested proxy start must remain valid with proxy.backend: rust."""
    source = LANE.read_text()

    assert 'proxy["backend"] = "rust"' in source
    assert 'proxy["rust_config"] = str(native_config)' in source
    assert 'proxy["upstream_proxy"] = sys.argv[6]' in source
    assert "native_config.unlink(missing_ok=True)" in source

    starts = [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith("uv run safeyolo start")
    ]
    assert starts == ["uv run safeyolo start"]
    assert source.count("configure_nested_rust_proxy") == 4
    assert source.count("start_nested_rust_proxy") == 4
