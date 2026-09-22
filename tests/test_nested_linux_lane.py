"""Static regression checks for the real nested-Linux acceptance lane."""

import os
import subprocess
from pathlib import Path

LANE = Path(__file__).parent / "nested-linux" / "acceptance.sh"


def _shell_function(name: str) -> str:
    source = LANE.read_text()
    start = source.index(f"{name}() {{")
    end = source.index("\n}\n", start) + 2
    return source[start:end]


def test_nested_linux_rust_starts_use_only_rust_compatible_flags() -> None:
    """Every nested proxy start must remain valid with proxy.backend: rust."""
    source = LANE.read_text()

    assert 'proxy["backend"] = "rust"' in source
    assert 'proxy["rust_config"] = str(native_config)' in source
    assert 'proxy["upstream_proxy"] = sys.argv[6]' in source
    assert "native_config.unlink(missing_ok=True)" in source
    assert "selected_nested_rust_config() {" in source
    assert "yaml.safe_load(Path(sys.argv[1]).read_text())" in source
    assert "jq -er '.proxy.rust_config'" not in source

    starts = [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith("uv run safeyolo start")
    ]
    assert starts == ["uv run safeyolo start"]
    assert source.count("configure_nested_rust_proxy") == 4
    assert source.count("start_nested_rust_proxy") == 4


def test_nested_linux_lane_assertion_reads_the_selected_rust_config_as_yaml(tmp_path: Path) -> None:
    """The shell assertion must read the lane's YAML config before startup."""
    native_config = tmp_path / "data" / "native.json"
    native_config.parent.mkdir()
    (tmp_path / "config.yaml").write_text(
        f"proxy:\n  rust_config: {native_config}\n",
    )

    result = subprocess.run(
        [
            "bash",
            "-c",
            "\n".join(
                (
                    "set -euo pipefail",
                    "die() { exit 1; }",
                    "jq() { return 0; }",
                    _shell_function("selected_nested_rust_config"),
                    _shell_function("assert_nested_rust_runtime_config"),
                    "assert_nested_rust_runtime_config",
                )
            ),
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={
            **os.environ,
            "LAB_STATE": str(tmp_path),
            "SAFEYOLO_UPSTREAM_PROXY": "http://127.0.0.1:8080",
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
