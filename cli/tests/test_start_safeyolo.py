"""Regression tests for the legacy executable SafeYolo startup script."""

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
STARTUP_SCRIPT = REPO_ROOT / "scripts/start-safeyolo.sh"


def _pattern_block_fragment() -> str:
    """Extract the startup script's pattern block for an isolated shell run."""
    source = STARTUP_SCRIPT.read_text()
    start = source.index("# pattern-scanner: defaults to WARN-ONLY")
    end = source.index("# test-context: defaults to BLOCK", start)
    fragment = source[start:end]
    # The full script guards this section on the addon file being present. The
    # policy logic itself is what this regression executes; replacing that
    # fixed image-path probe keeps the test host-independent.
    fragment = fragment.replace(
        'if [ -f "/app/addons/pattern_scanner.py" ]; then\n',
        "if true; then\n",
    )
    return fragment


def _startup_options(**variables: str) -> str:
    env = os.environ.copy()
    for name in (
        "SAFEYOLO_BLOCK",
        "PATTERN_BLOCK",
        "PATTERN_BLOCK_WEBSOCKET_REQUEST",
        "PATTERN_BLOCK_WEBSOCKET_RESPONSE",
    ):
        env.pop(name, None)
    env.update(variables)
    command = (
        "set -e\n"
        "MITM_OPTS=''\n"
        f"{_pattern_block_fragment()}"
        "printf '%s\\n' \"${MITM_OPTS}\"\n"
    )
    result = subprocess.run(
        ["bash", "-c", command],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.splitlines()[-1]


def test_startup_script_uses_registered_websocket_options() -> None:
    """The executable launcher must not emit removed input/output options."""
    source = STARTUP_SCRIPT.read_text()
    assert "pattern_block_input" not in source
    assert "pattern_block_output" not in source
    assert "pattern_block_request=true" in source
    assert "pattern_block_response=true" in source
    assert "pattern_block_websocket_request" in source
    assert "pattern_block_websocket_response" in source


def test_pattern_block_startup_defaults_all_directions_to_block() -> None:
    options = _startup_options(PATTERN_BLOCK="true")
    assert "--set pattern_block_request=true" in options
    assert "--set pattern_block_response=true" in options
    assert "--set pattern_block_websocket_request=true" in options
    assert "--set pattern_block_websocket_response=true" in options


def test_directional_websocket_override_beats_pattern_block() -> None:
    options = _startup_options(
        PATTERN_BLOCK="true",
        PATTERN_BLOCK_WEBSOCKET_REQUEST="false",
    )
    assert "--set pattern_block_request=true" in options
    assert "--set pattern_block_response=true" in options
    assert "--set pattern_block_websocket_request=false" in options
    assert "--set pattern_block_websocket_response=true" in options


def test_safeyolo_block_forces_directional_websocket_overrides() -> None:
    options = _startup_options(
        SAFEYOLO_BLOCK="true",
        PATTERN_BLOCK_WEBSOCKET_REQUEST="false",
        PATTERN_BLOCK_WEBSOCKET_RESPONSE="false",
    )
    assert "--set pattern_block_request=true" in options
    assert "--set pattern_block_response=true" in options
    assert "--set pattern_block_websocket_request=true" in options
    assert "--set pattern_block_websocket_response=true" in options
