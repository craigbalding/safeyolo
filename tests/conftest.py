"""Shared fixtures for current Python and native proxy tests."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# The audit writer reads this setting on first import. Keep test writes out of
# the operator's normal log path.
os.environ.setdefault(
    "SAFEYOLO_LOG_PATH",
    str(Path(tempfile.gettempdir()) / "safeyolo-test.jsonl"),
)

# Use the checked-out CLI package when testing local edits.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli" / "src"))


@pytest.fixture(scope="session")
def _binary_cache(tmp_path_factory):
    """Cache a test NATS binary once per session for isolated Coord fixtures."""
    from safeyolo.coord import nats_runtime as nr

    cache_dir = tmp_path_factory.mktemp("nats-binary-cache")
    previous = os.environ.get("SAFEYOLO_COORD_DATA_DIR")
    os.environ["SAFEYOLO_COORD_DATA_DIR"] = str(cache_dir)
    try:
        try:
            return nr.ensure_binary()
        except Exception as error:
            pytest.skip(f"nats-server binary unavailable: {error!s}")
    finally:
        if previous is None:
            os.environ.pop("SAFEYOLO_COORD_DATA_DIR", None)
        else:
            os.environ["SAFEYOLO_COORD_DATA_DIR"] = previous
