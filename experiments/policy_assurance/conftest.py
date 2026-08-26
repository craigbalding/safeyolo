"""Local pytest setup for policy experiments invoked outside normal testpaths."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# Set this before policy modules import core.utils, which resolves the audit path
# at import time. Experiment output should report policy evidence, not failures
# caused by the container-only /app/logs default being absent on a developer host.
os.environ.setdefault(
    "SAFEYOLO_LOG_PATH",
    str(Path(tempfile.gettempdir()) / f"safeyolo-policy-experiment-{os.getpid()}.jsonl"),
)

ROOT = Path(__file__).resolve().parents[2]
CLI_SRC = ROOT / "cli" / "src"
MITM_ADDONS = CLI_SRC / "safeyolo" / "mitm_addons"
for source in (ROOT, CLI_SRC, MITM_ADDONS):
    sys.path.insert(0, str(source))
