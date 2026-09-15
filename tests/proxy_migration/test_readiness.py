"""A retained marker cannot establish readiness for a different proxy child."""

import json
import os
import sys

from tests.proxy_migration.harness import child_process, wait_ready


def test_readiness_waits_for_this_child(tmp_path):
    marker = tmp_path / "ready.json"
    marker.write_text(json.dumps({"ready": True, "pid": 2147483647}))
    script = """
import json, os, sys, time
from pathlib import Path
time.sleep(0.2)
Path(sys.argv[1]).write_text(json.dumps({'ready': True, 'pid': os.getpid()}))
time.sleep(30)
"""
    with child_process([sys.executable, "-c", script, str(marker)], tmp_path, os.environ.copy()) as child:
        wait_ready(child, [marker], tmp_path / "process.log", readiness_file=marker)
        assert json.loads(marker.read_text())["pid"] == child.pid
