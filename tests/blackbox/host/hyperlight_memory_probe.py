"""Check only the memory observer with owned Python processes; run no VM/job.

From the prepared driver directory, use its existing Python/tomlkit environment:
python tests/blackbox/host/hyperlight_memory_probe.py --output /new/private/probe
The output prefix must have an existing parent and no prior .memory.json file.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import hyperlight_services as driver


def observe(prefix):
    memory_path = prefix.with_suffix(".memory.json")
    if memory_path.exists():
        raise FileExistsError(memory_path)
    helper = [sys.executable, "-c", "import time; memory=bytearray(16*1024*1024); time.sleep(10)"]
    program = ("import subprocess\n"
               f"child=subprocess.Popen({helper!r})\n"
               "print(child.pid, flush=True)\n"
               "try:\n input()\n"
               "except EOFError:\n pass\n"
               "finally:\n child.terminate()\n child.wait()\n")
    proxy = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    child = subprocess.Popen([sys.executable, "-c", program], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, text=True)
    try:
        helper_pid = int(child.stdout.readline())
        with driver.sample_job_memory(child, proxy, prefix):
            time.sleep(0.2)
            child.stdin.close()
            child.wait(timeout=5)
        sample = json.loads(memory_path.read_bytes())
        assert sample["error"] is None and sample["sample_count"] > 0, sample
        expected = {child.pid, helper_pid, proxy.pid}
        assert {row["pid"] for row in sample["peak"]["processes"]} == expected, sample
        assert sample["active_peak"] is not None, sample
        assert any(row["pid"] == helper_pid and row["parent_pid"] == child.pid
                   for row in sample["active_peak"]["processes"]), sample
        assert sample["peak"]["rss_sum_bytes"] > sample["idle"]["rss_sum_bytes"] > 0, sample
        assert [row["pid"] for row in sample["idle"]["processes"]] == [proxy.pid], sample
        vanished = driver.process_memory([child.pid, helper_pid])
        assert vanished["processes"] == [] and vanished["rss_sum_bytes"] == 0, vanished
        return {"uid": os.getuid(), "platform": sys.platform, "python": sys.version.split()[0],
                "driver_sha256": driver.digest(Path(driver.__file__)), "memory_path": str(memory_path),
                "sample": sample, "vanished": vanished, "native_vm_executed": False}
    finally:
        if not child.stdin.closed:
            child.stdin.close()
        try:
            child.wait(timeout=5)
        finally:
            try:
                driver.stop(proxy)
            finally:
                driver.stop(unrelated)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    print(json.dumps(observe(parser.parse_args().output), indent=2))
