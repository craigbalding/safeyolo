"""Diagnostic for initialized restores; this is not an adopted predicate."""

import builtins
import json
import os
import random
import time
from pathlib import Path

data = Path("/input/request.json").read_bytes()
request = json.loads(data)
started_ms = time.time_ns() // 1_000_000
initialized_random_state_inherited = random.getstate() == builtins._sy_initialized_random_state
builtins._sy_probe_calls = getattr(builtins, "_sy_probe_calls", 0) + 1
prior_file = Path("/work/prior-invocation")
inherited_file = prior_file.exists()
prior_file.write_text("invocation mutation")
if request.get("mode") == "fail":
    raise RuntimeError("requested predecessor failure")
if request.get("mode") == "spin":
    print("template-spin-entered", flush=True)
    while True:
        pass
if request.get("mode") == "hold":
    time.sleep(1)
print(json.dumps({
    "initialized_at": builtins._sy_initialized_ns,
    "calls": builtins._sy_probe_calls,
    "inherited_file": inherited_file,
    "initialized_random_state_inherited": initialized_random_state_inherited,
    "input": list(data),
    "completed_unix_ms": time.time_ns() // 1_000_000,
    "context": {"invocation_id": os.environ["SY_INVOCATION_ID"],
                "deadline_monotonic_ms": int(os.environ["SY_DEADLINE_MONOTONIC_MS"]),
                "unix_ms": started_ms,
                "random": list(os.urandom(32)), "runtime_random": random.random()},
}))
