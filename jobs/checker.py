"""The same offline input-size workload as the core-ABI Rust example."""

import json
from pathlib import Path

print(json.dumps({"input_bytes": len(Path("/input/request.json").read_bytes())}, separators=(",", ":")))
