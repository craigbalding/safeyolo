"""Regenerate native routing classifiers from SafeYolo's single source catalogue.

Run from the repository root with Python 3.12. This does not fetch provider data.
"""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
source = root / "cli/src/safeyolo/detection/credential_catalog.py"
spec = importlib.util.spec_from_file_location("safeyolo_credential_catalog_snapshot", source)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
rules = module.build_default_rule_configs()
output = root / "proxy/data/credential_guard"
output.mkdir(parents=True, exist_ok=True)
data = (json.dumps(rules, indent=2, ensure_ascii=True) + "\n").encode()
(output / "catalogue.json").write_bytes(data)
(output / "README.md").write_text(f"""# Credential routing catalogue

Generated from [`credential_catalog.py`](../../../cli/src/safeyolo/detection/credential_catalog.py)
by [`generate_credential_guard_data.py`](../../tools/generate_credential_guard_data.py).
The source and generated data are covered by the repository [MIT license](../../../LICENSE).
No external provider lookup runs during generation or request inspection.

- Source SHA-256: `{hashlib.sha256(source.read_bytes()).hexdigest()}`
- Generated SHA-256: `{hashlib.sha256(data).hexdigest()}`
- Routing rules: {len(rules)}
- Input: `build_default_rule_configs()` in source order. DLP-only patterns are excluded.

Regenerate from the repository root:

```sh
python proxy/tools/generate_credential_guard_data.py
```

The Rust historical oracle compares this snapshot to the actual Python catalogue.
""")
