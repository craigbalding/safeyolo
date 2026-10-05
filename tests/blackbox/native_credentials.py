"""Seed synthetic test credentials through the native host command.

SAFEYOLO_NATIVE_CLI selects an installed native CLI. Source fixtures default to
the repository's debug artifact. This helper never reads or encrypts secrets.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


def store_credential(data_dir: Path, name: str, value: str, *, kind: str = "bearer",
                     refresh_token: str | None = None, token_url: str | None = None,
                     client_id: str | None = None, client_secret: str | None = None,
                     expires_at: str | None = None, binary: Path | None = None) -> None:
    """Write one synthetic record, without placing values in argv or output."""
    repository = Path(__file__).resolve().parents[2]
    binary = binary or Path(os.environ.get("SAFEYOLO_NATIVE_CLI", repository / "proxy/target/debug/safeyolo"))
    data_dir.mkdir(parents=True, exist_ok=True)
    # Keep input files outside the instance. The host command chooses the single
    # native store through this temporary config; it does not need a live proxy.
    with tempfile.TemporaryDirectory(prefix="credential-input-", dir=data_dir.parent) as temporary:
        root = Path(temporary)
        (root / "config.toml").write_text(f"data_dir={json.dumps(str(data_dir.resolve()))}\n")
        command = [str(binary), "--root", str(root), "credentials", "add", name, "--type", kind]
        for field, secret in (("value", value), ("refresh-token", refresh_token), ("client-secret", client_secret)):
            if secret is not None:
                path = root / field
                path.write_text(secret)
                path.chmod(0o600)
                command.extend([f"--{field}-file", str(path)])
        for field, content in (("token-url", token_url), ("client-id", client_id), ("expires-at", expires_at)):
            if content is not None:
                command.extend([f"--{field}", content])
        result = subprocess.run(command, capture_output=True, timeout=15, check=False)
        if result.returncode:
            # Failure output is deliberately not copied into a test report.
            raise RuntimeError(f"Native synthetic credential setup exited {result.returncode}; check SAFEYOLO_NATIVE_CLI")
