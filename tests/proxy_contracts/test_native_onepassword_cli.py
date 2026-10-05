"""Optional #819 C3 witness: a real authenticated host op and synthetic item.

Run with SAFEYOLO_819_OP_EXECUTABLE=/absolute/path/to/op and
SAFEYOLO_819_OP_REFERENCE=op://VAULT/DEDICATED-SYNTHETIC-ITEM/FIELD. The approved
item's value must be synthetic-native-external-credential-819. Authentication
must already be available in the host environment. Bind its nonsecret method
and setup identity in SAFEYOLO_819_OP_AUTH_METHOD and SAFEYOLO_819_OP_SETUP_ID. This host listener witness
is distinct from the required guest isolation observation.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

import pytest

from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_native_credentials_cli import (
    EXTERNAL,
    POLICY,
    authorize,
    cli,
    deliver,
    setup,
    surfaces,
    token,
)
from tests.proxy_contracts.test_native_policy_cli import native_instance


@pytest.mark.skipif(
    not (os.environ.get("SAFEYOLO_819_OP_EXECUTABLE") and os.environ.get("SAFEYOLO_819_OP_REFERENCE")),
    reason="C3 requires an approved real host op/authentication setup and dedicated synthetic item",
)
def test_real_onepassword_resolves_only_after_host_approval(tmp_path):
    executable = Path(os.environ["SAFEYOLO_819_OP_EXECUTABLE"])
    reference = os.environ["SAFEYOLO_819_OP_REFERENCE"]
    method = os.environ["SAFEYOLO_819_OP_AUTH_METHOD"]
    setup_identity = os.environ["SAFEYOLO_819_OP_SETUP_ID"]
    assert method and setup_identity  # nonsecret identifiers bound before execution
    assert executable.is_absolute() and reference.startswith("op://")
    version = subprocess.run([str(executable), "--version"], capture_output=True, text=True,
                             check=True, timeout=10).stdout.strip()
    assert version and EXTERNAL not in version
    # Count actual resolver invocations while delegating every read to real op.
    # No authentication or resolved value is recorded by the wrapper.
    calls, wrapper = tmp_path / "op-calls", tmp_path / "count-op"
    wrapper.write_text("#!/bin/sh\nprintf 'read\\n' >> " + shlex.quote(str(calls)) +
                       "\nexec " + shlex.quote(str(executable)) + ' "$@"\n')
    wrapper.chmod(0o700)
    with origin_server(capture_heads=True) as origin, native_instance(
        tmp_path, POLICY, services=True, capture=True,
        extra_config=f'onepassword_executable={json.dumps(str(wrapper))}\n',
    ) as instance:
        setup(instance, tmp_path)
        cli(instance, "credentials", "reference", "external", "--provider", "onepassword",
            "--reference", reference)
        authorize(instance, "external")
        credential = token(instance)
        deliver(instance, origin, credential, agent="bob", status=403)
        deliver(instance, origin, credential, path="/notes/risky", status=428)
        assert not calls.exists()
        cli(instance, "services", "approve", "alice", "notes", "GET", "/notes/risky")
        deliver(instance, origin, credential, path="/notes/risky", value=EXTERNAL, timeout=15)
        assert calls.read_text().splitlines() == ["read"]
        surfaces(instance)
    # Report only the nonsecret tool version and observations, never the value.
    print(json.dumps({"op_version": version, "authentication_method": method,
                      "setup_identity": setup_identity, "resolver_invocations": 1,
                      "denied_and_pending_invocations": 0, "exact_synthetic_value_matched": True}))
