#!/usr/bin/env python3
"""Prepare the accepted access-only provisioning input for one Claude attempt."""

from __future__ import annotations

import argparse
import base64
import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def require_private(info: os.stat_result) -> None:
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("input and provisioning paths must be private and operator-owned")


def read_private(path: Path) -> bytes:
    """Read a private operator-owned file through its checked descriptor."""
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        require_private(info)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("access input must be a regular file")
        return stream.read()


def read_access(source: Path) -> dict:
    """Decrypt the existing access-only handoff in memory; retain no plaintext."""
    require_private(source.stat())
    sealed = json.loads(read_private(source / "sealed-access.json"))
    key = serialization.load_pem_private_key(read_private(source / "transport-private.pem"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("expected the receiver's RSA transport key")
    transport = key.decrypt(base64.b64decode(sealed["wrapped_key"], validate=True),
                            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    access = json.loads(Fernet(transport).decrypt(sealed["ciphertext"].encode()))
    if not isinstance(access, dict) or set(access) != {"value", "expires_at", "source_expires_at"}:
        raise ValueError("expected access-only payload")
    if not isinstance(access["value"], str) or not access["value"]:
        raise ValueError("access value must be a nonempty string")
    expires = datetime.fromisoformat(access["expires_at"])
    source_expires = datetime.fromisoformat(access["source_expires_at"])
    # The existing consumer requires more than ten minutes of remaining access.
    if (expires.utcoffset() is None or source_expires.utcoffset() is None
            or not datetime.now(UTC) + timedelta(minutes=10) < expires <= source_expires):
        raise ValueError("access expiry is not usable")
    return access


def prepare(source: Path, output: Path) -> None:
    """Create fresh transport files; an existing attempt is never overwritten."""
    os.umask(0o077)
    require_private(output.parent.stat())
    output.mkdir(mode=0o700)
    access = read_access(source)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transport = Fernet.generate_key()
    wrapped = key.public_key().encrypt(
        transport, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    envelope = {"wrapped_key": base64.b64encode(wrapped).decode(),
                "ciphertext": Fernet(transport).encrypt(json.dumps(access).encode()).decode()}
    with (output / "transport-private.pem").open("xb") as stream:
        stream.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    with (output / "sealed-access.json").open("x") as stream:
        json.dump(envelope, stream)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Private directory with the existing sealed access-only handoff")
    parser.add_argument("--output", type=Path, required=True, help="New per-attempt provisioning directory")
    args = parser.parse_args()
    try:
        prepare(args.source, args.output)
    except (OSError, ValueError, TypeError, KeyError, InvalidToken) as exc:
        # JSON parsing diagnostics can contain private input. Report only the class.
        print("Claude access preparation failed: " + type(exc).__name__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
