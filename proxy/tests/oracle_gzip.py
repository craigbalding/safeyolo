"""Platform-stable gzip input for checked-in Python source oracles."""

import gzip


def compress(payload: bytes) -> bytes:
    """Use the goldens' OS byte without changing any other compressed byte."""
    encoded = gzip.compress(payload, mtime=0)
    return encoded[:9] + b"\x03" + encoded[10:]
