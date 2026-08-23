"""
providers/onepassword.py - Resolve `op://vault/item/field` via the host `op` CLI.

The 1Password CLI runs on the host, authenticated by the operator (via `op signin`
or the desktop-integration session). The agent container never sees `op`
authentication material, and the resolved secret never appears in logs, exception
messages, or persisted config.

Resolution failures never carry secret material out — only a small non-secret
diagnostic (exit-class and sanitised ref). The subprocess is invoked with a list
of arguments (no shell), a hard timeout, and both stdout/stderr captured.
"""

from __future__ import annotations

import logging
import shutil
import subprocess

from safeyolo.core.credential_provider import (
    CredentialNotFound,
    ResolveFailed,
    ResolvedCredential,
)
from safeyolo.core.utils import sanitize_for_log

log = logging.getLogger("safeyolo.credential-provider.onepassword")

_OP_BINARY = "op"
_OP_TIMEOUT_SECONDS = 10.0

# `op read` documents these exit-code classes; we translate them into our
# non-secret error taxonomy. Anything else is a generic ResolveFailed.
_OP_NOT_FOUND_EXIT_CODES = frozenset({6})


class OnePasswordProvider:
    scheme = "op"

    def __init__(
        self,
        binary: str = _OP_BINARY,
        timeout: float = _OP_TIMEOUT_SECONDS,
    ):
        self._binary = binary
        self._timeout = timeout

    def _resolve_binary(self) -> str:
        path = shutil.which(self._binary)
        if path is None:
            raise ResolveFailed(
                f"1Password CLI '{self._binary}' is not installed on the host"
            )
        return path

    def resolve(self, ref: str) -> ResolvedCredential:
        if not ref.startswith("op://"):
            raise ResolveFailed(
                f"Reference '{sanitize_for_log(ref)}' is not an op:// URI"
            )
        binary = self._resolve_binary()
        try:
            result = subprocess.run(
                [binary, "read", "--no-newline", ref],
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ResolveFailed(
                f"1Password lookup for '{sanitize_for_log(ref)}' timed out after "
                f"{self._timeout:.0f}s"
            ) from exc
        except OSError as exc:
            # Never log exc.args — could echo command line back in some shells.
            raise ResolveFailed(
                f"Failed to invoke 1Password CLI for '{sanitize_for_log(ref)}': "
                f"{type(exc).__name__}"
            ) from None

        if result.returncode == 0:
            value = result.stdout.decode("utf-8", errors="strict")
            if not value:
                # `op read` returned zero but no data — treat as not-found so the
                # gateway can surface a useful message without leaking anything.
                raise CredentialNotFound(
                    f"1Password reference '{sanitize_for_log(ref)}' resolved to empty value"
                )
            return ResolvedCredential(value=value, type="bearer")

        # Non-zero exit. Do NOT return stderr verbatim — 1Password error output
        # occasionally echoes the ref or nearby item names.
        if result.returncode in _OP_NOT_FOUND_EXIT_CODES:
            raise CredentialNotFound(
                f"1Password has no item at '{sanitize_for_log(ref)}'"
            )
        log.warning(
            "op read exit=%s for ref=%s",
            result.returncode,
            sanitize_for_log(ref),
        )
        raise ResolveFailed(
            f"1Password lookup for '{sanitize_for_log(ref)}' failed "
            f"(exit={result.returncode})"
        )

    def refresh(self, ref: str) -> ResolvedCredential | None:
        # 1Password items are not OAuth2-refreshable through this path; a fresh
        # `resolve()` call already returns the current stored value.
        return None
