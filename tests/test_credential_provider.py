"""Tests for the provider-neutral credential resolver + built-in providers."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

# Import the package so built-in providers register themselves.
import safeyolo.core.providers  # noqa: F401
from safeyolo.core.credential_provider import (
    CredentialNotFound,
    ResolveFailed,
    ResolvedCredential,
    UnknownScheme,
    _reset_for_tests,
    _split_ref,
    get_provider,
    refresh_credential,
    register_provider,
    resolve_credential,
    strip_scheme,
)
from safeyolo.core.providers.local import LocalVaultProvider
from safeyolo.core.providers.onepassword import OnePasswordProvider
from safeyolo.core.vault import Vault, VaultCredential


# --- Helpers --------------------------------------------------------------


class _StubProvider:
    """Minimal in-memory provider for isolating dispatcher tests."""

    def __init__(self, scheme: str, values: dict[str, str] | None = None):
        self.scheme = scheme
        self._values = values or {}

    def resolve(self, ref: str) -> ResolvedCredential:
        if ref not in self._values:
            raise CredentialNotFound(f"stub has no {ref}")
        return ResolvedCredential(value=self._values[ref], type="bearer")


@pytest.fixture
def clean_registry():
    """Give each test a pristine provider registry with only the built-ins."""
    _reset_for_tests()
    from safeyolo.core.providers import register_builtin_providers

    register_builtin_providers()
    yield
    _reset_for_tests()
    register_builtin_providers()


# --- Reference parsing ----------------------------------------------------


class TestSplitRef:
    def test_bare_name_is_local(self):
        assert _split_ref("github-pat") == ("local", "github-pat")

    def test_local_scheme_explicit(self):
        assert _split_ref("local://github-pat") == ("local", "github-pat")

    def test_op_scheme(self):
        assert _split_ref("op://Engineering/GitHub PAT/credential") == (
            "op",
            "Engineering/GitHub PAT/credential",
        )

    def test_unknown_scheme_preserved(self):
        """We keep the scheme so the dispatcher can fail closed with a real name."""
        scheme, _rest = _split_ref("vault://path/to/secret")
        assert scheme == "vault"

    def test_names_with_colon_are_treated_as_local(self):
        # A bare name that happens to contain a colon (odd, but possible) —
        # only "://" is a scheme delimiter, so this must not parse as a scheme.
        assert _split_ref("weird:name") == ("local", "weird:name")

    def test_empty_ref_is_local(self):
        assert _split_ref("") == ("local", "")


class TestStripScheme:
    def test_bare_name_unchanged(self):
        assert strip_scheme("github-pat") == "github-pat"

    def test_local_scheme_stripped(self):
        assert strip_scheme("local://github-pat") == "github-pat"

    def test_op_scheme_stripped(self):
        assert strip_scheme("op://Vault/Item/field") == "Vault/Item/field"


# --- Dispatcher fail-closed behaviour -------------------------------------


class TestResolveCredentialFailClosed:
    def test_unknown_scheme_raises(self, clean_registry):
        """Unrecognised URI scheme must NEVER fall through to local vault."""
        with pytest.raises(UnknownScheme):
            resolve_credential("vault://oops/i/leaked")

    def test_unknown_scheme_error_contains_no_secret_bits(self, clean_registry):
        """The exception message identifies the scheme but never the value."""
        with pytest.raises(UnknownScheme) as excinfo:
            resolve_credential("hashicorp://kv/data/prod/api-key-CAFE")
        message = str(excinfo.value)
        # The scheme is fair game; the path (which could name a secret item)
        # must not appear verbatim.
        assert "hashicorp" in message
        assert "api-key-CAFE" not in message
        assert "prod" not in message


class TestDispatchToRegisteredProvider:
    def test_bare_name_routes_to_local(self, clean_registry):
        # Replace the local provider with a stub so we can prove routing.
        register_provider(_StubProvider(scheme="local", values={"github-pat": "s3cret"}))
        cred = resolve_credential("github-pat")
        assert cred.value == "s3cret"

    def test_explicit_local_scheme_routes_to_local(self, clean_registry):
        # A stub that records which ref it was asked about.
        seen: list[str] = []

        class _RecordingStub:
            scheme = "local"

            def resolve(self, ref):
                seen.append(ref)
                return ResolvedCredential(value="ok", type="bearer")

        register_provider(_RecordingStub())
        resolve_credential("local://github-pat")
        assert seen == ["local://github-pat"]

    def test_new_provider_registers_by_scheme(self, clean_registry):
        register_provider(_StubProvider(scheme="stub", values={"stub://x": "v"}))
        cred = resolve_credential("stub://x")
        assert cred.value == "v"

    def test_refresh_returns_none_for_provider_without_support(self, clean_registry):
        # OnePassword provider registered by builtin — refresh always None.
        assert refresh_credential("op://Vault/Item/field") is None


# --- Local provider -------------------------------------------------------


class TestLocalVaultProvider:
    def _make_vault(self, tmp_path, creds):
        vault_path = tmp_path / "vault.yaml.enc"
        v = Vault(vault_path)
        v.unlock("pw")
        for c in creds:
            v.store(c)
        return v

    def test_resolves_bare_name(self, tmp_path):
        vault = self._make_vault(tmp_path, [VaultCredential(name="gh", type="bearer", value="gho_test")])
        with patch("safeyolo.core.providers.local.get_vault", return_value=vault):
            cred = LocalVaultProvider().resolve("gh")
        assert cred.value == "gho_test"
        assert cred.type == "bearer"

    def test_resolves_local_scheme(self, tmp_path):
        vault = self._make_vault(tmp_path, [VaultCredential(name="gh", type="bearer", value="gho_test")])
        with patch("safeyolo.core.providers.local.get_vault", return_value=vault):
            cred = LocalVaultProvider().resolve("local://gh")
        assert cred.value == "gho_test"

    def test_missing_raises_not_found(self, tmp_path):
        vault = self._make_vault(tmp_path, [])
        with patch("safeyolo.core.providers.local.get_vault", return_value=vault):
            with pytest.raises(CredentialNotFound):
                LocalVaultProvider().resolve("nope")

    def test_no_vault_raises_resolve_failed(self):
        with patch("safeyolo.core.providers.local.get_vault", return_value=None):
            with pytest.raises(ResolveFailed):
                LocalVaultProvider().resolve("gh")


# --- 1Password provider ---------------------------------------------------


class TestOnePasswordProvider:
    def test_success_returns_value(self):
        provider = OnePasswordProvider()
        completed = MagicMock(returncode=0, stdout=b"ghp_realtoken", stderr=b"")
        with patch("shutil.which", return_value="/usr/local/bin/op"), \
             patch("subprocess.run", return_value=completed):
            cred = provider.resolve("op://Engineering/GitHub PAT/credential")
        assert cred.value == "ghp_realtoken"
        assert cred.type == "bearer"

    def test_reference_must_be_op_scheme(self):
        with pytest.raises(ResolveFailed):
            OnePasswordProvider().resolve("not-an-op-ref")

    def test_missing_binary_fails_closed(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(ResolveFailed):
                OnePasswordProvider().resolve("op://Vault/Item/field")

    def test_timeout_fails_closed_no_leak(self):
        provider = OnePasswordProvider(timeout=0.001)
        with patch("shutil.which", return_value="/usr/local/bin/op"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="op", timeout=0.001)):
            with pytest.raises(ResolveFailed) as excinfo:
                provider.resolve("op://Vault/Item/field")
        # No secret-shaped content in the message — should be a bounded diagnostic.
        msg = str(excinfo.value)
        assert "timed out" in msg
        assert "op://Vault/Item/field" in msg  # ref is fine to echo (name only)

    def test_not_found_exit_code_maps_to_not_found(self):
        # Do NOT echo stderr back through the exception — even if op prints it.
        completed = MagicMock(
            returncode=6,
            stdout=b"",
            stderr=b"[ERROR] 2024/03/05 12:00:00 secret ghp_LEAKY_TOKEN_FROM_ANOTHER_ITEM",
        )
        with patch("shutil.which", return_value="/usr/local/bin/op"), \
             patch("subprocess.run", return_value=completed):
            with pytest.raises(CredentialNotFound) as excinfo:
                OnePasswordProvider().resolve("op://Vault/Missing/field")
        assert "ghp_LEAKY_TOKEN_FROM_ANOTHER_ITEM" not in str(excinfo.value)

    def test_generic_failure_does_not_expose_stderr(self):
        completed = MagicMock(
            returncode=99,
            stdout=b"",
            stderr=b"secret leaked: ghp_ANOTHER_ONE",
        )
        with patch("shutil.which", return_value="/usr/local/bin/op"), \
             patch("subprocess.run", return_value=completed):
            with pytest.raises(ResolveFailed) as excinfo:
                OnePasswordProvider().resolve("op://Vault/Item/field")
        assert "ghp_ANOTHER_ONE" not in str(excinfo.value)
        assert "exit=99" in str(excinfo.value)

    def test_empty_output_treated_as_not_found(self):
        completed = MagicMock(returncode=0, stdout=b"", stderr=b"")
        with patch("shutil.which", return_value="/usr/local/bin/op"), \
             patch("subprocess.run", return_value=completed):
            with pytest.raises(CredentialNotFound):
                OnePasswordProvider().resolve("op://Vault/Empty/field")

    def test_refresh_is_noop(self):
        assert OnePasswordProvider().refresh("op://Vault/Item/field") is None


# --- Registry sanity ------------------------------------------------------


def test_builtin_providers_registered():
    assert isinstance(get_provider("local"), LocalVaultProvider)
    assert isinstance(get_provider("op"), OnePasswordProvider)
