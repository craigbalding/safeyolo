"""Drift check between the trace manifest and the addon-load list.

The manifest (`safeyolo.core.trace.EXPECTED_ADDONS`) is deliberately
independent of module import (issue #213 second-pass review). But it
still has to stay in step with:

- `safeyolo.proxy.ADDON_CHAIN`: the actual .py files loaded into the
  mitmproxy subprocess. Every trace-participating addon named in the
  manifest must correspond to a file present in ADDON_CHAIN. Otherwise
  `/trace` reports `not_loaded` for an addon we never intended to load,
  which would be noise.

- The `trace_expected = True` class attribute on `SecurityAddon`
  subclasses (documentation-only). Every subclass so marked must appear
  in the manifest, and every SecurityAddon addon in the manifest must
  actually be marked. Prevents copy-paste drift where a new addon lands
  without updating the manifest.
"""

from __future__ import annotations

import importlib

from safeyolo.core.trace import EXPECTED_ADDONS

# Mapping from an addon's mitmproxy `.name` attribute to the .py file that
# defines it. Only trace-participating addons are enumerated — the manifest
# is the closed set here, so any new entry has to be added deliberately.
NAME_TO_FILE = {
    "service-gateway": "service_gateway.py",
    "network-guard": "network_guard.py",
    "circuit-breaker": "circuit_breaker.py",
    "credential-guard": "credential_guard.py",
    "pattern-scanner": "pattern_scanner.py",
    "test-context": "test_context.py",
}


def test_manifest_names_map_to_known_addon_files():
    unknown = [name for name in EXPECTED_ADDONS if name not in NAME_TO_FILE]
    assert not unknown, (
        f"manifest names have no NAME_TO_FILE mapping: {unknown}. "
        f"Add them to NAME_TO_FILE in this test or remove from EXPECTED_ADDONS."
    )


def test_every_manifest_addon_is_in_addon_chain():
    from safeyolo.proxy import ADDON_CHAIN

    missing = [
        name for name in EXPECTED_ADDONS if NAME_TO_FILE[name] not in ADDON_CHAIN
    ]
    assert not missing, (
        f"manifest lists trace-participating addons not present in "
        f"proxy.ADDON_CHAIN: {missing}. Either add them to ADDON_CHAIN or "
        f"remove them from EXPECTED_ADDONS — /trace would otherwise report "
        f"them as `not_loaded` for every request."
    )


def test_trace_expected_class_attribute_matches_manifest():
    """Every SecurityAddon subclass with `trace_expected = True` must appear
    in the manifest, and every SecurityAddon addon in the manifest must have
    its class marker set. Prevents the code and the manifest drifting apart.
    """
    # Force-import the participating modules so their subclasses exist.
    from safeyolo.core.base import SecurityAddon

    for module_name in (
        "credential_guard", "pattern_scanner", "network_guard",
        "circuit_breaker", "test_context",
    ):
        importlib.import_module(module_name)

    marked = {
        cls.name for cls in _walk_subclasses(SecurityAddon)
        if getattr(cls, "trace_expected", False)
    }
    manifest = set(EXPECTED_ADDONS)

    # SecurityAddon-based expected addons must be marked. Non-SecurityAddon
    # participants (service-gateway) don't have this attribute — filter them
    # out via NAME_TO_FILE knowledge rather than reflection.
    security_addon_expected = {
        name for name in manifest
        if name in NAME_TO_FILE and name != "service-gateway"
    }

    unmarked = security_addon_expected - marked
    stray = marked - security_addon_expected
    assert not unmarked, (
        f"manifest lists SecurityAddon-based addons without "
        f"`trace_expected = True`: {unmarked}"
    )
    assert not stray, (
        f"`trace_expected = True` set on addons not in the manifest: {stray}"
    )


def _walk_subclasses(cls):
    seen = set()
    stack = [cls]
    while stack:
        parent = stack.pop()
        for sub in parent.__subclasses__():
            if sub in seen:
                continue
            seen.add(sub)
            stack.append(sub)
            yield sub
