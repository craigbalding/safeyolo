"""Real-ingress hostname evidence through mitmproxy, NetworkGuard and PDP."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest
from mitmproxy.test import taddons, tflow
from network_guard import NetworkGuard, detect_homoglyph_attack

from experiments.policy_assurance.harness import append_observation
from pdp import PolicyClientConfig, configure_policy_client, reset_policy_client


@dataclass(frozen=True)
class HostObservation:
    raw_url: str
    host_header: str | None
    request_host: str
    pretty_host: str
    port: int
    homoglyph: bool
    final_decision: str


CASES = (
    ("https://api.example.com/path", None),
    ("https://API.EXAMPLE.COM/path", None),
    ("https://api.example.com./path", None),
    ("https://trusted.example/path", None),
    ("https://child.trusted.example/path", None),
    ("https://deep.child.trusted.example/path", None),
    ("https://eviltrusted.example/path", None),
    ("https://xn--bcher-kva.example/path", None),
    ("https://bücher.example/path", None),
    ("https://api。example.com/path", None),
    ("http://127.0.0.1/path", None),
    ("http://0177.0.0.1/path", None),
    ("http://[::1]/path", None),
    ("https://api.example.com:8443/path", "API.EXAMPLE.COM:8443"),
    ("https://api.example.com/path", "untrusted.invalid"),
)


@pytest.fixture
def ingress(tmp_path: Path):
    policy = tmp_path / "host-policy.toml"
    policy.write_text(
        """[metadata]
version = "2.0"

[hosts]
"api.example.com" = { rate = 100000 }
"*.trusted.example" = { rate = 100000 }
"xn--bcher-kva.example" = { rate = 100000 }
"*" = { egress = "deny" }
"""
    )
    reset_policy_client()
    configure_policy_client(PolicyClientConfig(baseline_path=policy))
    addon = NetworkGuard()
    with taddons.context(addon) as context:
        context.options.network_guard_enabled = True
        context.options.network_guard_block = True
        context.options.network_guard_homoglyph = True
        yield addon
    reset_policy_client()


def _observe(addon: NetworkGuard, raw_url: str, host_header: str | None) -> HostObservation:
    flow = tflow.tflow()
    parsed = urlsplit(raw_url)
    hostname = parsed.hostname or ""
    wire_hostname = hostname.encode("idna").decode("ascii")
    if ":" in wire_hostname:
        wire_hostname = f"[{wire_hostname}]"
    wire_authority = wire_hostname
    if parsed.port is not None:
        wire_authority += f":{parsed.port}"
    flow.request.url = urlunsplit((parsed.scheme, wire_authority, parsed.path, parsed.query, parsed.fragment))
    if host_header is not None:
        flow.request.headers["Host"] = host_header
    request_host = flow.request.host
    pretty_host = flow.request.pretty_host
    port = flow.request.port
    homoglyph = bool(detect_homoglyph_attack(request_host))
    addon.request(flow)
    if flow.response is None:
        decision = "allow"
    elif flow.response.status_code == 428:
        decision = "prompt"
    else:
        decision = "deny"
    result = HostObservation(
        raw_url=raw_url,
        host_header=flow.request.headers.get("Host"),
        request_host=request_host,
        pretty_host=pretty_host,
        port=port,
        homoglyph=homoglyph,
        final_decision=decision,
    )
    append_observation({"status": "OBSERVATION", "family": "hostname", **asdict(result)})
    return result


def test_real_ingress_hostname_matrix_records_evidence(ingress: NetworkGuard) -> None:
    observations = [_observe(ingress, *case) for case in CASES]
    assert len(observations) == len(CASES)
    assert any(item.request_host != item.pretty_host for item in observations)


def test_dns_case_is_insensitive_at_real_ingress(ingress: NetworkGuard) -> None:
    lower = _observe(ingress, "https://api.example.com/", None)
    upper = _observe(ingress, "https://API.EXAMPLE.COM/", None)
    assert lower.final_decision == upper.final_decision == "allow"


def test_wildcard_dns_case_is_insensitive_at_real_ingress(ingress: NetworkGuard) -> None:
    lower = _observe(ingress, "https://child.trusted.example/", None)
    upper = _observe(ingress, "https://CHILD.TRUSTED.EXAMPLE/", None)
    assert lower.final_decision == upper.final_decision == "allow"


def test_wildcards_keep_dns_label_boundaries(ingress: NetworkGuard) -> None:
    apex = _observe(ingress, "https://trusted.example/", None)
    child = _observe(ingress, "https://child.trusted.example/", None)
    deep = _observe(ingress, "https://deep.child.trusted.example/", None)
    sibling = _observe(ingress, "https://eviltrusted.example/", None)
    assert {child.final_decision, deep.final_decision} == {"allow"}
    assert sibling.final_decision == "deny"
    append_observation(
        {
            "status": "OBSERVATION",
            "family": "wildcard-apex",
            "final_decision": apex.final_decision,
        }
    )


def test_same_mitmproxy_host_has_one_effective_decision(ingress: NetworkGuard) -> None:
    observations = [_observe(ingress, *case) for case in CASES]
    by_host: dict[str, set[str]] = {}
    for item in observations:
        by_host.setdefault(item.request_host, set()).add(item.final_decision)
    assert all(len(decisions) == 1 for decisions in by_host.values()), by_host


def test_trailing_dot_idna_and_authority_are_non_normative_observations(
    ingress: NetworkGuard,
) -> None:
    cases = (
        ("https://api.example.com./", None),
        ("https://bücher.example/", None),
        ("https://xn--bcher-kva.example/", None),
        ("https://api。example.com/", None),
        ("https://api.example.com:9443/", "other.invalid:9443"),
    )
    assert all(_observe(ingress, *case).final_decision for case in cases)
