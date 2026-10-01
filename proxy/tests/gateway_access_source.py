"""Owned source contract for POST /gateway/request-access.

The observations call the installed AgentAPI request dispatcher with finite
mitmproxy flows, a real ServiceRegistry populated by owned dataclasses, and a
captured write_event callback.  They never read the operational token, service
files, vault, database, socket, or network: the active-token helper, registry
singleton, and audit sink are replaced by owned in-memory seams.

Run with ``--write`` to freeze the adjacent JSON, or ``--check`` to rerun the
source handler and compare the complete deterministic document.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
CLI_SRC = ROOT / "cli" / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(CLI_SRC) not in sys.path:
    sys.path.insert(0, str(CLI_SRC))

from mitmproxy.test import taddons, tflow  # noqa: E402

from safeyolo.core.service_loader import (  # noqa: E402
    Capability,
    ContractTemplate,
    ServiceDefinition,
    ServiceRegistry,
)
from safeyolo.mitm_addons import agent_api  # noqa: E402
from safeyolo.proxy_modes.unix_listener import UnixMode  # noqa: E402

BASE_COMMIT = "eaf70cf54cd47d501b403132971ccf3c3c7b297a"
API_TOKEN = "owned-agent-api-token"
TRUSTED_AGENT = "owned-agent"
SERVICE_NAME = "owned-mail"
HOST = "mail.owned.invalid"

SOURCE_FILES = {
    "agent_api.py": "cli/src/safeyolo/mitm_addons/agent_api.py",
    "identity.py": "cli/src/safeyolo/core/identity.py",
    "service_loader.py": "cli/src/safeyolo/core/service_loader.py",
    "audit_schema.py": "cli/src/safeyolo/core/audit_schema.py",
    "utils.py": "cli/src/safeyolo/core/utils.py",
    "unix_listener.py": "cli/src/safeyolo/proxy_modes/unix_listener.py",
    "tokens.py": "pdp/tokens.py",
}


def _binding_contract() -> ContractTemplate:
    """Build the smallest grantable contract through source parser objects."""
    return ContractTemplate.from_dict(
        {
            "template": "owned-mail-read-v1",
            "bindings": {
                "folder": {
                    "source": "agent",
                    "type": "enum",
                    "options": ["inbox", "sent"],
                    "visible_to_operator": True,
                }
            },
            "operations": [
                {
                    "name": "read_messages",
                    "request": {
                        "method": "GET",
                        "path": "/v1/messages",
                    },
                }
            ],
            "enforcement": {"request_shape": "enforced"},
        }
    )


def _unenforceable_contract() -> ContractTemplate:
    return ContractTemplate.from_dict(
        {
            "template": "owned-mail-write-v1",
            "operations": [
                {
                    "name": "send_message",
                    "requires_enforcement": "response_validators",
                    "request": {"method": "POST", "path": "/v1/send"},
                }
            ],
            "enforcement": {"response_validators": "declared"},
        }
    )


def _registry() -> ServiceRegistry:
    """Return a real registry containing only the owned synthetic catalog."""
    service = ServiceDefinition(
        name=SERVICE_NAME,
        description="Owned source contract mail service",
        default_host=HOST,
        capabilities={
            "read": Capability(
                name="read",
                description="Read the owned mailbox",
            ),
            "bound": Capability(
                name="bound",
                description="Read a bound mailbox",
                contract=_binding_contract(),
            ),
            "blocked": Capability(
                name="blocked",
                description="Write a capability with an unavailable validator",
                contract=_unenforceable_contract(),
            ),
        },
    )
    registry = ServiceRegistry(
        ROOT / "owned-gateway-user-services",
        builtin_dir=ROOT / "owned-gateway-builtin-services",
    )
    registry._services = {SERVICE_NAME: service}
    return registry


def _request_body(spec: dict) -> bytes:
    if "body_hex" in spec:
        return bytes.fromhex(spec["body_hex"])
    return json.dumps(spec["body"], separators=(",", ":")).encode()


def _flow(spec: dict):
    flow = tflow.tflow(resp=False)
    flow.request.url = "http://_safeyolo.proxy.internal/gateway/request-access"
    flow.request.method = "POST"
    flow.request.headers["authorization"] = f"Bearer {API_TOKEN}"
    flow.request.content = _request_body(spec)
    flow.client_conn.peername = ("198.51.100.8", 4242)
    if spec.get("identity", "trusted") == "trusted":
        flow.client_conn.proxy_mode = UnixMode.parse(
            f"unix:/tmp/{flow.client_conn.peername[0]}_{TRUSTED_AGENT}/proxy.sock"
        )
    return flow


def _jsonable(value):
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _audit_view(event: str, kwargs: dict) -> dict:
    return {"event": event, **{key: _jsonable(value) for key, value in kwargs.items()}}


def _response_view(flow, events: list[dict]) -> dict:
    response = flow.response
    return {
        "status": response.status_code if response is not None else None,
        "body": json.loads(response.content) if response is not None else None,
        "headers": (
            [[name, value] for name, value in response.headers.items(multi=True)] if response is not None else []
        ),
        "audit": events,
        "identity": {
            "agent": flow.metadata.get("agent"),
            "status": flow.metadata.get("agent_identity_status"),
            "source": flow.metadata.get("agent_identity_source"),
        },
    }


class _QuietLog:
    """Keep source error-path logging out of mitmproxy's loop-owned logger."""

    def error(self, *_args, **_kwargs):
        return None

    def info(self, *_args, **_kwargs):
        return None


def observe_case(spec: dict, registry: ServiceRegistry | None) -> dict:
    flow = _flow(spec)
    events: list[dict] = []

    def audit(event, **kwargs):
        events.append(_audit_view(event, kwargs))
        if spec.get("audit_failure"):
            raise RuntimeError("owned audit callback failure")

    api = agent_api.AgentAPI()
    with ExitStack() as stack:
        stack.enter_context(taddons.context(api))
        stack.enter_context(patch("pdp.tokens.read_active_token", return_value=API_TOKEN))
        stack.enter_context(patch("safeyolo.core.service_loader.get_service_registry", return_value=registry))
        stack.enter_context(patch.object(agent_api, "write_event", autospec=True, side_effect=audit))
        stack.enter_context(patch.object(agent_api, "log", _QuietLog()))
        asyncio.run(api.request(flow))
    return {"name": spec["name"], "input": spec, **_response_view(flow, events)}


def cases() -> list[dict]:
    valid = {"service": SERVICE_NAME, "capability": "read", "reason": "owned inbox review"}
    return [
        {"name": "ordinary_no_contract_approval", "body": valid},
        {
            "name": "enforceable_binding_challenge",
            "body": {"service": SERVICE_NAME, "capability": "bound", "reason": "owned folder"},
        },
        {
            "name": "unenforceable_contract_response",
            "body": {"service": SERVICE_NAME, "capability": "blocked"},
        },
        {"name": "absent_trusted_identity", "identity": "absent", "body": valid},
        {"name": "absent_service_registry", "registry": "absent", "body": valid},
        {
            "name": "absent_service",
            "body": {"service": "missing-service", "capability": "read"},
        },
        {
            "name": "absent_capability",
            "body": {"service": SERVICE_NAME, "capability": "missing-capability"},
        },
        {"name": "malformed_body", "body_hex": "7b6e6f742d6a736f6e"},
        {"name": "missing_body", "body_hex": ""},
        {"name": "audit_failure_after_validation", "audit_failure": True, "body": valid},
    ]


def source_hashes() -> dict[str, str]:
    return {name: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() for name, relative in SOURCE_FILES.items()}


def document() -> dict:
    registry = _registry()
    rows = [observe_case(spec, None if spec.get("registry") == "absent" else registry) for spec in cases()]
    result = {
        "schema_version": 1,
        "source": "installed_agent_api_gateway_request_access",
        "base_commit": BASE_COMMIT,
        "versions": {
            "python": sys.version.split()[0],
            "mitmproxy": importlib.metadata.version("mitmproxy"),
        },
        "source_sha256": source_hashes(),
        "route": {
            "method": "POST",
            "path": "/gateway/request-access",
            "body": "JSON object with service, capability, and optional reason",
            "identity": "trusted UDS proxy-mode agent; metadata alone is not trusted",
            "catalog": "owned ServiceRegistry with one service and three capabilities",
        },
        "cases": rows,
    }
    assert_contract(result)
    return result


def _by_name(document_data: dict) -> dict[str, dict]:
    return {row["name"]: row for row in document_data["cases"]}


def assert_contract(document_data: dict) -> None:
    rows = _by_name(document_data)
    ordinary = rows["ordinary_no_contract_approval"]
    assert ordinary["status"] == 202
    assert ordinary["body"] == {
        "status": "pending",
        "agent": TRUSTED_AGENT,
        "service": SERVICE_NAME,
        "capability": "read",
        "reason": "owned inbox review",
        "message": "Access request submitted. Operator will review in watch.",
    }
    assert ordinary["identity"] == {
        "agent": TRUSTED_AGENT,
        "status": "resolved",
        "source": "uds",
    }
    assert len(ordinary["audit"]) == 1
    assert ordinary["audit"][0] == {
        "event": "gateway.request_access",
        "kind": "gateway",
        "severity": "critical",
        "summary": f"{TRUSTED_AGENT} requests {SERVICE_NAME}/read: owned inbox review",
        "decision": "require_approval",
        "host": HOST,
        "agent": TRUSTED_AGENT,
        "addon": "agent-api",
        "confirm_append": True,
        "approval": {
            "required": True,
            "approval_type": "service",
            "key": f"{TRUSTED_AGENT}:{SERVICE_NAME}",
            "target": SERVICE_NAME,
            "scope_hint": {
                "service": SERVICE_NAME,
                "capability": "read",
                "description": "Owned source contract mail service",
                "capability_description": "Read the owned mailbox",
                "reason": "owned inbox review",
                "proposed_lifetime": "session",
            },
        },
    }

    binding = rows["enforceable_binding_challenge"]
    assert binding["status"] == 200
    assert binding["body"] == {
        "decision": "needs_contract_binding",
        "service": SERVICE_NAME,
        "capability": "bound",
        "template": "owned-mail-read-v1",
        "bindings": {
            "folder": {
                "source": "agent",
                "type": "enum",
                "visible_to_operator": True,
                "options": ["inbox", "sent"],
            }
        },
        "grantable_operations": [{"name": "read_messages", "method": "GET", "path": "/v1/messages"}],
    }
    blocked = rows["unenforceable_contract_response"]
    assert blocked["status"] == 200
    assert blocked["body"] == {
        "decision": "contract_not_enforceable",
        "service": SERVICE_NAME,
        "capability": "blocked",
        "missing_tiers": ["response_validators"],
    }
    assert binding["audit"] == [] and blocked["audit"] == []

    assert rows["absent_trusted_identity"]["status"] == 403
    assert rows["absent_trusted_identity"]["body"] == {"error": "Could not identify agent"}
    assert rows["absent_trusted_identity"]["identity"] == {
        "agent": None,
        "status": "unavailable",
        "source": None,
    }
    assert rows["absent_service_registry"]["status"] == 503
    assert rows["absent_service_registry"]["body"] == {"error": "Service registry not available"}
    assert rows["absent_service"]["status"] == 404
    assert rows["absent_service"]["body"] == {"error": "Service 'missing-service' not found"}
    assert rows["absent_capability"]["status"] == 404
    assert rows["absent_capability"]["body"] == {
        "error": f"Capability 'missing-capability' not found in service '{SERVICE_NAME}'"
    }
    for name in (
        "absent_trusted_identity",
        "absent_service_registry",
        "absent_service",
        "absent_capability",
    ):
        assert rows[name]["audit"] == []

    assert rows["malformed_body"]["status"] == 400
    assert rows["malformed_body"]["body"] == {"error": "Invalid JSON body"}
    assert rows["malformed_body"]["audit"] == []
    assert rows["missing_body"]["status"] == 400
    assert rows["missing_body"]["body"] == {"error": "service and capability are required"}
    assert rows["missing_body"]["audit"] == []

    audit_failure = rows["audit_failure_after_validation"]
    assert audit_failure["status"] == 500
    assert audit_failure["body"] == {"error": "Internal error: RuntimeError"}
    assert len(audit_failure["audit"]) == 1
    assert audit_failure["audit"][0]["event"] == "gateway.request_access"
    assert audit_failure["audit"][0]["confirm_append"] is True
    assert audit_failure["identity"]["status"] == "resolved"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--write", action="store_true")
    modes.add_argument("--check", action="store_true")
    args = parser.parse_args()
    observed = document()
    rendered = json.dumps(observed, indent=2, ensure_ascii=True) + "\n"
    output = Path(__file__).with_suffix(".json")
    if args.write:
        output.write_text(rendered, encoding="utf-8")
        print(f"wrote {output}")
    elif args.check:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("gateway access source fixture differs")
        print(f"matched {len(observed['cases'])} gateway request-access source cases")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
