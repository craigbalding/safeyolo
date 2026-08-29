"""Tests for contract enforcement logic in service_gateway.py."""

import json
import socket
import subprocess
import threading

import pytest
from mitmproxy.http import Headers
from mitmproxy.test import tflow
from service_gateway import (
    ContractBindingState,
    ServiceGateway,
    _check_ambiguous_encoding,
    _extract_path_params,
    _reject_duplicate_json_keys,
)

from safeyolo.core.service_loader import (
    AuthConfig,
    BodyConstraint,
    Capability,
    CapabilityRoute,
    ContractOperation,
    ContractTemplate,
    EnforcementStatus,
    QueryConstraint,
    ServiceDefinition,
    TransportConstraint,
)
from safeyolo.detection.matching import reject_path_tricks

pytestmark = pytest.mark.assurance_boundary

# --- Helpers ---


def _make_flow(method="GET", path="/test", headers=None, body=None, query=""):
    """Create a real mitmproxy flow while preserving the raw request target."""
    flow = tflow.tflow()
    flow.request.method = method
    flow.request.path = f"{path}?{query}" if query else path
    flow.request.host = "example.com"
    flow.request.scheme = "https"
    flow.request.content = body.encode() if isinstance(body, str) else body
    flow.request.headers = Headers()
    for name, value in (headers or {}).items():
        flow.request.headers[name] = value
    flow.response = None
    return flow


def _make_binding_state(bound_values=None, grantable_ops=None):
    return ContractBindingState(
        binding_id="cbs_test123",
        agent="claude",
        service="gmail",
        capability="read_messages",
        template="gmail.read_messages.v1",
        bound_values=bound_values or {"approved_category": "CATEGORY_PROMOTIONS"},
        grantable_operations=grantable_ops or ["list_messages"],
    )


def _make_contract(operations=None, enforcement=None):
    """Create a ContractTemplate with sensible defaults."""
    if enforcement is None:
        enforcement = EnforcementStatus(
            request_shape="enforced",
            transport_hygiene="enforced",
        )
    if operations is None:
        operations = [
            ContractOperation(
                name="list_messages",
                method="GET",
                path="/gmail/v1/users/me/messages",
                transport=TransportConstraint(
                    require_no_body=True,
                    allow_headers=["Accept", "User-Agent"],
                    deny_ambiguous_encoding=True,
                ),
                query_allow={
                    "labelIds": QueryConstraint(equals_var="approved_category"),
                    "maxResults": QueryConstraint(integer_range=[1, 100]),
                    "pageToken": QueryConstraint(type="string"),
                },
                query_deny_unknown=True,
            ),
        ]
    return ContractTemplate(
        template="gmail.read_messages.v1",
        bindings={},
        operations=operations,
        enforcement=enforcement,
    )


def _make_contract_flow(method="GET", path="/test", headers=None, body=None, query="",
                         header_fields=None):
    """Create a real flow with optional duplicate raw header fields.

    Args:
        headers: dict of headers (no duplicates)
        header_fields: list of (name, value) tuples for raw fields (supports duplicates)
    """
    flow = _make_flow(method=method, path=path, headers=headers, body=body, query=query)

    if header_fields is not None:
        flow.request.headers = Headers(
            fields=[(k.encode(), v.encode()) for k, v in header_fields]
        )
    return flow


def _make_service(auth_header="Authorization"):
    """Create the same concrete service definition used by the gateway."""
    return ServiceDefinition(
        name="test-service",
        auth=AuthConfig(type="bearer", header=auth_header),
    )


def _make_capability_with_contract(contract=None):
    return Capability(
        name="read_messages",
        description="Read-only access",
        routes=[
            CapabilityRoute(methods=["GET"], path="/gmail/v1/users/me/messages"),
            CapabilityRoute(methods=["GET"], path="/gmail/v1/users/me/messages/*"),
        ],
        contract=contract or _make_contract(),
    )


# --- Operation Matching ---


class TestOperationMatching:
    def test_exact_match(self):
        contract = _make_contract()
        op = contract.match_operation("GET", "/gmail/v1/users/me/messages")
        assert op is not None
        assert op.name == "list_messages"

    def test_method_mismatch(self):
        contract = _make_contract()
        op = contract.match_operation("POST", "/gmail/v1/users/me/messages")
        assert op is None

    def test_path_mismatch(self):
        contract = _make_contract()
        op = contract.match_operation("GET", "/gmail/v1/users/me/threads")
        assert op is None

    def test_parameterized_match(self):
        ops = [
            ContractOperation(name="get_item", method="GET", path="/api/items/{id}"),
        ]
        enforcement = EnforcementStatus(request_shape="enforced")
        contract = _make_contract(operations=ops, enforcement=enforcement)
        op = contract.match_operation("GET", "/api/items/123")
        assert op is not None
        assert op.name == "get_item"

    def test_exact_preferred_over_parameterized(self):
        ops = [
            ContractOperation(name="list_items", method="GET", path="/api/items"),
            ContractOperation(name="get_item", method="GET", path="/api/{collection}"),
        ]
        enforcement = EnforcementStatus(request_shape="enforced")
        contract = _make_contract(operations=ops, enforcement=enforcement)
        op = contract.match_operation("GET", "/api/items")
        assert op is not None
        assert op.name == "list_items"

    def test_non_grantable_excluded(self):
        ops = [
            ContractOperation(
                name="guarded",
                method="GET",
                path="/api/items/{id}",
                requires_enforcement="state_enforcement",
            ),
        ]
        enforcement = EnforcementStatus(
            request_shape="enforced",
            state_enforcement="declared",
        )
        contract = _make_contract(operations=ops, enforcement=enforcement)
        op = contract.match_operation("GET", "/api/items/123")
        assert op is None


# --- Transport Enforcement ---


def _enforce(gateway, flow, op, binding=None, service=None):
    """Run _enforce_contract with minimal wiring for a single operation."""
    if binding is None:
        binding = _make_binding_state(grantable_ops=[op.name])
    if service is None:
        service = _make_service()
    contract = _make_contract(operations=[op])
    capability = _make_capability_with_contract(contract)
    # Override routes to match the operation path
    capability.routes = [CapabilityRoute(methods=[op.method], path=op.path)]
    return gateway._enforce_contract(flow, binding, service, capability, op.method, flow.request.path.split("?")[0])


class TestTransportEnforcement:
    @pytest.fixture
    def gateway(self):
        return ServiceGateway()

    def test_allowed_headers_pass(self, gateway):
        flow = _make_contract_flow(headers={"Accept": "application/json"})
        op = ContractOperation(
            name="test", method="GET", path="/test",
            transport=TransportConstraint(allow_headers=["Accept"]),
        )
        assert _enforce(gateway, flow, op) is True

    def test_disallowed_header_rejected(self, gateway):
        flow = _make_contract_flow(headers={
            "Accept": "application/json",
            "X-Custom": "evil",
        })
        op = ContractOperation(
            name="test", method="GET", path="/test",
            transport=TransportConstraint(allow_headers=["Accept"]),
        )
        assert _enforce(gateway, flow, op) is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_HEADER_DENIED" in body["reason_codes"]

    def test_implicit_headers_always_allowed(self, gateway):
        flow = _make_contract_flow(headers={
            "Host": "example.com",
            "Connection": "keep-alive",
            "Content-Length": "0",
        })
        op = ContractOperation(
            name="test", method="GET", path="/test",
            transport=TransportConstraint(allow_headers=["Accept"]),
        )
        assert _enforce(gateway, flow, op) is True

    def test_service_auth_header_implicitly_allowed(self, gateway):
        """The service's auth header (carrying sgw_ token) is implicitly allowed."""
        flow = _make_contract_flow(headers={
            "X-Auth-Token": "sgw_test123",
            "Accept": "application/json",
        })
        op = ContractOperation(
            name="test", method="GET", path="/test",
            transport=TransportConstraint(allow_headers=["Accept"]),
        )
        service = _make_service(auth_header="X-Auth-Token")
        assert _enforce(gateway, flow, op, service=service) is True

    def test_require_no_body_rejects_body(self, gateway):
        flow = _make_contract_flow(body="hello")
        op = ContractOperation(
            name="test", method="GET", path="/test",
            transport=TransportConstraint(require_no_body=True),
        )
        assert _enforce(gateway, flow, op) is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_BODY_DENIED" in body["reason_codes"]

    def test_require_no_body_allows_empty(self, gateway):
        flow = _make_contract_flow(body=None)
        op = ContractOperation(
            name="test", method="GET", path="/test",
            transport=TransportConstraint(require_no_body=True),
        )
        assert _enforce(gateway, flow, op) is True

    def test_ambiguous_encoding_rejected(self, gateway):
        flow = _make_contract_flow(query="a=1&a=2")
        op = ContractOperation(
            name="test", method="GET", path="/test",
        )
        assert _enforce(gateway, flow, op) is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_AMBIGUOUS_ENCODING" in body["reason_codes"]


# --- Query Enforcement ---


class TestQueryEnforcement:
    @pytest.fixture
    def gateway(self):
        return ServiceGateway()

    def _make_op(self, query_allow, deny_unknown=True):
        return ContractOperation(
            name="test", method="GET", path="/test",
            query_allow=query_allow,
            query_deny_unknown=deny_unknown,
        )

    def test_equals_var_correct(self, gateway):
        flow = _make_contract_flow(query="labelIds=CATEGORY_PROMOTIONS")
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"labelIds": QueryConstraint(equals_var="approved_category")})
        assert _enforce(gateway, flow, op, binding=binding) is True

    def test_equals_var_wrong(self, gateway):
        flow = _make_contract_flow(query="labelIds=INBOX")
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"labelIds": QueryConstraint(equals_var="approved_category")})
        assert _enforce(gateway, flow, op, binding=binding) is False
        body = json.loads(flow.response.content)
        assert body["field"] == "labelIds"

    def test_integer_range_in_bounds(self, gateway):
        flow = _make_contract_flow(query="maxResults=50")
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"maxResults": QueryConstraint(integer_range=[1, 100])})
        assert _enforce(gateway, flow, op, binding=binding) is True

    def test_integer_range_out_of_bounds(self, gateway):
        flow = _make_contract_flow(query="maxResults=200")
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"maxResults": QueryConstraint(integer_range=[1, 100])})
        assert _enforce(gateway, flow, op, binding=binding) is False
        body = json.loads(flow.response.content)
        assert body["field"] == "maxResults"

    def test_integer_range_not_integer(self, gateway):
        flow = _make_contract_flow(query="maxResults=abc")
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"maxResults": QueryConstraint(integer_range=[1, 100])})
        assert _enforce(gateway, flow, op, binding=binding) is False

    def test_unknown_param_denied(self, gateway):
        flow = _make_contract_flow(query="q=secret")
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"labelIds": QueryConstraint(equals_var="approved_category")}, deny_unknown=True)
        assert _enforce(gateway, flow, op, binding=binding) is False
        body = json.loads(flow.response.content)
        assert body["field"] == "q"

    def test_unknown_param_allowed_when_deny_false(self, gateway):
        flow = _make_contract_flow(query="q=secret")
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({}, deny_unknown=False)
        assert _enforce(gateway, flow, op, binding=binding) is True

    def test_string_type_passes(self, gateway):
        flow = _make_contract_flow(query="pageToken=abc123")
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"pageToken": QueryConstraint(type="string")})
        assert _enforce(gateway, flow, op, binding=binding) is True


# --- Body Enforcement ---


class TestBodyEnforcement:
    @pytest.fixture
    def gateway(self):
        return ServiceGateway()

    def _make_op(self, body_allow, deny_unknown=True):
        return ContractOperation(
            name="test", method="POST", path="/test",
            body_allow=body_allow,
            body_deny_unknown=deny_unknown,
        )

    def test_allowed_fields_pass(self, gateway):
        flow = _make_contract_flow(method="POST", body='{"name": "test"}',
                                    headers={"Content-Type": "application/json"})
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"name": BodyConstraint(type="string")})
        assert _enforce(gateway, flow, op, binding=binding) is True

    def test_unknown_field_denied(self, gateway):
        flow = _make_contract_flow(method="POST", body='{"name": "test", "evil": "data"}',
                                    headers={"Content-Type": "application/json"})
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"name": BodyConstraint(type="string")})
        assert _enforce(gateway, flow, op, binding=binding) is False
        body = json.loads(flow.response.content)
        assert body["field"] == "evil"

    def test_unknown_field_allowed_when_deny_false(self, gateway):
        flow = _make_contract_flow(method="POST", body='{"name": "test", "extra": "ok"}',
                                    headers={"Content-Type": "application/json"})
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"name": BodyConstraint(type="string")}, deny_unknown=False)
        assert _enforce(gateway, flow, op, binding=binding) is True

    def test_equals_var_match(self, gateway):
        flow = _make_contract_flow(method="POST", body='{"category": "CATEGORY_PROMOTIONS"}',
                                    headers={"Content-Type": "application/json"})
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"category": BodyConstraint(equals_var="approved_category")})
        assert _enforce(gateway, flow, op, binding=binding) is True

    def test_equals_var_mismatch(self, gateway):
        flow = _make_contract_flow(method="POST", body='{"category": "INBOX"}',
                                    headers={"Content-Type": "application/json"})
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"category": BodyConstraint(equals_var="approved_category")})
        assert _enforce(gateway, flow, op, binding=binding) is False

    def test_empty_body_passes(self, gateway):
        flow = _make_contract_flow(method="POST", body=None)
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"name": BodyConstraint(type="string")})
        assert _enforce(gateway, flow, op, binding=binding) is True

    def test_invalid_json_rejected(self, gateway):
        flow = _make_contract_flow(method="POST", body="not json",
                                    headers={"Content-Type": "application/json"})
        binding = _make_binding_state(grantable_ops=["test"])
        op = self._make_op({"name": BodyConstraint(type="string")})
        assert _enforce(gateway, flow, op, binding=binding) is False


# --- Ambiguous Encoding ---


class TestAmbiguousEncoding:
    def test_double_encoding_in_query_detected(self):
        flow = _make_flow(query="path=%252Ftest")
        assert _check_ambiguous_encoding(flow) is not None
        assert "double-encoded" in _check_ambiguous_encoding(flow)

    def test_non_canonical_percent_in_query(self):
        flow = _make_flow(query="path=%2ftest")
        assert _check_ambiguous_encoding(flow) is not None
        assert "non-canonical" in _check_ambiguous_encoding(flow)

    def test_duplicate_params(self):
        flow = _make_flow(query="a=1&a=2")
        assert _check_ambiguous_encoding(flow) is not None
        assert "duplicate" in _check_ambiguous_encoding(flow)

    def test_method_override_header(self):
        flow = _make_flow(headers={"X-HTTP-Method-Override": "DELETE"})
        assert _check_ambiguous_encoding(flow) is not None
        assert "override" in _check_ambiguous_encoding(flow).lower()

    def test_method_query_param(self):
        flow = _make_flow(query="_method=DELETE")
        assert _check_ambiguous_encoding(flow) is not None
        assert "_method" in _check_ambiguous_encoding(flow)

    def test_clean_request_passes(self):
        flow = _make_flow(path="/api/v1/items", query="limit=10")
        assert _check_ambiguous_encoding(flow) is None

    def test_canonical_percent_in_query_passes(self):
        flow = _make_flow(query="path=%2Ftest")
        assert _check_ambiguous_encoding(flow) is None


# --- Path Parameter Extraction ---


class TestExtractPathParams:
    def test_basic_extraction(self):
        params = _extract_path_params("/api/items/123", "/api/items/{id}")
        assert params == {"id": "123"}

    def test_multiple_params(self):
        params = _extract_path_params("/api/users/42/posts/99", "/api/users/{uid}/posts/{pid}")
        assert params == {"uid": "42", "pid": "99"}

    def test_no_params(self):
        params = _extract_path_params("/api/items", "/api/items")
        assert params == {}

    def test_mismatch_returns_none(self):
        params = _extract_path_params("/api/items/123", "/api/users/{id}")
        assert params is None

    def test_length_mismatch_returns_none(self):
        params = _extract_path_params("/api/items", "/api/items/{id}")
        assert params is None


# ============================================================================
# Transport Hygiene: New test classes for all 7 rules
# ============================================================================


class TestPathTricks:
    """Rule 6: Dot segments, encoded separators, double encoding, empty segments."""

    def test_dot_segment_rejected(self):
        assert reject_path_tricks("/api/../admin") is not None
        assert "dot segment" in reject_path_tricks("/api/../admin")

    def test_single_dot_segment_rejected(self):
        assert reject_path_tricks("/api/./items") is not None
        assert "dot segment" in reject_path_tricks("/api/./items")

    def test_encoded_slash_rejected(self):
        assert reject_path_tricks("/api/items%2Fhidden") is not None
        assert "encoded path separator" in reject_path_tricks("/api/items%2Fhidden")

    def test_encoded_slash_lowercase_rejected(self):
        assert reject_path_tricks("/api/items%2fhidden") is not None

    def test_encoded_backslash_rejected(self):
        assert reject_path_tricks("/api/items%5Chidden") is not None
        assert "encoded path separator" in reject_path_tricks("/api/items%5Chidden")

    def test_double_encoded_percent_rejected(self):
        assert reject_path_tricks("/api/items%252Fhidden") is not None
        assert "double-encoded" in reject_path_tricks("/api/items%252Fhidden")

    def test_non_canonical_percent_rejected(self):
        assert reject_path_tricks("/api/items%2a") is not None
        assert "non-canonical" in reject_path_tricks("/api/items%2a")

    def test_empty_segments_rejected(self):
        assert reject_path_tricks("/api//items") is not None
        assert "empty path segment" in reject_path_tricks("/api//items")

    def test_clean_path_passes(self):
        assert reject_path_tricks("/api/v1/items/123") is None

    def test_root_path_passes(self):
        assert reject_path_tricks("/") is None

    def test_canonical_percent_passes(self):
        # %2A is canonical uppercase — but it's an encoded path separator check
        # Actually %2A is '*' not a separator, so it passes encoded separator
        # but fails non-canonical check only if lowercase
        assert reject_path_tricks("/api/items%2Astar") is None

    def test_query_not_checked(self):
        # Query string after ? should not trigger path checks
        assert reject_path_tricks("/api/items?foo=../bar") is None


class TestDuplicateHeaders:
    """Rule 2: Same header name appearing more than once → reject."""

    @pytest.fixture
    def gateway(self):
        return ServiceGateway()

    def test_duplicate_header_rejected(self, gateway):
        flow = _make_contract_flow(
            header_fields=[("Accept", "text/html"), ("Accept", "application/json")],
        )
        result = gateway._reject_duplicate_headers(flow)
        assert result == "accept"

    def test_different_headers_pass(self, gateway):
        flow = _make_contract_flow(
            header_fields=[("Accept", "text/html"), ("Content-Type", "application/json")],
        )
        assert gateway._reject_duplicate_headers(flow) is None

    def test_case_insensitive_duplicate(self, gateway):
        flow = _make_contract_flow(
            header_fields=[("Accept", "text/html"), ("accept", "application/json")],
        )
        result = gateway._reject_duplicate_headers(flow)
        assert result == "accept"

    def test_duplicate_in_contract_flow_denied(self, gateway):
        """Full contract enforcement rejects duplicate headers."""
        ops = [ContractOperation(name="test", method="GET", path="/test")]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["test"])
        service = _make_service()
        flow = _make_contract_flow(
            path="/test",
            header_fields=[("Accept", "a"), ("Accept", "b")],
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "GET", "/test")
        assert result is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_DUPLICATE_HEADER" in body["reason_codes"]


class TestHeaderAllowlistDefaults:
    """Omission is usable; empty and explicit lists retain exact intent."""

    @pytest.fixture
    def gateway(self):
        return ServiceGateway()

    def test_omitted_allow_headers_rejects_custom_header(self, gateway):
        """The ordinary-client default never broadens to custom headers."""
        ops = [
            ContractOperation(
                name="test", method="GET", path="/test",
                transport=TransportConstraint(),
            ),
        ]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["test"])
        service = _make_service()
        flow = _make_contract_flow(
            path="/test",
            headers={"X-Custom": "evil"},
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "GET", "/test")
        assert result is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_HEADER_DENIED" in body["reason_codes"]

    @pytest.mark.parametrize(
        ("configured", "sent"),
        [
            ("X-Client-Context", "x-client-context"),
            ("x-client-context", "X-CLIENT-CONTEXT"),
            ("X-cLiEnT-CoNtExT", "x-ClIeNt-cOnTeXt"),
        ],
    )
    def test_explicit_header_names_are_case_insensitive(
        self, gateway, configured, sent
    ):
        op = ContractOperation(
            name="test",
            method="GET",
            path="/test",
            transport=TransportConstraint(allow_headers=[configured]),
        )
        flow = _make_contract_flow(path="/test", headers={sent: "value"})

        assert _enforce(gateway, flow, op) is True

    @pytest.mark.parametrize("header_name", ["Accept", "User-Agent"])
    def test_explicit_empty_rejects_ordinary_client_headers(
        self, gateway, header_name
    ):
        op = ContractOperation(
            name="test",
            method="GET",
            path="/test",
            transport=TransportConstraint(allow_headers=[]),
        )
        flow = _make_contract_flow(
            path="/test", headers={header_name: "client-value"}
        )

        assert _enforce(gateway, flow, op) is False
        body = json.loads(flow.response.content)
        assert body["reason_codes"] == ["TRANSPORT_HEADER_DENIED"]

    def test_explicit_nonempty_list_does_not_add_omitted_defaults(self, gateway):
        op = ContractOperation(
            name="test",
            method="GET",
            path="/test",
            transport=TransportConstraint(allow_headers=["X-Client-Context"]),
        )
        flow = _make_contract_flow(
            path="/test", headers={"User-Agent": "ordinary-client"}
        )

        assert _enforce(gateway, flow, op) is False
        body = json.loads(flow.response.content)
        assert body["reason_codes"] == ["TRANSPORT_HEADER_DENIED"]

    @pytest.mark.parametrize("with_transport_block", [False, True])
    def test_omission_allows_common_client_metadata(
        self, gateway, with_transport_block
    ):
        """No transport block and an omitted key have the same safe default."""
        transport = (
            TransportConstraint(require_no_body=True)
            if with_transport_block
            else None
        )
        op = ContractOperation(
            name="test",
            method="GET",
            path="/test",
            transport=transport,
        )
        flow = _make_contract_flow(
            path="/test",
            headers={
                "aCcEpT": "application/json",
                "USER-agent": "curl/test",
                "Accept-Encoding": "gzip",
            },
        )

        assert _enforce(gateway, flow, op) is True

    def test_implicit_and_service_auth_headers_always_pass(self, gateway):
        """Explicit empty cannot remove transport or configured auth headers."""
        ops = [
            ContractOperation(
                name="test", method="GET", path="/test",
                transport=TransportConstraint(allow_headers=[]),
            ),
        ]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["test"])
        flow = _make_contract_flow(
            path="/test",
            headers={
                "Host": "example.com",
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip",
                "X-Auth-Token": "gateway-token",
            },
        )
        service = _make_service(auth_header="X-Auth-Token")
        result = gateway._enforce_contract(
            flow, binding, service, capability, "GET", "/test"
        )
        assert result is True

    def test_no_transport_block_still_runs_header_dedup(self, gateway):
        """Even without a transport block, duplicate headers are rejected."""
        ops = [ContractOperation(name="test", method="GET", path="/test")]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["test"])
        service = _make_service()
        flow = _make_contract_flow(
            path="/test",
            header_fields=[("Host", "a"), ("Host", "b")],
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "GET", "/test")
        assert result is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_DUPLICATE_HEADER" in body["reason_codes"]

    def test_no_transport_block_still_rejects_unrelated_headers(self, gateway):
        """Omission changes only the three documented client headers."""
        ops = [ContractOperation(name="test", method="GET", path="/test")]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["test"])
        service = _make_service()
        flow = _make_contract_flow(
            path="/test",
            headers={"X-Evil": "value"},
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "GET", "/test")
        assert result is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_HEADER_DENIED" in body["reason_codes"]


def _capture_curl_headers_over_uds(socket_path, extra_header=None):
    """Capture the real HTTP/1.1 headers curl emits over a Unix socket."""
    raw_request = bytearray()
    errors = []
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    listener.settimeout(5)

    def serve_once():
        try:
            connection, _ = listener.accept()
            with connection:
                while b"\r\n\r\n" not in raw_request:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    raw_request.extend(chunk)
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    b"Connection: close\r\n\r\nok"
                )
        except Exception as error:  # surfaced in the test thread
            errors.append(error)

    server = threading.Thread(target=serve_once)
    server.start()
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        "5",
        "--http1.1",
        "--compressed",
        "--unix-socket",
        str(socket_path),
    ]
    if extra_header:
        command.extend(["--header", extra_header])
    command.append("http://localhost/test")
    result = subprocess.run(command, check=True, capture_output=True)
    server.join(timeout=5)
    listener.close()

    assert result.stdout == b"ok"
    assert not server.is_alive()
    assert errors == []
    request_head = bytes(raw_request).split(b"\r\n\r\n", 1)[0]
    lines = request_head.decode("latin-1").split("\r\n")
    return [tuple(line.split(":", 1)) for line in lines[1:] if ":" in line]


@pytest.mark.parametrize(
    ("extra_header", "expected_reason"),
    [
        (None, None),
        ("X-Unrelated: denied", "TRANSPORT_HEADER_DENIED"),
        ("X-HTTP-Method-Override: DELETE", "TRANSPORT_AMBIGUOUS_ENCODING"),
    ],
)
def test_real_curl_uds_headers_follow_omitted_default(
    tmp_path, extra_header, expected_reason
):
    """Exercise curl's real auto-headers, including --compressed encoding."""
    fields = _capture_curl_headers_over_uds(
        tmp_path / "curl.sock", extra_header=extra_header
    )
    header_names = {name.strip().lower() for name, _ in fields}
    assert {"accept", "user-agent", "accept-encoding"} <= header_names

    flow = _make_contract_flow(
        path="/test",
        header_fields=[(name.strip(), value.strip()) for name, value in fields],
    )
    op = ContractOperation(name="test", method="GET", path="/test")
    gateway = ServiceGateway()

    assert _enforce(gateway, flow, op) is (expected_reason is None)
    if expected_reason:
        body = json.loads(flow.response.content)
        assert body["reason_codes"] == [expected_reason]


class TestContentType:
    """Rule 4: Unexpected content type → reject."""

    @pytest.fixture
    def gateway(self):
        return ServiceGateway()

    def test_wrong_content_type_rejected(self, gateway):
        ops = [
            ContractOperation(
                name="create", method="POST", path="/test",
                body_allow={"name": BodyConstraint(type="string")},
            ),
        ]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["create"])
        service = _make_service()
        flow = _make_contract_flow(
            method="POST", path="/test",
            headers={"Content-Type": "text/plain"},
            body='{"name": "test"}',
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "POST", "/test")
        assert result is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_CONTENT_TYPE" in body["reason_codes"]

    def test_application_json_passes(self, gateway):
        ops = [
            ContractOperation(
                name="create", method="POST", path="/test",
                body_allow={"name": BodyConstraint(type="string")},
            ),
        ]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["create"])
        service = _make_service()
        flow = _make_contract_flow(
            method="POST", path="/test",
            headers={"Content-Type": "application/json"},
            body='{"name": "test"}',
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "POST", "/test")
        assert result is True

    def test_application_json_with_charset_passes(self, gateway):
        ops = [
            ContractOperation(
                name="create", method="POST", path="/test",
                body_allow={"name": BodyConstraint(type="string")},
            ),
        ]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["create"])
        service = _make_service()
        flow = _make_contract_flow(
            method="POST", path="/test",
            headers={"Content-Type": "application/json; charset=utf-8"},
            body='{"name": "test"}',
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "POST", "/test")
        assert result is True

    def test_missing_content_type_on_post_rejected(self, gateway):
        ops = [
            ContractOperation(
                name="create", method="POST", path="/test",
                body_allow={"name": BodyConstraint(type="string")},
            ),
        ]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["create"])
        service = _make_service()
        flow = _make_contract_flow(
            method="POST", path="/test",
            body='{"name": "test"}',
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "POST", "/test")
        assert result is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_CONTENT_TYPE" in body["reason_codes"]

    def test_form_urlencoded_rejected(self, gateway):
        ops = [
            ContractOperation(
                name="create", method="POST", path="/test",
                body_allow={"name": BodyConstraint(type="string")},
            ),
        ]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["create"])
        service = _make_service()
        flow = _make_contract_flow(
            method="POST", path="/test",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body='name=test',
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "POST", "/test")
        assert result is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_CONTENT_TYPE" in body["reason_codes"]


class TestDuplicateJsonKeys:
    """Rule 5: Duplicate JSON keys → reject."""

    @pytest.fixture
    def gateway(self):
        return ServiceGateway()

    def test_duplicate_key_rejected(self, gateway):
        ops = [
            ContractOperation(
                name="create", method="POST", path="/test",
                body_allow={"a": BodyConstraint(type="string")},
            ),
        ]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["create"])
        service = _make_service()
        flow = _make_contract_flow(
            method="POST", path="/test",
            headers={"Content-Type": "application/json"},
            body='{"a": 1, "a": 2}',
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "POST", "/test")
        assert result is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_DUPLICATE_JSON_KEY" in body["reason_codes"]

    def test_normal_json_passes(self, gateway):
        ops = [
            ContractOperation(
                name="create", method="POST", path="/test",
                body_allow={"a": BodyConstraint(type="string"), "b": BodyConstraint(type="string")},
            ),
        ]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["create"])
        service = _make_service()
        flow = _make_contract_flow(
            method="POST", path="/test",
            headers={"Content-Type": "application/json"},
            body='{"a": 1, "b": 2}',
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "POST", "/test")
        assert result is True

    def test_duplicate_key_hook_standalone(self):
        """Test the object_pairs_hook directly."""
        with pytest.raises(ValueError, match="duplicate JSON key"):
            json.loads('{"a": 1, "a": 2}', object_pairs_hook=_reject_duplicate_json_keys)

    def test_unique_keys_hook_standalone(self):
        result = json.loads('{"a": 1, "b": 2}', object_pairs_hook=_reject_duplicate_json_keys)
        assert result == {"a": 1, "b": 2}


class TestCrossLocationFields:
    """Rule 3: Same field in query and body → reject."""

    @pytest.fixture
    def gateway(self):
        return ServiceGateway()

    def test_overlap_rejected(self, gateway):
        ops = [
            ContractOperation(
                name="create", method="POST", path="/test",
                body_allow={"name": BodyConstraint(type="string")},
                body_deny_unknown=False,
                query_allow={"name": QueryConstraint(type="string")},
                query_deny_unknown=False,
            ),
        ]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["create"])
        service = _make_service()
        flow = _make_contract_flow(
            method="POST", path="/test",
            query="name=query_value",
            headers={"Content-Type": "application/json"},
            body='{"name": "body_value"}',
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "POST", "/test")
        assert result is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_CROSS_LOCATION" in body["reason_codes"]

    def test_no_overlap_passes(self, gateway):
        ops = [
            ContractOperation(
                name="create", method="POST", path="/test",
                body_allow={"name": BodyConstraint(type="string")},
                body_deny_unknown=False,
                query_allow={"page": QueryConstraint(type="string")},
                query_deny_unknown=False,
            ),
        ]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["create"])
        service = _make_service()
        flow = _make_contract_flow(
            method="POST", path="/test",
            query="page=1",
            headers={"Content-Type": "application/json"},
            body='{"name": "test"}',
        )
        result = gateway._enforce_contract(flow, binding, service, capability, "POST", "/test")
        assert result is True


class TestQueryStringEncoding:
    """Encoding checks in query string scope."""

    def test_double_encoded_query_rejected(self):
        flow = _make_flow(query="path=%252Ftest")
        result = _check_ambiguous_encoding(flow)
        assert result is not None
        assert "double-encoded" in result

    def test_non_canonical_percent_in_query_rejected(self):
        flow = _make_flow(query="path=%2ftest")
        result = _check_ambiguous_encoding(flow)
        assert result is not None
        assert "non-canonical" in result

    def test_clean_query_passes(self):
        flow = _make_flow(query="limit=10&offset=0")
        assert _check_ambiguous_encoding(flow) is None

    def test_canonical_percent_in_query_passes(self):
        flow = _make_flow(query="path=%2Ftest")
        assert _check_ambiguous_encoding(flow) is None


class TestContractPathTrickIntegration:
    """Integration: path tricks rejected via _enforce_contract."""

    @pytest.fixture
    def gateway(self):
        return ServiceGateway()

    def _run_contract(self, gateway, path, method="GET"):
        ops = [ContractOperation(name="test", method=method, path="/api/items")]
        contract = _make_contract(operations=ops)
        capability = _make_capability_with_contract(contract)
        binding = _make_binding_state(grantable_ops=["test"])
        service = _make_service()
        flow = _make_contract_flow(path=path, method=method)
        return gateway._enforce_contract(flow, binding, service, capability, method, path), flow

    def test_dot_dot_in_path_denied(self, gateway):
        ok, flow = self._run_contract(gateway, "/api/../admin")
        assert ok is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_PATH_TRICK" in body["reason_codes"]

    def test_double_slash_denied(self, gateway):
        ok, flow = self._run_contract(gateway, "/api//items")
        assert ok is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_PATH_TRICK" in body["reason_codes"]

    def test_encoded_slash_denied(self, gateway):
        ok, flow = self._run_contract(gateway, "/api/items%2Fhidden")
        assert ok is False
        body = json.loads(flow.response.content)
        assert "TRANSPORT_PATH_TRICK" in body["reason_codes"]

    def test_clean_path_passes(self, gateway):
        ok, flow = self._run_contract(gateway, "/api/items")
        assert ok is True
