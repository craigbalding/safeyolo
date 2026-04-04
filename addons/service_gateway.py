"""
service_gateway.py - Service Gateway addon for credential injection (v2)

Intercepts requests with sgw_ gateway tokens, validates capability route
lists, checks risky routes against PDP risk appetite, strips the gateway
token, and injects real credentials from the vault.

Agents use real hostnames with existing SDKs (zero code changes) but never
see real credentials. The gateway holds credentials and injects them.

Flow:
  Agent sends Authorization: Bearer sgw_abc123... to gmail.googleapis.com
  → proxy intercepts → validates capability routes (positive list)
  → checks risky routes (PDP risk appetite) → strips sgw_ token
  → injects real OAuth token from vault → forwards upstream.

Loading order: Layer 0.5, between policy_engine and network_guard.
Does NOT inherit SecurityAddon - follows AgentRelay pattern.

Usage:
    mitmdump -s addons/service_gateway.py \\
        --set gateway_enabled=true \\
        --set gateway_services_dir=/safeyolo/services \\
        --set gateway_vault_path=/safeyolo/data/vault.yaml.enc
"""

import json as json_mod
import logging
import re
import secrets
import threading
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from detection.matching import normalize_path, reject_path_tricks
from mitmproxy import ctx, http
from service_loader import get_service_registry
from utils import make_block_response, matches_resource_pattern, sanitize_for_log, write_event
from vault import get_vault

from audit_schema import ApprovalRequest, Decision, EventKind, Severity

log = logging.getLogger("safeyolo.service-gateway")

# Token prefix for gateway tokens
SGW_TOKEN_PREFIX = "sgw_"
SGW_TOKEN_LEN = 64  # hex chars after prefix


@dataclass
class TokenBinding:
    """Maps a gateway token to an agent/service/capability + vault credential."""

    agent: str
    service_name: str
    capability_name: str
    vault_token: str  # vault credential name
    account: str = "agent"  # persona


DEFAULT_GRANT_TTL_SECONDS = 3600  # 1 hour — once-grants expire if unused


@dataclass
class GrantEntry:
    """A granted approval for a risky route."""

    grant_id: str
    agent: str
    service: str
    method: str
    path: str
    scope: str = "once"  # once | session | remembered
    created: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    expires: str = field(default_factory=lambda: "")

    def __post_init__(self):
        if not self.expires:
            from datetime import timedelta

            created_dt = datetime.fromisoformat(self.created)
            self.expires = (created_dt + timedelta(seconds=DEFAULT_GRANT_TTL_SECONDS)).isoformat()

    def is_expired(self) -> bool:
        """Check if this grant has exceeded its TTL."""
        try:
            expires_dt = datetime.fromisoformat(self.expires)
            # Ensure timezone-aware comparison
            now = datetime.now(UTC)
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=UTC)
            return now >= expires_dt
        except (ValueError, TypeError):
            return True  # Malformed expiry = treat as expired (fail safe)

    def matches(self, agent: str, service: str, method: str, path: str) -> bool:
        """Check if this grant covers the given request.

        Grant path may be a glob pattern (e.g. /v1/feeds/*) from the risky route
        definition, so we use the same pattern matching as capability routes.
        Returns False if the grant has expired.
        """
        if self.is_expired():
            return False
        if self.agent != agent or self.service != service:
            return False
        if self.method.upper() != method.upper():
            return False
        return matches_resource_pattern(path, self.path)


@dataclass
class ContractBindingState:
    """An active contract binding for an agent/service/capability tuple."""

    binding_id: str
    agent: str
    service: str
    capability: str
    template: str
    bound_values: dict  # var_name -> resolved value
    grantable_operations: list[str]
    created: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


def _mint_binding_id() -> str:
    """Generate a unique contract binding ID."""
    return f"cbs_{secrets.token_hex(12)}"


def _mint_grant_id() -> str:
    """Generate a unique grant ID."""
    return f"grt_{secrets.token_hex(12)}"


@dataclass
class GatewayStats:
    """Statistics for the gateway."""

    requests: int = 0
    injected: int = 0
    denied_route: int = 0
    denied_token: int = 0
    refreshed: int = 0
    tokens_registered: int = 0


def mint_gateway_token() -> str:
    """Generate a new gateway token."""
    return f"{SGW_TOKEN_PREFIX}{secrets.token_hex(SGW_TOKEN_LEN // 2)}"


@dataclass
class CanonicalRequest:
    """Parsed, validated, canonical representation of a contract-bound request."""

    method: str
    path: str  # normalised via yarl after raw rejection
    query: dict[str, str]  # single value per key (duplicates already rejected)
    body: dict | None  # strict-parsed JSON (duplicates already rejected), or None
    content_type: str  # parsed media type, lowercase, no params
    headers: dict[str, str]  # lowercase keys, single value per key


def _parse_content_type(flow) -> str:
    """Extract media type from Content-Type header, lowercase, no params."""
    raw = flow.request.headers.get("content-type", "")
    return raw.split(";")[0].strip().lower()


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    """object_pairs_hook that rejects duplicate JSON keys."""
    seen: set[str] = set()
    result = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON key: {key}")
        seen.add(key)
        result[key] = value
    return result


class ServiceGateway:
    """Service Gateway addon - credential injection for agents (v2).

    Follows AgentRelay pattern (not SecurityAddon). Positioned between
    policy_engine and network_guard in the addon chain.
    """

    name = "service-gateway"

    def __init__(self):
        self._token_map: dict[str, TokenBinding] = {}
        self._host_map: dict[str, str] = {}
        self._grants: dict[str, GrantEntry] = {}  # grant_id -> GrantEntry
        self._contract_bindings: dict[tuple[str, str, str], ContractBindingState] = {}
        self._grant_ttl: int = DEFAULT_GRANT_TTL_SECONDS
        self._lock = threading.RLock()
        self.stats = GatewayStats()

    def load(self, loader):
        loader.add_option(
            name="gateway_enabled",
            typespec=bool,
            default=False,
            help="Enable the service gateway for credential injection",
        )
        loader.add_option(
            name="gateway_services_dir",
            typespec=str,
            default="/safeyolo/services",
            help="Directory containing service definition YAML files",
        )
        loader.add_option(
            name="gateway_vault_path",
            typespec=str,
            default="/safeyolo/data/vault.yaml.enc",
            help="Path to encrypted vault file",
        )
        loader.add_option(
            name="gateway_vault_key",
            typespec=str,
            default="/safeyolo/data/vault.key",
            help="Path to vault key file (auto-generated by CLI)",
        )

    def configure(self, updates):
        if not ctx.options.gateway_enabled:
            return

        if "gateway_enabled" in updates or "gateway_services_dir" in updates:
            self._init_services()
            # Registry now available — trigger policy reload so compiler can
            # emit gateway:request permissions from capability routes
            self._trigger_policy_reload()

        if "gateway_enabled" in updates or "gateway_vault_path" in updates:
            self._init_vault()

        # Mint tokens, load grants and contract bindings when gateway enables
        if "gateway_enabled" in updates:
            self._mint_tokens_from_policy()
            self._load_grants_from_policy()
            self._load_contract_bindings_from_policy()
            self._register_reload_callback()

    def _init_services(self):
        """Initialize service registry from service definition files."""
        try:
            from service_loader import init_service_registry

            user_dir = Path(ctx.options.gateway_services_dir)
            registry = init_service_registry(user_dir)
            registry.start_watcher()
            log.info(f"Service registry loaded from {user_dir}")
        except Exception as e:
            log.error(f"Failed to load service registry: {type(e).__name__}: {e}")

    def _trigger_policy_reload(self):
        """Trigger a policy reload so the compiler can use the now-available registry."""
        try:
            from pdp import get_policy_client, is_policy_client_configured

            if not is_policy_client_configured():
                return
            client = get_policy_client()
            pdp = getattr(client, "_pdp", None)
            engine = getattr(pdp, "_engine", None) if pdp else None
            loader = getattr(engine, "_loader", None) if engine else None
            if loader:
                loader.reload()
                gw_count = sum(1 for p in loader.baseline.permissions if p.action == "gateway:request")
                log.info(f"Policy reloaded after service registry init ({gw_count} gateway:request permissions)")
        except Exception as e:
            log.error(f"Policy reload after registry init failed: {type(e).__name__}: {e}")

    def _init_vault(self):
        """Initialize vault from encrypted file, using auto-generated key file."""
        key_path = Path(ctx.options.gateway_vault_key)
        vault_path = Path(ctx.options.gateway_vault_path)

        if not key_path.exists():
            log.info(f"Gateway vault key not found at {key_path} — vault disabled")
            return

        if not vault_path.exists():
            log.info(f"Gateway vault not found at {vault_path} — vault disabled")
            return

        try:
            from vault import init_vault

            key = key_path.read_text().strip()
            vault = init_vault(vault_path, key)
            vault.start_watcher()
            log.info("Vault unlocked")
        except Exception as e:
            log.error(f"Failed to unlock vault: {type(e).__name__}: {e}")

    def _mint_tokens_from_policy(self):
        """Read agents section from compiled policy and mint gateway tokens."""
        try:
            from pdp import get_policy_client, is_policy_client_configured

            if not is_policy_client_configured():
                log.debug("PolicyClient not configured yet, skipping token minting")
                return

            client = get_policy_client()
            gateway_config = client.get_gateway_config()
            if not gateway_config:
                log.debug("No gateway config in policy (no agents: section?)")
                return

            token_map = gateway_config.get("token_map", {})
            agent_env = gateway_config.get("agent_env", {})
            self._host_map = gateway_config.get("host_map", {})

            # Read grant TTL from policy (gateway.grant_ttl_seconds)
            ttl = gateway_config.get("grant_ttl_seconds")
            if ttl is not None and isinstance(ttl, (int, float)) and ttl > 0:
                self._grant_ttl = int(ttl)
                log.info(f"Grant TTL set from policy: {self._grant_ttl}s")

            if not token_map:
                return

            # Rebuild token map from policy — convert dicts to TokenBinding
            with self._lock:
                self._token_map.clear()
                self.stats.tokens_registered = 0
                for token, binding in token_map.items():
                    self._token_map[token] = TokenBinding(
                        agent=binding["agent"],
                        service_name=binding["service"],
                        capability_name=binding.get("capability", binding.get("role", "")),
                        vault_token=binding["token"],
                        account=binding.get("account", "agent"),
                    )
                    self.stats.tokens_registered += 1

            safe_agents = [sanitize_for_log(a) for a in agent_env.keys()]
            log.info(f"Minted {self.stats.tokens_registered} tokens from policy for agents: {safe_agents}")

        except Exception as e:
            log.error(f"Failed to mint tokens from policy: {type(e).__name__}: {e}")

    def _register_reload_callback(self):
        """Register for policy reload notifications to re-mint tokens."""
        try:
            from pdp import get_policy_client, is_policy_client_configured

            if not is_policy_client_configured():
                return

            client = get_policy_client()
            if hasattr(client, "add_reload_callback"):
                client.add_reload_callback(self._mint_tokens_from_policy)
                log.info("Registered gateway token re-mint on policy reload")
        except Exception as e:
            log.warning(f"Failed to register reload callback: {type(e).__name__}: {e}")

    def done(self):
        """Clean shutdown — stop file watchers."""
        registry = get_service_registry()
        if registry:
            registry.stop_watcher()
        vault = get_vault()
        if vault:
            vault.stop_watcher()

    def running(self):
        if ctx.options.gateway_enabled:
            log.info(f"Service gateway active ({self.stats.tokens_registered} tokens registered)")
        else:
            log.info("Service gateway disabled")

    def request(self, flow: http.HTTPFlow):
        """Intercept requests with sgw_ gateway tokens."""
        if not ctx.options.gateway_enabled:
            return

        # Already handled by another addon
        if flow.response:
            return

        # Extract sgw_ token from Authorization header
        token = self._extract_sgw_token(flow)
        if not token:
            return  # Not a gateway request - pass through

        self.stats.requests += 1

        # Lookup token binding
        with self._lock:
            binding = self._token_map.get(token)

        if not binding:
            self._deny(
                flow,
                403,
                "Invalid gateway token",
                "INVALID_TOKEN",
                action="self_correct",
                reflection="The gateway token is not recognized. Check that the agent is authorized and the token has not expired.",
            )
            self.stats.denied_token += 1
            return

        # Validate agent matches (if service_discovery stamped flow.metadata["agent"])
        agent = flow.metadata.get("agent")
        if agent and agent != binding.agent:
            self._deny(
                flow,
                403,
                f"Token not authorized for agent '{agent}'",
                "AGENT_MISMATCH",
                action="self_correct",
                reflection=f"This token belongs to a different agent. Agent '{sanitize_for_log(agent)}' is not authorized to use it.",
            )
            self.stats.denied_token += 1
            return

        # Get service
        registry = get_service_registry()
        if not registry:
            self._deny(
                flow,
                503,
                "Service registry not available",
                "REGISTRY_UNAVAILABLE",
                action="abort",
                reflection="The service registry is not loaded. The proxy may still be starting up.",
            )
            return

        service = registry.get_service(binding.service_name)
        if not service:
            self._deny(
                flow,
                403,
                f"Service '{binding.service_name}' not found",
                "SERVICE_NOT_FOUND",
                action="self_correct",
                reflection=f"Service '{sanitize_for_log(binding.service_name)}' is not in the service registry. Check the service name in policy.toml [agents] section.",
            )
            self.stats.denied_token += 1
            return

        # Get capability
        capability = service.capabilities.get(binding.capability_name)
        if not capability:
            cap_names = ", ".join(service.capabilities.keys()) if service.capabilities else "none"
            self._deny(
                flow,
                403,
                f"Capability '{binding.capability_name}' not found",
                "CAPABILITY_NOT_FOUND",
                action="self_correct",
                reflection=f"Capability '{sanitize_for_log(binding.capability_name)}' does not exist in service '{sanitize_for_log(binding.service_name)}'. Available: {sanitize_for_log(cap_names)}.",
            )
            self.stats.denied_token += 1
            return

        # Validate host matches via host_map (policy binds host → service)
        expected_service = self._host_map.get(flow.request.host.lower())
        if expected_service != binding.service_name:
            self._deny(
                flow,
                403,
                f"Host '{flow.request.host}' is not mapped to service '{binding.service_name}'",
                "HOST_MISMATCH",
                action="self_correct",
                reflection=f"Host '{sanitize_for_log(flow.request.host)}' is not mapped to service '{sanitize_for_log(binding.service_name)}' in policy.yaml. Add the host binding under the hosts section.",
            )
            self.stats.denied_token += 1
            return

        path = flow.request.path.split("?")[0]  # Strip query string
        method = flow.request.method

        # 1. Capability route check — delegate to PDP (compiled permissions)
        from pdp import get_policy_client, is_policy_client_configured

        if is_policy_client_configured():
            client = get_policy_client()
            route_decision = client.evaluate_gateway_request(
                service=binding.service_name,
                capability=binding.capability_name,
                agent=binding.agent,
                method=method,
                path=path,
            )
            from pdp.schemas import Effect

            if route_decision.effect != Effect.ALLOW:
                self._deny(
                    flow,
                    403,
                    f"Route {method} {path} not in capability '{capability.name}'",
                    "ROUTE_DENIED",
                    action="self_correct",
                    reflection=f"Route {sanitize_for_log(method)} {sanitize_for_log(path)} is not allowed by capability '{sanitize_for_log(capability.name)}'. Check the service definition for allowed routes.",
                )
                self.stats.denied_route += 1
                return
        else:
            # Fallback: local route check if PDP not configured
            if not self._evaluate_capability_routes(method, path, capability):
                self._deny(
                    flow,
                    403,
                    f"Route {method} {path} not in capability '{capability.name}'",
                    "ROUTE_DENIED",
                    action="self_correct",
                    reflection=f"Route {sanitize_for_log(method)} {sanitize_for_log(path)} is not allowed by capability '{sanitize_for_log(capability.name)}'. Check the service definition for allowed routes.",
                )
                self.stats.denied_route += 1
                return

        # 1.5. Contract enforcement (if capability has a bound contract)
        if capability.contract and capability.contract.is_grantable:
            cbs = self.get_contract_binding(binding.agent, service.name, capability.name)
            if not self._enforce_contract(flow, cbs, service, capability, method, path):
                return  # flow.response already set

        # 2. Risky route check (grant bypass → PDP)
        risky = self._match_risky_route(method, path, service.risky_routes)
        if risky:
            grant = self._check_grant(binding.agent, service.name, method, path)
            if grant:
                # Grant exists — skip PDP, stamp for response() hook
                flow.metadata["gateway_grant_id"] = grant.grant_id
                log.info(
                    f"Grant {grant.grant_id} covers risky route {sanitize_for_log(method)} {sanitize_for_log(path)}"
                )
            else:
                pdp_decision = self._check_risky_route(flow, service, capability, risky, binding)
                if pdp_decision is not None:
                    # flow.response already set from PDP immediate_response
                    return

        # 3. Inject credential using service.auth
        vault = get_vault()
        if not vault:
            self._deny(
                flow,
                503,
                "Vault not available",
                "VAULT_UNAVAILABLE",
                action="abort",
                reflection="The credential vault is not loaded. The proxy may still be starting up.",
            )
            return

        cred = vault.get(binding.vault_token)
        if not cred:
            self._deny(
                flow,
                503,
                "Credential not found in vault",
                "CREDENTIAL_NOT_FOUND",
                action="self_correct",
                reflection=f"Credential '{sanitize_for_log(binding.vault_token)}' is not in the vault. Re-run `safeyolo agent authorize` to store it.",
            )
            return

        # Auto-refresh OAuth2 if expired
        if service.auth and cred.type == "oauth2" and cred.is_expired() and service.auth.refresh_on_401:
            if vault.refresh_oauth2(binding.vault_token):
                self.stats.refreshed += 1
                cred = vault.get(binding.vault_token)
                if not cred:
                    self._deny(
                        flow,
                        503,
                        "Credential lost after refresh",
                        "CREDENTIAL_NOT_FOUND",
                        action="abort",
                        reflection="The credential was lost during OAuth2 token refresh. Re-run `safeyolo agent authorize` to restore it.",
                    )
                    return

        # Refuse to inject credentials over plaintext HTTP — redirect to HTTPS
        if flow.request.scheme == "http":
            https_url = "https://" + flow.request.url[len("http://") :]
            flow.response = http.Response.make(
                301,
                b"",
                {
                    "Location": https_url,
                    "X-SafeYolo-Reason": "credential-injection-requires-https",
                },
            )
            log.warning(
                f"Blocked credential injection over HTTP, redirecting to HTTPS: "
                f"{sanitize_for_log(flow.request.host)}{sanitize_for_log(path)}"
            )
            write_event(
                "gateway.https_redirect",
                kind=EventKind.GATEWAY,
                severity=Severity.HIGH,
                summary=f"Gateway redirected HTTP→HTTPS: {service.name}{path}",
                decision=Decision.DENY,
                host=flow.request.host,
                request_id=flow.metadata.get("request_id"),
                agent=binding.agent,
                addon=self.name,
                details={"service": service.name, "path": path, "redirect": https_url},
            )
            return

        # Strip sgw_ token and inject real credential (same header)
        auth_header = service.auth.header if service.auth else "Authorization"
        del flow.request.headers[auth_header]
        injected_header = auth_header
        if service.auth and service.auth.type == "bearer":
            flow.request.headers[auth_header] = f"{service.auth.scheme} {cred.value}"
        elif service.auth and service.auth.type == "api_key":
            flow.request.headers[auth_header] = cred.value

        # Stamp metadata
        flow.metadata["gateway_service"] = service.name
        flow.metadata["gateway_capability"] = capability.name
        flow.metadata["gateway_agent"] = binding.agent
        flow.metadata["gateway_account"] = binding.account
        flow.metadata["gateway_injected_header"] = injected_header

        # Log allow event
        write_event(
            "gateway.allow",
            kind=EventKind.GATEWAY,
            severity=Severity.LOW,
            summary=f"Gateway {method} {service.name}{path} → injected ({capability.name})",
            decision=Decision.ALLOW,
            host=flow.request.host,
            request_id=flow.metadata.get("request_id"),
            agent=binding.agent,
            addon=self.name,
            details={
                "service": service.name,
                "capability": capability.name,
                "account": binding.account,
                "method": method,
                "path": path,
            },
        )

        self.stats.injected += 1

    # =========================================================================
    # Grant management
    # =========================================================================

    def add_grant(
        self,
        agent: str,
        service: str,
        method: str,
        path: str,
        scope: str = "once",
    ) -> GrantEntry:
        """Add a risky route grant. Returns the new GrantEntry."""
        from datetime import timedelta

        created = datetime.now(UTC).isoformat()
        created_dt = datetime.fromisoformat(created)
        expires = (created_dt + timedelta(seconds=self._grant_ttl)).isoformat()

        grant = GrantEntry(
            grant_id=_mint_grant_id(),
            agent=agent,
            service=service,
            method=method,
            path=path,
            scope=scope,
            created=created,
            expires=expires,
        )
        with self._lock:
            self._grants[grant.grant_id] = grant

        self._persist_grants()

        log.info(
            f"Grant added: {grant.grant_id} {sanitize_for_log(agent)}/{sanitize_for_log(service)} "
            f"{sanitize_for_log(method)} {sanitize_for_log(path)} scope={scope}"
        )
        write_event(
            "gateway.grant_added",
            kind=EventKind.GATEWAY,
            severity=Severity.MEDIUM,
            summary=f"Grant added: {agent}/{service} {method} {path} ({scope})",
            decision=Decision.ALLOW,
            agent=agent,
            addon=self.name,
            details={
                "grant_id": grant.grant_id,
                "service": service,
                "method": method,
                "path": path,
                "scope": scope,
            },
        )
        return grant

    def list_grants(self) -> list[dict]:
        """List all active grants (safe for API response)."""
        with self._lock:
            return [
                {
                    "grant_id": g.grant_id,
                    "agent": g.agent,
                    "service": g.service,
                    "method": g.method,
                    "path": g.path,
                    "scope": g.scope,
                    "created": g.created,
                    "expires": g.expires,
                    "expired": g.is_expired(),
                }
                for g in self._grants.values()
            ]

    def revoke_grant(self, grant_id: str) -> bool:
        """Revoke a grant by ID. Returns True if found and removed."""
        with self._lock:
            grant = self._grants.pop(grant_id, None)
        if grant:
            self._persist_grants()
            log.info(f"Grant revoked: {sanitize_for_log(grant_id)}")
            write_event(
                "gateway.grant_revoked",
                kind=EventKind.GATEWAY,
                severity=Severity.MEDIUM,
                summary=f"Grant revoked: {grant.agent}/{grant.service} {grant.method} {grant.path}",
                agent=grant.agent,
                addon=self.name,
                details={"grant_id": grant_id},
            )
            return True
        return False

    def _check_grant(self, agent: str, service: str, method: str, path: str) -> GrantEntry | None:
        """Find a matching grant for the given request. Cleans up expired grants."""
        expired = []
        result = None
        with self._lock:
            for grant in self._grants.values():
                if grant.is_expired():
                    expired.append(grant)
                elif result is None and grant.matches(agent, service, method, path):
                    result = grant
            for grant in expired:
                self._grants.pop(grant.grant_id, None)

        if expired:
            self._persist_grants()
            for grant in expired:
                log.info(
                    f"Grant expired: {grant.grant_id} {sanitize_for_log(grant.agent)}/{sanitize_for_log(grant.service)} "
                    f"{sanitize_for_log(grant.method)} {sanitize_for_log(grant.path)}"
                )
                write_event(
                    "gateway.grant_expired",
                    kind=EventKind.GATEWAY,
                    severity=Severity.LOW,
                    summary=f"Grant expired: {grant.agent}/{grant.service} {grant.method} {grant.path}",
                    agent=grant.agent,
                    addon=self.name,
                    details={"grant_id": grant.grant_id},
                )

        return result

    def _consume_grant(self, grant: GrantEntry) -> None:
        """Consume a once-scope grant after successful response."""
        with self._lock:
            self._grants.pop(grant.grant_id, None)
        self._persist_grants()
        log.info(f"Grant consumed (once): {sanitize_for_log(grant.grant_id)}")
        write_event(
            "gateway.grant_consumed",
            kind=EventKind.GATEWAY,
            severity=Severity.LOW,
            summary=f"Grant consumed: {grant.agent}/{grant.service} {grant.method} {grant.path}",
            agent=grant.agent,
            addon=self.name,
            details={"grant_id": grant.grant_id},
        )

    @staticmethod
    def _get_policy_path():
        """Get the baseline policy path from the policy loader."""
        from toml_roundtrip import policy_path_for_loader

        from pdp import get_policy_client, is_policy_client_configured

        if not is_policy_client_configured():
            return None

        client = get_policy_client()
        pdp = getattr(client, "_pdp", None)
        engine = getattr(pdp, "_engine", None) if pdp else None
        loader = getattr(engine, "_loader", None) if engine else None
        if not loader:
            return None

        return policy_path_for_loader(loader)

    def _load_grants_from_policy(self) -> None:
        """Load persisted grants from policy.toml [agents] section."""
        try:
            from toml_roundtrip import load_agents, load_roundtrip

            policy_path = self._get_policy_path()
            if not policy_path:
                return

            doc = load_roundtrip(policy_path)
            agents = load_agents(doc)

            with self._lock:
                for agent_name, agent_data in agents.items():
                    if not isinstance(agent_data, dict):
                        continue
                    for grant_data in agent_data.get("grants", []):
                        scope = grant_data.get("scope", "once")
                        if scope == "session":
                            continue  # Session grants don't survive restart
                        grant = GrantEntry(
                            grant_id=grant_data.get("grant_id", _mint_grant_id()),
                            agent=agent_name,
                            service=grant_data["service"],
                            method=grant_data["method"],
                            path=grant_data["path"],
                            scope=scope,
                            created=grant_data.get("created", datetime.now(UTC).isoformat()),
                            expires=grant_data.get("expires", ""),
                        )
                        if grant.is_expired():
                            continue
                        self._grants[grant.grant_id] = grant

            if self._grants:
                log.info(f"Loaded {len(self._grants)} grants from policy.toml")

        except Exception as e:
            log.warning(f"Failed to load grants from policy.toml: {type(e).__name__}: {e}")

    def _persist_grants(self) -> None:
        """Write grants back to policy.toml [agents] section."""
        try:
            from toml_roundtrip import load_agents, locked_policy_mutate, upsert_agent

            policy_path = self._get_policy_path()
            if not policy_path:
                return

            with self._lock:
                # Snapshot current grants grouped by agent
                grants_by_agent: dict[str, list[dict]] = {}
                for grant in self._grants.values():
                    grants_by_agent.setdefault(grant.agent, []).append(
                        {
                            "grant_id": grant.grant_id,
                            "service": grant.service,
                            "method": grant.method,
                            "path": grant.path,
                            "scope": grant.scope,
                            "created": grant.created,
                            "expires": grant.expires,
                        }
                    )

            def _mutate(doc):
                agents = load_agents(doc)
                # Clear existing grants
                for agent_data in agents.values():
                    agent_data.pop("grants", None)
                # Write new grants
                for agent_name, grants in grants_by_agent.items():
                    if agent_name in agents:
                        agents[agent_name]["grants"] = grants
                # Write back modified agents
                for name, data in agents.items():
                    upsert_agent(doc, name, data)

            locked_policy_mutate(policy_path, _mutate)

        except Exception as e:
            log.warning(f"Failed to persist grants: {type(e).__name__}: {e}")

    # =========================================================================
    # Contract binding management
    # =========================================================================

    def add_contract_binding(
        self,
        agent: str,
        service: str,
        capability: str,
        template: str,
        bound_values: dict,
        grantable_operations: list[str],
    ) -> ContractBindingState:
        """Create and store a contract binding. Replaces existing for same key."""
        binding = ContractBindingState(
            binding_id=_mint_binding_id(),
            agent=agent,
            service=service,
            capability=capability,
            template=template,
            bound_values=bound_values,
            grantable_operations=grantable_operations,
        )
        key = (agent, service, capability)
        with self._lock:
            self._contract_bindings[key] = binding

        self._persist_contract_bindings()

        log.info(
            f"Contract binding added: {binding.binding_id} "
            f"{sanitize_for_log(agent)}/{sanitize_for_log(service)}/{sanitize_for_log(capability)}"
        )
        return binding

    def get_contract_binding(self, agent: str, service: str, capability: str) -> ContractBindingState | None:
        """Look up active contract binding."""
        with self._lock:
            return self._contract_bindings.get((agent, service, capability))

    def revoke_contract_binding(self, binding_id: str) -> bool:
        """Remove a contract binding by ID. Returns True if found."""
        with self._lock:
            for key, binding in self._contract_bindings.items():
                if binding.binding_id == binding_id:
                    del self._contract_bindings[key]
                    log.info(f"Contract binding revoked: {sanitize_for_log(binding_id)}")
                    self._persist_contract_bindings()
                    return True
        return False

    def _load_contract_bindings_from_policy(self) -> None:
        """Load persisted contract bindings from policy.toml [agents] section."""
        try:
            from toml_roundtrip import load_agents, load_roundtrip

            policy_path = self._get_policy_path()
            if not policy_path:
                return

            doc = load_roundtrip(policy_path)
            agents = load_agents(doc)

            with self._lock:
                for agent_name, agent_data in agents.items():
                    if not isinstance(agent_data, dict):
                        continue
                    for cb_data in agent_data.get("contract_bindings", []):
                        binding = ContractBindingState(
                            binding_id=cb_data.get("binding_id", _mint_binding_id()),
                            agent=agent_name,
                            service=cb_data["service"],
                            capability=cb_data["capability"],
                            template=cb_data.get("template", ""),
                            bound_values=cb_data.get("bound_values", {}),
                            grantable_operations=cb_data.get("grantable_operations", []),
                            created=cb_data.get("created", datetime.now(UTC).isoformat()),
                        )
                        key = (agent_name, binding.service, binding.capability)
                        self._contract_bindings[key] = binding

            if self._contract_bindings:
                log.info(f"Loaded {len(self._contract_bindings)} contract bindings from policy.toml")

        except Exception as e:
            log.warning(f"Failed to load contract bindings from policy.toml: {type(e).__name__}: {e}")

    def _persist_contract_bindings(self) -> None:
        """Write contract bindings to policy.toml [agents] section."""
        try:
            from toml_roundtrip import load_agents, locked_policy_mutate, upsert_agent

            policy_path = self._get_policy_path()
            if not policy_path:
                return

            with self._lock:
                # Snapshot current bindings grouped by agent
                bindings_by_agent: dict[str, list[dict]] = {}
                for binding in self._contract_bindings.values():
                    bindings_by_agent.setdefault(binding.agent, []).append(
                        {
                            "binding_id": binding.binding_id,
                            "service": binding.service,
                            "capability": binding.capability,
                            "template": binding.template,
                            "bound_values": binding.bound_values,
                            "grantable_operations": binding.grantable_operations,
                            "created": binding.created,
                        }
                    )

            def _mutate(doc):
                agents = load_agents(doc)
                # Clear existing contract_bindings
                for agent_data in agents.values():
                    agent_data.pop("contract_bindings", None)
                # Write new bindings
                for agent_name, bindings in bindings_by_agent.items():
                    if agent_name in agents:
                        agents[agent_name]["contract_bindings"] = bindings
                # Write back modified agents
                for name, data in agents.items():
                    upsert_agent(doc, name, data)

            locked_policy_mutate(policy_path, _mutate)

        except Exception as e:
            log.warning(f"Failed to persist contract bindings: {type(e).__name__}: {e}")

    def response(self, flow: http.HTTPFlow):
        """Consume once-grants after successful upstream response."""
        if not ctx.options.gateway_enabled:
            return

        # Only care about gateway-handled flows
        grant_id = flow.metadata.get("gateway_grant_id")
        if not grant_id:
            return

        # Consume on 2xx
        if flow.response and 200 <= flow.response.status_code < 300:
            with self._lock:
                grant = self._grants.get(grant_id)
            if grant and grant.scope == "once":
                self._consume_grant(grant)

    def _extract_sgw_token(self, flow: http.HTTPFlow) -> str | None:
        """Extract sgw_ token from the service-specific auth header.

        Uses host → service → auth.header to know which header to read.
        """
        # Look up service by host
        service_name = self._host_map.get(flow.request.host.lower())
        if not service_name:
            return None

        # Get service definition for auth config
        registry = get_service_registry()
        if not registry:
            return None
        service = registry.get_service(service_name)
        if not service or not service.auth:
            return None

        # Read from the service's auth header
        auth_header = service.auth.header  # e.g. "Authorization", "X-Auth-Token"
        value = flow.request.headers.get(auth_header, "")

        # For bearer-type auth, strip the scheme prefix (e.g. "Bearer sgw_...")
        if service.auth.type == "bearer" and " " in value:
            value = value.split(" ", 1)[1]

        value = value.strip()
        if value.startswith(SGW_TOKEN_PREFIX):
            return value
        return None

    def _evaluate_capability_routes(self, method, path, capability) -> bool:
        """Check if method+path is in the capability's route list (positive-list only)."""
        for route in capability.routes:
            if self._method_matches(method, route.methods) and matches_resource_pattern(path, route.path):
                return True
        return False

    def _match_risky_route(self, method, path, risky_routes):
        """Find first matching risky route, or None."""
        for route in risky_routes:
            if self._method_matches(method, route.methods) and matches_resource_pattern(path, route.path):
                return route
        return None

    def _check_risky_route(self, flow, service, capability, risky, binding):
        """Check risky route with PDP. Returns None on allow, sets flow.response on non-allow."""
        try:
            from datetime import datetime

            from pdp import get_policy_client, is_policy_client_configured
            from pdp.schemas import (
                BodyBlock,
                BodyObserved,
                ContextBlock,
                CredentialBlock,
                EventBlock,
                EventPhase,
                HttpBlock,
                HttpEvent,
                IdentitySource,
                PrincipalBlock,
            )
            from pdp.schemas import (
                EventKind as SchemaEventKind,
            )

            if not is_policy_client_configured():
                log.debug("PolicyClient not configured, skipping risky route check")
                return None

            client = get_policy_client()
            request_id = flow.metadata.get("request_id", "evt-gateway-risky")

            event = HttpEvent(
                version=1,
                event=EventBlock(
                    event_id=request_id,
                    trace_id=request_id,
                    kind=SchemaEventKind.HTTP_REQUEST,
                    phase=EventPhase.PRE_UPSTREAM,
                    timestamp=datetime.utcnow(),
                    sensor_id="service-gateway",
                ),
                principal=PrincipalBlock(
                    principal_id=f"agent:{binding.agent}",
                    identity_source=IdentitySource.MANUAL,
                ),
                http=HttpBlock(
                    method=flow.request.method,
                    scheme="https",
                    host=flow.request.host,
                    port=443,
                    path=flow.request.path.split("?")[0],
                    headers_present=list(flow.request.headers.keys()),
                ),
                credential=CredentialBlock(detected=False),
                body=BodyBlock(present=False, observed=BodyObserved.METADATA),
                context=ContextBlock(
                    gateway_service=service.name,
                    gateway_capability=capability.name,
                    gateway_account=binding.account,
                    gateway_risky_route={
                        "path": risky.path,
                        "methods": risky.methods,
                        "tactics": risky.tactics,
                        "enables": risky.enables,
                        "irreversible": risky.irreversible,
                        "description": risky.description,
                        "group": risky.group,
                    },
                ),
            )

            decision = client.evaluate(event)

            from pdp.schemas import Effect

            if decision.effect == Effect.ALLOW:
                return None

            # Non-allow: build response from PDP immediate_response
            if decision.immediate_response:
                body = decision.immediate_response.body_json
                body["addon"] = self.name
                body.setdefault("type", "gateway_risky_route")
                body.setdefault("action", "wait_for_approval")
                body.setdefault(
                    "reflection",
                    "This route is flagged as risky. An operator must approve it via `safeyolo watch` before it can proceed.",
                )
                flow.response = make_block_response(
                    decision.immediate_response.status_code,
                    body,
                    self.name,
                )
            else:
                self._deny(
                    flow,
                    428,
                    "Risky route requires approval",
                    "GATEWAY_RISKY_ROUTE",
                    action="wait_for_approval",
                    reflection="This route is flagged as risky. An operator must approve it via `safeyolo watch` before it can proceed.",
                )

            flow.metadata["blocked_by"] = self.name

            method = flow.request.method
            path = flow.request.path.split("?")[0]
            signals = ", ".join(risky.tactics) if risky.tactics else "no tactics"
            if risky.irreversible:
                signals += ", irreversible"

            write_event(
                "gateway.risky_route",
                kind=EventKind.GATEWAY,
                severity=Severity.HIGH,
                summary=f"Risky route {method} {service.name}{path} [{signals}] → {decision.effect.value}",
                decision=Decision.DENY if decision.effect.value == "deny" else Decision.REQUIRE_APPROVAL,
                host=flow.request.host,
                request_id=flow.metadata.get("request_id"),
                agent=binding.agent,
                addon=self.name,
                approval=ApprovalRequest(
                    required=True,
                    approval_type="gateway_route",
                    key=f"gw:{binding.agent}:{service.name}:{method}:{path}",
                    target=service.name,
                    scope_hint={
                        "method": method,
                        "path": path,
                    },
                ),
                details={
                    "service": service.name,
                    "capability": capability.name,
                    "method": method,
                    "path": path,
                    "risky_route": risky.path,
                    "tactics": risky.tactics,
                    "enables": risky.enables,
                    "irreversible": risky.irreversible,
                    "description": risky.description,
                    "group": risky.group,
                    "effect": decision.effect.value,
                },
            )

            return decision  # non-None signals the caller to stop

        except Exception as e:
            log.error(f"Risky route PDP check failed: {type(e).__name__}: {e}")
            # Fail safe: deny on PDP error
            self._deny(
                flow,
                503,
                "Risky route check failed",
                "PDP_ERROR",
                action="abort",
                reflection="The policy engine failed while checking this risky route. The request was denied as a safety precaution.",
            )
            return True  # non-None

    # =========================================================================
    # Contract enforcement
    # =========================================================================

    # Headers implicitly allowed (proxy/transport layer)
    _IMPLICIT_HEADERS = frozenset(
        {
            "host",
            "connection",
            "content-length",
            "content-type",
            "transfer-encoding",
            "accept-encoding",
            "via",
            "proxy-connection",
        }
    )

    def _enforce_contract(self, flow, binding_state, service, capability, method, path) -> bool:
        """Enforce contract constraints. Returns True if allowed, False if denied.

        Three-phase enforcement:
          Phase 1: Raw rejection (on raw request, before any parsing)
          Phase 2: Canonical parse (build CanonicalRequest)
          Phase 3: Contract enforcement (on canonical object only)

        When returning False, flow.response is already set.
        """
        contract = capability.contract
        auth_header = service.auth.header.lower() if service.auth else "authorization"

        # 1. Binding required
        if not binding_state:
            self._deny(
                flow,
                403,
                f"Contract not bound for capability '{capability.name}'",
                "CONTRACT_NOT_BOUND",
                action="request_binding",
                reflection=(
                    f"Capability '{sanitize_for_log(capability.name)}' requires a contract binding. "
                    "Submit a binding via /gateway/submit-binding before making requests."
                ),
            )
            return False

        # ── Phase 1: Raw rejection ──────────────────────────────────────
        raw_path = flow.request.path.split("?", 1)[0]

        # Path tricks (dot segments, encoded separators, double encoding, etc.)
        trick = reject_path_tricks(raw_path)
        if trick:
            self._deny(
                flow,
                403,
                f"Path trick detected: {sanitize_for_log(trick)}",
                "TRANSPORT_PATH_TRICK",
                action="self_correct",
                reflection=f"The request path contains a bypass trick: {trick}.",
            )
            return False

        # Duplicate headers (check raw tuples before mitmproxy folds them)
        dup_header = self._reject_duplicate_headers(flow)
        if dup_header:
            self._deny(
                flow,
                403,
                f"Duplicate header: {sanitize_for_log(dup_header)}",
                "TRANSPORT_DUPLICATE_HEADER",
                action="self_correct",
                reflection=f"Header '{sanitize_for_log(dup_header)}' appears more than once.",
            )
            return False

        # Query string raw checks (ambiguous encoding)
        ambiguity = _check_ambiguous_encoding(flow)
        if ambiguity:
            self._deny(
                flow,
                403,
                f"Ambiguous encoding detected: {ambiguity}",
                "TRANSPORT_AMBIGUOUS_ENCODING",
                action="self_correct",
                reflection="The request contains ambiguous encoding that could be used to bypass contract constraints.",
            )
            return False

        # ── Phase 2: Canonical parse ────────────────────────────────────
        canonical_path = normalize_path(raw_path)

        # Match operation (needs canonical path)
        op = contract.match_operation(method, canonical_path)
        if not op:
            self._deny(
                flow,
                403,
                f"Operation {method} {canonical_path} not grantable in contract",
                "OPERATION_NOT_GRANTABLE",
                action="self_correct",
                reflection=(
                    f"No grantable operation matches {sanitize_for_log(method)} {sanitize_for_log(canonical_path)} "
                    f"in the bound contract for '{sanitize_for_log(capability.name)}'."
                ),
            )
            return False

        # Parse query
        raw_qs = flow.request.url.split("?", 1)[1] if "?" in flow.request.url else ""
        qs_params = urllib.parse.parse_qs(raw_qs, keep_blank_values=True)
        canonical_query = {k: v[0] for k, v in qs_params.items()}

        # Parse headers (de-duplication already rejected, safe to build dict)
        canonical_headers: dict[str, str] = {}
        if hasattr(flow.request.headers, "fields"):
            for name_bytes, val_bytes in flow.request.headers.fields:
                lower = name_bytes.decode("latin-1").lower()
                canonical_headers[lower] = val_bytes.decode("latin-1")
        else:
            for name in flow.request.headers:
                canonical_headers[name.lower()] = flow.request.headers[name]

        # Parse content type
        content_type = _parse_content_type(flow)

        # Parse body (strict JSON with duplicate key rejection)
        canonical_body = None
        if method in ("POST", "PUT", "PATCH") and flow.request.content:
            # Content-Type enforcement
            if content_type != "application/json":
                self._deny(
                    flow,
                    403,
                    f"Unexpected content type: {sanitize_for_log(content_type) or '(missing)'}",
                    "TRANSPORT_CONTENT_TYPE",
                    action="self_correct",
                    reflection="This operation only accepts application/json.",
                )
                return False

            try:
                canonical_body = json_mod.loads(
                    flow.request.content,
                    object_pairs_hook=_reject_duplicate_json_keys,
                )
            except json_mod.JSONDecodeError:
                self._deny(
                    flow,
                    403,
                    "Request body is not valid JSON",
                    "CONTRACT_VIOLATION",
                    action="self_correct",
                    reflection="The request body must be valid JSON for contract enforcement.",
                )
                return False
            except ValueError as e:
                if "duplicate JSON key" in str(e):
                    self._deny(
                        flow,
                        403,
                        f"Duplicate JSON key in request body: {sanitize_for_log(str(e))}",
                        "TRANSPORT_DUPLICATE_JSON_KEY",
                        action="self_correct",
                        reflection="The request body contains duplicate JSON keys.",
                    )
                    return False
                raise

            if not isinstance(canonical_body, dict):
                self._deny(
                    flow,
                    403,
                    "Request body must be a JSON object",
                    "CONTRACT_VIOLATION",
                    action="self_correct",
                    reflection="The request body must be a JSON object.",
                )
                return False

        # Cross-location field overlap
        if canonical_body is not None and canonical_query:
            overlap = set(canonical_query.keys()) & set(canonical_body.keys())
            if overlap:
                field_name = sorted(overlap)[0]
                self._deny(
                    flow,
                    403,
                    f"Field '{sanitize_for_log(field_name)}' appears in both query and body",
                    "TRANSPORT_CROSS_LOCATION",
                    action="self_correct",
                    reflection=f"Field '{sanitize_for_log(field_name)}' appears in both query string and request body.",
                    field=field_name,
                )
                return False

        canonical = CanonicalRequest(
            method=method,
            path=canonical_path,
            query=canonical_query,
            body=canonical_body,
            content_type=content_type,
            headers=canonical_headers,
        )

        # ── Phase 3: Contract enforcement (on canonical object) ─────────

        # Transport: require_no_body
        if op.transport and op.transport.require_no_body and flow.request.content:
            self._deny(
                flow,
                403,
                "Request body not allowed for this operation",
                "TRANSPORT_BODY_DENIED",
                action="self_correct",
                reflection="This operation requires no request body.",
            )
            return False

        # Transport: header allowlist (always runs — absent allow_headers = restrictive)
        if not self._enforce_header_allowlist(flow, op, canonical, auth_header):
            return False

        # Query enforcement (runs if allow or deny_unknown is configured)
        if op.query_allow is not None or op.query_deny_unknown:
            if not self._enforce_query_canonical(flow, op, binding_state, canonical):
                return False

        # Body enforcement
        if method in ("POST", "PUT", "PATCH") and (op.body_allow is not None or op.body_deny_unknown):
            if not self._enforce_body_canonical(flow, op, binding_state, canonical):
                return False

        # Path param validation
        if op.path_params:
            params = _extract_path_params(canonical.path, op.path)
            if params is None:
                self._deny(
                    flow,
                    403,
                    f"Path does not match operation template '{op.path}'",
                    "CONTRACT_VIOLATION",
                    action="self_correct",
                    reflection="Request path does not match the operation template.",
                )
                return False
            for param_name, param_value in params.items():
                constraint = op.path_params.get(param_name)
                if not constraint:
                    continue
                if constraint.equals_var:
                    expected = binding_state.bound_values.get(constraint.equals_var)
                    if expected is not None and str(param_value) != str(expected):
                        self._deny(
                            flow,
                            403,
                            f"Path parameter '{param_name}' does not match bound value",
                            "CONTRACT_VIOLATION",
                            action="self_correct",
                            reflection=f"Path parameter '{sanitize_for_log(param_name)}' does not match the bound contract value.",
                            field=param_name,
                        )
                        return False

        return True

    def _reject_duplicate_headers(self, flow) -> str | None:
        """Check for duplicate headers in raw request. Returns duplicate name or None."""
        if not hasattr(flow.request.headers, "fields"):
            return None
        seen: set[str] = set()
        for name_bytes, _ in flow.request.headers.fields:
            lower = name_bytes.decode("latin-1").lower()
            if lower in seen:
                return lower
            seen.add(lower)
        return None

    def _enforce_header_allowlist(self, flow, op, canonical, service_auth_header) -> bool:
        """Enforce header allowlist. Always runs — absent allow_headers = restrictive."""
        implicit = self._IMPLICIT_HEADERS
        if service_auth_header:
            implicit = implicit | {service_auth_header}

        allowed_set = implicit.copy()
        if op.transport and op.transport.allow_headers:
            allowed_set |= {h.lower() for h in op.transport.allow_headers}

        for header_name in canonical.headers:
            if header_name not in allowed_set:
                self._deny(
                    flow,
                    403,
                    f"Header '{sanitize_for_log(header_name)}' not in allowlist",
                    "TRANSPORT_HEADER_DENIED",
                    action="self_correct",
                    reflection=f"Header '{sanitize_for_log(header_name)}' is not permitted for this operation.",
                )
                return False
        return True

    def _enforce_query_canonical(self, flow, op, binding_state, canonical) -> bool:
        """Enforce query parameter constraints using canonical request."""
        for param_name, value in canonical.query.items():
            constraint = op.query_allow.get(param_name)
            if not constraint:
                if op.query_deny_unknown:
                    self._deny(
                        flow,
                        403,
                        f"Unknown query parameter '{sanitize_for_log(param_name)}'",
                        "CONTRACT_VIOLATION",
                        action="self_correct",
                        reflection=f"Query parameter '{sanitize_for_log(param_name)}' is not allowed by the contract.",
                        field=param_name,
                    )
                    return False
                continue

            if constraint.equals_var:
                expected = binding_state.bound_values.get(constraint.equals_var, "")
                if value != expected:
                    self._deny(
                        flow,
                        403,
                        f"Query parameter '{sanitize_for_log(param_name)}' does not match bound value",
                        "CONTRACT_VIOLATION",
                        action="self_correct",
                        reflection=f"Query parameter '{sanitize_for_log(param_name)}' does not match the bound contract value.",
                        field=param_name,
                    )
                    return False
            elif constraint.integer_range:
                try:
                    int_val = int(value)
                except (ValueError, TypeError):
                    self._deny(
                        flow,
                        403,
                        f"Query parameter '{sanitize_for_log(param_name)}' must be an integer",
                        "CONTRACT_VIOLATION",
                        action="self_correct",
                        reflection=f"Query parameter '{sanitize_for_log(param_name)}' must be a valid integer.",
                        field=param_name,
                    )
                    return False
                lo, hi = constraint.integer_range[0], constraint.integer_range[1]
                if int_val < lo or int_val > hi:
                    self._deny(
                        flow,
                        403,
                        f"Query parameter '{sanitize_for_log(param_name)}' out of range",
                        "CONTRACT_VIOLATION",
                        action="self_correct",
                        reflection=f"Query parameter '{sanitize_for_log(param_name)}' is outside the allowed range.",
                        field=param_name,
                    )
                    return False
        return True

    def _enforce_body_canonical(self, flow, op, binding_state, canonical) -> bool:
        """Enforce body field constraints using canonical request."""
        body = canonical.body
        if body is None:
            return True

        for field_name, value in body.items():
            constraint = op.body_allow.get(field_name)
            if not constraint:
                if op.body_deny_unknown:
                    self._deny(
                        flow,
                        403,
                        f"Unknown body field '{sanitize_for_log(field_name)}'",
                        "CONTRACT_VIOLATION",
                        action="self_correct",
                        reflection=f"Body field '{sanitize_for_log(field_name)}' is not allowed by the contract.",
                        field=field_name,
                    )
                    return False
                continue

            if constraint.equals_var:
                expected = binding_state.bound_values.get(constraint.equals_var, "")
                if value != expected:
                    self._deny(
                        flow,
                        403,
                        f"Body field '{sanitize_for_log(field_name)}' does not match bound value",
                        "CONTRACT_VIOLATION",
                        action="self_correct",
                        reflection=f"Body field '{sanitize_for_log(field_name)}' does not match the bound contract value.",
                        field=field_name,
                    )
                    return False

        return True

    def _method_matches(self, method: str, allowed_methods: list[str]) -> bool:
        """Check if HTTP method matches allowed methods list."""
        if "*" in allowed_methods:
            return True
        return method.upper() in [m.upper() for m in allowed_methods]

    def _deny(
        self,
        flow: http.HTTPFlow,
        status: int,
        reason: str,
        code: str,
        *,
        action: str = "abort",
        reflection: str = "",
        field: str = "",
    ) -> None:
        """Block request with standard JSON response."""
        body = {
            "error": reason,
            "type": code.lower(),
            "reason_codes": [code],
            "action": action,
            "reflection": reflection or reason,
            "addon": self.name,
        }
        if field:
            body["field"] = field
        flow.response = make_block_response(status, body, self.name)
        flow.metadata["blocked_by"] = self.name

        method = flow.request.method
        path = flow.request.path.split("?")[0]
        service = flow.metadata.get("gateway_service") or self._host_map.get(
            flow.request.host.lower(), flow.request.host
        )

        write_event(
            "gateway.deny",
            kind=EventKind.GATEWAY,
            severity=Severity.HIGH,
            summary=f"Gateway denied {sanitize_for_log(method)} {sanitize_for_log(service)}{sanitize_for_log(path)}: {sanitize_for_log(reason)}",
            decision=Decision.DENY,
            host=flow.request.host,
            request_id=flow.metadata.get("request_id"),
            agent=flow.metadata.get("agent"),
            addon=self.name,
            details={"reason": reason, "code": code, "method": method, "path": path, "service": service},
        )

    def mint_tokens(self, agent_bindings: dict[str, dict[str, dict[str, str]]]) -> dict[str, dict[str, str]]:
        """Mint gateway tokens for agent/service bindings.

        Args:
            agent_bindings: {agent_name: {service_name: {"capability": cap_name, "token": vault_token, "account": persona}}}

        Returns:
            {agent_name: {service_name: sgw_token}}
        """
        agent_env: dict[str, dict[str, str]] = {}

        with self._lock:
            for agent, services in agent_bindings.items():
                agent_env[agent] = {}
                for service_name, config in services.items():
                    sgw_token = mint_gateway_token()
                    self._token_map[sgw_token] = TokenBinding(
                        agent=agent,
                        service_name=service_name,
                        capability_name=config.get("capability", config.get("role", "")),
                        vault_token=config.get("token", ""),
                        account=config.get("account", "agent"),
                    )
                    agent_env[agent][service_name] = sgw_token
                    self.stats.tokens_registered += 1

        log.info(f"Minted {self.stats.tokens_registered} gateway tokens")
        return agent_env

    def get_stats(self) -> dict:
        """Return stats for admin API (no secrets)."""
        with self._lock:
            bindings = []
            for binding in self._token_map.values():
                bindings.append(
                    {
                        "agent": binding.agent,
                        "service": binding.service_name,
                        "capability": binding.capability_name,
                        "account": binding.account,
                    }
                )

        return {
            "requests": self.stats.requests,
            "injected": self.stats.injected,
            "denied_route": self.stats.denied_route,
            "denied_token": self.stats.denied_token,
            "refreshed": self.stats.refreshed,
            "tokens_registered": self.stats.tokens_registered,
            "active_grants": len(self._grants),
            "bindings": bindings,
        }

    def get_agent_services(self) -> dict[str, dict[str, dict]]:
        """Return agent service bindings (host + token + capability + account). For agent API /gateway/services."""
        # Build reverse map: service_name → host
        reverse_host_map: dict[str, str] = {}
        for host, service_name in self._host_map.items():
            reverse_host_map[service_name] = host

        with self._lock:
            result: dict[str, dict[str, dict]] = {}
            for token, binding in self._token_map.items():
                host = reverse_host_map.get(binding.service_name, "")
                result.setdefault(binding.agent, {})[binding.service_name] = {
                    "host": host,
                    "token": token,
                    "capability": binding.capability_name,
                    "account": binding.account,
                }
            return result


def _check_ambiguous_encoding(flow) -> str | None:
    """Check for ambiguous encoding in query string and headers. Returns description or None.

    Path checks are handled by reject_path_tricks() in matching.py.
    This function covers query-string and header-level ambiguity.
    """
    url = flow.request.url

    if "?" in url:
        qs = url.split("?", 1)[1]

        # Duplicate query parameters
        raw_keys = [p.split("=", 1)[0] for p in qs.split("&") if p]
        if len(raw_keys) != len(set(raw_keys)):
            return "duplicate query parameters"

        # Double-encoded percent in query string: %25xx
        if re.search(r"%25[0-9A-Fa-f]{2}", qs):
            return "double-encoded percent in query string"

        # Non-canonical percent encoding in query string
        for m in re.finditer(r"%([0-9A-Fa-f]{2})", qs):
            hex_part = m.group(1)
            if hex_part != hex_part.upper():
                return "non-canonical percent encoding in query string"

        # Method override via _method query param
        qs_params = urllib.parse.parse_qs(qs, keep_blank_values=True)
        if "_method" in qs_params:
            return "_method query parameter"

    # Method override headers
    override_headers = {"x-http-method-override", "x-method-override"}
    for header_name in flow.request.headers:
        if header_name.lower() in override_headers:
            return f"method override header: {header_name}"

    return None


def _extract_path_params(actual_path: str, template_path: str) -> dict[str, str] | None:
    """Extract path parameters from actual path using template. Returns dict or None."""
    actual_parts = [p for p in actual_path.strip("/").split("/") if p]
    template_parts = [p for p in template_path.strip("/").split("/") if p]

    if len(actual_parts) != len(template_parts):
        return None

    params: dict[str, str] = {}
    for actual_seg, tmpl_seg in zip(actual_parts, template_parts):
        if tmpl_seg.startswith("{") and tmpl_seg.endswith("}"):
            param_name = tmpl_seg[1:-1]
            params[param_name] = actual_seg
        elif actual_seg != tmpl_seg:
            return None

    return params


addons = [ServiceGateway()]
