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

import logging
import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

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

        if "gateway_enabled" in updates or "gateway_vault_path" in updates:
            self._init_vault()

        # Mint tokens and load grants when gateway enables
        if "gateway_enabled" in updates:
            self._mint_tokens_from_policy()
            self._load_grants_from_agents_yaml()
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
                flow, 403, "Invalid gateway token", "INVALID_TOKEN",
                action="self_correct",
                reflection="The gateway token is not recognized. Check that the agent is authorized and the token has not expired.",
            )
            self.stats.denied_token += 1
            return

        # Validate agent matches (if service_discovery stamped flow.metadata["agent"])
        agent = flow.metadata.get("agent")
        if agent and agent != binding.agent:
            self._deny(
                flow, 403, f"Token not authorized for agent '{agent}'", "AGENT_MISMATCH",
                action="self_correct",
                reflection=f"This token belongs to a different agent. Agent '{sanitize_for_log(agent)}' is not authorized to use it.",
            )
            self.stats.denied_token += 1
            return

        # Get service
        registry = get_service_registry()
        if not registry:
            self._deny(
                flow, 503, "Service registry not available", "REGISTRY_UNAVAILABLE",
                action="abort",
                reflection="The service registry is not loaded. The proxy may still be starting up.",
            )
            return

        service = registry.get_service(binding.service_name)
        if not service:
            self._deny(
                flow, 403, f"Service '{binding.service_name}' not found", "SERVICE_NOT_FOUND",
                action="self_correct",
                reflection=f"Service '{sanitize_for_log(binding.service_name)}' is not in the service registry. Check the service name in agents.yaml.",
            )
            self.stats.denied_token += 1
            return

        # Get capability
        capability = service.capabilities.get(binding.capability_name)
        if not capability:
            cap_names = ", ".join(service.capabilities.keys()) if service.capabilities else "none"
            self._deny(
                flow, 403, f"Capability '{binding.capability_name}' not found", "CAPABILITY_NOT_FOUND",
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

        # 1. Capability route check (positive list)
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
                flow, 503, "Vault not available", "VAULT_UNAVAILABLE",
                action="abort",
                reflection="The credential vault is not loaded. The proxy may still be starting up.",
            )
            return

        cred = vault.get(binding.vault_token)
        if not cred:
            self._deny(
                flow, 503, "Credential not found in vault", "CREDENTIAL_NOT_FOUND",
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
                        flow, 503, "Credential lost after refresh", "CREDENTIAL_NOT_FOUND",
                        action="abort",
                        reflection="The credential was lost during OAuth2 token refresh. Re-run `safeyolo agent authorize` to restore it.",
                    )
                    return

        # Strip sgw_ token and inject real credential
        del flow.request.headers["Authorization"]
        injected_header = "Authorization"
        if service.auth and service.auth.type == "bearer":
            flow.request.headers["Authorization"] = f"{service.auth.scheme} {cred.value}"
        elif service.auth and service.auth.type == "api_key":
            injected_header = service.auth.header
            flow.request.headers[service.auth.header] = cred.value

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

    def _load_grants_from_agents_yaml(self) -> None:
        """Load persisted grants from agents.yaml (if it exists beside the baseline)."""
        try:
            from pdp import get_policy_client, is_policy_client_configured

            if not is_policy_client_configured():
                return

            client = get_policy_client()
            pdp = getattr(client, "_pdp", None)
            engine = getattr(pdp, "_engine", None) if pdp else None
            loader = getattr(engine, "_loader", None) if engine else None
            if not loader:
                return

            agents_path = getattr(loader, "_agents_path", lambda: None)()
            if not agents_path or not agents_path.exists():
                return

            import yaml

            raw = yaml.safe_load(agents_path.read_text()) or {}

            with self._lock:
                # Clear session grants from previous run
                for agent_name, agent_data in raw.items():
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
                        # Skip expired grants on load
                        if grant.is_expired():
                            continue
                        self._grants[grant.grant_id] = grant

            if self._grants:
                log.info(f"Loaded {len(self._grants)} grants from agents.yaml")

        except Exception as e:
            log.warning(f"Failed to load grants from agents.yaml: {type(e).__name__}: {e}")

    def _persist_grants(self) -> None:
        """Write grants back to agents.yaml."""
        try:
            from pdp import get_policy_client, is_policy_client_configured

            if not is_policy_client_configured():
                return

            client = get_policy_client()
            pdp = getattr(client, "_pdp", None)
            engine = getattr(pdp, "_engine", None) if pdp else None
            loader = getattr(engine, "_loader", None) if engine else None
            if not loader:
                return

            agents_path = getattr(loader, "_agents_path", lambda: None)()
            if not agents_path:
                return

            import yaml

            # Hold lock for entire read-modify-write to prevent TOCTOU
            with self._lock:
                # Read existing agents.yaml
                if agents_path.exists():
                    raw = yaml.safe_load(agents_path.read_text()) or {}
                else:
                    raw = {}

                # Clear all existing grants sections
                for agent_data in raw.values():
                    if isinstance(agent_data, dict) and "grants" in agent_data:
                        del agent_data["grants"]

                # Group current grants by agent
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

                # Write grants into agent sections
                for agent_name, grants in grants_by_agent.items():
                    if agent_name not in raw:
                        raw[agent_name] = {}
                    raw[agent_name]["grants"] = grants

                # Atomic write
                tmp = agents_path.with_suffix(".tmp")
                tmp.write_text(yaml.dump(raw, default_flow_style=False, sort_keys=False))
                tmp.rename(agents_path)

        except Exception as e:
            log.warning(f"Failed to persist grants: {type(e).__name__}: {e}")

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
        """Extract sgw_ token from request headers."""
        auth = flow.request.headers.get("authorization", "")

        # Check Bearer token
        if auth.startswith("Bearer ") or auth.startswith("bearer "):
            token = auth[7:].strip()
            if token.startswith(SGW_TOKEN_PREFIX):
                return token

        # Check raw Authorization header
        if auth.startswith(SGW_TOKEN_PREFIX):
            return auth.strip()

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
                body.setdefault("reflection", "This route is flagged as risky. An operator must approve it via `safeyolo watch` before it can proceed.")
                flow.response = make_block_response(
                    decision.immediate_response.status_code,
                    body,
                    self.name,
                )
            else:
                self._deny(
                    flow, 428, "Risky route requires approval", "GATEWAY_RISKY_ROUTE",
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
                flow, 503, "Risky route check failed", "PDP_ERROR",
                action="abort",
                reflection="The policy engine failed while checking this risky route. The request was denied as a safety precaution.",
            )
            return True  # non-None

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
        flow.response = make_block_response(status, body, self.name)
        flow.metadata["blocked_by"] = self.name

        write_event(
            "gateway.deny",
            kind=EventKind.GATEWAY,
            severity=Severity.HIGH,
            summary=f"Gateway denied: {sanitize_for_log(reason)}",
            decision=Decision.DENY,
            host=flow.request.host,
            request_id=flow.metadata.get("request_id"),
            agent=flow.metadata.get("agent"),
            addon=self.name,
            details={"reason": reason, "code": code},
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


addons = [ServiceGateway()]
