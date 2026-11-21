use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    pub calls: u64,
    pub concurrent: u64,
    pub timeout_seconds: u64,
    pub output_bytes: u64,
}

impl Budgets {
    fn intersect(&self, other: &Self, execution: &ExecutionLimits) -> Self {
        Self {
            calls: self.calls.min(other.calls),
            concurrent: self.concurrent.min(other.concurrent),
            timeout_seconds: self
                .timeout_seconds
                .min(other.timeout_seconds)
                .min(execution.timeout_seconds),
            output_bytes: self
                .output_bytes
                .min(other.output_bytes)
                .min(execution.output_bytes),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationScope {
    pub implementation_sha256: String,
    pub resources: BTreeSet<String>,
    /// Missing argument authority denies a supplied/defaulted argument. Each
    /// choice is one complete native JSON value, including a complete list.
    pub arguments: BTreeMap<String, Vec<Value>>,
    pub budgets: Budgets,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub principal: Principal,
    pub not_before: u64,
    pub expires_at: u64,
    pub verbs: BTreeSet<Verb>,
    pub operations: BTreeMap<String, OperationScope>,
}

/// A verified, fresh projection from the issuer's existing policy owners.
/// The request cannot supply or replace this snapshot.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IssuerAuthority {
    pub revision: String,
    pub assessment_revision: String,
    pub observed_at: u64,
    pub valid_until: u64,
    pub grants: BTreeMap<String, Grant>,
}

/// Operator-owned trust. Public key IDs are scoped to one durable issuer.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IssuerTrust {
    pub revision: String,
    pub public_keys: BTreeMap<String, String>,
    pub authority: IssuerAuthority,
}

/// Operator-owned target inputs, supplied by the adopting executor. This
/// contract creates no policy file, enrolment endpoint or ceiling mutation.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub target_id: String,
    pub ceiling_revision: String,
    pub allowed_verbs: BTreeSet<Verb>,
    pub max_authority_age_seconds: u64,
    pub issuers: BTreeMap<String, IssuerTrust>,
    pub ceiling: BTreeMap<String, OperationScope>,
    pub package: Package,
}

/// Consumption belongs to an atomic durable target ledger, keyed by issuer,
/// grant revision and operation. The witness supplies its small reference ledger.
#[derive(Clone, Copy, Debug, Default)]
pub struct Usage {
    pub admitted: u64,
    pub active: u64,
}

pub struct Authorized<'a> {
    target: &'a Target,
    request: Request,
    grant: &'a Grant,
    revisions: AuthorityRevisions,
    valid_until: u64,
}

impl Authorized<'_> {
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// Unrelated issuer snapshot changes must not reset this grant's usage.
    pub fn grant_revision(&self) -> String {
        revision(self.grant)
    }
}

impl Target {
    /// Bind owner revision references together with the actual trusted inputs.
    /// Labels alone must not conceal a changed key set, grant or local ceiling.
    pub fn revisions(&self, issuer_id: &str) -> Result<AuthorityRevisions, Refusal> {
        let trust = self.issuers.get(issuer_id).ok_or_else(|| Refusal {
            code: RefusalCode::Issuer,
            message: "issuer is not enrolled at this target".into(),
        })?;
        Ok(AuthorityRevisions {
            trust: revision(&(issuer_id, &trust.revision, &trust.public_keys)),
            authority: revision(&(&trust.authority.revision, &trust.authority.grants)),
            ceiling: revision(&(
                &self.ceiling_revision,
                &self.allowed_verbs,
                self.max_authority_age_seconds,
                &self.ceiling,
            )),
            assessment: trust.authority.assessment_revision.clone(),
        })
    }
    pub fn validate(&self) -> Result<(), crate::Error> {
        self.package.validate()?;
        if !selector(&self.target_id)
            || self.ceiling_revision.is_empty()
            || self.max_authority_age_seconds == 0
        {
            return Err(
                "target needs durable identity, ceiling revision and finite freshness bound".into(),
            );
        }
        for (issuer, trust) in &self.issuers {
            if !selector(issuer)
                || trust.revision.is_empty()
                || trust.authority.revision.is_empty()
                || trust.authority.assessment_revision.is_empty()
                || trust.authority.valid_until <= trust.authority.observed_at
                || trust.public_keys.is_empty()
            {
                return Err("issuer trust needs keys and revisioned finite authority".into());
            }
            for (key_id, key) in &trust.public_keys {
                if !selector(key_id) || STANDARD.decode(key)?.len() != 32 {
                    return Err("issuer needs a literal key ID and Ed25519 public key".into());
                }
            }
        }
        Ok(())
    }

    /// The HTTP adapter must bound request bytes and use authenticated TLS (or
    /// an operator-adopted protected local transport) to authenticate the target.
    pub fn authenticate(
        &self,
        method: &str,
        path: &str,
        bytes: &[u8],
        now: u64,
    ) -> Result<Authorized<'_>, Refusal> {
        self.validate().map_err(|_| Refusal {
            code: RefusalCode::Unavailable,
            message: "target adoption or trust inputs are invalid".into(),
        })?;
        let signed: SignedRequest = serde_json::from_slice(bytes).map_err(|_| Refusal {
            code: RefusalCode::Malformed,
            message: "invalid signed request schema".into(),
        })?;
        let req = &signed.request;
        require(
            req.version == VERSION
                && req
                    .required_features
                    .iter()
                    .all(|f| FEATURES.contains(&f.as_str()))
                && method == "POST"
                && path == req.action.verb().path(),
            RefusalCode::Protocol,
            "unsupported version, required feature or route",
        )?;
        require(
            req.target_id == self.target_id,
            RefusalCode::Target,
            "request addresses another durable target",
        )?;
        let trust = self.issuers.get(&req.issuer_id).ok_or_else(|| Refusal {
            code: RefusalCode::Issuer,
            message: "issuer is not enrolled at this target".into(),
        })?;
        let key = trust
            .public_keys
            .get(&signed.key_id)
            .and_then(|key| STANDARD.decode(key).ok())
            .ok_or_else(|| Refusal {
                code: RefusalCode::Issuer,
                message: "issuer key is not currently trusted".into(),
            })?;
        let signature = STANDARD.decode(&signed.signature).map_err(|_| Refusal {
            code: RefusalCode::Signature,
            message: "invalid signature encoding".into(),
        })?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
            .verify(
                &SignedRequest::signing_message(req, &signed.key_id),
                &signature,
            )
            .map_err(|_| Refusal {
                code: RefusalCode::Signature,
                message: "issuer signature differs".into(),
            })?;
        require(
            selector(&req.request_id)
                && selector(&req.grant_id)
                && selector(&req.issuer_id)
                && req.action.job_id().is_none_or(selector),
            RefusalCode::Selector,
            "malformed literal selector",
        )?;
        let principal = &req.principal;
        require(
            crate::agent_api::coord::valid_agent_id(&principal.run.agent_id)
                && !principal.run.agent.is_empty()
                && principal.run.run_id.len() == 32
                && principal.run.run_id.bytes().all(|b| b.is_ascii_hexdigit())
                && principal.task_id.as_deref().is_none_or(selector),
            RefusalCode::Principal,
            "invalid principal/run/task binding",
        )?;
        let authority = &trust.authority;
        require(
            now >= authority.observed_at
                && now < authority.valid_until
                && now - authority.observed_at < self.max_authority_age_seconds,
            RefusalCode::Stale,
            "issuer authority is unavailable or stale; refresh from its owner",
        )?;
        let grant = authority.grants.get(&req.grant_id).ok_or_else(|| Refusal {
            code: RefusalCode::Authority,
            message: "grant is absent or revoked".into(),
        })?;
        require(
            grant.principal == *principal,
            RefusalCode::Principal,
            "authenticated issuer grant belongs to another principal, run or task",
        )?;
        require(
            now >= grant.not_before && now < grant.expires_at && now < req.expires_at,
            RefusalCode::Expired,
            "request or delegated authority is expired or not yet valid",
        )?;
        require(
            grant.verbs.contains(&req.action.verb())
                && self.allowed_verbs.contains(&req.action.verb()),
            RefusalCode::Authority,
            "grant or target ceiling does not permit this protocol operation",
        )?;
        let revisions = self.revisions(&req.issuer_id)?;
        if req.action.verb() != Verb::Discover {
            require(
                req.expected.as_ref() == Some(&revisions),
                RefusalCode::Stale,
                "expected trust, authority, ceiling or assessment changed; rediscover and reassess",
            )?;
        }
        let valid_until = authority
            .valid_until
            .min(
                authority
                    .observed_at
                    .saturating_add(self.max_authority_age_seconds),
            )
            .min(grant.expires_at)
            .min(req.expires_at);
        Ok(Authorized {
            target: self,
            request: signed.request,
            grant,
            revisions,
            valid_until,
        })
    }

    pub fn discover(&self, authorized: &Authorized<'_>) -> Result<Discovery, Refusal> {
        require(
            std::ptr::eq(self, authorized.target),
            RefusalCode::Target,
            "authentication belongs to another target context",
        )?;
        require(
            matches!(authorized.request.action, Action::Discover),
            RefusalCode::Protocol,
            "discovery requires its own request",
        )?;
        Ok(Discovery {
            target_id: self.target_id.clone(),
            version: VERSION.into(),
            features: FEATURES.iter().map(|s| s.to_string()).collect(),
            routes: [
                Verb::Discover,
                Verb::Propose,
                Verb::Invoke,
                Verb::Job,
                Verb::Output,
                Verb::Cancel,
            ]
            .into_iter()
            .map(|v| (v, v.path().into()))
            .collect(),
            package_sha256: revision(&self.package),
            package_version: self.package.version,
            revisions: authorized.revisions.clone(),
            authority_valid_until: authorized.valid_until,
            operations: self
                .package
                .operations
                .iter()
                .map(|(id, op)| OperationDiscovery {
                    operation_id: id.clone(),
                    implementation_sha256: op.implementation_sha256(),
                    definition: op.clone(),
                    has_invocation_scope: authorized.grant.verbs.contains(&Verb::Invoke)
                        && authorized.grant.operations.contains_key(id)
                        && self.ceiling.contains_key(id),
                })
                .collect(),
        })
    }

    /// Re-run immediately before the ledger atomically reserves admission. A
    /// previous proposal or a generic HTTP route grant is never sufficient.
    pub fn prepare(&self, authorized: &Authorized<'_>, usage: Usage) -> Result<Prepared, Refusal> {
        require(
            std::ptr::eq(self, authorized.target),
            RefusalCode::Target,
            "authentication belongs to another target context",
        )?;
        let invocation = match &authorized.request.action {
            Action::Propose { invocation } | Action::Invoke { invocation } => invocation,
            _ => {
                return Err(Refusal {
                    code: RefusalCode::Protocol,
                    message: "proposal/invocation required".into(),
                });
            }
        };
        require(
            selector(&invocation.operation_id) && selector(&invocation.resource_id),
            RefusalCode::Selector,
            "operation/resource selectors must be literal IDs",
        )?;
        let op = self
            .package
            .operations
            .get(&invocation.operation_id)
            .ok_or_else(|| Refusal {
                code: RefusalCode::Selector,
                message: "operation is not adopted".into(),
            })?;
        require(
            invocation.package_sha256 == revision(&self.package)
                && invocation.implementation_sha256 == op.implementation_sha256(),
            RefusalCode::Stale,
            "adopted package or implementation changed",
        )?;
        let delegated = authorized
            .grant
            .operations
            .get(&invocation.operation_id)
            .ok_or_else(|| Refusal {
                code: RefusalCode::Authority,
                message: "operation membership grants no invocation authority".into(),
            })?;
        let ceiling = self
            .ceiling
            .get(&invocation.operation_id)
            .ok_or_else(|| Refusal {
                code: RefusalCode::Authority,
                message: "operation exceeds the target local ceiling".into(),
            })?;
        let arguments = op.arguments(&invocation.arguments)?;
        op.command(&arguments)?;
        for scope in [delegated, ceiling] {
            require(
                scope.implementation_sha256 == op.implementation_sha256(),
                RefusalCode::Stale,
                "authority is bound to another implementation",
            )?;
            require(
                op.resources.contains(&invocation.resource_id)
                    && scope.resources.contains(&invocation.resource_id),
                RefusalCode::Authority,
                "resource is outside effective authority",
            )?;
            require(
                arguments.iter().all(|(name, value)| {
                    scope
                        .arguments
                        .get(name)
                        .is_some_and(|choices| choices.contains(value))
                }),
                RefusalCode::Authority,
                "argument/default is outside effective authority",
            )?;
        }
        let limits = delegated
            .budgets
            .intersect(&ceiling.budgets, &op.execution.resources);
        require(
            usage.admitted < limits.calls
                && usage.active < limits.concurrent
                && limits.timeout_seconds > 0
                && limits.output_bytes > 0,
            RefusalCode::Budget,
            "effective admission or execution budget is exhausted",
        )?;
        let mut normalized = invocation.clone();
        normalized.arguments = arguments;
        normalized.expected_assessment_sha256 = None;
        let assessment_sha256 = revision(&(
            &normalized,
            &authorized.revisions,
            &limits,
            authorized.valid_until,
        ));
        if matches!(authorized.request.action, Action::Invoke { .. })
            || invocation.expected_assessment_sha256.is_some()
        {
            require(
                invocation.expected_assessment_sha256.as_deref() == Some(&assessment_sha256),
                RefusalCode::Stale,
                "proposal assessment inputs changed; prepare the exact invocation again",
            )?;
        }
        normalized.expected_assessment_sha256 = Some(assessment_sha256.clone());
        Ok(Prepared {
            invocation: normalized,
            revisions: authorized.revisions.clone(),
            limits,
            valid_until: authorized.valid_until,
            assessment_sha256,
        })
    }

    pub fn authorize_job(
        &self,
        authorized: &Authorized<'_>,
        receipt: &Receipt,
    ) -> Result<(), Refusal> {
        require(
            std::ptr::eq(self, authorized.target),
            RefusalCode::Target,
            "authentication belongs to another target context",
        )?;
        require(
            authorized.request.action.job_id() == Some(receipt.job_id.as_str())
                && receipt.target_id == self.target_id
                && receipt.issuer_id == authorized.request.issuer_id
                && receipt.principal == authorized.request.principal
                && receipt.grant_id == authorized.request.grant_id,
            RefusalCode::Authority,
            "job/output belongs to another target, issuer, principal or grant",
        )
    }

    /// The executor must reserve Usage and retain this receipt atomically
    /// before starting the native operation. This method alone stores nothing.
    pub fn admit(
        &self,
        authorized: &Authorized<'_>,
        usage: Usage,
        now: u64,
    ) -> Result<Receipt, Refusal> {
        let prepared = self.prepare(authorized, usage)?;
        Receipt::admitted(&authorized.request, prepared, now)
    }
}
