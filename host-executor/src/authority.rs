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
    /// Exact grants gain update authority only by explicit owner adoption.
    #[serde(default)]
    pub updates: Option<UpdateRule>,
    #[serde(default)]
    pub checks: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub principal: Principal,
    /// Explicit standing authority for later host-observed runs of this same
    /// durable agent and task. It changes neither expiry nor budget ownership.
    #[serde(default)]
    pub allow_run_refresh: bool,
    pub not_before: u64,
    pub expires_at: u64,
    pub verbs: BTreeSet<Verb>,
    pub operations: BTreeMap<String, OperationScope>,
    #[serde(default)]
    pub families: Vec<OperationFamily>,
}

impl Grant {
    pub fn allows_principal(&self, principal: &Principal) -> bool {
        self.principal == *principal
            || self.allow_run_refresh
                && self.principal.task_id.is_some()
                && self.principal.task_id == principal.task_id
                && self.principal.run.agent_id == principal.run.agent_id
                && self.principal.run.agent == principal.run.agent
    }
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
    #[serde(default)]
    pub families: Vec<OperationFamily>,
    #[serde(default)]
    pub catalogue: Option<CatalogueStatus>,
}

/// Consumption of one selected exact-operation or family scope.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScopeUsage {
    pub admitted: u64,
    pub active: u64,
}

/// The durable ledger reserves both scopes atomically. Issuer usage belongs to
/// the selected grant; target usage is shared across issuers and grants.
#[derive(Clone, Copy, Debug, Default)]
pub struct Usage {
    pub issuer: ScopeUsage,
    pub target: ScopeUsage,
}

pub(crate) struct SelectedScope<'a> {
    pub operation: String,
    pub scope: &'a OperationScope,
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

    /// Authorise code intake separately from invocation and publisher updates.
    /// The target still qualifies native inputs before committing the catalogue.
    pub fn agent_code_package(&self) -> Result<Package, Refusal> {
        let Action::Adopt {
            operation_id,
            operation,
            base_package_sha256,
            package_sha256,
            ..
        } = &self.request.action
        else {
            return Err(crate::native::unavailable("code adoption request required"));
        };
        require(
            *base_package_sha256 == revision(&self.target.package),
            RefusalCode::Stale,
            "code adoption was prepared against another package; inspect the original adoption before preparing again",
        )?;
        for (scopes, families) in [
            (&self.grant.operations, &self.grant.families),
            (&self.target.ceiling, &self.target.families),
        ] {
            let selected = self
                .target
                .scope(operation_id, operation, scopes, families)
                .ok_or_else(|| Refusal {
                    code: RefusalCode::Authority,
                    message: "agent code is outside the issuer or target's adopted operation class"
                        .into(),
                })?;
            let rule = if let Some(exact) = scopes.get(operation_id) {
                exact.updates.as_ref()
            } else {
                families
                    .iter()
                    .find(|family| family.contains(operation_id, operation))
                    .map(|family| &family.rule)
            };
            require(
                rule.is_some_and(|rule| rule.allows_agent_code(operation))
                    && operation.resources.is_subset(&selected.scope.resources)
                    && operation.required_checks.is_subset(&selected.scope.checks),
                RefusalCode::Authority,
                "agent code needs an explicitly adopted code class at both owners; publisher update trust is insufficient",
            )?;
        }
        let package = self.target.revised_package(operation_id, operation)?;
        require(
            *package_sha256 == revision(&package),
            RefusalCode::Stale,
            "code adoption differs from the issuer's exact resulting package",
        )?;
        Ok(package)
    }

    /// Unrelated issuer snapshot changes must not reset this grant's usage.
    pub fn grant_revision(&self) -> String {
        revision(self.grant)
    }

    pub(crate) fn scopes(
        &self,
        id: &str,
    ) -> Result<(SelectedScope<'_>, SelectedScope<'_>), Refusal> {
        let op = self
            .target
            .package
            .operations
            .get(id)
            .ok_or_else(|| Refusal {
                code: RefusalCode::Selector,
                message: "operation is not adopted".into(),
            })?;
        let delegated = self
            .target
            .scope(id, op, &self.grant.operations, &self.grant.families)
            .ok_or_else(|| Refusal {
                code: RefusalCode::Authority,
                message: "operation membership grants no invocation authority".into(),
            })?;
        let ceiling = self
            .target
            .scope(id, op, &self.target.ceiling, &self.target.families)
            .ok_or_else(|| Refusal {
                code: RefusalCode::Authority,
                message: "operation exceeds the target local ceiling".into(),
            })?;
        Ok((delegated, ceiling))
    }
}

impl Target {
    /// Pure authoring: construct the exact next package without running code,
    /// modifying adoption or granting access.
    pub fn revised_package(
        &self,
        operation_id: &str,
        operation: &Operation,
    ) -> Result<Package, Refusal> {
        require(
            selector(operation_id),
            RefusalCode::Selector,
            "code adoption needs a literal operation selector",
        )?;
        let mut package = self.package.clone();
        package.version = package.version.checked_add(1).ok_or_else(|| Refusal {
            code: RefusalCode::Conflict,
            message: "package revision is exhausted".into(),
        })?;
        package
            .operations
            .insert(operation_id.to_owned(), operation.clone());
        package.validate().map_err(crate::native::unavailable)?;
        Ok(package)
    }
    /// Project represented current authority for read-only assessment. Use the
    /// same exact/family selection and update trust as execution. Ledger usage
    /// and fresh admission remain execution-time inputs.
    pub fn effective_operations(&self, grant: &Grant) -> BTreeMap<String, OperationScope> {
        if !grant.verbs.contains(&Verb::Invoke) || !self.allowed_verbs.contains(&Verb::Invoke) {
            return BTreeMap::new();
        }
        self.package
            .operations
            .iter()
            .filter_map(|(id, op)| {
                let delegated = self.scope(id, op, &grant.operations, &grant.families)?;
                let ceiling = self.scope(id, op, &self.ceiling, &self.families)?;
                if !self.scope_is_current(id, op, delegated.scope, &grant.families)
                    || !self.scope_is_current(id, op, ceiling.scope, &self.families)
                    || !op.required_checks.is_subset(&delegated.scope.checks)
                    || !op.required_checks.is_subset(&ceiling.scope.checks)
                {
                    return None;
                }
                let budgets = delegated
                    .scope
                    .budgets
                    .intersect(&ceiling.scope.budgets, &op.execution.resources);
                if budgets.calls == 0
                    || budgets.concurrent == 0
                    || budgets.timeout_seconds == 0
                    || budgets.output_bytes == 0
                {
                    return None;
                }
                let resources: BTreeSet<_> = delegated
                    .scope
                    .resources
                    .intersection(&ceiling.scope.resources)
                    .filter(|r| op.resources.contains(*r))
                    .cloned()
                    .collect();
                if resources.is_empty() {
                    return None;
                }
                let arguments: BTreeMap<_, _> = op
                    .arguments
                    .iter()
                    .map(|(name, arg)| {
                        let choices = delegated
                            .scope
                            .arguments
                            .get(name)
                            .into_iter()
                            .flatten()
                            .filter(|v| {
                                arg.accepts(v)
                                    && ceiling
                                        .scope
                                        .arguments
                                        .get(name)
                                        .is_some_and(|allowed| allowed.contains(*v))
                            })
                            .cloned()
                            .collect::<Vec<_>>();
                        (name.clone(), choices)
                    })
                    .collect();
                if op.arguments.iter().any(|(name, arg)| {
                    (arg.required || arg.default.is_some()) && arguments[name].is_empty()
                }) {
                    return None;
                }
                Some((
                    id.clone(),
                    OperationScope {
                        implementation_sha256: op.implementation_sha256(),
                        resources,
                        arguments,
                        budgets,
                        updates: None,
                        checks: delegated
                            .scope
                            .checks
                            .intersection(&ceiling.scope.checks)
                            .cloned()
                            .collect(),
                    },
                ))
            })
            .collect()
    }

    fn scope_is_current(
        &self,
        id: &str,
        op: &Operation,
        scope: &OperationScope,
        families: &[OperationFamily],
    ) -> bool {
        scope.implementation_sha256 == op.implementation_sha256()
            || self
                .catalogue
                .as_ref()
                .is_some_and(|s| s.active == revision(&self.package))
                && (scope.updates.as_ref().is_some_and(|rule| rule.allows(op))
                    || families
                        .iter()
                        .any(|f| std::ptr::eq(&f.scope, scope) && f.contains(id, op)))
    }

    /// Bind only the selected operation and grant. The full-source identity is
    /// still disclosed separately; unrelated edits cannot invalidate this call.
    pub fn request_revisions(
        &self,
        issuer: &str,
        grant_id: &str,
        action: &Action,
    ) -> Result<AuthorityRevisions, Refusal> {
        let mut result = self.revisions(issuer)?;
        if let Action::Propose { invocation } | Action::Invoke { invocation } = action {
            let trust = &self.issuers[issuer];
            let grant = trust.authority.grants.get(grant_id);
            let op = &invocation.operation_id;
            result.authority = revision(&(
                grant.map(|g| {
                    (
                        &g.principal,
                        g.allow_run_refresh,
                        g.not_before,
                        g.expires_at,
                        &g.verbs,
                        g.operations.get(op),
                        &g.families,
                    )
                }),
                op,
            ));
            result.ceiling = revision(&(
                &self.allowed_verbs,
                self.max_authority_age_seconds,
                self.ceiling.get(op),
                &self.families,
                op,
            ));
            result.assessment = revision(&(
                &trust.authority.assessment_revision,
                self.package
                    .operation_revisions(op)
                    .map(|r| r.understanding),
            ));
        }
        Ok(result)
    }

    fn scope<'a>(
        &'a self,
        id: &str,
        op: &Operation,
        exact: &'a BTreeMap<String, OperationScope>,
        families: &'a [OperationFamily],
    ) -> Option<SelectedScope<'a>> {
        exact
            .get(id)
            .map(|scope| SelectedScope {
                operation: id.into(),
                scope,
            })
            .or_else(|| {
                self.catalogue
                    .as_ref()
                    .filter(|s| s.active == revision(&self.package))?;
                families
                    .iter()
                    .find(|f| f.contains(id, op))
                    .map(|f| SelectedScope {
                        operation: format!("@family:{}", f.prefix),
                        scope: &f.scope,
                    })
            })
    }

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
                &self.families,
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
            valid_agent_id(&principal.run.agent_id)
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
            grant.allows_principal(principal),
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
        let revisions = self.request_revisions(&req.issuer_id, &req.grant_id, &req.action)?;
        if let Action::Propose { invocation } | Action::Invoke { invocation } = &req.action {
            require(
                selector(&invocation.operation_id)
                    && selector(&invocation.resource_id)
                    && self
                        .package
                        .operations
                        .contains_key(&invocation.operation_id),
                RefusalCode::Selector,
                "operation/resource must be literal adopted selectors",
            )?;
        }
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
                #[cfg(unix)]
                Verb::File,
                Verb::Cancel,
                Verb::Adopt,
                Verb::Adoption,
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
                    semantic_revisions: self
                        .package
                        .operation_revisions(id)
                        .expect("adopted operation"),
                    operation_sha256: self
                        .package
                        .operation_sha256(id)
                        .expect("adopted operation"),
                    authority_sha256: op.authority_sha256(),
                    assessment_sha256: self.package.operation_revisions(id).unwrap().understanding,
                    revisions: self
                        .request_revisions(
                            &authorized.request.issuer_id,
                            &authorized.request.grant_id,
                            &Action::Propose {
                                invocation: Invocation {
                                    operation_id: id.clone(),
                                    resource_id: String::new(),
                                    operation_sha256: String::new(),
                                    implementation_sha256: String::new(),
                                    arguments: BTreeMap::new(),
                                    expected_assessment_sha256: None,
                                },
                            },
                        )
                        .expect("authenticated issuer"),
                    definition: op.clone(),
                    network_enforcement: Vec::new(),
                    has_invocation_scope: authorized.grant.verbs.contains(&Verb::Invoke)
                        && self
                            .scope(
                                id,
                                op,
                                &authorized.grant.operations,
                                &authorized.grant.families,
                            )
                            .is_some()
                        && self.scope(id, op, &self.ceiling, &self.families).is_some(),
                })
                .collect(),
            catalogue: self.catalogue.clone(),
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
            invocation.operation_sha256
                == self.package.operation_sha256(&invocation.operation_id)?
                && invocation.implementation_sha256 == op.implementation_sha256(),
            RefusalCode::Stale,
            "adopted operation or implementation changed",
        )?;
        let (delegated, ceiling) = authorized.scopes(&invocation.operation_id)?;
        let (delegated, ceiling) = (delegated.scope, ceiling.scope);
        let arguments = op.arguments(&invocation.arguments)?;
        op.command(&arguments)?;
        for (scope, used, families) in [
            (delegated, usage.issuer, &authorized.grant.families),
            (ceiling, usage.target, &self.families),
        ] {
            require(
                used.admitted < scope.budgets.calls && used.active < scope.budgets.concurrent,
                RefusalCode::Budget,
                "selected issuer or target admission budget is exhausted",
            )?;
            require(
                self.scope_is_current(&invocation.operation_id, op, scope, families),
                RefusalCode::Stale,
                "authority is bound to another implementation",
            )?;
            require(
                op.required_checks.is_subset(&scope.checks),
                RefusalCode::Authority,
                "required qualification/check evidence is absent from current authority",
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
            limits.timeout_seconds > 0 && limits.output_bytes > 0,
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
            file_roots: op.execution.filesystem.write.clone(),
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
                && authorized.grant.allows_principal(&receipt.principal)
                && receipt.grant_id == authorized.request.grant_id,
            RefusalCode::Authority,
            "job/output belongs to another target, issuer, principal or grant",
        )
    }

    pub(crate) fn file_result_roots<'a>(
        &'a self,
        authorized: &Authorized<'_>,
        receipt: &Receipt,
        max_bytes: u64,
    ) -> Result<&'a [String], Refusal> {
        self.authorize_job(authorized, receipt)?;
        let invocation = &receipt.prepared.invocation;
        let op = self
            .package
            .operations
            .get(&invocation.operation_id)
            .ok_or_else(|| Refusal {
                code: RefusalCode::Authority,
                message: "file results need a currently adopted operation and file scope".into(),
            })?;
        let (delegated, ceiling) = authorized.scopes(&invocation.operation_id)?;
        for (scope, families) in [
            (delegated.scope, &authorized.grant.families),
            (ceiling.scope, &self.families),
        ] {
            require(
                self.scope_is_current(&invocation.operation_id, op, scope, families)
                    && op.required_checks.is_subset(&scope.checks)
                    && op.resources.contains(&invocation.resource_id)
                    && scope.resources.contains(&invocation.resource_id),
                RefusalCode::Authority,
                "file results are outside current operation/resource authority",
            )?;
            require(
                max_bytes > 0 && max_bytes <= scope.budgets.output_bytes,
                RefusalCode::Arguments,
                "file chunk exceeds current output limit",
            )?;
        }
        require(
            max_bytes <= receipt.prepared.limits.output_bytes
                && max_bytes <= op.execution.resources.output_bytes,
            RefusalCode::Arguments,
            "file chunk exceeds admitted or current execution output limit",
        )?;
        Ok(&op.execution.filesystem.write)
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
