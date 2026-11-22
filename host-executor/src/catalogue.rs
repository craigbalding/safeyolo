//! Deterministic host-catalogue adoption. Publisher trust, qualification and
//! invocation grants are separate inputs owned by the existing configuration.
use crate::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    Equivalent,
    Narrower,
    Broader,
    Incompatible,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Difference {
    pub path: String,
    pub before: Value,
    pub after: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationChange {
    pub comparison: Comparison,
    pub differences: Vec<Difference>,
    pub implementation: String,
    pub authority: String,
    pub assessment: String,
}

// Only contract fields whose order has no meaning are treated as sets. Native
// argv, list arguments, defaults and effect descriptions retain their meaning.
pub(crate) fn canonical_operation(op: &Operation) -> Value {
    let mut value = serde_json::to_value(op).expect("operation serialization");
    fn set(value: &mut Value) {
        if let Some(items) = value.as_array_mut() {
            items.sort_by_key(revision);
            items.dedup();
        }
    }
    for path in [
        "/execution/identity/groups",
        "/execution/filesystem/read",
        "/execution/filesystem/write",
        "/execution/network/destinations",
        "/execution/network/ipc",
        "/execution/broader",
        "/enforcement/enforced",
        "/enforcement/adopted",
        "/enforcement/unresolved",
    ] {
        if let Some(v) = value.pointer_mut(path) {
            set(v);
        }
    }
    for arg in value["arguments"]
        .as_object_mut()
        .expect("arguments")
        .values_mut()
    {
        set(&mut arg["options"]);
    }
    for effect in value["effects"]
        .as_object_mut()
        .expect("effects")
        .values_mut()
    {
        set(&mut effect["evidence"]);
    }
    for service in value["execution"]["delegated_services"]
        .as_array_mut()
        .expect("services")
    {
        set(&mut service["resources"]);
    }
    set(&mut value["execution"]["delegated_services"]);
    value
}

fn subset(actual: &Value, ceiling: &Value) -> bool {
    match (actual.as_array(), ceiling.as_array()) {
        (Some(a), Some(b)) => a.iter().all(|v| b.contains(v)),
        _ => false,
    }
}

/// A conservative inclusion proof for represented bounds. Recipes, defaults,
/// environment, identity and service-manager authority must match the ceiling.
/// Code trust can allow new bytes; it never proves arbitrary code equivalence.
pub fn within_operation(op: &Operation, ceiling: &Operation, allow_code: bool) -> bool {
    let (mut a, mut b) = (canonical_operation(op), canonical_operation(ceiling));
    for path in [
        "/resources",
        "/execution/filesystem/read",
        "/execution/filesystem/write",
        "/execution/network/destinations",
        "/execution/network/ipc",
        "/execution/broader",
    ] {
        if !subset(a.pointer(path).unwrap(), b.pointer(path).unwrap()) {
            return false;
        }
        *a.pointer_mut(path).unwrap() = Value::Null;
        *b.pointer_mut(path).unwrap() = Value::Null;
    }
    // Free-text enforcement disclosures are assessment inputs, not a proof
    // that a claimed new guarantee is implemented by the selected backend.
    if !subset(&b["required_checks"], &a["required_checks"]) {
        return false;
    }
    a["required_checks"] = Value::Null;
    b["required_checks"] = Value::Null;
    for field in [
        "timeout_seconds",
        "output_bytes",
        "memory_bytes",
        "processes",
    ] {
        if a["execution"]["resources"][field].as_u64() > b["execution"]["resources"][field].as_u64()
        {
            return false;
        }
        a["execution"]["resources"][field] = Value::Null;
        b["execution"]["resources"][field] = Value::Null;
    }
    if a["arguments"]
        .as_object()
        .unwrap()
        .keys()
        .ne(b["arguments"].as_object().unwrap().keys())
    {
        return false;
    }
    for name in op.arguments.keys() {
        if matches!(op.arguments[name].kind, ArgumentType::Enum) {
            if !subset(
                &a["arguments"][name]["options"],
                &b["arguments"][name]["options"],
            ) {
                return false;
            }
            a["arguments"][name]["options"] = Value::Null;
            b["arguments"][name]["options"] = Value::Null;
        }
    }
    for (path, dependency) in a["execution"]["dependencies"].as_object().unwrap() {
        let Some(ceiling) = b["execution"]["dependencies"].get(path) else {
            return false;
        };
        if dependency["bytes"].as_u64() > ceiling["bytes"].as_u64() {
            return false;
        }
    }
    for value in [&mut a, &mut b] {
        for dependency in value["execution"]["dependencies"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            dependency["bytes"] = Value::Null;
        }
    }
    if allow_code {
        a["execution"]["executable_sha256"] = Value::Null;
        b["execution"]["executable_sha256"] = Value::Null;
        // Dependencies cannot acquire new paths or a weaker enforcement mode.
        for value in [&mut a, &mut b] {
            for dependency in value["execution"]["dependencies"]
                .as_object_mut()
                .unwrap()
                .values_mut()
            {
                dependency["sha256"] = Value::Null;
            }
        }
    }
    a == b
}

pub fn compare_operations(before: &Operation, after: &Operation) -> OperationChange {
    let (a, b) = (canonical_operation(before), canonical_operation(after));
    let comparison = if a == b {
        Comparison::Equivalent
    } else if within_operation(after, before, false) {
        Comparison::Narrower
    } else if within_operation(before, after, false) {
        Comparison::Broader
    } else if before.arguments.iter().any(|(k, v)| {
        after
            .arguments
            .get(k)
            .is_none_or(|n| revision(&n.kind) != revision(&v.kind))
    }) {
        Comparison::Incompatible
    } else {
        Comparison::Unknown
    };
    fn differences(path: String, a: &Value, b: &Value, result: &mut Vec<Difference>) {
        if a == b {
            return;
        }
        if let (Some(a), Some(b)) = (a.as_object(), b.as_object()) {
            let keys: BTreeSet<_> = a.keys().chain(b.keys()).collect();
            for key in keys {
                differences(
                    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                    a.get(key).unwrap_or(&Value::Null),
                    b.get(key).unwrap_or(&Value::Null),
                    result,
                );
            }
        } else {
            result.push(Difference {
                path,
                before: a.clone(),
                after: b.clone(),
            });
        }
    }
    let mut changes = Vec::new();
    differences(String::new(), &a, &b, &mut changes);
    OperationChange {
        comparison,
        differences: changes,
        implementation: after.implementation_sha256(),
        authority: after.authority_sha256(),
        assessment: after.assessment_sha256(),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateRule {
    /// The complete potential authority, effects and compositions must be
    /// assessed when this rule is adopted, including future family members.
    pub ceiling: Operation,
    pub allow_narrower: bool,
    pub allow_implementation_updates: bool,
}
impl UpdateRule {
    pub fn allows(&self, op: &Operation) -> bool {
        op.enforcement.unresolved.is_empty()
            && within_operation(op, &self.ceiling, self.allow_implementation_updates)
            && (self.allow_narrower
                || canonical_operation(op) == canonical_operation(&self.ceiling)
                || self.allow_implementation_updates && within_operation(&self.ceiling, op, true))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationFamily {
    pub prefix: String,
    pub excluded: BTreeSet<String>,
    pub rule: UpdateRule,
    pub scope: OperationScope,
}
impl OperationFamily {
    pub fn contains(&self, id: &str, op: &Operation) -> bool {
        selector(&self.prefix)
            && self.prefix.ends_with(':')
            && id.starts_with(&self.prefix)
            && id.len() > self.prefix.len()
            && !self.excluded.contains(id)
            && self.rule.allows(op)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueRevision {
    pub publisher: String,
    pub announcement_revision: u64,
    pub package: Package,
    pub observed_at: u64,
    pub expires_at: u64,
    pub withdrawn: bool,
    pub previous: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedCatalogue {
    pub catalogue: CatalogueRevision,
    pub signature: String,
}
impl SignedCatalogue {
    fn message(catalogue: &CatalogueRevision) -> Vec<u8> {
        format!("safeyolo.host-catalogue/v1\n{}", revision(catalogue)).into_bytes()
    }
    pub fn sign(catalogue: CatalogueRevision, key: &Ed25519KeyPair) -> Self {
        let signature = STANDARD.encode(key.sign(&Self::message(&catalogue)).as_ref());
        Self {
            catalogue,
            signature,
        }
    }
    pub fn verify(&self, policy: &CataloguePolicy, now: u64) -> Result<(), Refusal> {
        require(
            self.catalogue.observed_at <= now && now < self.catalogue.expires_at,
            RefusalCode::Expired,
            "catalogue announcement is stale or not yet valid",
        )?;
        self.verify_retained(policy)
    }
    fn verify_retained(&self, policy: &CataloguePolicy) -> Result<(), Refusal> {
        require(
            self.catalogue.announcement_revision > 0,
            RefusalCode::Protocol,
            "catalogue announcement revision must be positive",
        )?;
        require(
            self.catalogue.publisher == policy.publisher
                && self.catalogue.package.name == policy.package_name,
            RefusalCode::Issuer,
            "catalogue publisher or package name differs from adoption",
        )?;
        self.catalogue
            .package
            .validate()
            .map_err(crate::native::unavailable)?;
        require(
            self.catalogue.expires_at > self.catalogue.observed_at,
            RefusalCode::Expired,
            "catalogue announcement needs a finite lifetime",
        )?;
        let key = STANDARD
            .decode(&policy.public_key)
            .map_err(crate::native::unavailable)?;
        let signature = STANDARD
            .decode(&self.signature)
            .map_err(crate::native::unavailable)?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&Self::message(&self.catalogue), &signature)
            .map_err(|_| Refusal {
                code: RefusalCode::Signature,
                message: "catalogue publisher signature differs".into(),
            })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CataloguePolicy {
    pub publisher: String,
    pub public_key: String,
    pub package_name: String,
    pub operations: BTreeMap<String, UpdateRule>,
    pub families: Vec<OperationFamily>,
    pub on_withdraw: Withdrawal,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Withdrawal {
    Retain,
    Previous,
}

/// Stored with the existing target or issuer adoption configuration. This is
/// not invocation policy and contains no approval queue or publisher code hook.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueAdoption {
    pub policy: CataloguePolicy,
    pub active: SignedCatalogue,
    pub previous: Option<SignedCatalogue>,
    /// Discovery and signals can supply the same authenticated candidate.
    pub observed: SignedCatalogue,
    pub pin: Option<String>,
    /// Optional publisher/discovery input. The existing policy watcher and
    /// every target invocation read its actual bytes, never only size or mtime.
    #[serde(default)]
    pub observed_file: Option<ObservedCatalogueFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedCatalogueFile {
    pub path: std::path::PathBuf,
    pub max_bytes: u64,
}
impl ObservedCatalogueFile {
    fn read(&self) -> Result<SignedCatalogue, Refusal> {
        use std::io::Read;
        require(
            self.path.is_absolute() && self.max_bytes > 0 && self.max_bytes < isize::MAX as u64,
            RefusalCode::Unavailable,
            "catalogue discovery needs an absolute path and a finite adopted byte ceiling",
        )?;
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(&self.path)
                .map_err(crate::native::unavailable)?
        };
        #[cfg(windows)]
        let file = crate::windows::security::read_file(&self.path)?;
        require(
            file.metadata()
                .map_err(crate::native::unavailable)?
                .is_file(),
            RefusalCode::Unavailable,
            "catalogue discovery input must be a regular file",
        )?;
        let mut bytes = Vec::new();
        file.take(self.max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(crate::native::unavailable)?;
        require(
            bytes.len() as u64 <= self.max_bytes,
            RefusalCode::Budget,
            "catalogue discovery exceeds its adopted byte ceiling",
        )?;
        serde_json::from_slice(&bytes).map_err(crate::native::unavailable)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueStatus {
    pub observed: String,
    pub proposed: String,
    pub qualified: Option<String>,
    pub active: String,
    pub state: String,
    pub reason: String,
    pub changes: BTreeMap<String, OperationChange>,
    pub discovered: BTreeMap<String, Operation>,
    pub policy_sha256: String,
    pub pending: String,
    pub running: String,
}
pub struct CataloguePlan {
    pub package: Package,
    pub status: CatalogueStatus,
    pub selected: SignedCatalogue,
    pub verified_observation: Option<SignedCatalogue>,
}

impl CatalogueAdoption {
    /// Qualification executes no candidate program. The caller must validate
    /// platform enforcement and derive BOTH projections before committing.
    pub fn plan(&self, now: u64) -> Result<CataloguePlan, Refusal> {
        if let Some(source) = &self.observed_file
            && self.pin.is_none()
        {
            let mut adopted = self.clone();
            adopted.observed_file = None;
            let observed = source.read();
            let observed_sha = observed.as_ref().ok().map(|c| revision(&c.catalogue));
            let observation=observed.and_then(|candidate|{
                candidate.verify(&self.policy,now)?;
                require(candidate.catalogue.announcement_revision >= self.observed.catalogue.announcement_revision,
                    RefusalCode::Stale,"older catalogue announcement refused; retained withdrawal/update observation remains authoritative")?;
                require(candidate.catalogue.announcement_revision != self.observed.catalogue.announcement_revision
                    || revision(&candidate.catalogue)==revision(&self.observed.catalogue),
                    RefusalCode::Conflict,"catalogue announcement revision identifies conflicting content")?;
                Ok(candidate)
            });
            match observation {
                Ok(candidate) => {
                    adopted.observed = candidate;
                    return adopted.plan(now);
                }
                Err(error) => {
                    adopted.observed = self.active.clone();
                    adopted.pin = None;
                    let mut plan = adopted.plan(now)?;
                    plan.status.state =
                        if matches!(error.code, RefusalCode::Unavailable | RefusalCode::Budget) {
                            "unavailable"
                        } else {
                            "refused"
                        }
                        .into();
                    plan.status.reason = format!(
                        "current catalogue discovery failed; retained active provenance is shown: {error}"
                    );
                    if let Some(sha) = observed_sha {
                        plan.status.observed = sha;
                    }
                    plan.status.qualified = None;
                    plan.verified_observation = None;
                    return Ok(plan);
                }
            }
        }
        self.active.verify_retained(&self.policy)?;
        let active = &self.active.catalogue.package;
        let verified_observation = self
            .observed
            .verify(&self.policy, now)
            .is_ok()
            .then(|| self.observed.clone());
        let mut status = CatalogueStatus {
            observed: revision(&self.observed.catalogue), proposed: revision(&self.observed.catalogue.package),
            qualified: None, active: revision(active), state: "awaiting_review".into(), reason: String::new(),
            changes: BTreeMap::new(), discovered: BTreeMap::new(), policy_sha256: revision(&self.policy),
            pending: "Prepared requests and pending approvals retain their exact operation, authority and assessment inputs; changed inputs require reassessment, never inherited approval.".into(),
            running: "Admitted jobs revalidate before launch. Running jobs retain admitted limits and original implementation; activation or withdrawal does not reverse effects or relaunch jobs. Existing cancellation and retained receipts apply.".into(),
        };
        let retained = |reason: String, mut status: CatalogueStatus| {
            status.reason = reason;
            CataloguePlan {
                package: active.clone(),
                status,
                selected: self.active.clone(),
                verified_observation: verified_observation.clone(),
            }
        };
        if let Err(error) = self.observed.verify(&self.policy, now)
            && self.pin.is_none()
        {
            status.state = "refused".into();
            return Ok(retained(error.to_string(), status));
        }
        let observed = &self.observed.catalogue;
        if self.pin.is_none() && !observed.withdrawn && observed.package.version < active.version {
            status.state = "refused".into();
            return Ok(retained("An older announcement cannot select rollback; use an explicit retained pin or the adopted withdrawal policy.".into(), status));
        }
        let candidate = if let Some(pin) = &self.pin {
            [&self.active, &self.observed]
                .into_iter()
                .chain(self.previous.iter())
                .find(|c| revision(&c.catalogue.package) == *pin)
                .ok_or_else(|| Refusal {
                    code: RefusalCode::Stale,
                    message: "pinned catalogue revision is unavailable".into(),
                })?
        } else if observed.withdrawn {
            match self.policy.on_withdraw {
                Withdrawal::Retain => {
                    status.state = "withdrawn".into();
                    return Ok(retained("Withdrawal retains the active revision under current standing authority; no grant is restored.".into(), status));
                }
                Withdrawal::Previous => Some(&self.active)
                    .filter(|p| {
                        observed.previous.as_deref()
                            == Some(revision(&p.catalogue.package).as_str())
                    })
                    .or(self.previous.as_ref())
                    .filter(|p| {
                        observed.previous.as_deref()
                            == Some(revision(&p.catalogue.package).as_str())
                    })
                    .ok_or_else(|| Refusal {
                        code: RefusalCode::Stale,
                        message: "withdrawal has no identified retained previous revision".into(),
                    })?,
            }
        } else {
            &self.observed
        };
        candidate.verify_retained(&self.policy)?;
        require(
            !candidate.catalogue.withdrawn,
            RefusalCode::Stale,
            "selected catalogue is withdrawn",
        )?;
        let proposed = &candidate.catalogue.package;
        status.proposed = revision(proposed);
        let mut allowed = true;
        for (id, op) in &proposed.operations {
            let old = active.operations.get(id);
            let change = old.map(|old| compare_operations(old, op));
            let equivalent = change
                .as_ref()
                .is_some_and(|c| c.comparison == Comparison::Equivalent);
            let rule = self.policy.operations.get(id).or_else(|| {
                self.policy
                    .families
                    .iter()
                    .find(|f| f.contains(id, op))
                    .map(|f| &f.rule)
            });
            let covered = equivalent || rule.is_some_and(|r| r.allows(op));
            // Unknown operations stay discoverable without acquiring authority.
            if !covered {
                allowed = false;
                status.discovered.insert(id.clone(), op.clone());
            }
            if let Some(change) = change {
                status.changes.insert(id.clone(), change);
            } else {
                status.changes.insert(
                    id.clone(),
                    OperationChange {
                        comparison: Comparison::Broader,
                        differences: vec![Difference {
                            path: format!("/operations/{id}"),
                            before: Value::Null,
                            after: json!(op),
                        }],
                        implementation: op.implementation_sha256(),
                        authority: op.authority_sha256(),
                        assessment: op.assessment_sha256(),
                    },
                );
            }
        }
        // Removing an operation narrows availability; no old entry is recreated.
        for (id, op) in &active.operations {
            if !proposed.operations.contains_key(id) {
                status.changes.insert(
                    id.clone(),
                    OperationChange {
                        comparison: Comparison::Narrower,
                        differences: vec![Difference {
                            path: format!("/operations/{id}"),
                            before: json!(op),
                            after: Value::Null,
                        }],
                        implementation: String::new(),
                        authority: String::new(),
                        assessment: String::new(),
                    },
                );
            }
        }
        if !allowed {
            return Ok(retained("Candidate contains an operation outside the adopted update ceiling or an unresolved contract. Use existing policy assessment/challenge/review to change adoption; publisher authentication grants no execution.".into(), status));
        }
        status.qualified = Some(revision(proposed));
        status.active = revision(proposed);
        status.state = if self.pin.is_some() || observed.withdrawn {
            "rolled_back"
        } else {
            "active"
        }
        .into();
        status.reason = "Canonical equivalence or the explicitly adopted publisher/update ceiling covers every changed operation; platform qualification and matching gateway/target projections remain required.".into();
        Ok(CataloguePlan {
            package: proposed.clone(),
            status,
            selected: candidate.clone(),
            verified_observation,
        })
    }

    /// Advance only after this exact plan passed the owning runtime's complete
    /// qualification. The owner saves this with its existing configuration.
    pub fn advance(&mut self, plan: &CataloguePlan) -> bool {
        let mut changed = false;
        if let Some(observed) = &plan.verified_observation
            && revision(&observed.catalogue) != revision(&self.observed.catalogue)
        {
            self.observed = observed.clone();
            changed = true;
        }
        if plan.status.qualified.as_deref() != Some(plan.status.active.as_str())
            || revision(&plan.selected.catalogue.package) != plan.status.active
            || revision(&self.active.catalogue.package) == plan.status.active
        {
            return changed;
        }
        self.previous = Some(self.active.clone());
        self.active = plan.selected.clone();
        true
    }
}
