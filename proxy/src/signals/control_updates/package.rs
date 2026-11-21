//! Immutable native check definitions and sandbox job specifications.
use super::*;
use crate::policy::checks::{
    Check, EvidenceSource, Finding, ResultType, Subject, SubjectKind,
    challenges::{Challenge, Step},
};
use std::io::{Read, Write};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub check: String,
    pub subject: Subject,
    pub positive: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub format: String,
    pub name: String,
    pub publisher: String,
    pub revision: u64,
    pub observed_at: u64,
    pub expires_at: u64,
    pub withdrawn: bool,
    pub previous: Option<String>,
    pub requires: Vec<String>,
    pub changes: String,
    pub checks: BTreeMap<String, Check>,
    pub jobs: BTreeMap<String, crate::jobs::JobSpec>,
    pub challenge: Challenge,
    pub fixtures: Vec<Fixture>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBundle {
    pub bundle: Bundle,
    pub sha256: String,
    pub signature: String,
}
pub(super) fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl SignedBundle {
    pub fn signing_message(bundle: &Bundle) -> Vec<u8> {
        format!("safeyolo.control-update/v1\n{}", digest(bundle)).into_bytes()
    }
    pub(super) fn verify(
        &self,
        name_: &str,
        publisher: &str,
        public_key: &str,
    ) -> Result<(), Error> {
        if !sha256(&self.sha256)
            || digest(&self.bundle) != self.sha256
            || self.bundle.name != name_
            || self.bundle.publisher != publisher
        {
            return Err("control update publisher, name or content digest differs".into());
        }
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            STANDARD.decode(public_key)?,
        )
        .verify(
            &Self::signing_message(&self.bundle),
            &STANDARD.decode(&self.signature)?,
        )
        .map_err(|_| "control update publisher signature is invalid")?;
        self.bundle.validate()
    }
}
impl Bundle {
    fn validate(&self) -> Result<(), Error> {
        if self.format != "safeyolo.control-update/v1"
            || self.revision == 0
            || self.changes.trim().is_empty()
            || self.expires_at <= self.observed_at
            || self.previous.as_ref().is_some_and(|p| !sha256(p))
            || !self
                .requires
                .iter()
                .all(|r| matches!(r.as_str(), "gateway-route-v1" | "platform-job-v1"))
            || !self.requires.iter().any(|r| r == "gateway-route-v1")
        {
            return Err(
                "incompatible control update format, revision or required runtime primitive".into(),
            );
        }
        name(&self.name)?;
        name(&self.publisher)?;
        for (check_name, check) in &self.checks {
            name(check_name)?;
            if !check_name.starts_with(&format!("{}.", self.name))
                || check.subject != SubjectKind::Value
                || check.result_type != ResultType::Finding
            {
                return Err(
                    "bundled checks need the update's namespace and value/finding types".into(),
                );
            }
            let EvidenceSource::Job { spec, limits, .. } = &check.source else {
                return Err(
                    "incompatible new check source; this runtime supports bundled platform jobs"
                        .into(),
                );
            };
            let key = spec.to_str().ok_or("invalid bundled job reference")?;
            name(key)?;
            let job = self
                .jobs
                .get(key)
                .ok_or("bundled check references an absent immutable job")?;
            if !matches!(job.engine, crate::jobs::JobEngine::Platform)
                || job.mediated_services.is_some()
                || !self.requires.iter().any(|r| r == "platform-job-v1")
            {
                return Err("incompatible job engine; non-platform implementations need an adopted artifact primitive".into());
            }
            job.validate()?;
            if job.max_input_bytes > limits.max_input_bytes as u64
                || job.retain_bytes > limits.max_output_bytes
                || serde_json::to_vec(job)?.len() > limits.max_input_bytes
            {
                return Err("bundled job exceeds its named check byte limits".into());
            }
            if !self
                .fixtures
                .iter()
                .any(|f| &f.check == check_name && f.positive)
                || !self
                    .fixtures
                    .iter()
                    .any(|f| &f.check == check_name && !f.positive)
            {
                return Err("new checks need versioned positive and negative fixtures".into());
            }
        }
        for (key, job) in &self.jobs {
            name(key)?;
            if !self
                .checks
                .values()
                .any(|c| matches!(&c.source,EvidenceSource::Job{spec,..} if spec==Path::new(key)))
            {
                return Err("bundle contains an unreferenced job".into());
            }
            job.validate()?;
        }
        for step in &self.challenge.steps {
            if let Step::Check { check, .. } = step
                && !self.checks.contains_key(check)
            {
                return Err("challenge references a check outside its coherent revision".into());
            }
        }
        Ok(())
    }
}

impl Bounds {
    pub(super) fn allows(&self, bundle: &Bundle) -> bool {
        let includes =
            |allowed: &[String], actual: &str| allowed.iter().any(|a| a == "*" || a == actual);
        let c = &bundle.challenge;
        c.agents.iter().all(|a| includes(&self.agents, a))
            && includes(&self.services, &c.service)
            && includes(&self.capabilities, &c.capability)
            && c.methods.iter().all(|m| includes(&self.methods, m))
            && includes(&self.paths, &c.path)
            && bundle.checks.values().all(|check| {
                let EvidenceSource::Job {
                    spec,
                    limits,
                    effects,
                    ..
                } = &check.source
                else {
                    return false;
                };
                let Some(job) = spec.to_str().and_then(|s| bundle.jobs.get(s)) else {
                    return false;
                };
                let effect = serde_json::to_value(effects)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned));
                effect.is_some_and(|e| includes(&self.effects, &e))
                    && check.invokers.iter().all(|a| includes(&self.agents, a))
                    && limits.timeout_ms <= self.max_timeout_ms
                    && job.timeout_seconds.saturating_mul(1000) <= self.max_timeout_ms
                    && job.memory_mb <= self.max_memory_mb
                    && limits.max_input_bytes <= self.max_input_bytes
                    && limits.max_output_bytes <= self.max_output_bytes
                    && limits.max_concurrent <= self.max_concurrent
                    && limits.max_pending <= self.max_pending
                    && limits.max_cached <= self.max_cached
                    && (!job.network || self.allow_network)
                    && (!job.network || includes(&self.network_gates, &job.gate_id))
                    && (job.privilege != crate::jobs::Privilege::GuestRoot || self.allow_guest_root)
            })
    }
}

fn immutable(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::File::open(path.parent().unwrap())?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut known = Vec::new();
            fs::File::open(path)?
                .take(bytes.len().saturating_add(1) as u64)
                .read_to_end(&mut known)?;
            if known != bytes {
                return Err("retained immutable update bytes changed".into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
pub(super) fn retain(root: &Path, candidate: &SignedBundle) -> Result<(), Error> {
    let directory = candidate_path(root, &candidate.sha256)
        .parent()
        .unwrap()
        .to_owned();
    fs::create_dir_all(&directory)?;
    immutable(
        &directory.join("bundle.json"),
        &serde_json::to_vec(candidate)?,
    )?;
    for (name, job) in &candidate.bundle.jobs {
        immutable(&directory.join(name), &serde_json::to_vec(job)?)?;
    }
    Ok(())
}

fn without_nulls(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.retain(|_, v| !v.is_null());
            for v in fields.values_mut() {
                without_nulls(v);
            }
        }
        Value::Array(values) => {
            for v in values {
                without_nulls(v);
            }
        }
        _ => {}
    }
}
fn item(value: &impl Serialize) -> Result<toml_edit::Item, Error> {
    let mut value = serde_json::to_value(value)?;
    without_nulls(&mut value);
    Ok(toml_edit::Item::Value(
        crate::admin_api::json_toml_value(&value)
            .map_err(|_| "native update cannot be represented as TOML")?,
    ))
}
pub(super) fn materialize(
    root: &Path,
    policy: &Policy,
    name_: &str,
    target: &SignedBundle,
    previous: &Value,
    qualification: Value,
) -> Result<(String, Value), Error> {
    let source = policy
        .native_source_text()
        .ok_or("native policy unavailable")?;
    let original = crate::policy::parse_toml_document(source)?;
    let (mut document, context) = crate::policy::parse_toml_for_edit(source)?;
    // Only this named update's previously owned definitions may be replaced.
    let old_names = previous["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    for old in &old_names {
        if let Some(table) = document
            .get_mut("checks")
            .and_then(toml_edit::Item::as_table_like_mut)
        {
            table.remove(old);
        }
    }
    let mut checks = target.bundle.checks.clone();
    for (name, check) in &mut checks {
        if original["checks"].get(name).is_some() && !old_names.contains(name.as_str()) {
            return Err("update would replace an independently owned check".into());
        }
        let EvidenceSource::Job {
            spec, spec_sha256, ..
        } = &mut check.source
        else {
            unreachable!()
        };
        *spec_sha256 = Some(digest(
            &target.bundle.jobs[spec.to_str().ok_or("invalid bundled job reference")?],
        ));
        *spec = candidate_path(root, &target.sha256)
            .parent()
            .unwrap()
            .join(&*spec);
        document["checks"][name] = item(check)?;
    }
    if original["route_challenges"].get(name_).is_some() && previous.is_null() {
        return Err("update would replace an independently owned challenge".into());
    }
    let mut challenge = target.bundle.challenge.clone();
    challenge.revision = target.sha256.clone();
    challenge.generation = previous["generation"]
        .as_u64()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or("control update activation generation exhausted")?;
    document["route_challenges"][name_] = item(&challenge)?;
    let receipt = json!({"sha256":target.sha256,"publisher":target.bundle.publisher,"revision":target.bundle.revision,
        "generation":challenge.generation,
        "previous":if previous["sha256"].is_string(){previous["sha256"].clone()}else{target.bundle.previous.clone().map(Value::String).unwrap_or(Value::Null)},
        "checks":checks.keys().collect::<Vec<_>>(),"definition_digest":digest(&json!([checks,challenge])),"qualification":qualification});
    document["control_update_revisions"][name_] =
        toml_edit::value(serde_json::to_string(&receipt)?);
    let text = crate::policy::restore_large_toml_integers(&document.to_string(), &context);
    let proposed = json!({"publisher":target.bundle.publisher,"sha256":target.sha256,"revision":target.bundle.revision,
        "changes":target.bundle.changes,"requires":target.bundle.requires,"previous":previous,
        "before":{"checks":old_names.iter().filter_map(|n|original["checks"].get(*n).map(|c|(*n,c))).collect::<BTreeMap<_,_>>(),"challenge":original["route_challenges"][name_]},
        "after":{"checks":checks,"challenge":challenge,"jobs":target.bundle.jobs},
        "effects":"Question context and host-bound action/effect identity enter the named checks. Job engine, argv, gate, guest privilege, network selection, resource limits and check inputs are explicit in after. Existing gate/service/network/credential controls apply; no route or credential grant is restored."});
    Ok((text, proposed))
}

pub(super) async fn qualify(
    bundle: &Bundle,
    independent: &[Fixture],
    candidate: &Policy,
    runtime: &crate::Runtime,
    state: &RuntimeState,
) -> Result<Value, Error> {
    for check in bundle.checks.keys() {
        if !independent.iter().any(|f| &f.check == check) {
            return Err(format!(
                "qualification lacks an operator-defined regression fixture for {check}"
            )
            .into());
        }
    }
    let mut results = Vec::new();
    for (origin, fixture) in bundle.fixtures.iter().map(|f| ("publisher", f)).chain(
        independent
            .iter()
            .filter(|f| bundle.checks.contains_key(&f.check))
            .map(|f| ("operator", f)),
    ) {
        let entry = candidate
            .named_checks()
            .invoke_challenge(&fixture.check, fixture.subject.clone(), runtime, state)
            .await?;
        let actual = if entry.unavailable.is_none() {
            entry.result.as_ref().and_then(|r| match &r.finding {
                Finding::Finding { positive } => Some(*positive),
                _ => None,
            })
        } else {
            None
        };
        results.push(json!({"origin":origin,"fixture":fixture,"evidence":entry}));
        if actual != Some(fixture.positive) {
            return Err(format!(
                "qualification fixture did not produce its required independent finding: {}",
                serde_json::to_string(results.last().unwrap())?
            )
            .into());
        }
    }
    let definitions = candidate
        .named_checks()
        .checks
        .iter()
        .filter(|(name, _)| bundle.checks.contains_key(*name))
        .map(|(name, check)| (name.clone(), digest(check)))
        .collect::<BTreeMap<_, _>>();
    Ok(json!({"status":"qualified","results":results,"definitions":definitions,"at":now()}))
}
pub(super) fn qualification_current(
    evidence: &Value,
    checks: &checks::Checks,
) -> Result<(), Error> {
    for result in evidence["results"]
        .as_array()
        .ok_or("qualification results unavailable")?
    {
        let mut entry: checks::Evidence = serde_json::from_value(result["evidence"].clone())?;
        let check = checks
            .checks
            .get(&entry.check)
            .ok_or("qualified check removed")?;
        checks::validate_evidence(check, &mut entry, crate::policy::current_time_ms() as u64);
        if entry.unavailable.is_some() {
            return Err(
                "qualification evidence expired or became unavailable before activation".into(),
            );
        }
    }
    for (name, expected) in evidence["definitions"]
        .as_object()
        .ok_or("qualification bindings unavailable")?
    {
        let check = checks.checks.get(name).ok_or("qualified check removed")?;
        if digest(check) != expected.as_str().ok_or("qualification binding invalid")? {
            return Err("qualified definition changed before activation".into());
        }
        let EvidenceSource::Job { spec, limits, .. } = &check.source else {
            return Err("qualified source changed".into());
        };
        let mut bytes = Vec::new();
        fs::File::open(spec)?
            .take(limits.max_input_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)?;
        let expected = evidence["results"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["fixture"]["check"] == *name)
            .map(|r| &r["evidence"]["execution"]["definition_digest"])
            .ok_or("qualification execution unavailable")?;
        if checks::content_digest(&bytes)
            != expected
                .as_str()
                .ok_or("qualified job identity unavailable")?
        {
            return Err("qualified job bytes changed before activation".into());
        }
    }
    Ok(())
}
