//! Signed content on the existing signals path; adoption belongs to the host.
mod package;
#[cfg(test)]
mod tests;
use super::*;
use crate::{
    RuntimeState,
    approvals::{self, pending},
    policy::{Policy, checks},
};
use base64::{Engine, engine::general_purpose::STANDARD};
pub use package::{Bundle, Fixture, SignedBundle};
use std::collections::BTreeSet;

/// Qualification and automatic activation have separate standing bounds.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bounds {
    pub agents: Vec<String>,
    pub services: Vec<String>,
    pub capabilities: Vec<String>,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub effects: Vec<String>,
    #[serde(default)]
    pub network_gates: Vec<String>,
    pub max_timeout_ms: u64,
    pub max_memory_mb: u64,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_concurrent: usize,
    pub max_pending: usize,
    pub max_cached: usize,
    pub allow_network: bool,
    pub allow_guest_root: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Adoption {
    source: String,
    key: String,
    publisher: String,
    public_key: String,
    automatic: Option<Bounds>,
    qualification: Bounds,
    fixtures: Vec<Fixture>,
    on_withdraw: Withdrawal,
    /// An operator-selected retained revision overrides new announcements.
    pin: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Withdrawal {
    Retain,
    Previous,
}

pub(super) fn validate(config: &Configuration) -> Result<(), Error> {
    let mut selected = BTreeSet::new();
    for (name_, adoption) in &config.control_updates {
        name(name_)?;
        name(&adoption.publisher)?;
        name(&adoption.key)?;
        if !config.sources.contains_key(&adoption.source)
            || !selected.insert((&adoption.source, &adoption.key))
            || STANDARD.decode(&adoption.public_key)?.len() != 32
            || adoption
                .pin
                .as_ref()
                .is_some_and(|pin| !package::sha256(pin))
        {
            return Err("control update adoption needs a unique source/key, Ed25519 publisher key and valid optional pin".into());
        }
    }
    Ok(())
}
fn retained_directory(root: &Path) -> PathBuf {
    directory(root).join("control-updates")
}
fn candidate_path(root: &Path, digest: &str) -> PathBuf {
    retained_directory(root).join(digest).join("bundle.json")
}
fn report_path(root: &Path, name: &str) -> PathBuf {
    retained_directory(root).join(format!("{name}.json"))
}

pub(super) fn sign(bundle: &Path, key: &Path, output: &Path) -> Result<(), Error> {
    use ring::signature::KeyPair;
    let bundle: Bundle = serde_json::from_slice(&fs::read(bundle)?)?;
    let private = zeroize::Zeroizing::new(fs::read(key)?);
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&private)
        .map_err(|_| "publisher key must be Ed25519 PKCS#8 DER")?;
    let signed = SignedBundle {
        sha256: digest(&bundle),
        signature: STANDARD.encode(pair.sign(&SignedBundle::signing_message(&bundle)).as_ref()),
        bundle,
    };
    signed.verify(
        &signed.bundle.name,
        &signed.bundle.publisher,
        &STANDARD.encode(pair.public_key().as_ref()),
    )?;
    save(output, &signed)?;
    println!(
        "{}",
        json!({"sha256":signed.sha256,"publisher":signed.bundle.publisher,"public_key":STANDARD.encode(pair.public_key().as_ref()),"output":output,"activation":"none"})
    );
    Ok(())
}
pub(super) fn keygen(path: &Path) -> Result<(), Error> {
    use ring::signature::KeyPair;
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| "cannot generate publisher key")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(key.as_ref())?;
    file.sync_all()?;
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(key.as_ref())
        .map_err(|_| "cannot read generated publisher key")?;
    println!(
        "{}",
        json!({"public_key":STANDARD.encode(pair.public_key().as_ref()),"private_key_file":path})
    );
    Ok(())
}

fn native_receipt(policy: &Policy, name: &str) -> Result<Value, Error> {
    let source = policy
        .native_source_text()
        .ok_or("native policy unavailable")?;
    let document = crate::policy::parse_toml_document(source)?;
    document["control_update_revisions"][name]
        .as_str()
        .map(|s| serde_json::from_str(s).map_err(Into::into))
        .unwrap_or(Ok(Value::Null))
}

pub fn status(root: &Path) -> Result<Value, Error> {
    let config = configuration(root)?;
    let mut statuses = BTreeMap::new();
    for name in config.control_updates.keys() {
        statuses.insert(
            name,
            crate::guest_commands::read_state(&report_path(root, name))?,
        );
    }
    Ok(json!(statuses))
}

fn load_retained(root: &Path, digest: &str, maximum: usize) -> Result<SignedBundle, Error> {
    if !package::sha256(digest) {
        return Err("invalid retained update digest".into());
    }
    let value =
        crate::guest_commands::read_state_bounded(&candidate_path(root, digest), maximum as u64)?
            .ok_or("retained revision unavailable")?;
    let candidate: SignedBundle = serde_json::from_value(value)?;
    if candidate.sha256 != digest {
        return Err("retained revision identity differs".into());
    }
    Ok(candidate)
}

/// One finite control-loop pass. Every selected update has an inspectable
/// result; failure never silently drops the previous policy's controls.
pub(super) async fn reconcile(root: &Path, state: &RuntimeState) -> Result<u64, Error> {
    let config = configuration(root)?;
    for (name, adoption) in &config.control_updates {
        let result = reconcile_one(root, state, &config, name, adoption).await;
        if let Err(error) = result {
            let prior =
                crate::guest_commands::read_state(&report_path(root, name))?.unwrap_or(Value::Null);
            let runtime = state
                .read()
                .map_err(|_| "update runtime unavailable")?
                .clone();
            let active = runtime
                .policy
                .as_deref()
                .map(|p| native_receipt(p, name))
                .transpose()?;
            record_status(
                root,
                name,
                state,
                &json!({"state":"rejected","reason":error.to_string(),"active":active,"previous_result":prior["candidate"],"next_action":"inspect the candidate, adoption bounds and active revision; a changed candidate or authority is required"}),
            )?;
        }
    }
    Ok(if config.control_updates.is_empty() {
        u64::MAX
    } else {
        now() + 1
    })
}

async fn reconcile_one(
    root: &Path,
    state: &RuntimeState,
    config: &Configuration,
    name_: &str,
    adoption: &Adoption,
) -> Result<(), Error> {
    let source = &config.sources[&adoption.source];
    let accepted = read_accepted(root, &adoption.source, source)?;
    let announcement = accepted.iter().find(|a| a.update.id == adoption.key);
    let runtime = state
        .read()
        .map_err(|_| "update runtime unavailable")?
        .clone();
    let policy = runtime
        .policy
        .as_deref()
        .ok_or("update policy unavailable")?;
    let previous = native_receipt(policy, name_)?;
    let target = if let Some(pin) = &adoption.pin {
        load_retained(root, pin, source.max_bytes)?
    } else {
        let Some(announcement) = announcement else {
            return Ok(());
        };
        let Evidence::ControlUpdate { candidate } = &announcement.update.evidence else {
            return Err("selected signal is not a control update".into());
        };
        let announced: SignedBundle = serde_json::from_value(candidate.clone())?;
        announced.verify(name_, &adoption.publisher, &adoption.public_key)?;
        if !announcement_matches(&announced, &announcement.update) {
            return Err(
                "signed revision, withdrawal and evidence times must equal the announcement".into(),
            );
        }
        if !announcement.update.fresh(source, now()) {
            return Err("control update announcement is stale; active protection retained".into());
        }
        if announcement.update.withdrawn {
            match adoption.on_withdraw {
                Withdrawal::Retain => {
                    record_status(
                        root,
                        name_,
                        state,
                        &json!({"state":"withdrawn","candidate":announced.sha256,"active":previous,"next_action":"protection retained under on_withdraw=retain; select an identified replacement or pin"}),
                    )?;
                    return Ok(());
                }
                Withdrawal::Previous => {
                    let prior=announced.bundle.previous.as_deref().ok_or("withdrawal has no identified usable previous revision; current protection retained")?;
                    load_retained(root, prior, source.max_bytes)?
                }
            }
        } else {
            announced
        }
    };
    target.verify(name_, &adoption.publisher, &adoption.public_key)?;
    let active = previous["sha256"] == target.sha256;
    package::retain(root, &target)?;
    if active {
        let definitions = policy.named_checks();
        let owned = previous["checks"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter_map(|name| definitions.checks.get(name).map(|c| (name, c)))
            .collect::<BTreeMap<_, _>>();
        if digest(&json!([owned, definitions.route_challenges.get(name_)]))
            != previous["definition_digest"]
        {
            return Err("active update definitions were changed through another policy edit; inspect current policy before selecting a replacement".into());
        }
        let prior =
            crate::guest_commands::read_state(&report_path(root, name_))?.unwrap_or(Value::Null);
        if prior["active"]["sha256"] != target.sha256 {
            record_status(
                root,
                name_,
                state,
                &json!({"state":"active","candidate":target.sha256,"active":previous,"announcement_withdrawn":announcement.is_some_and(|a|a.update.withdrawn)}),
            )?;
        }
        return Ok(());
    }
    let (materialized, proposed) =
        package::materialize(root, policy, name_, &target, &previous, Value::Null)?;
    let path = runtime
        .config
        .policy_file
        .as_deref()
        .ok_or("native policy unavailable")?;
    let candidate_policy = policy.reload_native_source(&materialized, path)?;
    let automatic = adoption
        .automatic
        .as_ref()
        .is_some_and(|bounds| bounds.allows(&target.bundle))
        && adoption.qualification.allows(&target.bundle);
    let identity = digest(
        &json!({"candidate":target.sha256,"authority":adoption,"source":source,
        "base":checks::content_digest(policy.native_source_text().unwrap().as_bytes()),"previous":previous}),
    );
    let operation = format!("req-{}", &identity[..32]);
    if !automatic {
        let approval = request_update_approval(
            state, config, name_, &target, &proposed, &identity, &operation,
        )?;
        if approval.current_status(policy)? != "approved" {
            record_status(
                root,
                name_,
                state,
                &json!({"state":if approval.status=="rejected"{"rejected"}else{"pending_approval"},"candidate":target.sha256,"active":previous,"approval_id":approval.approval_id,"proposed":proposed}),
            )?;
            return Ok(());
        }
    }
    let prior =
        crate::guest_commands::read_state(&report_path(root, name_))?.unwrap_or(Value::Null);
    if prior["attempt_identity"] == identity
        && matches!(prior["state"].as_str(), Some("failed" | "unavailable"))
    {
        return Ok(());
    }
    record_status(
        root,
        name_,
        state,
        &json!({"state":"candidate","candidate":target.sha256,"active":previous,"attempt_identity":identity,"proposed":proposed}),
    )?;
    let qualification = package::qualify(
        &target.bundle,
        &adoption.fixtures,
        &candidate_policy,
        &runtime,
        state,
    )
    .await;
    let mut qualification = match qualification {
        Ok(evidence) => evidence,
        Err(error) => {
            record_status(
                root,
                name_,
                state,
                &json!({"state":"unavailable","candidate":target.sha256,"active":previous,"attempt_identity":identity,"error":error.to_string(),"next_action":"inspect retained check execution evidence; change the candidate or adopted inputs before another attempt"}),
            )?;
            return Ok(());
        }
    };
    qualification["adoption"] = json!({"authority":if automatic{"standing"}else{"reviewed"},"authority_digest":digest(adoption),"source":adoption.source,"source_id":source.source_id,"key":adoption.key,"announcement_revision":announcement.map(|a|a.update.revision)});
    record_status(
        root,
        name_,
        state,
        &json!({"state":"qualified","candidate":target.sha256,"active":previous,"attempt_identity":identity,"qualification":qualification}),
    )?;
    let state_owned = state.clone();
    let root_owned = root.to_owned();
    let config_owned = config.clone();
    let name_owned = name_.to_owned();
    let target_owned = target.clone();
    let previous_owned = previous.clone();
    let qualification_owned = qualification.clone();
    let selected_announcement = announcement.map(|a| a.update.clone());
    let outcome = tokio::task::spawn_blocking(move || {
        crate::adopt_native_policy(
            &state_owned,
            |saved, current, _| {
                if digest(&configuration(&root_owned).map_err(approval_error)?)
                    != digest(&config_owned)
                    || current
                        .policy
                        .as_ref()
                        .is_none_or(|p| p.native_source_text() != Some(saved))
                    || saved
                        != runtime
                            .policy
                            .as_ref()
                            .unwrap()
                            .native_source_text()
                            .unwrap()
                {
                    return Err(approvals::invalid(
                        "update base or adoption authority changed during qualification",
                    ));
                }
                // Re-verify retained bytes and all qualification input identities at
                // commit. No publisher-controlled host command runs in this path.
                target_owned
                    .verify(
                        &name_owned,
                        &config_owned.control_updates[&name_owned].publisher,
                        &config_owned.control_updates[&name_owned].public_key,
                    )
                    .map_err(approval_error)?;
                package::retain(&root_owned, &target_owned).map_err(approval_error)?;
                let adoption = &config_owned.control_updates[&name_owned];
                let source = &config_owned.sources[&adoption.source];
                let accepted =
                    read_accepted(&root_owned, &adoption.source, source).map_err(approval_error)?;
                if adoption.pin.is_none()
                    && selected_announcement.as_ref().is_none_or(|selected| {
                        !selected.fresh(source, now())
                            || !accepted.iter().any(|a| a.update == *selected)
                    })
                {
                    return Err(approvals::invalid(
                        "announcement changed or expired during qualification",
                    ));
                }
                if !automatic {
                    let record = current
                        .audit
                        .approvals()
                        .get(&operation)?
                        .ok_or_else(|| approvals::invalid("update approval unavailable"))?;
                    if record.current_status(current.policy.as_ref().unwrap())? != "approved"
                        || approval_revision(
                            current.policy.as_ref().unwrap(),
                            &record.authority.action,
                        )
                        .as_deref()
                            != Some(record.authority.revision.as_str())
                    {
                        return Err(approvals::invalid("update approval changed"));
                    }
                }
                let (text, _) = package::materialize(
                    &root_owned,
                    current.policy.as_ref().unwrap(),
                    &name_owned,
                    &target_owned,
                    &previous_owned,
                    qualification_owned.clone(),
                )
                .map_err(approval_error)?;
                let compiled = current
                    .policy
                    .as_ref()
                    .unwrap()
                    .reload_native_source(&text, current.config.policy_file.as_ref().unwrap())
                    .map_err(approval_error)?;
                package::qualification_current(&qualification_owned, compiled.named_checks())
                    .map_err(approval_error)?;
                Ok((text, compiled))
            },
            || Ok(()),
        )
    })
    .await?;
    if let Err(error) = outcome {
        record_status(
            root,
            name_,
            state,
            &json!({"state":"failed","candidate":target.sha256,"active":previous,"attempt_identity":identity,"qualification":qualification,"error":error.to_string()}),
        )?;
        return Ok(());
    }
    let current = state
        .read()
        .map_err(|_| "update runtime unavailable")?
        .clone();
    let active = native_receipt(current.policy.as_ref().unwrap(), name_)?;
    let rolled_back = adoption.pin.is_some() || announcement.is_some_and(|a| a.update.withdrawn);
    record_status(
        root,
        name_,
        state,
        &json!({"state":if rolled_back{"rolled_back"}else{"active"},"candidate":target.sha256,"active":active,"superseded":previous,"qualification":qualification,"authority":if automatic{"standing"}else{"reviewed"}}),
    )?;
    let mut event = crate::audit::Event::new(
        "ops.control_update_activated",
        crate::audit::Kind::Ops,
        crate::audit::Severity::Low,
        "Versioned check and challenge update activated",
    );
    event.details =
        json!({"name":name_,"active":active,"previous":previous,"rolled_back":rolled_back}).into();
    current.audit.emit_confirmed(event).await?;
    Ok(())
}

fn request_update_approval(
    state: &RuntimeState,
    config: &Configuration,
    name_: &str,
    target: &SignedBundle,
    proposed: &Value,
    identity: &str,
    operation: &str,
) -> Result<pending::Record, Error> {
    let adoption = &config.control_updates[name_];
    let runtime = state
        .read()
        .map_err(|_| "update runtime unavailable")?
        .clone();
    if let Some(record) = runtime.audit.approvals().get(operation)? {
        return Ok(record);
    }
    let policy = runtime.policy.as_ref().ok_or("update policy unavailable")?;
    let agent = target
        .bundle
        .challenge
        .agents
        .first()
        .ok_or("update scope has no agent")?;
    let action = json!({"kind":"signal_response","control_update":true,"name":name_,"agent":agent,"agent_id":policy.evidence_agent_id(agent),
        "basis":digest(config),"identity":identity,"base":checks::content_digest(policy.native_source_text().unwrap().as_bytes()),
        "candidate":target.sha256,"publisher":adoption.publisher,"proposed":proposed});
    let authority = pending::Authority {
        revision: approval_revision(policy, &action).ok_or("update authority unavailable")?,
        resource_digest: digest(&action),
        action,
        method: "POST".into(),
        scheme: "http".into(),
        port: None,
        options: vec![pending::OptionScope {
            id: "once".into(),
            session_id: None,
            effect: format!(
                "Qualify and activate immutable update {} from {}. Inspect proposed native checks/challenge differences, execution/disclosure effects and limits. This decision changes no route or credential grant.",
                target.sha256, adoption.publisher
            ),
            parameters: proposed.clone(),
        }],
        expires_at: None,
        credential_bindings: Default::default(),
    };
    let record = runtime
        .audit
        .approvals()
        .submit(authority, operation, policy)?;
    let mut event = crate::audit::Event::new(
        "ops.signal_response_requested",
        crate::audit::Kind::Ops,
        crate::audit::Severity::Low,
        "Versioned control update requires its host operator's decision",
    );
    event.request_id = Some(operation.into());
    event.agent = Some(agent.clone());
    event.approval = Some(crate::audit::Approval {
        required: true,
        approval_type: crate::audit::ApprovalType::SignalResponse,
        key: record.approval_id.clone(),
        target: name_.into(),
        scope_hint: json!({"publisher":adoption.publisher,"sha256":target.sha256}).into(),
    });
    event.details = json!({"approval_id":record.approval_id,"authority":record.authority}).into();
    runtime.audit.emit(event)?;
    Ok(record)
}

pub(crate) fn approval_revision(policy: &Policy, action: &Value) -> Option<String> {
    let root = policy.source_path()?.parent()?;
    let config = configuration(root).ok()?;
    let adoption = config.control_updates.get(action["name"].as_str()?)?;
    let source = config.sources.get(&adoption.source)?;
    let expected = if let Some(pin) = &adoption.pin {
        let retained = load_retained(root, pin, source.max_bytes).ok()?;
        retained
            .verify(
                action["name"].as_str()?,
                &adoption.publisher,
                &adoption.public_key,
            )
            .ok()?;
        pin.clone()
    } else {
        let accepted = read_accepted(root, &adoption.source, source).ok()?;
        let target = accepted.iter().find(|a| a.update.id == adoption.key)?;
        let announced = match &target.update.evidence {
            Evidence::ControlUpdate { candidate } => {
                serde_json::from_value::<SignedBundle>(candidate.clone()).ok()?
            }
            _ => return None,
        };
        announced
            .verify(
                action["name"].as_str()?,
                &adoption.publisher,
                &adoption.public_key,
            )
            .ok()?;
        if !announcement_matches(&announced, &target.update) || !target.update.fresh(source, now())
        {
            return None;
        }
        if target.update.withdrawn {
            if !matches!(adoption.on_withdraw, Withdrawal::Previous) {
                return None;
            }
            announced.bundle.previous?
        } else {
            announced.sha256
        }
    };
    (digest(&config) == action["basis"]
        && action["candidate"] == expected
        && checks::content_digest(policy.native_source_text()?.as_bytes()) == action["base"])
        .then(|| {
            digest(&json!([
                action["identity"],
                action["base"],
                digest(adoption)
            ]))
        })
}

pub(crate) fn resolve(
    state: &RuntimeState,
    writer: &crate::audit::Writer,
    id: &str,
    decision: approvals::network_action::Decision,
    reviewer: bool,
) -> approvals::Result<(u16, Value)> {
    if reviewer {
        return Err(approvals::invalid(
            "control update adoption requires its host operator",
        ));
    }
    let runtime = state.read().map_err(approval_error)?.clone();
    let policy = runtime
        .policy
        .as_ref()
        .ok_or_else(|| approvals::invalid("policy unavailable"))?;
    let record=writer.approvals().decide(id,|record|{
        if record.status!="pending" {return Ok(());}
        record.status=record.current_status(policy)?;
        if record.status!="pending" {return Ok(());}
        record.status=if matches!(decision,approvals::network_action::Decision::Reject){"rejected"}else{"approved"}.into();
        record.option=(record.status=="approved").then(||"once".into());
        record.result=json!({"status":"decision_recorded","activation":"pending current qualification and policy revalidation"});
        Ok(())
    })?.ok_or_else(||approvals::invalid("control update approval unavailable"))?;
    Ok((
        200,
        json!({"approval_id":record.approval_id,"status":record.status,"result":record.result}),
    ))
}

fn approval_error(error: impl std::fmt::Display) -> approvals::ApprovalError {
    approvals::invalid(error.to_string())
}

fn record_status(
    root: &Path,
    name: &str,
    state: &RuntimeState,
    value: &Value,
) -> Result<(), Error> {
    let path = report_path(root, name);
    let previous = crate::guest_commands::read_state(&path)?.unwrap_or(Value::Null);
    let mut comparison = previous.clone();
    if let Some(fields) = comparison.as_object_mut() {
        fields.remove("observed_at");
        fields.remove("observation");
    }
    if comparison == *value {
        return Ok(());
    }
    let mut record = value.clone();
    record["observed_at"] = json!(now());
    record["observation"] =
        json!("recorded control-loop result; inspect policy show for current saved/active state");
    save(&path, &record)?;
    let runtime = state
        .read()
        .map_err(|_| "update runtime unavailable")?
        .clone();
    let mut event = crate::audit::Event::new(
        "ops.control_update_state",
        crate::audit::Kind::Ops,
        crate::audit::Severity::Low,
        "Versioned check and challenge update state changed",
    );
    event.details=json!({"name":name,"state":value["state"],"candidate":value["candidate"],"active_revision":value["active"]["sha256"],"previous_state":previous["state"],"previous_candidate":previous["candidate"],"retained_status":path}).into();
    runtime.audit.emit(event)?;
    Ok(())
}

fn announcement_matches(candidate: &SignedBundle, update: &Update) -> bool {
    candidate.bundle.revision == update.revision
        && candidate.bundle.observed_at == update.observed_at
        && candidate.bundle.expires_at == update.expires_at
        && candidate.bundle.withdrawn == update.withdrawn
}
