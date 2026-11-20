//! Host-side signal evidence. Receipt never confers effect authority.
pub mod control_updates;
mod guest_inventory;
mod responses;
mod transport;
pub(crate) fn approval_revision(policy: &crate::policy::Policy, action: &Value) -> Option<String> {
    if action["control_update"] == true {
        control_updates::approval_revision(policy, action)
    } else {
        responses::approval_revision(policy, action)
    }
}
pub(crate) fn resolve(
    state: &crate::RuntimeState,
    writer: &crate::audit::Writer,
    id: &str,
    decision: crate::approvals::network_action::Decision,
    reviewer: bool,
) -> crate::approvals::Result<(u16, Value)> {
    if writer
        .approvals()
        .get(id)?
        .is_some_and(|r| r.authority.action["control_update"] == true)
    {
        control_updates::resolve(state, writer, id, decision, reviewer)
    } else {
        responses::resolve(state, writer, id, decision, reviewer)
    }
}
#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/support/controlled_runs.rs"]
mod test_runs;
#[cfg(test)]
mod tests;

use crate::Error;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use transport::Source;

pub const HELP: &str = "safeyolo [--root ROOT] signals configure FILE\nsafeyolo [--root ROOT] signals status\nsafeyolo [--root ROOT] signals assess RULE\nsafeyolo [--root ROOT] signals publish SOURCE KEY FILE\nsafeyolo signals keygen-update PRIVATE_KEY.der\nsafeyolo signals sign-update BUNDLE.json PRIVATE_KEY.der SIGNED.json\n\nconfigure validates and saves private host sources and response rules. The running proxy follows NATS KV current state and reconciles responses through its existing control loop. No proxy means no automatic response. assess requests current Debian package collection for an explicitly adopted rule; read status for completion. It starts no stopped agent. status shows retained evidence, freshness, authority and action results; delivery is not verification. publish validates an evidence envelope and writes through the selected host-held NATS credential; broker ACLs own publication authority. keygen-update creates a private Ed25519 PKCS#8 key and reports its public key. sign-update writes a signed immutable native check/challenge bundle without executing or adopting it. Source credentials, publisher private keys and endpoints stay outside guests. See docs/signals.md.";

fn now() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
}
fn name(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > 120
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(
            "signal names need 1..120 ASCII letters, digits, dots, underscores or hyphens".into(),
        );
    }
    Ok(())
}
fn digest(value: &impl Serialize) -> String {
    crate::policy::checks::content_digest(
        &serde_json::to_vec(value).expect("serializable signal value"),
    )
}
fn save(path: &Path, value: &impl Serialize) -> Result<(), Error> {
    fs::create_dir_all(
        path.parent()
            .ok_or("signal state has no parent directory")?,
    )?;
    crate::guest_commands::write_json(path, &serde_json::to_value(value)?)
}
fn directory(root: &Path) -> PathBuf {
    root.join("data/signals")
}
fn configuration(root: &Path) -> Result<Configuration, Error> {
    let path = root.join("signals.toml");
    if !path.try_exists()? {
        return Ok(Configuration::default());
    }
    parse(&fs::read_to_string(path).map_err(|_| "cannot read signal configuration")?)
}
fn parse(text: &str) -> Result<Configuration, Error> {
    let value = crate::policy::parse_toml_document(text)
        .map_err(|_| "invalid signal configuration TOML")?;
    let config: Configuration = serde_json::from_value(value)
        .map_err(|_| "invalid signal configuration fields; see docs/signals.md")?;
    for (name_, source) in &config.sources {
        name(name_)?;
        source.validate()?;
    }
    responses::validate(&config)?;
    control_updates::validate(&config)?;
    Ok(config)
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    #[serde(default)]
    sources: BTreeMap<String, Source>,
    #[serde(default)]
    rules: BTreeMap<String, responses::Rule>,
    #[serde(default)]
    control_updates: BTreeMap<String, control_updates::Adoption>,
}

/// A publisher reports evidence, never a command or a selected response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Update {
    pub source_id: String,
    pub id: String,
    pub revision: u64,
    pub observed_at: u64,
    pub expires_at: u64,
    pub withdrawn: bool,
    pub evidence_refs: Vec<String>,
    pub evidence: Evidence,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Evidence {
    ControlUpdate {
        candidate: Value,
    },
    List {
        body: String,
    },
    Advisory {
        distribution: Option<String>,
        #[serde(deserialize_with = "crate::policy::checks::deserialize_score_value")]
        severity: f64,
        subject: Subject,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Subject {
    Service {
        name: String,
    },
    Destination {
        hostname: String,
    },
    /// Package findings compare the host-selected effective inventory.
    Package {
        name: String,
        distribution: String,
        fixed_version: Option<String>,
    },
}
impl Update {
    fn validate(&self, source: &Source, key: &str, at: u64) -> Result<(), Error> {
        name(&self.id)?;
        if self.source_id != source.source_id
            || self.id != key
            || self.revision == 0
            || self.observed_at > at
            || self.expires_at <= self.observed_at
            || i64::try_from(self.expires_at)
                .ok()
                .and_then(|at| time::OffsetDateTime::from_unix_timestamp(at).ok())
                .is_none()
            || self.evidence_refs.len() > 16
            || self.evidence_refs.iter().any(|r| r.len() > 2048)
        {
            return Err("invalid signal identity, revision, evidence time or references".into());
        }
        if let Evidence::Advisory { severity, .. } = &self.evidence
            && (!severity.is_finite() || !(0.0..=10.0).contains(severity))
        {
            return Err("advisory severity must be 0..10".into());
        }
        if let Evidence::Advisory { subject, .. } = &self.evidence {
            match subject {
                Subject::Service { name } if name.is_empty() || name.len() > 256 => {
                    return Err("advisory service name is invalid".into());
                }
                Subject::Destination { hostname } => {
                    crate::policy::checks::Subject::Hostname {
                        hostname: hostname.clone(),
                    }
                    .normalized()?;
                }
                Subject::Package {
                    name,
                    distribution,
                    fixed_version,
                } => {
                    if name.is_empty()
                        || !name.bytes().all(|b| {
                            b.is_ascii_lowercase()
                                || b.is_ascii_digit()
                                || matches!(b, b'+' | b'-' | b'.')
                        })
                        || distribution.is_empty()
                        || fixed_version
                            .as_deref()
                            .is_some_and(|version| !responses::valid_debian_version(version))
                    {
                        return Err("package evidence needs a package, distribution and a valid Debian fixed version when a fix is available".into());
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
    fn fresh(&self, source: &Source, at: u64) -> bool {
        at >= self.observed_at
            && at < self.expires_at
            && at - self.observed_at < source.max_age_seconds
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Accepted {
    source_digest: String,
    update: Update,
}
fn accepted_path(root: &Path, source: &str, key: &str) -> PathBuf {
    directory(root)
        .join("accepted")
        .join(source)
        .join(format!("{key}.json"))
}
fn accept(
    root: &Path,
    source_name: &str,
    source: &Source,
    key: &str,
    bytes: &[u8],
) -> Result<bool, Error> {
    if bytes.len() > source.max_bytes {
        return Err("signal exceeds max_bytes".into());
    }
    let update: Update = serde_json::from_slice(bytes).map_err(|_| "malformed signal envelope")?;
    update.validate(source, key, now())?;
    let _lock = crate::approvals::lock_policy(&root.join("policy.toml"))?;
    if configuration(root)?
        .sources
        .get(source_name)
        .is_none_or(|current| digest(current) != digest(source))
    {
        return Err("signal source was changed or removed".into());
    }
    let path = accepted_path(root, source_name, key);
    if !path.try_exists()?
        && path.parent().is_some_and(|dir| dir.is_dir())
        && fs::read_dir(path.parent().expect("accepted directory"))?
            .take(source.max_signals + 1)
            .count()
            >= source.max_signals
    {
        return Err(
            "signal source reached its adopted max_signals limit; prior accepted view retained"
                .into(),
        );
    }
    if let Some(previous) =
        crate::guest_commands::read_state_bounded(&path, source.max_bytes as u64 + 65536)?
    {
        let previous: Accepted = serde_json::from_value(previous)?;
        // Connection, filter and retention edits do not reset the source's
        // revision high-water mark or permit a withdrawn finding to resurrect.
        if previous.update.source_id == update.source_id {
            if update.revision < previous.update.revision {
                return Err("older signal revision".into());
            }
            if update.revision == previous.update.revision {
                if update == previous.update && previous.source_digest == digest(source) {
                    return Ok(false);
                }
                if update != previous.update {
                    return Err("conflicting signal revision".into());
                }
            }
            if update.observed_at < previous.update.observed_at {
                return Err("signal evidence time moved backwards".into());
            }
        }
    }
    // Validate list content before retaining any new revision. Adoption uses the
    // existing complete-snapshot owner and never edits the operator's list effect.
    if let Evidence::List { body } = &update.evidence {
        let list = source
            .list
            .as_deref()
            .ok_or("source has no adopted list target")?;
        crate::policy_feeds::adopt_signal(root, list, &update, body)?;
    } else if source.list.is_some() {
        return Err("list source received an advisory".into());
    }
    save(
        &path,
        &Accepted {
            source_digest: digest(source),
            update,
        },
    )?;
    Ok(true)
}
fn health(root: &Path, source: &str, state: &str, error: Option<&str>) -> Result<(), Error> {
    save(
        &directory(root)
            .join("sources")
            .join(format!("{source}.json")),
        &json!({"state":state,"diagnostic":error,"observed_at":now()}),
    )
}

#[derive(Default)]
pub(crate) struct Follow {
    sources: BTreeMap<String, (String, tokio::task::JoinHandle<()>)>,
    response: Option<tokio::task::JoinHandle<Result<u64, Error>>>,
    response_identity: String,
    response_due: u64,
}
impl Follow {
    pub(crate) async fn poll(
        &mut self,
        root: PathBuf,
        runtime: crate::RuntimeState,
        services: Value,
    ) -> Result<(), Error> {
        let config = configuration(&root)?;
        self.sources.retain(|name, (identity, task)| {
            let retain = config
                .sources
                .get(name)
                .is_some_and(|source| &digest(source) == identity)
                && !task.is_finished();
            if !retain {
                task.abort();
            }
            retain
        });
        for (name, source) in &config.sources {
            if !source.follow || self.sources.contains_key(name) {
                continue;
            }
            let (root, name, source) = (root.clone(), name.clone(), source.clone());
            let identity = digest(&source);
            let worker_name = name.clone();
            let task = tokio::spawn(async move {
                loop {
                    if source.follow(&root, &worker_name).await.is_err() {
                        let _ = health(
                            &root,
                            &worker_name,
                            "unavailable",
                            Some(
                                "NATS current-state connection unavailable; retained evidence keeps its original age",
                            ),
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(source.retry_seconds)).await;
                }
            });
            self.sources.insert(name, (identity, task));
        }
        if self
            .response
            .as_ref()
            .is_some_and(|task| !task.is_finished())
        {
            return Ok(());
        }
        if let Some(task) = self.response.take() {
            self.response_due = task.await??;
        }
        let metadata = |path: &Path| {
            fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .map(|time| format!("{time:?}"))
        };
        let source_changes = config
            .sources
            .keys()
            .map(|name| metadata(&directory(&root).join("accepted").join(name)))
            .collect::<Vec<_>>();
        let inventory_changes = config
            .rules
            .values()
            .filter_map(|rule| rule.inventory.as_deref())
            .map(&metadata)
            .collect::<Vec<_>>();
        let assessment_requests = config
            .rules
            .keys()
            .map(|rule| metadata(&guest_inventory::request_path(&root, rule)))
            .collect::<Vec<_>>();
        let (policy_identity, runs) = {
            let current = runtime.read().map_err(|_| "signal runtime unavailable")?;
            (
                current
                    .policy
                    .as_ref()
                    .map(|policy| std::sync::Arc::as_ptr(policy) as usize),
                config
                    .rules
                    .values()
                    .flat_map(|rule| rule.agents.iter())
                    .map(|agent| {
                        (
                            agent,
                            current
                                .policy
                                .as_ref()
                                .and_then(|policy| policy.agent_run(agent)),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let identity = digest(&json!([
            digest(&config),
            services,
            source_changes,
            inventory_changes,
            assessment_requests,
            policy_identity,
            runs
        ]));
        if (!config.rules.is_empty() || !config.control_updates.is_empty())
            && (identity != self.response_identity || now() >= self.response_due)
        {
            self.response_identity = identity;
            let host_config = runtime
                .read()
                .map_err(|_| "signal runtime unavailable")?
                .config
                .native_config_path
                .clone()
                .unwrap_or_else(|| root.join("config.toml"));
            self.response = Some(tokio::spawn(async move {
                crate::host_platform::in_config(host_config, async move {
                    let inventory_due = guest_inventory::collect_due(&root, &runtime).await?;
                    let due = responses::reconcile(root.clone(), runtime.clone(), services).await?;
                    let updates_due = control_updates::reconcile(&root, &runtime).await?;
                    Ok(inventory_due.min(due).min(updates_due))
                })
                .await
            }));
        }
        Ok(())
    }
}
impl Drop for Follow {
    fn drop(&mut self) {
        for (_, task) in self.sources.values() {
            task.abort();
        }
        if let Some(task) = &self.response {
            task.abort();
        }
    }
}

pub async fn command(root: &Path, args: &[String]) -> Result<(), Error> {
    match args {
        [help] if help == "--help" => println!("{HELP}"),
        [configure, file] if configure == "configure" => {
            use std::io::Write;
            let text = zeroize::Zeroizing::new(fs::read_to_string(file)?);
            let configuration = parse(&text)?;
            responses::validate_targets(root, &configuration)?;
            let mut temp = tempfile::NamedTempFile::new_in(root)?;
            temp.write_all(text.as_bytes())?;
            temp.as_file().sync_all()?;
            let _lock = crate::approvals::lock_policy(&root.join("policy.toml"))?;
            temp.persist(root.join("signals.toml"))?;
            fs::File::open(root)?.sync_all()?;
            println!(
                "Saved signal sources and rules for {}. The running proxy activates them on its next policy-control pass.",
                root.display()
            );
        }
        [show] if show == "status" => println!("{}", serde_json::to_string_pretty(&status(root)?)?),
        [assess, rule] if assess == "assess" => {
            let _lock = crate::approvals::lock_policy(&root.join("policy.toml"))?;
            let config = configuration(root)?;
            let selected = config.rules.get(rule).ok_or("unknown signal rule")?;
            if selected.guest_inventory.is_none() {
                return Err(
                    "rule has no adopted guest_inventory collection; see docs/signals.md".into(),
                );
            }
            let request =
                json!({"request_id":uuid::Uuid::new_v4().to_string(),"requested_at":now()});
            save(&guest_inventory::request_path(root, rule), &request)?;
            println!(
                "{}",
                json!({"root":root,"rule":rule,"agents":selected.agents,"request":request,
                "status":"requested","next_action":"Read signals status after the running proxy's next control pass. This request does not start stopped agents or establish assessment completion."})
            );
        }
        [sign, bundle, key, output] if sign == "sign-update" => {
            control_updates::sign(Path::new(bundle), Path::new(key), Path::new(output))?;
        }
        [generate, key] if generate == "keygen-update" => control_updates::keygen(Path::new(key))?,
        [publish, source, key, file] if publish == "publish" => {
            let config = configuration(root)?;
            let source = config.sources.get(source).ok_or("unknown source")?;
            let bytes = fs::read(file)?;
            if bytes.len() > source.max_bytes {
                return Err("signal exceeds max_bytes".into());
            }
            let update: Update = serde_json::from_slice(&bytes)?;
            update.validate(source, key, now())?;
            let client = source.connect().await?;
            let kv = async_nats::jetstream::new(client)
                .get_key_value(&source.bucket)
                .await?;
            let previous = kv.entry(key).await?;
            let revision = if let Some(previous) = previous {
                if previous.operation == async_nats::jetstream::kv::Operation::Put {
                    let known: Update = serde_json::from_slice(&previous.value)?;
                    if known == update {
                        previous.revision
                    } else {
                        if known.source_id != update.source_id
                            || known.id != update.id
                            || known.revision >= update.revision
                            || known.observed_at > update.observed_at
                        {
                            return Err("publication conflicts with the current source identity, revision or evidence time".into());
                        }
                        kv.update(key, bytes.into(), previous.revision).await?
                    }
                } else {
                    kv.update(key, bytes.into(), previous.revision).await?
                }
            } else {
                kv.create(key, bytes.into()).await?
            };
            println!(
                "{}",
                json!({"publication":"accepted_by_broker","kv_revision":revision,"signal_revision":update.revision,"response":"not_verified"})
            );
        }
        _ => return Err("see signals --help".into()),
    }
    Ok(())
}
pub fn status(root: &Path) -> Result<Value, Error> {
    let config = configuration(root)?;
    let mut sources = BTreeMap::new();
    for (name, source) in &config.sources {
        let health = crate::guest_commands::read_state(
            &directory(root).join("sources").join(format!("{name}.json")),
        )?;
        let updates = read_accepted(root, name, source)?
            .into_iter()
            .map(|a| {
                let mut evidence=serde_json::to_value(&a.update).expect("serializable accepted evidence");
                if let Evidence::List{body}=&a.update.evidence {
                    evidence["evidence"]=json!({"kind":"list","body_bytes":body.len(),"body_sha256":crate::policy::checks::content_digest(body.as_bytes())});
                }
                json!({"evidence":evidence,"fresh":a.update.fresh(source,now())})
            })
            .collect::<Vec<_>>();
        sources.insert(name,json!({"source_id":source.source_id,"bucket":source.bucket,"keys":source.keys,"health":health,"accepted":updates}));
    }
    Ok(
        json!({"root":root,"read_at":now(),"response_observations":"recorded at each selection observed_at; reading status does not collect guest state","sources":sources,"responses":responses::status(root)?,"control_updates":control_updates::status(root)?,"automatic":"while the native proxy is running"}),
    )
}
fn read_accepted(root: &Path, name: &str, source: &Source) -> Result<Vec<Accepted>, Error> {
    let path = directory(root).join("accepted").join(name);
    if !path.try_exists()? {
        return Ok(vec![]);
    }
    let mut values = vec![];
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.path().extension().is_none_or(|e| e != "json") {
            continue;
        }
        let value = crate::guest_commands::read_state_bounded(
            &entry.path(),
            source.max_bytes as u64 + 65536,
        )?
        .ok_or("accepted signal disappeared")?;
        let accepted: Accepted = serde_json::from_value(value)?;
        if accepted.source_digest == digest(source) {
            values.push(accepted);
        }
    }
    Ok(values)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub source: String,
    pub key: String,
}
impl Publication {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        name(&self.source)?;
        name(&self.key)
    }
}
pub(crate) async fn distribute_list(
    root: &Path,
    publication: &Publication,
    snapshot: &crate::policy_feeds::Snapshot,
    feed: &crate::policy_feeds::Source,
) -> Result<(), Error> {
    let config = configuration(root)?;
    let source = config
        .sources
        .get(&publication.source)
        .ok_or("feed publication source is not configured")?;
    let client = source.connect().await?;
    let kv = async_nats::jetstream::new(client)
        .get_key_value(&source.bucket)
        .await?;
    let body = snapshot
        .entries
        .iter()
        .map(|entry| match feed.format {
            crate::policy_feeds::Format::Hosts => format!("0.0.0.0 {entry}\n"),
            _ => format!("{entry}\n"),
        })
        .collect::<String>();
    let observed_at = snapshot
        .provider_observed_at
        .unwrap_or(snapshot.evidence_first_observed_at);
    let previous = kv.entry(&publication.key).await?;
    let known = previous
        .as_ref()
        .filter(|entry| entry.operation == async_nats::jetstream::kv::Operation::Put)
        .map(|entry| serde_json::from_slice::<Update>(&entry.value))
        .transpose()?;
    if let Some(known) = &known {
        if known.source_id != source.source_id || known.id != publication.key {
            return Err("publication key belongs to another source identity".into());
        }
        if known.observed_at > observed_at {
            return Err("publication would replace newer source evidence".into());
        }
        if known.observed_at == observed_at
            && known.evidence == (Evidence::List { body: body.clone() })
            && known.withdrawn == snapshot.withdrawn
        {
            return Ok(());
        }
    }
    let update = Update {
        source_id: source.source_id.clone(),
        id: publication.key.clone(),
        revision: known.as_ref().map_or(1, |u| u.revision.saturating_add(1)),
        observed_at,
        expires_at: snapshot
            .expires_at
            .unwrap_or(observed_at.saturating_add(feed.max_age_seconds)),
        withdrawn: snapshot.withdrawn,
        evidence_refs: vec![format!(
            "policy-feed:{}@{}",
            snapshot.source, snapshot.version
        )],
        evidence: Evidence::List { body },
    };
    update.validate(source, &publication.key, now())?;
    let bytes = serde_json::to_vec(&update)?;
    if bytes.len() > source.max_bytes {
        return Err("distributed list exceeds configured signal max_bytes; select a bounded list or increase the adopted limit within the broker's payload limit".into());
    }
    match previous {
        Some(entry) => {
            kv.update(&publication.key, bytes.into(), entry.revision)
                .await?;
        }
        None => {
            kv.create(&publication.key, bytes.into()).await?;
        }
    }
    Ok(())
}
