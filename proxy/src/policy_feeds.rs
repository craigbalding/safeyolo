//! Trusted host acquisition for native named lists. The existing proxy control
//! loop drives refresh; this module does not assign policy effects to members.

mod download;
mod parse;
#[cfg(test)]
mod tests;

use crate::Error;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const HELP: &str = "safeyolo policy feeds example hagezi|stevenblack\nsafeyolo [--root ROOT] policy feeds configure FILE\nsafeyolo [--root ROOT] policy feeds status\nsafeyolo [--root ROOT] policy feeds refresh NAME\nsafeyolo [--root ROOT] policy feeds rollback NAME\n\nconfigure validates and saves private host source configuration, then attempts the first due refresh. A failed acquisition keeps the configuration and retry schedule. The running proxy refreshes sources automatically through its policy control loop; restart resumes persisted deadlines and accepted snapshots. No proxy means no automatic refresh.\nstatus reports retained data and schedule, not proof of live activation. Use policy show for the running policy.\nrefresh explicitly attempts one source now. rollback selects its previous accepted snapshot without changing its evidence age. Policy watchers activate changed snapshots; source configuration never grants network access.\nReference a source in policy.toml with [lists] name = { feed = 'SOURCE' }, then [hosts.'$name'] egress = 'deny' (or another explicit policy effect). Local list filenames remain supported.\nSee docs/policy-feeds.md for formats, limits, failure behavior and researched examples. Endpoints belong in private host configuration, never guest policy or command arguments.";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Domains,
    Hosts,
    Wildcard,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Hostname,
    DomainSuffix,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stale {
    Deny,
    Retain,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Metadata {
    #[default]
    None,
    Hagezi,
    Stevenblack,
}

// Do not derive Debug: endpoint paths and queries can contain provider keys.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub endpoint: String,
    #[serde(default)]
    pub redirect_endpoints: Vec<String>,
    pub format: Format,
    pub scope: Scope,
    pub cadence_seconds: u64,
    pub max_age_seconds: u64,
    pub timeout_seconds: u64,
    pub max_bytes: u64,
    pub min_entries: usize,
    pub max_entries: usize,
    pub max_change_percent: u8,
    pub retry_seconds: u64,
    pub max_retry_seconds: u64,
    pub on_stale: Stale,
    // No first snapshot can represent an exclusion. The policy fails closed.
    pub on_unavailable: Unavailable,
    #[serde(default)]
    pub metadata: Metadata,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Unavailable {
    Deny,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    sources: BTreeMap<String, Source>,
}

fn source_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
    {
        return Err(
            "source names require 1..80 ASCII letters, digits, underscores or hyphens".into(),
        );
    }
    Ok(())
}
fn uri(endpoint: &str) -> Result<hyper::Uri, Error> {
    let uri: hyper::Uri = endpoint.parse().map_err(|_| "invalid feed endpoint")?;
    if !matches!(uri.scheme_str(), Some("https" | "http"))
        || uri.authority().is_none_or(|a| a.as_str().contains('@'))
        || endpoint.contains(['\r', '\n', '\0', '#'])
    {
        return Err(
            "feed endpoints require an absolute HTTP(S) URL without userinfo or fragment".into(),
        );
    }
    Ok(uri)
}
impl Source {
    fn validate(&self) -> Result<(), Error> {
        uri(&self.endpoint)?;
        for endpoint in &self.redirect_endpoints {
            uri(endpoint)?;
        }
        if !matches!(
            (self.format, self.scope),
            (Format::Domains | Format::Hosts, Scope::Hostname)
                | (Format::Domains | Format::Wildcard, Scope::DomainSuffix)
        ) {
            return Err("feed format and match scope disagree".into());
        }
        if self.cadence_seconds == 0
            || self.max_age_seconds == 0
            || self.timeout_seconds == 0
            || std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(self.timeout_seconds))
                .is_none()
            || self.max_bytes == 0
            || self.max_bytes > (usize::MAX as u64).saturating_sub(65536) / 4
            || self.min_entries == 0
            || self.max_entries < self.min_entries
            || self.max_change_percent > 100
            || self.retry_seconds == 0
            || self.max_retry_seconds < self.retry_seconds
        {
            return Err("feed cadence, age, timeout, byte/entry and retry limits must be positive and consistent; max_change_percent must be 0..100".into());
        }
        Ok(())
    }
    fn identity(&self) -> String {
        digest(
            &serde_json::to_vec(
                &json!({"endpoint":self.endpoint, "redirect_endpoints":self.redirect_endpoints,
            "format":self.format, "scope":self.scope, "metadata":self.metadata}),
            )
            .expect("source is serializable"),
        )
    }
    fn adoption_identity(&self) -> String {
        digest(&serde_json::to_vec(self).expect("source is serializable"))
    }
    fn redacted_endpoint(&self) -> String {
        let uri = uri(&self.endpoint).expect("validated source endpoint");
        format!(
            "{}://{}/[redacted]",
            uri.scheme_str().unwrap(),
            uri.authority().unwrap()
        )
    }
}

fn read_configuration(path: &Path) -> Result<Configuration, Error> {
    let source =
        Zeroizing::new(fs::read_to_string(path).map_err(|_| "cannot read feed configuration")?);
    // Parser diagnostics can contain secret-bearing source lines.
    parse_configuration(&source)
}
fn parse_configuration(source: &str) -> Result<Configuration, Error> {
    let value = crate::policy::parse_toml_document(source)
        .map_err(|_| "invalid feed configuration TOML")?;
    let config: Configuration = serde_json::from_value(value).map_err(
        |_| "invalid feed configuration fields; see policy feeds --help and docs/policy-feeds.md",
    )?;
    for (name, source) in &config.sources {
        source_name(name)?;
        source.validate()?;
    }
    Ok(config)
}
fn configuration(root: &Path) -> Result<Configuration, Error> {
    let path = root.join("policy-feeds.toml");
    if !path.try_exists()? {
        return Ok(Configuration {
            sources: BTreeMap::new(),
        });
    }
    read_configuration(&path)
}
fn directory(root: &Path, name: &str) -> PathBuf {
    root.join("data/policy-feeds").join(name)
}
pub(crate) fn snapshot_path(root: &Path, name: &str) -> Result<PathBuf, Error> {
    source_name(name)?;
    Ok(directory(root, name).join("accepted.json"))
}
fn digest(bytes: &[u8]) -> String {
    crate::jobs::hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}
fn now() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
}
fn atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    crate::guest_commands::write_json(path, &serde_json::to_value(value)?)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Snapshot {
    pub source: String,
    pub endpoint: String,
    pub format: Format,
    pub scope: Scope,
    pub version: String,
    pub source_sha256: String,
    pub acquired_at: u64,
    pub evidence_first_observed_at: u64,
    pub validated_at: u64,
    pub provider_observed_at: Option<u64>,
    pub provider_version: Option<String>,
    pub entries: Vec<String>,
    // Kept private on disk; never part of status or policy views.
    config_identity: String,
}
impl Snapshot {
    fn evidence_time(&self) -> u64 {
        self.provider_observed_at
            .unwrap_or(self.evidence_first_observed_at)
    }
    fn usable(&self, source: &Source, at: u64) -> bool {
        at >= self.evidence_time()
            && at.saturating_sub(self.evidence_time()) < source.max_age_seconds
    }
    pub(crate) fn status(&self) -> Value {
        json!({"source":self.source, "endpoint":self.endpoint, "format":self.format,
            "scope":self.scope, "version":self.version, "source_sha256":self.source_sha256,
            "acquired_at":self.acquired_at, "validated_at":self.validated_at,
            "evidence_first_observed_at":self.evidence_first_observed_at,
            "provider_observed_at":self.provider_observed_at, "provider_version":self.provider_version,
            "entries":self.entries.len()})
    }
}
fn snapshot(
    root: &Path,
    name: &str,
    source: &Source,
    filename: &str,
) -> Result<Option<Snapshot>, Error> {
    let path = directory(root, name).join(filename);
    let Some(value) =
        crate::guest_commands::read_state_bounded(&path, source.max_bytes * 4 + 65536)?
    else {
        return Ok(None);
    };
    let snapshot: Snapshot =
        serde_json::from_value(value).map_err(|_| "invalid accepted feed snapshot")?;
    if snapshot.config_identity != source.identity() {
        return Ok(None);
    }
    if snapshot.source != name || snapshot.entries.len() > source.max_entries {
        return Err("feed snapshot does not match its source".into());
    }
    Ok(Some(snapshot))
}

#[derive(Default, Deserialize, Serialize)]
struct State {
    config_identity: String,
    attempt_pending: bool,
    next_refresh: u64,
    failures: u32,
    last_attempt: Option<u64>,
    last_success: Option<u64>,
    last_failure: Option<String>,
    etag: Option<String>,
    last_modified: Option<String>,
    cache_endpoint: Option<String>,
}
fn state(root: &Path, name: &str, source: &Source) -> Result<State, Error> {
    let saved = crate::guest_commands::read_state(&directory(root, name).join("state.json"))?;
    let state: State = saved
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default();
    Ok(if state.config_identity == source.adoption_identity() {
        state
    } else {
        State::default()
    })
}

/// A compiled policy owns entries and metadata from the same accepted file.
/// Availability is evaluated at request time, including across expiry deadlines.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct List {
    pub(crate) name: String,
    source: Source,
    pub(crate) snapshot: Option<Snapshot>,
}
impl List {
    /// Canonicalize only known feed members before the existing rule matcher.
    /// DNS aliases must not evade a feed rule through a different wire spelling.
    pub(crate) fn canonical_member(&self, host: &str) -> Option<String> {
        let snapshot = self.snapshot.as_ref()?;
        let encoded = crate::host_names::encode_idna2003(host).ok()?;
        let canonical = encoded
            .strip_suffix('.')
            .unwrap_or(&encoded)
            .to_ascii_lowercase();
        let contains = |name: &str| {
            snapshot
                .entries
                .binary_search_by(|entry| entry.as_str().cmp(name))
                .is_ok()
        };
        let found = match snapshot.scope {
            Scope::Hostname => contains(&canonical),
            Scope::DomainSuffix => {
                let mut suffix = canonical.as_str();
                loop {
                    if contains(&format!("*.{suffix}")) {
                        break true;
                    }
                    match suffix.split_once('.') {
                        Some((_, rest)) => suffix = rest,
                        None => break false,
                    }
                }
            }
        };
        found.then_some(canonical)
    }

    pub(crate) fn unavailable(&self, now_ms: f64) -> bool {
        self.snapshot.as_ref().is_none_or(|snapshot| {
            matches!(self.source.on_stale, Stale::Deny)
                && !snapshot.usable(&self.source, (now_ms / 1000.).max(0.) as u64)
        })
    }
    pub(crate) fn status(&self, now_ms: f64) -> Value {
        let mut value = self
            .snapshot
            .as_ref()
            .map(Snapshot::status)
            .unwrap_or_else(|| json!({"source":self.name}));
        value["unavailable"] = json!(self.unavailable(now_ms));
        value["stale"] = json!(
            self.snapshot
                .as_ref()
                .map(|snapshot| !snapshot.usable(&self.source, (now_ms / 1000.).max(0.) as u64))
        );
        value["evidence_age_seconds"] = json!(self.snapshot.as_ref().map(|snapshot| {
            ((now_ms / 1000.).max(0.) as u64).saturating_sub(snapshot.evidence_time())
        }));
        value["on_stale"] = json!(self.source.on_stale);
        value["max_age_seconds"] = json!(self.source.max_age_seconds);
        value
    }
}
pub(crate) fn load_list(root: &Path, name: &str) -> Result<List, Error> {
    source_name(name)?;
    let mut config = configuration(root)?;
    let source = config
        .sources
        .remove(name)
        .ok_or("policy references an unconfigured feed")?;
    let snapshot = snapshot(root, name, &source, "accepted.json")?;
    Ok(List {
        name: name.into(),
        source,
        snapshot,
    })
}

pub async fn command(root: &Path, args: &[String]) -> Result<(), Error> {
    match args {
        [help] if help == "--help" => println!("{HELP}"),
        [example, name] if example == "example" => print!("{}", match name.as_str() {
            "hagezi" => include_str!("../config/policy-feeds/hagezi.toml"),
            "stevenblack" => include_str!("../config/policy-feeds/stevenblack.toml"),
            _ => return Err("choose example hagezi or stevenblack; see docs/policy-feeds.md for source scope and terms".into()),
        }),
        [configure, file] if configure == "configure" => {
            let source = Zeroizing::new(
                fs::read_to_string(file).map_err(|_| "cannot read feed configuration")?,
            );
            parse_configuration(&source)?;
            let mut temp = tempfile::NamedTempFile::new_in(root)?;
            use std::io::Write;
            temp.write_all(source.as_bytes())?;
            temp.as_file().sync_all()?;
            {
                let _lock = crate::approvals::lock_policy(&root.join("policy.toml"))?;
                temp.persist(root.join("policy-feeds.toml"))?;
                fs::File::open(root)?.sync_all()?;
            }
            let result = refresh_due(root, None).await;
            println!("{}", serde_json::to_string_pretty(&status(root)?)?);
            result?;
        }
        [show] if show == "status" => println!("{}", serde_json::to_string_pretty(&status(root)?)?),
        [refresh, name] if refresh == "refresh" => {
            source_name(name)?;
            let result = refresh_due(root, Some(name)).await;
            println!("{}", serde_json::to_string_pretty(&status(root)?)?);
            result?;
        }
        [rollback, name] if rollback == "rollback" => {
            source_name(name)?;
            let config = configuration(root)?;
            let source = config.sources.get(name).ok_or("unknown source")?;
            let dir = directory(root, name);
            let _lock = crate::host_platform::try_lock_host_state(&dir.join("refresh.lock"))?;
            let previous = snapshot(root, name, source, "previous.json")?
                .ok_or("no previous accepted snapshot for this source configuration")?;
            let current = snapshot(root, name, source, "accepted.json")?;
            atomic(&dir.join("accepted.json"), &previous)?;
            if let Some(current) = current {
                atomic(&dir.join("previous.json"), &current)?;
            }
            println!("{}", serde_json::to_string_pretty(&status(root)?)?);
        }
        _ => return Err("see policy feeds --help".into()),
    }
    Ok(())
}
pub fn status(root: &Path) -> Result<Value, Error> {
    let mut sources = serde_json::Map::new();
    for (name, source) in configuration(root)?.sources {
        let snapshot = snapshot(root, &name, &source, "accepted.json")?;
        let state = state(root, &name, &source)?;
        let at = now();
        sources.insert(name.clone(), json!({"identity":name, "endpoint":source.redacted_endpoint(),
            "format":source.format, "scope":source.scope, "cadence_seconds":source.cadence_seconds,
            "max_age_seconds":source.max_age_seconds, "on_stale":source.on_stale,
            "on_unavailable":source.on_unavailable, "snapshot":snapshot.as_ref().map(Snapshot::status),
            "evidence_age_seconds":snapshot.as_ref().map(|s| at.saturating_sub(s.evidence_time())),
            "stale":snapshot.as_ref().map(|s| !s.usable(&source, at)),
            "next_refresh":state.next_refresh, "last_attempt":state.last_attempt,
            "last_success":state.last_success, "last_failure":state.last_failure,
            "consecutive_failures":state.failures, "attempt_pending_or_interrupted":state.attempt_pending}));
    }
    Ok(json!({"policy_directory":root, "sources":sources,
        "automatic_refresh":"while the native proxy is running", "activation":"inspect policy show for the running policy"}))
}

/// One cancellable acquisition worker, driven by the existing policy watcher.
#[derive(Default)]
pub(crate) struct Refresh {
    worker: Option<tokio::task::JoinHandle<Result<(), Error>>>,
}
impl Refresh {
    pub(crate) async fn poll(&mut self, root: PathBuf) -> Result<(), Error> {
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            return Ok(());
        }
        if let Some(worker) = self.worker.take() {
            worker.await??;
        }
        self.worker = Some(tokio::spawn(async move { refresh_due(&root, None).await }));
        Ok(())
    }
}
impl Drop for Refresh {
    fn drop(&mut self) {
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

async fn refresh_due(root: &Path, selected: Option<&str>) -> Result<(), Error> {
    let config = configuration(root)?;
    if selected.is_some_and(|name| !config.sources.contains_key(name)) {
        return Err("unknown source".into());
    }
    let mut failed = false;
    for (name, source) in config.sources {
        if selected.is_some_and(|selected| selected != name) {
            continue;
        }
        let dir = directory(root, &name);
        fs::create_dir_all(&dir)?;
        let _lock = match crate::host_platform::try_lock_host_state(&dir.join("refresh.lock")) {
            Ok(lock) => lock,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if selected.is_some() {
                    return Err(
                        "feed refresh is already in progress; inspect policy feeds status".into(),
                    );
                }
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let mut state = state(root, &name, &source)?;
        if selected.is_none() && now() < state.next_refresh {
            continue;
        }
        let attempt = now();
        state.config_identity = source.adoption_identity();
        state.last_attempt = Some(attempt);
        // Reserve the next retry before I/O: interruption and restart do not
        // reset backoff or create an acquisition storm.
        if state.attempt_pending {
            state.failures = state.failures.saturating_add(1);
        }
        state.attempt_pending = true;
        let retry = source
            .retry_seconds
            .saturating_mul(1u64 << state.failures.min(31))
            .min(source.max_retry_seconds);
        state.next_refresh = attempt.saturating_add(retry);
        atomic(&dir.join("state.json"), &state)?;
        let result = update(root, &name, &source, &mut state).await;
        state.attempt_pending = false;
        match result {
            Ok(()) => {
                state.failures = 0;
                state.last_failure = None;
                state.last_success = Some(now());
                state.next_refresh = now().saturating_add(source.cadence_seconds);
            }
            Err(error) => {
                state.failures = state.failures.saturating_add(1);
                state.next_refresh = now().saturating_add(retry);
                state.last_failure = Some(error.to_string());
                failed = true;
            }
        }
        atomic(&dir.join("state.json"), &state)?;
    }
    if failed {
        return Err(
            "feed refresh rejected; inspect policy feeds status; accepted data is retained".into(),
        );
    }
    Ok(())
}
async fn update(root: &Path, name: &str, source: &Source, state: &mut State) -> Result<(), Error> {
    let current = snapshot(root, name, source, "accepted.json")?;
    let downloaded = download::fetch(root, name, source, state).await?;
    if downloaded.status == 304 {
        if current.is_none() {
            return Err("received 304 without an accepted snapshot".into());
        }
        return Ok(());
    }
    let source_sha256 = digest(&downloaded.body);
    let parse::ParsedFeed {
        entries,
        provider_observed_at,
        provider_version,
    } = parse::entries(source, &downloaded.body)?;
    if let Some(current) = &current {
        parse::validate_change(&current.entries, &entries, source.max_change_percent)?;
        if current.source_sha256 == source_sha256 {
            // A repeated fetch cannot make unchanged upstream evidence young.
            state.etag = downloaded.etag;
            state.last_modified = downloaded.last_modified;
            state.cache_endpoint = Some(downloaded.endpoint);
            return Ok(());
        }
    }
    let at = now();
    if provider_observed_at.is_some_and(|time| time > at) {
        return Err("provider evidence timestamp is in the future".into());
    }
    let accepted = Snapshot {
        source: name.into(),
        endpoint: source.redacted_endpoint(),
        format: source.format,
        scope: source.scope,
        version: uuid::Uuid::new_v4().to_string(),
        source_sha256,
        acquired_at: at,
        evidence_first_observed_at: current
            .as_ref()
            .filter(|current| current.entries == entries)
            .map_or(at, |current| current.evidence_first_observed_at),
        validated_at: at,
        provider_observed_at,
        provider_version,
        entries,
        config_identity: source.identity(),
    };
    let dir = directory(root, name);
    // Recheck saved adoption after pending I/O. Old configuration cannot publish
    // a result into a newly selected source definition.
    let _policy_lock = crate::approvals::lock_policy(&root.join("policy.toml"))?;
    let adopted = configuration(root)?;
    if adopted
        .sources
        .get(name)
        .is_none_or(|s| s.adoption_identity() != source.adoption_identity())
    {
        return Err("source configuration changed during acquisition".into());
    }
    if let Some(current) = current {
        atomic(&dir.join("previous.json"), &current)?;
    }
    atomic(&dir.join("accepted.json"), &accepted)?;
    state.etag = downloaded.etag;
    state.last_modified = downloaded.last_modified;
    state.cache_endpoint = Some(downloaded.endpoint);
    Ok(())
}
