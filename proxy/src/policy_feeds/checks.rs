//! Captured managed snapshots for the shared named-check evaluator.
use super::*;
use crate::policy::checks::{
    Check, CheckResult, Evidence, FileVersion, Finding, Provenance, Subject,
};

/// Local binding, separate from optional upstream provider metadata.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FeedVersion {
    pub source: String,
    pub snapshot_version: Option<String>,
    pub content_digest: Option<String>,
    pub configuration_digest: Option<String>,
    configuration_file: Option<FileVersion>,
    snapshot_file: Option<FileVersion>,
}

pub(crate) struct CheckFeed {
    root: PathBuf,
    list: Option<List>,
    pub(crate) version: FeedVersion,
}
impl std::fmt::Debug for CheckFeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CheckFeed")
            .field("version", &self.version)
            .finish()
    }
}

fn file_version(path: &Path) -> std::io::Result<Option<FileVersion>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(FileVersion::from_metadata(&metadata))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

impl CheckFeed {
    pub(crate) fn status(&self) -> Value {
        let snapshot = self.list.as_ref().and_then(|list| list.snapshot.as_ref());
        json!({"active_snapshot":snapshot.map(Snapshot::status),
            "saved_matches_active":self.current(), "binding":self.version,
            "stale":self.list.as_ref().and_then(|list| list.snapshot.as_ref().map(|snapshot|!snapshot.usable(&list.source,now())))})
    }

    pub(crate) fn capture(root: &Path, name: &str) -> Result<Self, Error> {
        let path = snapshot_path(root, name)?;
        let configuration_file = file_version(&root.join("policy-feeds.toml"))?;
        let snapshot_file = file_version(&path)?;
        // Failed reads supply unavailable evidence, never negative membership.
        let list = load_list(root, name).ok();
        let version = FeedVersion {
            source: name.into(),
            snapshot_version: list
                .as_ref()
                .and_then(|list| list.snapshot.as_ref())
                .map(|s| s.version.clone()),
            content_digest: list
                .as_ref()
                .and_then(|list| list.snapshot.as_ref())
                .map(|snapshot| snapshot.source_sha256.clone()),
            configuration_digest: list.as_ref().map(|list| list.source.adoption_identity()),
            configuration_file,
            snapshot_file,
        };
        let mut captured = Self {
            root: root.into(),
            list,
            version,
        };
        // Never pair entries read from one version with another's provenance.
        // A racing write remains visible to the existing policy watcher.
        if !captured.current() {
            captured.list = None;
        }
        Ok(captured)
    }

    pub(crate) fn current(&self) -> bool {
        file_version(&self.root.join("policy-feeds.toml"))
            .is_ok_and(|version| version == self.version.configuration_file)
            && snapshot_path(&self.root, &self.version.source).is_ok_and(|path| {
                file_version(&path).is_ok_and(|version| version == self.version.snapshot_file)
            })
    }

    pub(crate) fn collect(&self, check: &Check, subject: &Subject, entry: &mut Evidence) {
        entry.acquisition = "managed_feed_snapshot".into();
        entry.feed_version = Some(self.version.clone());
        let Some(list) = &self.list else {
            entry.unavailable = Some("managed feed source unavailable".into());
            return;
        };
        let Some(snapshot) = &list.snapshot else {
            entry.unavailable = Some("managed feed snapshot unavailable".into());
            return;
        };
        let Subject::Hostname { hostname } = subject else {
            entry.unavailable = Some("managed feed covers hostname subjects only".into());
            return;
        };
        let at = crate::policy::current_time_ms().max(0.) as u64;
        let observed = snapshot.evidence_time().saturating_mul(1000);
        if observed > at {
            entry.unavailable = Some("future feed evidence time".into());
            return;
        }
        let source_age = check
            .max_source_age_seconds
            .map_or(list.source.max_age_seconds, |age| {
                age.min(list.source.max_age_seconds)
            });
        entry.result = Some(CheckResult {
            subject: subject.clone(),
            input_digest: entry.input_digest.clone().expect("normalized check input"),
            implementation_version: check.implementation_version.clone(),
            configuration_version: check.configuration_version.clone(),
            collected_at_ms: at,
            valid_until_ms: Some(observed.saturating_add(source_age.saturating_mul(1000))),
            source: Provenance {
                source_id: check.source_id.clone(),
                source_revision: snapshot.provider_version.clone(),
                content_digest: Some(snapshot.source_sha256.clone()),
                source_observed_at_ms: snapshot
                    .provider_observed_at
                    .map(|time| time.saturating_mul(1000)),
            },
            finding: Finding::Finding {
                positive: list.canonical_member(hostname).is_some(),
            },
        });
    }
}
