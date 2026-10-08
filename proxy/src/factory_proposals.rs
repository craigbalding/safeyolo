//! Bounded proposal correlation. Only verified caller input enters this ledger;
//! nominations and operator decisions are read from canonical Coord owners.

mod commands;
#[cfg(test)]
mod tests;

use crate::{
    Error,
    completion_notes::{hex_id, provenance},
    coord_tools::text,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use unicode_normalization::UnicodeNormalization;

pub use commands::{HELP, run_agent, run_operator};
const LEDGER_VERSION: u32 = 1;
const MAX_LEDGER_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROPOSALS: usize = 256;
const MAX_EVIDENCE: usize = 64;
const MAX_FACTS: usize = 16;
const MAX_KEY_BYTES: usize = 128;
const MAX_REF_BYTES: usize = 512;
const MAX_FACT_BYTES: usize = 512;
const MAX_TEXT_BYTES: usize = 2 * 1024;
const LEDGER_NAME: &str = "factory-proposals.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Observed,
    ProposalReady,
    Presented,
    Accepted,
    Rejected,
    Deferred,
    Covered,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    kind: String,
    #[serde(rename = "ref")]
    ref_: String,
    task_key: String,
    #[serde(default)]
    nomination: bool,
}

// The public wire uses ref, while Rust reserves that keyword.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    correlation_key: String,
    task_key: String,
    facts: Vec<String>,
    inference: String,
    recommendation: String,
    recommendation_key: String,
    evidence: Vec<Evidence>,
    #[serde(default)]
    impact: Option<String>,
    #[serde(default)]
    confidence: Option<String>,
    #[serde(default)]
    material: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    correlation_key: String,
    facts: Vec<String>,
    inference: String,
    recommendation: String,
    recommendation_key: String,
    impact: Option<String>,
    confidence: Option<String>,
    covered_by: Option<String>,
    source_sent_at: u64,
    source_msg_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    evidence: Vec<Evidence>,
    fingerprint: String,
    first_seen: u64,
    last_seen: u64,
    last_presented_revision: Option<String>,
    proposal: Proposal,
    status: Status,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    proposals: BTreeMap<String, Record>,
}

fn bounded(value: &str, field: &str, maximum: usize) -> Result<String, Error> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(|c| c < ' ') {
        return Err(format!(
            "{field} must be nonempty text without controls, at most {maximum} UTF-8 bytes"
        )
        .into());
    }
    Ok(value.trim().to_owned())
}
fn optional(value: &Option<String>, field: &str, maximum: usize) -> Result<Option<String>, Error> {
    value
        .as_deref()
        .map(|v| bounded(v, field, maximum))
        .transpose()
}
fn stable_key(value: &str) -> Result<String, Error> {
    let value = bounded(value, "proposal key", MAX_KEY_BYTES)?;
    // NFKC handles compatibility ASCII/ligatures. The only case-fold expansions
    // contributing ASCII beyond lowercase are the two sharp-s code points.
    let folded: String = value
        .nfkc()
        .flat_map(|c| {
            if matches!(c, '\u{00df}' | '\u{1e9e}') {
                "ss".chars().collect::<Vec<_>>()
            } else {
                c.to_lowercase().collect()
            }
        })
        .collect();
    let normalized = folded
        .split(|c: char| !c.is_ascii_lowercase() && !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if normalized.is_empty() || normalized.len() > MAX_KEY_BYTES {
        return Err("proposal key has no bounded stable form".into());
    }
    Ok(normalized)
}
fn task_key(value: &str) -> Result<String, Error> {
    let value = bounded(value, "task_key", MAX_KEY_BYTES)?;
    if !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/#-".contains(&b))
    {
        return Err("invalid task_key".into());
    }
    Ok(value)
}
fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn fingerprint(key: &str) -> String {
    format!(
        "factory-{}",
        digest(format!("safeyolo-factory-proposal-v1\0{key}").as_bytes())
    )
}
fn evidence(values: Vec<Evidence>) -> Result<Vec<Evidence>, Error> {
    let mut normalized = BTreeSet::new();
    for mut item in values {
        if !crate::completion_notes::evidence_kind(&item.kind) {
            return Err("unknown evidence kind".into());
        }
        item.ref_ = bounded(&item.ref_, "evidence ref", MAX_REF_BYTES)?;
        item.task_key = task_key(&item.task_key)?;
        normalized.insert(item);
        if normalized.len() > MAX_EVIDENCE {
            return Err("proposal supports at most 64 evidence references".into());
        }
    }
    Ok(normalized.into_iter().collect())
}
fn facts(values: &[String]) -> Result<Vec<String>, Error> {
    if values.is_empty() || values.len() > MAX_FACTS {
        return Err("proposal requires 1..16 facts".into());
    }
    values
        .iter()
        .map(|s| bounded(s, "fact", MAX_FACT_BYTES))
        .collect::<Result<BTreeSet<_>, _>>()
        .map(|s| s.into_iter().collect())
}
impl Observation {
    fn normalize(&mut self) -> Result<(), Error> {
        self.correlation_key = stable_key(&self.correlation_key)?;
        self.recommendation_key = stable_key(&self.recommendation_key)?;
        self.task_key = task_key(&self.task_key)?;
        self.facts = facts(&self.facts)?;
        self.inference = bounded(&self.inference, "inference", MAX_TEXT_BYTES)?;
        self.recommendation = bounded(&self.recommendation, "recommendation", MAX_TEXT_BYTES)?;
        self.impact = optional(&self.impact, "impact", MAX_TEXT_BYTES)?;
        self.confidence = optional(&self.confidence, "confidence", MAX_FACT_BYTES)?;
        if self.evidence.iter().any(|e| e.nomination) {
            return Err("nomination evidence comes only from canonical Coord provenance".into());
        }
        self.evidence = evidence(std::mem::take(&mut self.evidence))?;
        Ok(())
    }
}
impl Record {
    fn revision(&self) -> Result<String, Error> {
        let tasks: BTreeSet<_> = self
            .evidence
            .iter()
            .filter(|e| e.nomination)
            .map(|e| &e.task_key)
            .collect();
        let verified: Vec<_> = self.evidence.iter().filter(|e| !e.nomination).collect();
        let value = json!({"nomination_tasks":tasks,
            "proposal":{"correlation_key":self.proposal.correlation_key,"facts":self.proposal.facts,"recommendation_key":self.proposal.recommendation_key},
            "verified_evidence":verified});
        Ok(format!(
            "rev-{}",
            digest(&serde_json::to_vec(&crate::coord_setup::sorted_json(
                &value
            ))?)
        ))
    }
    fn wire(&self) -> Result<Value, Error> {
        let mut value = serde_json::to_value(self)?;
        value["revision"] = json!(self.revision()?);
        Ok(value)
    }
    fn validate(&self, key: &str) -> Result<(), Error> {
        let p = &self.proposal;
        if stable_key(&p.correlation_key)? != p.correlation_key
            || stable_key(&p.recommendation_key)? != p.recommendation_key
            || fingerprint(&p.correlation_key) != key
            || self.fingerprint != key
            || facts(&p.facts)? != p.facts
            || evidence(self.evidence.clone())? != self.evidence
            || self.first_seen > self.last_seen
            || !(self.first_seen..=self.last_seen).contains(&p.source_sent_at)
            || !hex_id(&p.source_msg_id, "msg-", 32)
            || self
                .last_presented_revision
                .as_ref()
                .is_some_and(|r| !hex_id(r, "rev-", 64))
        {
            return Err("proposal ledger entry is invalid".into());
        }
        bounded(&p.inference, "stored inference", MAX_TEXT_BYTES)?;
        bounded(&p.recommendation, "stored recommendation", MAX_TEXT_BYTES)?;
        optional(&p.impact, "stored impact", MAX_TEXT_BYTES)?;
        optional(&p.confidence, "stored confidence", MAX_FACT_BYTES)?;
        optional(&p.covered_by, "stored coverage", MAX_REF_BYTES)?;
        if self.status == Status::Covered && p.covered_by.is_none()
            || matches!(
                self.status,
                Status::Presented | Status::Accepted | Status::Rejected | Status::Deferred
            ) && self.last_presented_revision.is_none()
            || matches!(self.status, Status::Presented | Status::Deferred)
                && self.last_presented_revision.as_ref() != Some(&self.revision()?)
        {
            return Err("proposal ledger status is inconsistent".into());
        }
        Ok(())
    }
    fn render(&self) -> Result<Value, Error> {
        if self.status != Status::ProposalReady {
            return Err("proposal is not ready".into());
        }
        let p = &self.proposal;
        let mut lines = vec![
            "Factory improvement proposal".to_owned(),
            String::new(),
            format!("Fingerprint: {}", self.fingerprint),
            format!("Revision: {}", self.revision()?),
            String::new(),
            "Observed facts (verified):".into(),
        ];
        lines.extend(p.facts.iter().map(|f| format!("- {f}")));
        lines.extend([String::new(), "Authoritative evidence:".into()]);
        lines.extend(
            self.evidence
                .iter()
                .map(|e| format!("- [{}] {} (task {})", e.kind, e.ref_, e.task_key)),
        );
        for (label, value) in [
            (
                "Observed cost/risk:",
                p.impact
                    .as_deref()
                    .unwrap_or("Not independently quantified."),
            ),
            ("Relay inference:", &p.inference),
            ("Relay recommendation:", &p.recommendation),
            (
                "Confidence / uncertainty:",
                p.confidence.as_deref().unwrap_or("Not stated."),
            ),
            (
                "Existing issue coverage:",
                p.covered_by
                    .as_deref()
                    .unwrap_or("None found during authoritative verification."),
            ),
        ] {
            lines.extend([String::new(), label.into(), value.into()]);
        }
        lines.extend([
            String::new(),
            "Operator decision required; no change has been applied.".into(),
        ]);
        Ok(
            json!({"fingerprint":self.fingerprint,"revision":self.revision()?,"body":lines.join("\n")}),
        )
    }
}

fn read_json(path: &Path) -> Result<Value, Error> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("proposal input/state must be a regular file".into());
    }
    let mut raw = String::new();
    file.take(MAX_LEDGER_BYTES as u64 + 1)
        .read_to_string(&mut raw)?;
    if raw.len() > MAX_LEDGER_BYTES {
        return Err("proposal input/state exceeds 2 MiB".into());
    }
    Ok(crate::policy::parse_json(&raw, true)?)
}
fn shape(value: &Value, keys: &[&str]) -> Result<(), Error> {
    if !value
        .as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
    {
        return Err("proposal ledger has invalid shape".into());
    }
    Ok(())
}
struct Ledger {
    path: PathBuf,
    _lock: fs::File,
    records: BTreeMap<String, Record>,
}
impl Ledger {
    fn open(path: &Path) -> Result<Self, Error> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // Preserve existing directory permissions. Only a newly created ledger
        // parent needs the existing private-state default.
        if !parent.try_exists()? {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        let lock_path = parent.join(format!(
            "{}.lock",
            path.file_name()
                .ok_or("ledger has no filename")?
                .to_string_lossy()
        ));
        let lock = crate::host_platform::lock_host_state(&lock_path)?;
        let records = match read_json(path) {
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                BTreeMap::new()
            }
            Err(error) => {
                return Err(format!(
                    "proposal ledger is corrupt or unreadable; left untouched: {error}"
                )
                .into());
            }
            Ok(value) => {
                shape(&value, &["version", "proposals"])?;
                let entries = value["proposals"]
                    .as_object()
                    .ok_or("proposal ledger entries must be an object")?;
                if entries.len() > MAX_PROPOSALS {
                    return Err("proposal ledger exceeds 256 proposals".into());
                }
                for item in entries.values() {
                    shape(
                        item,
                        &[
                            "evidence",
                            "fingerprint",
                            "first_seen",
                            "last_seen",
                            "last_presented_revision",
                            "proposal",
                            "status",
                        ],
                    )?;
                    shape(
                        &item["proposal"],
                        &[
                            "correlation_key",
                            "facts",
                            "inference",
                            "recommendation",
                            "recommendation_key",
                            "impact",
                            "confidence",
                            "covered_by",
                            "source_sent_at",
                            "source_msg_id",
                        ],
                    )?;
                }
                for item in entries.values() {
                    for entry in item["evidence"]
                        .as_array()
                        .ok_or("stored evidence must be an array")?
                    {
                        shape(entry, &["kind", "ref", "task_key", "nomination"])?;
                    }
                }
                let document: Document = serde_json::from_value(value)?;
                if document.version != LEDGER_VERSION {
                    return Err(
                        "unsupported native proposal ledger version; no historical conversion"
                            .into(),
                    );
                }
                for (key, item) in &document.proposals {
                    item.validate(key)?;
                }
                document.proposals
            }
        };
        Ok(Self {
            path: path.into(),
            _lock: lock,
            records,
        })
    }
    fn save(&self) -> Result<(), Error> {
        let value = json!({"version":LEDGER_VERSION,"proposals":self.records});
        let mut bytes = serde_json::to_vec(&crate::coord_setup::sorted_json(&value))?;
        bytes.push(b'\n');
        if bytes.len() > MAX_LEDGER_BYTES {
            return Err("proposal ledger exceeds 2 MiB; previous state retained".into());
        }
        crate::coord_supervisor::atomic_write(&self.path, &bytes, 0o600)
    }
    fn observe(
        &mut self,
        candidate: &Value,
        mut observation: Observation,
        coverage: Option<String>,
    ) -> Result<Record, Error> {
        observation.normalize()?;
        let covered_by = optional(&coverage, "existing issue ref", MAX_REF_BYTES)?;
        let source = &candidate["provenance"];
        let agent_id = source["sender_agent_id"].as_str().unwrap_or("none");
        let agent_name = source["sender_agent_name"].as_str().unwrap_or("none");
        let reference = format!(
            "msg_id={};sequence={};sender_kind={};sender_agent_id={agent_id};sender_agent_name={agent_name};origin={}",
            text(source, "msg_id")?,
            source["coord_sequence"],
            text(source, "sender_kind")?,
            text(source, "origin_instance_id")?
        );
        observation.evidence.push(Evidence {
            kind: "coord".into(),
            ref_: reference,
            task_key: observation.task_key.clone(),
            nomination: true,
        });
        let incoming = evidence(observation.evidence)?;
        let key = fingerprint(&observation.correlation_key);
        let seen_at = source["sent_at"]
            .as_u64()
            .ok_or("invalid canonical send time")?;
        let source_msg_id = text(source, "msg_id")?.to_owned();
        let proposal = Proposal {
            correlation_key: observation.correlation_key,
            facts: observation.facts,
            inference: observation.inference,
            recommendation: observation.recommendation,
            recommendation_key: observation.recommendation_key,
            impact: observation.impact,
            confidence: observation.confidence,
            covered_by,
            source_sent_at: seen_at,
            source_msg_id,
        };
        let updated = if let Some(current) = self.records.get(&key) {
            if matches!(
                current.status,
                Status::Accepted | Status::Rejected | Status::Covered
            ) {
                return Ok(current.clone());
            }
            let mut updated = current.clone();
            updated.evidence = evidence([current.evidence.clone(), incoming].concat())?;
            let merged_facts: BTreeSet<_> = current
                .proposal
                .facts
                .iter()
                .chain(&proposal.facts)
                .cloned()
                .collect();
            updated.proposal.facts = facts(&merged_facts.into_iter().collect::<Vec<_>>())?;
            updated.first_seen = updated.first_seen.min(seen_at);
            updated.last_seen = updated.last_seen.max(seen_at);
            let coverage = current
                .proposal
                .covered_by
                .clone()
                .or(proposal.covered_by.clone());
            if (proposal.source_sent_at, &proposal.source_msg_id)
                > (
                    current.proposal.source_sent_at,
                    &current.proposal.source_msg_id,
                )
            {
                let facts = updated.proposal.facts.clone();
                updated.proposal = proposal;
                updated.proposal.facts = facts;
            }
            updated.proposal.covered_by = coverage;
            if current.status == Status::ProposalReady
                && updated.revision()? == current.revision()?
                && updated.proposal.covered_by.is_none()
            {
                let (first, last) = (updated.first_seen, updated.last_seen);
                updated = current.clone();
                updated.first_seen = first;
                updated.last_seen = last;
            }
            let task_count = updated
                .evidence
                .iter()
                .map(|e| &e.task_key)
                .collect::<BTreeSet<_>>()
                .len();
            if current.status == Status::Observed && (observation.material || task_count >= 2)
                || matches!(current.status, Status::Presented | Status::Deferred)
                    && Some(updated.revision()?) != current.last_presented_revision
            {
                updated.status = Status::ProposalReady;
            } else if matches!(current.status, Status::Presented | Status::Deferred) {
                // Preserve rendered wording; new same-task source refs can stay
                // in the ledger without becoming another proposal revision.
                let facts = updated.proposal.facts.clone();
                let coverage = updated.proposal.covered_by.clone();
                updated.proposal = current.proposal.clone();
                updated.proposal.facts = facts;
                updated.proposal.covered_by = coverage;
            }
            if updated.proposal.covered_by.is_some() {
                updated.status = Status::Covered;
            }
            updated
        } else {
            if self.records.len() >= MAX_PROPOSALS {
                return Err("proposal ledger supports at most 256 proposals".into());
            }
            let task_count = incoming
                .iter()
                .map(|e| &e.task_key)
                .collect::<BTreeSet<_>>()
                .len();
            let status = if proposal.covered_by.is_some() {
                Status::Covered
            } else if observation.material || task_count >= 2 {
                Status::ProposalReady
            } else {
                Status::Observed
            };
            Record {
                evidence: incoming,
                fingerprint: key.clone(),
                first_seen: seen_at,
                last_seen: seen_at,
                last_presented_revision: None,
                proposal,
                status,
            }
        };
        updated.validate(&key)?;
        self.records.insert(key, updated.clone());
        self.save()?;
        Ok(updated)
    }
    fn pending(&self) -> Result<Vec<Value>, Error> {
        self.records
            .values()
            .filter(|r| r.status == Status::ProposalReady)
            .filter_map(|r| match r.revision() {
                Ok(revision) if Some(&revision) == r.last_presented_revision.as_ref() => None,
                Err(error) => Some(Err(error)),
                _ => Some(r.render()),
            })
            .collect()
    }
    fn presented(&mut self, envelope: &Value, relay: &str) -> Result<Option<Record>, Error> {
        let parsed = crate::completion_notes::parse(envelope)?;
        if parsed.delivery_state.is_some()
            || envelope["sender_kind"] != "agent"
            || envelope["sender_agent_name"] != relay
        {
            return Ok(None);
        }
        let body = text(envelope, "body")?;
        for rendered in self.pending()? {
            if rendered["body"] == body {
                let key = text(&rendered, "fingerprint")?;
                let record = self
                    .records
                    .get_mut(key)
                    .ok_or("proposal no longer exists")?;
                record.status = Status::Presented;
                record.last_presented_revision = Some(text(&rendered, "revision")?.into());
                let result = record.clone();
                self.save()?;
                return Ok(Some(result));
            }
        }
        Ok(None)
    }
    fn outcome(&mut self, envelope: &Value) -> Result<Record, Error> {
        provenance(envelope)?;
        let body = text(envelope, "body")?;
        let Some((key, status)) = body
            .strip_prefix("FACTORY_PROPOSAL_OUTCOME fingerprint=")
            .and_then(|b| b.split_once(" status="))
        else {
            return Err("outcome must be the exact canonical operator envelope".into());
        };
        if envelope["sender_kind"] != "operator" || !hex_id(key, "factory-", 64) {
            return Err("outcome must be the exact canonical operator envelope".into());
        }
        let status = match status {
            "accepted" => Status::Accepted,
            "rejected" => Status::Rejected,
            "deferred" => Status::Deferred,
            "covered" => Status::Covered,
            _ => return Err("invalid operator outcome".into()),
        };
        let record = self.records.get_mut(key).ok_or("proposal does not exist")?;
        if !matches!(record.status, Status::Presented | Status::Deferred) {
            return Err("cannot apply operator outcome from current status".into());
        }
        record.status = status;
        if status == Status::Covered {
            record.proposal.covered_by = Some(
                record
                    .proposal
                    .covered_by
                    .clone()
                    .unwrap_or_else(|| "operator-confirmed".into()),
            );
        }
        let result = record.clone();
        self.save()?;
        Ok(result)
    }
}
