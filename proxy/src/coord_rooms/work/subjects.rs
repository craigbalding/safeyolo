//! Exact subjects and named participants; authors still come only from transport.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Principal {
    pub kind: String,
    pub id: String,
}

impl Principal {
    pub(super) fn validate(&self, conn: &Connection, room: &str) -> Result<(), WorkError> {
        match self.kind.as_str() {
            "operator" if self.id == "operator" => Ok(()),
            "agent" => member(conn, room, &self.id, true),
            _ => Err(invalid(
                "participant must name an agent with room send/receive or operator:operator",
            )),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum SubjectRef {
    Work {
        work_id: String,
        version: i64,
    },
    Output {
        work_id: String,
        target_generation: i64,
    },
    Check {
        work_id: String,
        version: i64,
    },
}
impl SubjectRef {
    pub(super) fn work_id(&self) -> &str {
        match self {
            Self::Work { work_id, .. }
            | Self::Output { work_id, .. }
            | Self::Check { work_id, .. } => work_id,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Subject {
    pub reference: SubjectRef,
    pub root_work_id: String,
    pub work_version: i64,
    pub target_ref: Option<String>,
    pub producer: Option<Principal>,
}

pub(super) fn bind(
    conn: &Connection,
    room: &str,
    reference: SubjectRef,
) -> Result<Subject, WorkError> {
    // Read the named work first so cross-room IDs never grant access to history.
    let current = current(conn, room, reference.work_id())?;
    let version = match &reference {
        SubjectRef::Work {version,..} | SubjectRef::Check {version,..} if *version > 0 => *version,
        SubjectRef::Output {target_generation,..} if *target_generation > 0 => conn.query_row(
            "SELECT min(version) FROM coord_work_revisions WHERE room_id=?1 AND work_id=?2 AND json_extract(document_json,'$.target_generation')=?3",
            params![room, reference.work_id(), target_generation], |r| r.get::<_,Option<i64>>(0))?
            .ok_or_else(|| conflict("subject output generation does not exist"))?,
        _ => return Err(invalid("subject version or target generation must be positive")),
    };
    if version > current.version {
        return Err(conflict("subject work version does not exist"));
    }
    let work: Work = serde_json::from_value(revision(conn, room, reference.work_id(), version)?)?;
    let producer = if matches!(reference, SubjectRef::Check { .. }) {
        Some(
            work.check
                .as_ref()
                .and_then(|c| c.answer.as_ref())
                .filter(|_| work.state == "done")
                .ok_or_else(|| conflict("check subject must name an answered check revision"))?
                .author
                .clone(),
        )
    } else {
        work.output
            .as_ref()
            .map(|o| serde_json::from_value(o.producer.clone()))
            .transpose()?
    };
    let root_work_id = work
        .check
        .as_ref()
        .map(|c| &c.subject.root_work_id)
        .or_else(|| work.challenge.as_ref().map(|c| &c.subject.root_work_id))
        .cloned()
        .unwrap_or_else(|| reference.work_id().into());
    Ok(Subject {
        reference,
        root_work_id,
        work_version: version,
        target_ref: work.target_ref,
        producer,
    })
}

pub(super) fn is_current(
    conn: &Connection,
    room: &str,
    subject: &Subject,
) -> Result<bool, WorkError> {
    let work = current(conn, room, subject.reference.work_id())?;
    Ok(match &subject.reference {
        SubjectRef::Output {
            target_generation, ..
        } => work.target_generation == *target_generation,
        SubjectRef::Work { version, .. } | SubjectRef::Check { version, .. } => {
            work.version == *version
        }
    })
}

pub(super) fn independent(subject: &Subject, participant: &Principal) -> Result<(), WorkError> {
    let producer = subject
        .producer
        .as_ref()
        .ok_or_else(|| conflict("independent review requires an attributed subject producer"))?;
    if producer == participant {
        return Err(WorkError(
            403,
            "subject producer cannot provide its independent disposition".into(),
        ));
    }
    Ok(())
}

pub(super) fn evidence(summary: &str, refs: &[String]) -> Result<(), WorkError> {
    if summary.trim().is_empty()
        || summary.len() > 1024
        || refs.len() > 16
        || refs.iter().any(|r| r.len() > 1024)
    {
        return Err(invalid(
            "summary/reason must contain 1..1024 UTF-8 bytes; evidence_refs at most 16 strings of 1024 bytes each",
        ));
    }
    Ok(())
}

pub(super) fn record_bound<T: Serialize>(record: &T) -> Result<(), WorkError> {
    if serde_json::to_vec(record)?.len() > attestations::MAX_RECORD_BYTES {
        return Err(invalid(
            "review record exceeds 32768 serialized UTF-8 bytes",
        ));
    }
    Ok(())
}
