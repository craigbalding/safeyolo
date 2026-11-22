//! Durable admission for the native executor. A retained admission is never a
//! licence to replay an external effect after a lost reply or process failure.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::{fs::File, path::Path};

/// Target-owned admission and retention bounds. database_bytes caps logical
/// database pages. The native owner must also reserve space for the rollback
/// journal, filesystem overhead and any executable snapshots or other artifacts.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerLimits {
    pub jobs: u64,
    pub mutation_records: u64,
    pub output_bytes: u64,
    pub database_bytes: u64,
    pub request_bytes: u64,
}

impl LedgerLimits {
    pub(crate) fn validate(&self, target_id: &str) -> Result<(), Refusal> {
        require(
            selector(target_id)
                && self.jobs > 0
                && self.mutation_records >= self.jobs
                && self.output_bytes > 0
                && self.output_bytes <= i64::MAX as u64
                && self.request_bytes > 0
                && self.database_bytes >= 128 * 1024
                && self.database_bytes <= i64::MAX as u64,
            RefusalCode::Budget,
            "ledger needs literal target identity and positive bounded storage, output and record limits",
        )
    }
}

pub struct Ledger {
    connection: Connection,
    limits: LedgerLimits,
    target_id: String,
    _lock: File,
    #[cfg(target_os = "macos")]
    root: PathBuf,
}

pub struct Admission {
    pub response: Response,
    /// Only this result may select a first dispatch. A replay always returns
    /// false, including when a previous response was lost before dispatch.
    pub dispatch: bool,
}

fn unavailable(error: impl std::fmt::Display) -> Refusal {
    Refusal {
        code: RefusalCode::Unavailable,
        message: format!("native executor ledger: {error}"),
    }
}

fn json<T: Serialize>(value: &T) -> Result<String, Refusal> {
    serde_json::to_string(value).map_err(unavailable)
}

// The native backends emit fixed enforcement/dependency descriptions, plus the
// adopted Linux identity. Reserve those facts, numeric lifecycle fields and a
// bounded diagnostic before admission. Request/rationale bytes have no new cap.
const RECEIPT_GROWTH_BYTES: usize = 32 * 1024;
const DIAGNOSTIC_BYTES: usize = 4096;

fn diagnostic(mut value: String) -> String {
    if value.len() > DIAGNOSTIC_BYTES {
        let mut end = DIAGNOSTIC_BYTES;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
        value.push_str(" [diagnostic truncated]");
    }
    value
}

fn job_row(transaction: &Transaction<'_>, job_id: &str) -> Result<i64, Refusal> {
    transaction
        .query_row("SELECT rowid FROM jobs WHERE job_id=?1", [job_id], |row| {
            row.get(0)
        })
        .map_err(unavailable)
}

/// Incremental writes cannot change a cell's size or allocate database pages.
/// Their rollback journal still needs the separately documented host reserve.
fn write_blob(
    transaction: &Transaction<'_>,
    row: i64,
    column: &str,
    bytes: &[u8],
    offset: usize,
) -> Result<(), Refusal> {
    let mut blob = transaction
        .blob_open("main", "jobs", column, row, false)
        .map_err(unavailable)?;
    blob.write_at(bytes, offset).map_err(unavailable)?;
    blob.close().map_err(unavailable)
}

fn write_json(
    transaction: &Transaction<'_>,
    row: i64,
    column: &str,
    value: &impl Serialize,
) -> Result<(), Refusal> {
    let mut blob = transaction
        .blob_open("main", "jobs", column, row, false)
        .map_err(unavailable)?;
    let mut bytes = json(value)?.into_bytes();
    require(
        bytes.len() <= blob.len(),
        RefusalCode::Budget,
        "receipt exceeds its admitted storage reservation",
    )?;
    bytes.resize(blob.len(), b' ');
    blob.write_at(&bytes, 0).map_err(unavailable)?;
    blob.close().map_err(unavailable)
}

fn receipt(transaction: &Transaction<'_>, job_id: &str) -> Result<Receipt, Refusal> {
    let value: Option<String> = transaction
        .query_row(
            "SELECT CAST(receipt AS TEXT) FROM jobs WHERE job_id=?1",
            [job_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(unavailable)?;
    serde_json::from_str(&value.ok_or_else(|| Refusal {
        code: RefusalCode::Selector,
        message: "unknown retained job".into(),
    })?)
    .map_err(unavailable)
}

fn save_receipt(transaction: &Transaction<'_>, receipt: &Receipt) -> Result<(), Refusal> {
    write_json(
        transaction,
        job_row(transaction, &receipt.job_id)?,
        "receipt",
        receipt,
    )
}

fn usage(
    transaction: &Transaction<'_>,
    auth: &Authorized<'_>,
    operation: &str,
    excluded_job: Option<&str>,
) -> Result<Usage, Refusal> {
    let request = auth.request();
    let (issuer, target) = auth.scopes(operation)?;
    let issuer: (i64, i64) = transaction
        .query_row(
            "SELECT coalesce(sum(grant_revision=?3),0),coalesce(sum(active=x'01'),0)
             FROM jobs WHERE issuer=?1 AND grant_id=?2 AND issuer_operation=?4
             AND (?5 IS NULL OR job_id<>?5)",
            params![
                request.issuer_id,
                request.grant_id,
                auth.grant_revision(),
                issuer.operation,
                excluded_job
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(unavailable)?;
    // Uncertain jobs retain a live reservation. A terminal protocol state does
    // not establish that an orphaned native process stopped. The target ceiling
    // applies across issuers/grants; neither revision can release active usage.
    let target: (i64, i64) = transaction
        .query_row(
            "SELECT coalesce(sum(target_revision=?1),0),coalesce(sum(active=x'01'),0)
             FROM jobs WHERE target_operation=?2 AND (?3 IS NULL OR job_id<>?3)",
            params![revision(target.scope), target.operation, excluded_job],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(unavailable)?;
    Ok(Usage {
        issuer: ScopeUsage {
            admitted: issuer.0.try_into().map_err(unavailable)?,
            active: issuer.1.try_into().map_err(unavailable)?,
        },
        target: ScopeUsage {
            admitted: target.0.try_into().map_err(unavailable)?,
            active: target.1.try_into().map_err(unavailable)?,
        },
    })
}

impl Ledger {
    /// The caller supplies a protected target directory. Workload confinement
    /// must deny this directory and all aliases to it before any native launch.
    /// A second executor cannot open the same ledger while its owner is live.
    pub fn open(root: &Path, target_id: &str, limits: LedgerLimits) -> Result<Self, Refusal> {
        limits.validate(target_id)?;
        #[cfg(unix)]
        let metadata = std::fs::symlink_metadata(root).map_err(unavailable)?;
        // SAFETY: geteuid has no pointer arguments and reads this process's UID.
        #[cfg(unix)]
        let uid = unsafe { libc::geteuid() };
        #[cfg(unix)]
        require(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
            RefusalCode::Unavailable,
            "ledger directory must be owned by the executor and private",
        )?;
        #[cfg(unix)]
        let file = |name: &str| -> Result<File, Refusal> {
            let path = root.join(name);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .map_err(unavailable)?;
            let metadata = file.metadata().map_err(unavailable)?;
            require(
                metadata.is_file()
                    && metadata.uid() == uid
                    && metadata.nlink() == 1
                    && metadata.mode() & 0o077 == 0,
                RefusalCode::Unavailable,
                "ledger files must be private regular files with one link",
            )?;
            Ok(file)
        };
        #[cfg(windows)]
        let file = |name: &str| crate::windows::security::private_file(&root.join(name));
        let lock = file("executor.lock")?;
        lock.try_lock().map_err(unavailable)?;
        let database = file("jobs.sqlite")?;
        let connection = Connection::open(root.join("jobs.sqlite")).map_err(unavailable)?;
        let schema: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(unavailable)?;
        let pages: i64 = connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .map_err(unavailable)?;
        require(
            schema == 2 || pages == 0,
            RefusalCode::Unavailable,
            "retained ledger format differs from this executor; retained database was not changed",
        )?;
        // DELETE avoids an independently growing WAL. Each immediate
        // transaction has at most one rollback journal of the bounded database.
        connection
            .execute_batch(
                "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY;",
            )
            .map_err(unavailable)?;
        let page_size: i64 = connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .map_err(unavailable)?;
        let page_limit = limits.database_bytes / page_size as u64;
        let actual_limit: i64 = connection
            .query_row(&format!("PRAGMA max_page_count={page_limit}"), [], |row| {
                row.get(0)
            })
            .map_err(unavailable)?;
        require(
            actual_limit as u64 <= page_limit,
            RefusalCode::Budget,
            "existing database exceeds the selected storage ceiling",
        )?;
        connection
            .execute_batch(
                "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS target (singleton INTEGER PRIMARY KEY CHECK(singleton=1), id TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS jobs (
               job_id TEXT PRIMARY KEY, issuer TEXT NOT NULL, grant_id TEXT NOT NULL,
               grant_revision TEXT NOT NULL, issuer_operation TEXT NOT NULL,
               target_revision TEXT NOT NULL, target_operation TEXT NOT NULL, request BLOB NOT NULL,
               receipt BLOB NOT NULL, output BLOB NOT NULL, reserved_output INTEGER NOT NULL CHECK(reserved_output>0),
               active BLOB NOT NULL CHECK(active IN (x'00',x'01')),
               cancellation_key BLOB NOT NULL, cancellation_digest BLOB NOT NULL, cancellation_response BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS mutations (
               issuer TEXT NOT NULL, request_id TEXT NOT NULL, digest TEXT NOT NULL,
               response TEXT NOT NULL, PRIMARY KEY(issuer,request_id));
             PRAGMA user_version=2;
             COMMIT;",
            )
            .map_err(unavailable)?;
        connection
            .execute("INSERT OR IGNORE INTO target VALUES(1,?1)", [target_id])
            .map_err(unavailable)?;
        let targets: Vec<String> = connection
            .prepare("SELECT id FROM target")
            .map_err(unavailable)?
            .query_map([], |row| row.get(0))
            .map_err(unavailable)?
            .collect::<Result<_, _>>()
            .map_err(unavailable)?;
        require(
            targets == [target_id],
            RefusalCode::Target,
            "ledger belongs to another durable target",
        )?;
        database.sync_all().map_err(unavailable)?;
        #[cfg(unix)]
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(unavailable)?;
        Ok(Self {
            connection,
            limits,
            target_id: target_id.into(),
            _lock: lock,
            #[cfg(target_os = "macos")]
            root: root.to_owned(),
        })
    }

    /// Complete authentication and current job ownership are checked even for
    /// replay. Admission, usage reservation and the replay response commit as
    /// one transaction before a caller may dispatch the native operation.
    pub fn handle(
        &mut self,
        target: &Target,
        path: &str,
        bytes: &[u8],
        now: u64,
    ) -> Result<Admission, Refusal> {
        self.handle_runtime(target, path, bytes, now, None)
    }

    pub(crate) fn handle_native(
        &mut self,
        target: &Target,
        path: &str,
        bytes: &[u8],
        now: u64,
        runtime: &NativeRuntime,
    ) -> Result<Admission, Refusal> {
        self.handle_runtime(target, path, bytes, now, Some(runtime))
    }

    fn handle_runtime(
        &mut self,
        target: &Target,
        path: &str,
        bytes: &[u8],
        now: u64,
        runtime: Option<&NativeRuntime>,
    ) -> Result<Admission, Refusal> {
        require(
            target.target_id == self.target_id,
            RefusalCode::Target,
            "target differs from ledger",
        )?;
        require(
            bytes.len() as u64 <= self.limits.request_bytes,
            RefusalCode::Budget,
            "request exceeds the target byte ceiling",
        )?;
        let auth = target.authenticate("POST", path, bytes, now)?;
        let req = auth.request();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let replay: Option<(String, String)> = transaction
            .query_row(
                "SELECT digest,response FROM mutations WHERE issuer=?1 AND request_id=?2",
                params![req.issuer_id, req.request_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(unavailable)?;
        let cancellation_key = revision(&(&req.issuer_id, &req.request_id));
        let replay = match replay {
            Some(value) => Some(value),
            None => transaction.query_row(
                "SELECT CAST(cancellation_digest AS TEXT),CAST(cancellation_response AS TEXT) FROM jobs WHERE cancellation_key=?1",
                [cancellation_key.as_bytes()], |row| Ok((row.get(0)?, row.get(1)?))
            ).optional().map_err(unavailable)?,
        };
        if let Some((digest, response)) = replay {
            require(
                digest == revision(req),
                RefusalCode::Conflict,
                "request ID already identifies different content",
            )?;
            return Ok(Admission {
                response: serde_json::from_str(&response).map_err(unavailable)?,
                dispatch: false,
            });
        }
        let mutation = matches!(req.action, Action::Invoke { .. } | Action::Cancel { .. });
        if mutation {
            let count: i64 = transaction
                .query_row("SELECT (SELECT count(*) FROM mutations)+(SELECT count(*) FROM jobs WHERE cancellation_key!=zeroblob(64))", [], |row| row.get(0))
                .map_err(unavailable)?;
            require(
                (count as u64) < self.limits.mutation_records,
                RefusalCode::Budget,
                "retained mutation record ceiling reached",
            )?;
            let uncancelled: i64 = transaction.query_row(
                "SELECT count(*) FROM jobs WHERE active=x'01' AND json_extract(CAST(receipt AS TEXT),'$.cancellation_requested')=0",
                [], |row| row.get(0)
            ).map_err(unavailable)?;
            let releases_reserve = if let Action::Cancel { job_id, .. } = &req.action {
                let retained = receipt(&transaction, job_id)?;
                target.authorize_job(&auth, &retained)?;
                !retained.state.terminal() && !retained.cancellation_requested
            } else {
                false
            };
            let reserve = (uncancelled as u64)
                .saturating_sub(u64::from(releases_reserve))
                .saturating_add(u64::from(matches!(req.action, Action::Invoke { .. })));
            require(
                (count as u64).saturating_add(1).saturating_add(reserve)
                    <= self.limits.mutation_records,
                RefusalCode::Budget,
                "mutation storage must retain capacity to cancel each active job",
            )?;
        }
        let mut dispatch = false;
        let mut reserved_cancellation = None;
        let response = match &req.action {
            Action::Discover => Response::Discovery {
                discovery: Box::new(target.discover(&auth)?),
            },
            Action::Propose { invocation } => {
                let prepared = target.prepare(
                    &auth,
                    usage(&transaction, &auth, &invocation.operation_id, None)?,
                )?;
                if let Some(runtime) = runtime {
                    runtime.validate_command(
                        &target.package.operations[&invocation.operation_id]
                            .command(&prepared.invocation.arguments)?,
                    )?;
                }
                Response::Proposal {
                    prepared: Box::new(prepared),
                }
            }
            Action::Invoke { invocation } => {
                let (jobs, output): (i64, i64) = transaction
                    .query_row(
                        "SELECT count(*),coalesce(sum(reserved_output),0) FROM jobs",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(unavailable)?;
                let receipt = target.admit(
                    &auth,
                    usage(&transaction, &auth, &invocation.operation_id, None)?,
                    now,
                )?;
                if let Some(runtime) = runtime {
                    runtime.validate_command(
                        &target.package.operations[&invocation.operation_id]
                            .command(&receipt.prepared.invocation.arguments)?,
                    )?;
                }
                require(
                    (jobs as u64) < self.limits.jobs
                        && receipt.prepared.limits.output_bytes
                            <= self.limits.output_bytes.saturating_sub(output as u64),
                    RefusalCode::Budget,
                    "target job or retained-output ceiling reached",
                )?;
                let capacity = json(&receipt)?.len()
                    + 2 * json(
                        &target.package.operations[&invocation.operation_id]
                            .execution
                            .identity,
                    )?
                    .len()
                    + RECEIPT_GROWTH_BYTES;
                let (issuer, ceiling) = auth.scopes(&invocation.operation_id)?;
                transaction
                    .execute(
                        "INSERT INTO jobs VALUES(?1,?2,?3,?4,?5,?6,?7,?8,zeroblob(?9),zeroblob(?10),?10,x'01',zeroblob(64),zeroblob(64),zeroblob(?11))",
                        params![
                            receipt.job_id,
                            req.issuer_id,
                            req.grant_id,
                            auth.grant_revision(),
                            issuer.operation,
                            revision(ceiling.scope),
                            ceiling.operation,
                            bytes,
                            capacity as i64,
                            receipt.prepared.limits.output_bytes as i64,
                            (capacity + 64) as i64,
                        ],
                    )
                    .map_err(unavailable)?;
                save_receipt(&transaction, &receipt)?;
                dispatch = true;
                Response::Job {
                    receipt: Box::new(receipt),
                }
            }
            Action::Job { job_id }
            | Action::Output { job_id, .. }
            | Action::Cancel { job_id, .. } => {
                let mut retained = receipt(&transaction, job_id)?;
                target.authorize_job(&auth, &retained)?;
                match req.action {
                    Action::Cancel {
                        expected_revision, ..
                    } => {
                        if !retained.cancellation_requested {
                            reserved_cancellation = Some(job_row(&transaction, job_id)?);
                        }
                        retained.request_cancellation(expected_revision, now)?;
                        save_receipt(&transaction, &retained)?;
                        Response::Job {
                            receipt: Box::new(retained),
                        }
                    }
                    Action::Output {
                        offset, max_bytes, ..
                    } => {
                        let data: Vec<u8> = transaction
                            .query_row(
                                "SELECT substr(output,1,?2) FROM jobs WHERE job_id=?1",
                                params![job_id, retained.output_bytes as i64],
                                |row| row.get(0),
                            )
                            .map_err(unavailable)?;
                        require(
                            offset <= data.len() as u64
                                && max_bytes > 0
                                && max_bytes <= retained.prepared.limits.output_bytes,
                            RefusalCode::Arguments,
                            "output range exceeds retained bytes or admitted limit",
                        )?;
                        let end = offset.saturating_add(max_bytes).min(data.len() as u64) as usize;
                        Response::Output {
                            job_id: job_id.clone(),
                            revision: retained.revision,
                            offset,
                            data_base64: STANDARD.encode(&data[offset as usize..end]),
                            eof: end == data.len(),
                            retained_bytes: data.len() as u64,
                            sha256: retained.output_sha256,
                        }
                    }
                    _ => Response::Job {
                        receipt: Box::new(retained),
                    },
                }
            }
        };
        if let Some(row) = reserved_cancellation {
            write_json(&transaction, row, "cancellation_response", &response)?;
            write_blob(
                &transaction,
                row,
                "cancellation_key",
                cancellation_key.as_bytes(),
                0,
            )?;
            write_blob(
                &transaction,
                row,
                "cancellation_digest",
                revision(req).as_bytes(),
                0,
            )?;
        } else if mutation {
            transaction
                .execute(
                    "INSERT INTO mutations VALUES(?1,?2,?3,?4)",
                    params![
                        req.issuer_id,
                        req.request_id,
                        revision(req),
                        json(&response)?
                    ],
                )
                .map_err(unavailable)?;
        }
        transaction.commit().map_err(unavailable)?;
        Ok(Admission { response, dispatch })
    }

    /// Reauthenticate and reprepare the original request before its first
    /// dispatch. Recording Running precedes launch; a crash in that gap remains
    /// uncertain and never selects an automatic second launch.
    pub fn begin(&mut self, target: &Target, job_id: &str, now: u64) -> Result<Receipt, Refusal> {
        require(
            target.target_id == self.target_id,
            RefusalCode::Target,
            "target differs from ledger",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let mut retained = receipt(&transaction, job_id)?;
        require(
            retained.state == JobState::Admitted && !retained.cancellation_requested,
            RefusalCode::Conflict,
            "job is already dispatched or cancellation was requested",
        )?;
        let bytes: Vec<u8> = transaction
            .query_row(
                "SELECT request FROM jobs WHERE job_id=?1",
                [job_id],
                |row| row.get(0),
            )
            .map_err(unavailable)?;
        let auth = target.authenticate("POST", Verb::Invoke.path(), &bytes, now)?;
        let used = usage(
            &transaction,
            &auth,
            &retained.prepared.invocation.operation_id,
            Some(job_id),
        )?;
        let prepared = target.prepare(&auth, used)?;
        require(
            revision(&prepared) == revision(&retained.prepared),
            RefusalCode::Stale,
            "admitted execution inputs changed",
        )?;
        retained.transition(
            retained.revision,
            JobState::Running,
            now,
            "native dispatch selected; process creation has not yet been observed".into(),
        )?;
        save_receipt(&transaction, &retained)?;
        transaction.commit().map_err(unavailable)?;
        Ok(retained)
    }

    /// Append at most the admitted retained-output limit. The native owner must
    /// stop/drain the producer and report truncation; this method cannot infer
    /// producer termination from a full buffer.
    pub fn append_output(
        &mut self,
        job_id: &str,
        bytes: &[u8],
        now: u64,
    ) -> Result<usize, Refusal> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let mut retained = receipt(&transaction, job_id)?;
        let mut data: Vec<u8> = transaction
            .query_row(
                "SELECT substr(output,1,?2) FROM jobs WHERE job_id=?1",
                params![job_id, retained.output_bytes as i64],
                |row| row.get(0),
            )
            .map_err(unavailable)?;
        let available = retained
            .prepared
            .limits
            .output_bytes
            .saturating_sub(data.len() as u64);
        let take = (bytes.len() as u64).min(available) as usize;
        data.extend_from_slice(&bytes[..take]);
        retained.record_output(retained.revision, &data, now)?;
        write_blob(
            &transaction,
            job_row(&transaction, job_id)?,
            "output",
            &bytes[..take],
            data.len() - take,
        )?;
        save_receipt(&transaction, &retained)?;
        transaction.commit().map_err(unavailable)?;
        Ok(take)
    }

    pub fn finish(
        &mut self,
        job_id: &str,
        next: JobState,
        quiescent: bool,
        now: u64,
        detail: String,
    ) -> Result<Receipt, Refusal> {
        self.finish_observed(job_id, next, quiescent, now, detail, None)
    }

    pub fn observe(&self, job_id: &str) -> Result<Receipt, Refusal> {
        let value: String = self
            .connection
            .query_row(
                "SELECT CAST(receipt AS TEXT) FROM jobs WHERE job_id=?1",
                [job_id],
                |row| row.get(0),
            )
            .map_err(unavailable)?;
        serde_json::from_str(&value).map_err(unavailable)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn artifact_root(&self) -> &Path {
        &self.root
    }

    /// Save the identity of a suspended native process before it can perform
    /// workload effects. Failed capture must not be treated as absent execution.
    #[cfg(target_os = "macos")]
    pub(crate) fn attach_process(
        &mut self,
        job_id: &str,
        process: NativeProcess,
    ) -> Result<(), Refusal> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let mut retained = receipt(&transaction, job_id)?;
        require(
            retained.state == JobState::Running && retained.process.is_none(),
            RefusalCode::Conflict,
            "native process requires a running job without a prior process",
        )?;
        retained.process = Some(process);
        retained.revision += 1;
        save_receipt(&transaction, &retained)?;
        transaction.commit().map_err(unavailable)
    }

    /// Finish with the native observation in the same transaction as lifecycle
    /// and concurrency release. Only the trusted executor calls this method.
    pub fn finish_observed(
        &mut self,
        job_id: &str,
        next: JobState,
        quiescent: bool,
        now: u64,
        detail: String,
        native: Option<NativeObservation>,
    ) -> Result<Receipt, Refusal> {
        require(
            next.terminal() && (quiescent || next == JobState::Uncertain),
            RefusalCode::Conflict,
            "unconfirmed process cleanup must remain uncertain",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let mut retained = receipt(&transaction, job_id)?;
        require(
            native
                .as_ref()
                .is_none_or(|facts| facts.processes_stopped == quiescent),
            RefusalCode::Conflict,
            "native cleanup observation differs from reservation release",
        )?;
        retained.native = native;
        retained.transition(retained.revision, next, now, diagnostic(detail))?;
        save_receipt(&transaction, &retained)?;
        write_blob(
            &transaction,
            job_row(&transaction, job_id)?,
            "active",
            &[u8::from(!quiescent)],
            0,
        )?;
        transaction.commit().map_err(unavailable)?;
        Ok(retained)
    }

    /// Call after the exclusive executor lock is acquired on restart. No process
    /// is launched, signalled or presumed stopped. Uncertain reservations remain
    /// held until the native owner independently observes quiescence.
    pub fn recover(&mut self, now: u64) -> Result<Vec<Receipt>, Refusal> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let values: Vec<String> = transaction
            .prepare("SELECT CAST(receipt AS TEXT) FROM jobs WHERE active=x'01'")
            .map_err(unavailable)?
            .query_map([], |row| row.get(0))
            .map_err(unavailable)?
            .collect::<Result<_, _>>()
            .map_err(unavailable)?;
        let mut recovered = Vec::new();
        for value in values {
            let mut retained: Receipt = serde_json::from_str(&value).map_err(unavailable)?;
            if !retained.state.terminal() {
                retained.transition(retained.revision,JobState::Uncertain,now,
                    "executor restarted; prior process/effects require native reconciliation; no redispatch selected".into())?;
                save_receipt(&transaction, &retained)?;
            }
            recovered.push(retained);
        }
        transaction.commit().map_err(unavailable)?;
        Ok(recovered)
    }

    /// Only native observation can release an uncertain process reservation.
    /// The protocol outcome remains uncertain; quiescence does not reconstruct
    /// an unobserved exit code or erase prior side effects.
    pub fn confirm_quiescent(
        &mut self,
        job_id: &str,
        now: u64,
        observation: &str,
    ) -> Result<Receipt, Refusal> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let mut retained = receipt(&transaction, job_id)?;
        require(
            retained.state == JobState::Uncertain
                && now >= retained.updated_at
                && !observation.is_empty(),
            RefusalCode::Conflict,
            "quiescence reconciliation needs an uncertain job and current native observation",
        )?;
        retained.updated_at = now;
        retained.revision += 1;
        retained.detail = diagnostic(format!(
            "prior outcome remains uncertain; observed quiescence: {observation}"
        ));
        save_receipt(&transaction, &retained)?;
        write_blob(
            &transaction,
            job_row(&transaction, job_id)?,
            "active",
            &[0],
            0,
        )?;
        transaction.commit().map_err(unavailable)?;
        Ok(retained)
    }
}
