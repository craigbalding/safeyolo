use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::Ed25519KeyPair;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    Discover,
    Propose,
    Invoke,
    Job,
    Output,
    File,
    Cancel,
    Adopt,
    Adoption,
}

impl Verb {
    pub fn path(self) -> &'static str {
        match self {
            Self::Discover => "/v1/host-execution/discover",
            Self::Propose => "/v1/host-execution/propose",
            Self::Invoke => "/v1/host-execution/invoke",
            Self::Job => "/v1/host-execution/job",
            Self::Output => "/v1/host-execution/output",
            Self::File => "/v1/host-execution/file",
            Self::Cancel => "/v1/host-execution/cancel",
            Self::Adopt => "/v1/host-execution/adopt",
            Self::Adoption => "/v1/host-execution/adoption",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub run: AgentRun,
    pub task_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRevisions {
    pub trust: String,
    pub authority: String,
    pub ceiling: String,
    pub assessment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub operation_id: String,
    pub resource_id: String,
    pub operation_sha256: String,
    pub implementation_sha256: String,
    pub arguments: BTreeMap<String, Value>,
    pub expected_assessment_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Discover,
    Adopt {
        operation_id: String,
        operation: Box<Operation>,
        base_package_sha256: String,
        /// Derived by the trusted issuer from its complete adopted package.
        #[serde(default)]
        package_sha256: String,
        #[serde(default)]
        observed_at: u64,
    },
    Adoption {
        request_id: String,
    },
    Propose {
        invocation: Invocation,
    },
    Invoke {
        invocation: Invocation,
    },
    Job {
        job_id: String,
    },
    Output {
        job_id: String,
        offset: u64,
        max_bytes: u64,
    },
    File {
        job_id: String,
        path: String,
        offset: u64,
        max_bytes: u64,
        expected_file_revision: Option<String>,
    },
    Cancel {
        job_id: String,
        expected_revision: u64,
    },
}

impl Action {
    pub fn verb(&self) -> Verb {
        match self {
            Self::Discover => Verb::Discover,
            Self::Propose { .. } => Verb::Propose,
            Self::Invoke { .. } => Verb::Invoke,
            Self::Job { .. } => Verb::Job,
            Self::Output { .. } => Verb::Output,
            Self::File { .. } => Verb::File,
            Self::Cancel { .. } => Verb::Cancel,
            Self::Adopt { .. } => Verb::Adopt,
            Self::Adoption { .. } => Verb::Adoption,
        }
    }
    pub fn job_id(&self) -> Option<&str> {
        match self {
            Self::Job { job_id }
            | Self::Output { job_id, .. }
            | Self::File { job_id, .. }
            | Self::Cancel { job_id, .. } => Some(job_id),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: String,
    pub required_features: Vec<String>,
    pub request_id: String,
    pub target_id: String,
    pub issuer_id: String,
    pub grant_id: String,
    pub principal: Principal,
    pub expires_at: u64,
    pub expected: Option<AuthorityRevisions>,
    pub action: Action,
    pub untrusted_rationale: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest {
    pub request: Request,
    pub key_id: String,
    pub signature: String,
}

impl SignedRequest {
    pub fn signing_message(request: &Request, key_id: &str) -> Vec<u8> {
        format!("{VERSION}\n{key_id}\n{}", revision(request)).into_bytes()
    }

    /// Issuer-side only: the caller must first derive Request from trusted
    /// ingress/run/task and the existing policy, grant, check and approval owners.
    pub fn sign(request: Request, key_id: String, key: &Ed25519KeyPair) -> Self {
        let signature =
            STANDARD.encode(key.sign(&Self::signing_message(&request, &key_id)).as_ref());
        Self {
            request,
            key_id,
            signature,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    Malformed,
    Protocol,
    Target,
    Issuer,
    Signature,
    Principal,
    Expired,
    Stale,
    Authority,
    Selector,
    Arguments,
    Budget,
    Conflict,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    pub code: RefusalCode,
    pub message: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}
impl std::error::Error for Refusal {}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationDiscovery {
    pub operation_id: String,
    pub implementation_sha256: String,
    pub semantic_revisions: HostOperationRevisions,
    pub operation_sha256: String,
    pub authority_sha256: String,
    pub assessment_sha256: String,
    pub revisions: AuthorityRevisions,
    pub definition: Operation,
    /// Membership is not authority. Concrete arguments/resources still need proposal.
    pub has_invocation_scope: bool,
    /// Target-generated facts. Empty when no native target assessment is supplied.
    pub network_enforcement: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub target_id: String,
    pub version: String,
    pub features: Vec<String>,
    pub routes: BTreeMap<Verb, String>,
    pub package_sha256: String,
    pub package_version: u64,
    pub revisions: AuthorityRevisions,
    pub authority_valid_until: u64,
    pub operations: Vec<OperationDiscovery>,
    pub catalogue: Option<CatalogueStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub invocation: Invocation,
    pub revisions: AuthorityRevisions,
    pub limits: Budgets,
    pub valid_until: u64,
    /// A proposal is an assessment, never an approval or a reservation.
    pub assessment_sha256: String,
    /// Adopted writable paths at admission. File reads also need current scope.
    pub file_roots: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Admitted,
    Running,
    Completed,
    Failed,
    Cancelled,
    Uncertain,
}

impl JobState {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Uncertain
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub target_id: String,
    pub issuer_id: String,
    pub principal: Principal,
    pub grant_id: String,
    pub request_id: String,
    pub request_sha256: String,
    pub job_id: String,
    pub revision: u64,
    pub state: JobState,
    pub prepared: Prepared,
    pub admitted_at: u64,
    pub updated_at: u64,
    pub deadline: u64,
    pub cancellation_requested: bool,
    pub output_bytes: u64,
    pub output_sha256: Option<String>,
    pub native: Option<NativeObservation>,
    pub process: Option<NativeProcess>,
    /// Historical bind observation recorded before workload launch. Readiness
    /// and current reachability require their own observations.
    pub listener_handoff: Option<crate::endpoints::EndpointObservation>,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeProcess {
    pub pid: u32,
    pub process_group: u32,
    pub birth_seconds: u64,
    pub birth_microseconds: u32,
    /// The admitted macOS operation permits children whose lifetime cannot be
    /// proved from the original process group. Persist before resuming it.
    pub descendants_may_escape: bool,
}

/// Observed native facts. An absent exit code or cleanup observation stays
/// unknown; a transport reply does not establish either fact.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeObservation {
    pub backend: String,
    pub enforcement: Vec<String>,
    pub dependencies: Vec<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub processes_stopped: bool,
    pub output_truncated: bool,
    pub termination_reason: String,
}

impl Receipt {
    pub(super) fn admitted(
        request: &Request,
        prepared: Prepared,
        now: u64,
    ) -> Result<Self, Refusal> {
        require(
            matches!(request.action, Action::Invoke { .. }),
            RefusalCode::Protocol,
            "only invocation can admit a job",
        )?;
        require(
            now < prepared.valid_until,
            RefusalCode::Expired,
            "proposal expired before admission",
        )?;
        let request_sha256 = revision(request);
        Ok(Self {
            target_id: request.target_id.clone(),
            issuer_id: request.issuer_id.clone(),
            principal: request.principal.clone(),
            grant_id: request.grant_id.clone(),
            request_id: request.request_id.clone(),
            job_id: format!(
                "job-{}",
                revision(&(&request.target_id, &request.issuer_id, &request.request_id))
            ),
            request_sha256,
            revision: 1,
            state: JobState::Admitted,
            deadline: now.saturating_add(prepared.limits.timeout_seconds),
            prepared,
            admitted_at: now,
            updated_at: now,
            cancellation_requested: false,
            output_bytes: 0,
            output_sha256: None,
            native: None,
            process: None,
            listener_handoff: None,
            detail: "admitted; execution has not started".into(),
        })
    }

    pub fn transition(
        &mut self,
        expected_revision: u64,
        next: JobState,
        now: u64,
        detail: String,
    ) -> Result<(), Refusal> {
        require(
            self.revision == expected_revision,
            RefusalCode::Conflict,
            "job revision changed",
        )?;
        let allowed = matches!(
            (self.state, next),
            (
                JobState::Admitted,
                JobState::Running | JobState::Failed | JobState::Cancelled | JobState::Uncertain
            ) | (
                JobState::Running,
                JobState::Completed | JobState::Failed | JobState::Cancelled | JobState::Uncertain
            )
        );
        require(
            allowed && now >= self.updated_at,
            RefusalCode::Conflict,
            "invalid lifecycle transition or time",
        )?;
        require(
            next != JobState::Cancelled || self.cancellation_requested,
            RefusalCode::Conflict,
            "cancellation needs a confirmed request",
        )?;
        require(
            next != JobState::Running || now < self.prepared.valid_until && now < self.deadline,
            RefusalCode::Expired,
            "authority or execution deadline expired before start",
        )?;
        self.state = next;
        self.updated_at = now;
        self.detail = detail;
        self.revision += 1;
        Ok(())
    }

    /// Cancellation acceptance is not proof that the native process stopped.
    pub fn request_cancellation(
        &mut self,
        expected_revision: u64,
        now: u64,
    ) -> Result<(), Refusal> {
        require(
            self.revision == expected_revision,
            RefusalCode::Conflict,
            "job revision changed",
        )?;
        require(
            !self.state.terminal() && now >= self.updated_at,
            RefusalCode::Conflict,
            "job is terminal or time moved backwards",
        )?;
        if !self.cancellation_requested {
            self.cancellation_requested = true;
            self.updated_at = now;
            self.revision += 1;
        }
        Ok(())
    }

    pub fn record_output(
        &mut self,
        expected_revision: u64,
        bytes: &[u8],
        now: u64,
    ) -> Result<(), Refusal> {
        require(
            self.revision == expected_revision && !self.state.terminal() && now >= self.updated_at,
            RefusalCode::Conflict,
            "output requires the current active job",
        )?;
        require(
            bytes.len() as u64 <= self.prepared.limits.output_bytes,
            RefusalCode::Budget,
            "output budget exceeded",
        )?;
        self.output_bytes = bytes.len() as u64;
        self.output_sha256 = Some(
            ring::digest::digest(&ring::digest::SHA256, bytes)
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        );
        self.updated_at = now;
        self.revision += 1;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Adoption {
        original: Box<SignedRequest>,
        package_sha256: String,
        operation_sha256: String,
    },
    Discovery {
        discovery: Box<Discovery>,
    },
    Proposal {
        prepared: Box<Prepared>,
        /// Target-generated facts, separate from authored effects and rationale.
        network_enforcement: Vec<String>,
    },
    Job {
        receipt: Box<Receipt>,
    },
    Output {
        job_id: String,
        revision: u64,
        offset: u64,
        data_base64: String,
        eof: bool,
        retained_bytes: u64,
        sha256: Option<String>,
    },
    File {
        job_id: String,
        revision: u64,
        path: String,
        file_revision: String,
        observed_at: u64,
        offset: u64,
        data_base64: String,
        eof: bool,
        total_bytes: u64,
        chunk_sha256: String,
    },
    Refused {
        refusal: Refusal,
    },
}
