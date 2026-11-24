//! First-trust preparation reuses native target configuration, catalogue
//! qualification and the signed protocol. It never runs a proposed program.
use crate::*;
use base64::{Engine, engine::general_purpose::STANDARD};
#[cfg(unix)]
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
#[cfg(unix)]
use std::{fs, path::Path};

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskIntent {
    pub outcome: String,
    pub service_function: Option<String>,
    pub audience: Option<String>,
    pub data_and_functions: Option<String>,
    pub authentication: Option<String>,
    pub lifetime: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskPlan {
    pub intent: TaskIntent,
    pub hostname: String,
    pub control_listen: std::net::SocketAddr,
    pub root: PathBuf,
    pub read_paths: Vec<String>,
    pub network: Network,
    pub broader: BTreeSet<BroaderBound>,
    pub execution_limits: ExecutionLimits,
    pub budgets: Budgets,
    pub duration_seconds: u64,
    pub allow_agent_code: bool,
    pub allow_run_refresh: bool,
    pub executable_bytes: u64,
    pub dependency_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnrolmentRequest {
    pub operation_id: String,
    pub target_id: String,
    pub issuer_id: String,
    pub key_id: String,
    pub public_key: String,
    pub principal: Principal,
    pub task_revision: String,
    pub not_before: u64,
    pub expires_at: u64,
    pub plan: TaskPlan,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Enrolment {
    pub request: EnrolmentRequest,
    pub target: Target,
    pub catalogue: CatalogueAdoption,
    pub hostname: String,
    pub port: u16,
    pub certificate_pem: String,
    pub account: ExecutionIdentity,
    pub configuration: PathBuf,
    pub state: PathBuf,
    pub qualified: bool,
}

fn failure(error: impl std::fmt::Display) -> Refusal {
    crate::native::unavailable(error)
}

impl EnrolmentRequest {
    pub fn validate(&self) -> Result<(), Refusal> {
        require(
            selector(&self.operation_id)
                && selector(&self.target_id)
                && selector(&self.issuer_id)
                && selector(&self.key_id),
            RefusalCode::Selector,
            "enrolment needs its original operation and selected identities",
        )?;
        require(
            STANDARD.decode(&self.public_key).map_err(failure)?.len() == 32
                && self.principal.task_id.is_some()
                && self.task_revision.len() == 64
                && self.not_before <= now()
                && now() < self.expires_at
                && self.plan.duration_seconds > 0
                && self.plan.executable_bytes > 0
                && !self.plan.intent.outcome.is_empty(),
            RefusalCode::Authority,
            "enrolment needs a public signing key, task, finite future authority and retained intent",
        )?;
        Ok(())
    }
}

impl Enrolment {
    /// Check the returned preparation against its retained material choices.
    /// This validates a receipt; current transport and running state still need
    /// authenticated discovery after the issuer binding is adopted.
    pub fn validate(&self) -> Result<(), Refusal> {
        self.request.validate()?;
        self.target.validate().map_err(failure)?;
        let request = &self.request;
        let operation = self
            .target
            .package
            .operations
            .get("task:inspect")
            .ok_or_else(|| failure("initial task operation is absent"))?;
        let expected = task_operation(
            request,
            &self.account,
            &operation.execution.executable,
            &operation.execution.executable_sha256,
        )?;
        require(
            revision(operation) == revision(&expected)
                && self.target.package.operations.len() == 1
                && self.target.package.name == request.target_id
                && self.target.target_id == request.target_id
                && self.hostname == request.plan.hostname
                && self.port == request.plan.control_listen.port(),
            RefusalCode::Target,
            "returned target, account facts or execution boundary differs from the prepared task",
        )?;
        let trust = self
            .target
            .issuers
            .get(&request.issuer_id)
            .ok_or_else(|| failure("prepared issuer is absent"))?;
        let grant = trust
            .authority
            .grants
            .get("task")
            .ok_or_else(|| failure("prepared task grant is absent"))?;
        let scope = self
            .target
            .ceiling
            .get("task:inspect")
            .ok_or_else(|| failure("prepared task ceiling is absent"))?;
        let rule = UpdateRule {
            ceiling: expected.clone(),
            allow_narrower: true,
            allow_implementation_updates: false,
            allow_agent_code: request.plan.allow_agent_code,
            agent_dependency_bytes: request.plan.dependency_bytes,
        };
        let expected_scope = OperationScope {
            implementation_sha256: expected.implementation_sha256(),
            resources: expected.resources.clone(),
            arguments: BTreeMap::new(),
            budgets: request.plan.budgets.clone(),
            updates: Some(rule.clone()),
            checks: BTreeSet::new(),
        };
        let expected_family = OperationFamily {
            prefix: "task:".into(),
            excluded: BTreeSet::new(),
            rule: rule.clone(),
            scope: expected_scope.clone(),
        };
        let verbs: BTreeSet<_> = [
            Verb::Discover,
            Verb::Propose,
            Verb::Invoke,
            Verb::Job,
            Verb::Output,
            Verb::File,
            Verb::Cancel,
            Verb::Adopt,
            Verb::Adoption,
        ]
        .into();
        require(
            self.target.issuers.len() == 1
                && trust.authority.grants.len() == 1
                && trust.public_keys
                    == BTreeMap::from([(request.key_id.clone(), request.public_key.clone())])
                && grant.principal == request.principal
                && grant.not_before == request.not_before
                && grant.expires_at == request.expires_at
                && grant.allow_run_refresh == request.plan.allow_run_refresh
                && trust.authority.observed_at == request.not_before
                && trust.authority.valid_until == request.expires_at
                && request.expires_at.checked_sub(request.not_before)
                    == Some(request.plan.duration_seconds)
                && self.target.max_authority_age_seconds == request.plan.duration_seconds
                && self.target.allowed_verbs == verbs
                && grant.verbs == verbs
                && self.target.ceiling.len() == 1
                && revision(scope) == revision(&expected_scope)
                && revision(&self.target.families) == revision(&vec![expected_family])
                && trust.revision == revision(&trust.public_keys)
                && trust.authority.revision == revision(&trust.authority.grants)
                && trust.authority.assessment_revision == revision(&request.plan.intent)
                && revision(&scope.budgets) == revision(&request.plan.budgets)
                && revision(&grant.operations) == revision(&self.target.ceiling)
                && revision(&grant.families) == revision(&self.target.families)
                && self.target.families.len() == 1
                && self.target.families[0].prefix == "task:"
                && self.target.families[0].rule.allow_agent_code == request.plan.allow_agent_code
                && revision(&self.target.families[0].rule.ceiling) == revision(&expected)
                && revision(&self.target.families[0].scope) == revision(scope),
            RefusalCode::Authority,
            "returned trust, code class or task authority differs from the retained plan",
        )?;
        let plan = self.catalogue.plan(now())?;
        require(
            self.qualified
                && revision(&plan.package) == revision(&self.target.package)
                && self.catalogue.observed_file.is_none()
                && self.catalogue.policy.operations.len() == 1
                && revision(&self.catalogue.policy.operations.get("task:inspect"))
                    == revision(&Some(&rule))
                && revision(&self.catalogue.policy.families) == revision(&self.target.families)
                && self
                    .catalogue
                    .policy
                    .agent_code_keys
                    .get(&request.issuer_id)
                    == Some(&trust.public_keys),
            RefusalCode::Stale,
            "target catalogue preparation is incomplete or differs from the retained request",
        )?;
        Ok(())
    }
}

#[cfg(unix)]
fn create_directory(path: &Path) -> Result<(), Refusal> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(failure)?;
    }
    crate::server::protected(path, true)?;
    Ok(())
}

/// Target-local, explicitly selected first trust. The caller carries the
/// nonsecret request through its existing authorized install/transfer owner.
#[cfg(unix)]
pub fn prepare(
    request: EnrolmentRequest,
    directory: &Path,
    hostname: &str,
    listen: std::net::SocketAddr,
) -> Result<Enrolment, Refusal> {
    request.validate()?;
    require(
        hostname == request.plan.hostname && listen == request.plan.control_listen,
        RefusalCode::Target,
        "bootstrap transport differs from the prepared target context",
    )?;
    require(
        listen.port() > 0,
        RefusalCode::Arguments,
        "enrolment needs the selected nonzero control-listener port",
    )?;
    if directory.exists() {
        crate::server::protected(directory, true)?;
        let original: EnrolmentRequest = serde_json::from_reader(
            fs::File::open(directory.join("request.json")).map_err(failure)?,
        )
        .map_err(failure)?;
        require(
            revision(&original) == revision(&request),
            RefusalCode::Conflict,
            "this directory retains another enrolment request; inspect it instead of repeating bootstrap",
        )?;
        if directory.join("enrolment.json").exists() {
            let original: Enrolment = serde_json::from_reader(
                fs::File::open(directory.join("enrolment.json")).map_err(failure)?,
            )
            .map_err(failure)?;
            original.validate()?;
            return Ok(original);
        }
        if directory.join("target.json").exists() {
            let state = directory.join("state");
            let settings = crate::server::load(&directory.join("target.json"), &state)?;
            return finish(request, directory, hostname, listen, &settings, state);
        }
    }
    create_directory(directory)?;
    let request_path = directory.join("request.json");
    if !request_path.exists() {
        crate::https::private_file(
            &request_path,
            &serde_json::to_vec_pretty(&request).map_err(failure)?,
        )?;
    }
    // Retain the original request before any further setup. A partial attempt
    // is inspected in place; it is never silently replaced by a new enrolment.
    fs::create_dir_all(&request.plan.root).map_err(failure)?;
    let root = request.plan.root.canonicalize().map_err(failure)?;
    require(
        root == request.plan.root,
        RefusalCode::Arguments,
        "selected task root must be canonical",
    )?;
    let state = directory.join("state");
    create_directory(&state)?;
    let identity = crate::workflow::identity(None)?;
    let shell = fs::canonicalize("/bin/sh").map_err(failure)?;
    let shell_hash = crate::workflow::hash(&shell)?;
    let operation = task_operation(&request, &identity, &shell.to_string_lossy(), &shell_hash)?;
    let rule = UpdateRule {
        ceiling: operation.clone(),
        allow_narrower: true,
        allow_implementation_updates: false,
        allow_agent_code: request.plan.allow_agent_code,
        agent_dependency_bytes: request.plan.dependency_bytes,
    };
    let scope = OperationScope {
        implementation_sha256: operation.implementation_sha256(),
        resources: operation.resources.clone(),
        arguments: BTreeMap::new(),
        budgets: request.plan.budgets.clone(),
        updates: Some(rule.clone()),
        checks: BTreeSet::new(),
    };
    let family = OperationFamily {
        prefix: "task:".into(),
        excluded: BTreeSet::new(),
        rule: rule.clone(),
        scope: scope.clone(),
    };
    let package = Package {
        format: VERSION.into(),
        name: request.target_id.clone(),
        version: 1,
        source: Source {
            location: "Operator-selected host task enrolment".into(),
            version: "1".into(),
        },
        operations: BTreeMap::from([("task:inspect".into(), operation)]),
        semantics: None,
    };
    let key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).map_err(failure)?;
    let key = Ed25519KeyPair::from_pkcs8(key.as_ref()).map_err(failure)?;
    let active = SignedCatalogue::sign(
        CatalogueRevision {
            publisher: "target-bootstrap".into(),
            announcement_revision: 1,
            package: package.clone(),
            observed_at: request.not_before,
            expires_at: request.expires_at,
            withdrawn: false,
            previous: None,
        },
        &key,
    );
    let public_keys = BTreeMap::from([(request.key_id.clone(), request.public_key.clone())]);
    let catalogue = CatalogueAdoption {
        policy: CataloguePolicy {
            publisher: "target-bootstrap".into(),
            public_key: STANDARD.encode(key.public_key().as_ref()),
            agent_code_keys: BTreeMap::from([(request.issuer_id.clone(), public_keys.clone())]),
            package_name: package.name.clone(),
            operations: BTreeMap::from([("task:inspect".into(), rule)]),
            families: vec![family.clone()],
            on_withdraw: Withdrawal::Retain,
        },
        active: active.clone(),
        previous: None,
        observed: active,
        pin: None,
        observed_file: None,
    };
    let verbs = [
        Verb::Discover,
        Verb::Propose,
        Verb::Invoke,
        Verb::Job,
        Verb::Output,
        Verb::File,
        Verb::Cancel,
        Verb::Adopt,
        Verb::Adoption,
    ]
    .into();
    let grants = BTreeMap::from([(
        "task".into(),
        Grant {
            principal: request.principal.clone(),
            allow_run_refresh: request.plan.allow_run_refresh,
            not_before: request.not_before,
            expires_at: request.expires_at,
            verbs,
            operations: BTreeMap::from([("task:inspect".into(), scope.clone())]),
            families: vec![family.clone()],
        },
    )]);
    let trust = IssuerTrust {
        revision: revision(&public_keys),
        public_keys,
        authority: IssuerAuthority {
            revision: revision(&grants),
            assessment_revision: revision(&request.plan.intent),
            observed_at: request.not_before,
            valid_until: request.expires_at,
            grants,
        },
    };
    let plan = catalogue.plan(now())?;
    let target = Target {
        target_id: request.target_id.clone(),
        ceiling_revision: "1".into(),
        allowed_verbs: grants_verbs(&trust),
        max_authority_age_seconds: request.expires_at - request.not_before,
        issuers: BTreeMap::from([(request.issuer_id.clone(), trust)]),
        ceiling: BTreeMap::from([("task:inspect".into(), scope)]),
        package,
        families: vec![family],
        catalogue: Some(plan.status),
    };
    if !directory.join("target.pem").exists() && !directory.join("target-key.pem").exists() {
        crate::https::create(hostname, directory)?;
    }
    #[cfg(target_os = "linux")]
    let native = {
        let bubblewrap = fs::canonicalize("/usr/bin/bwrap").map_err(failure)?;
        let current = fs::read_to_string("/proc/self/cgroup").map_err(failure)?;
        let current = current
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| failure("a delegated cgroup v2 scope is required"))?;
        let cgroup = Path::new("/sys/fs/cgroup")
            .join(current.trim_start_matches('/'))
            .join(&request.target_id);
        if !cgroup.exists() {
            fs::create_dir(&cgroup).map_err(|error|failure(format!("create selected delegated task cgroup: {error}; run the bootstrap in an operator-delegated memory/pids scope")))?;
        }
        NativeRuntime::Linux(crate::linux::LinuxRuntime {
            bubblewrap_sha256: crate::workflow::hash(&bubblewrap)?,
            bubblewrap,
            cgroup,
            executable_bytes: request.plan.executable_bytes,
        })
    };
    #[cfg(target_os = "macos")]
    let native = NativeRuntime::Macos(crate::macos::MacRuntime {
        executable_bytes: request.plan.executable_bytes,
    });
    let configuration = directory.join("target.json");
    let settings = crate::server::Configuration {
        target: target.clone(),
        ledger: LedgerLimits {
            jobs: 128,
            mutation_records: 512,
            output_bytes: 16 * 1024 * 1024,
            database_bytes: 64 * 1024 * 1024,
            request_bytes: 1024 * 1024,
        },
        native,
        connections: 4,
        connection_timeout_seconds: 30,
        catalogue: Some(catalogue.clone()),
        https: Some(crate::https::Listener {
            listen,
            certificate: directory.join("target.pem"),
            private_key: directory.join("target-key.pem"),
        }),
    };
    crate::https::private_file(
        &configuration,
        &serde_json::to_vec_pretty(&settings).map_err(failure)?,
    )?;
    crate::server::load(&configuration, &state)?;
    finish(request, directory, hostname, listen, &settings, state)
}

#[cfg(unix)]
fn finish(
    request: EnrolmentRequest,
    directory: &Path,
    hostname: &str,
    listen: std::net::SocketAddr,
    settings: &crate::server::Configuration,
    state: PathBuf,
) -> Result<Enrolment, Refusal> {
    let account = settings
        .target
        .package
        .operations
        .get("task:inspect")
        .ok_or_else(|| failure("initial task operation unavailable"))?
        .execution
        .identity
        .clone();
    let result = Enrolment {
        request,
        target: settings.target.clone(),
        catalogue: settings
            .catalogue
            .clone()
            .ok_or_else(|| failure("initial catalogue unavailable"))?,
        hostname: hostname.into(),
        port: listen.port(),
        certificate_pem: fs::read_to_string(directory.join("target.pem")).map_err(failure)?,
        account,
        configuration: directory.join("target.json"),
        state,
        qualified: true,
    };
    result.validate()?;
    crate::https::private_file(
        &directory.join("enrolment.json"),
        &serde_json::to_vec_pretty(&result).map_err(failure)?,
    )?;
    Ok(result)
}

#[cfg(unix)]
fn grants_verbs(trust: &IssuerTrust) -> BTreeSet<Verb> {
    trust.authority.grants["task"].verbs.clone()
}

#[cfg(unix)]
pub(crate) fn command(args: &[String]) -> Result<bool, Refusal> {
    if args.first().is_none_or(|command| command != "enrol") {
        return Ok(false);
    }
    require(
        (args.len() == 5 || args.len() == 6 && args[5] == "--serve")
            && args[1] == "--request-base64"
            && args[3] == "--directory",
        RefusalCode::Arguments,
        "enrol --request-base64 PREPARED_PUBLIC_REQUEST --directory PRIVATE_CONTROL_DIRECTORY [--serve]",
    )?;
    let request: EnrolmentRequest =
        serde_json::from_slice(&STANDARD.decode(&args[2]).map_err(failure)?).map_err(failure)?;
    let directory = Path::new(&args[4]);
    let result = prepare(
        request.clone(),
        directory,
        &request.plan.hostname,
        request.plan.control_listen,
    )?;
    println!("{}", serde_json::to_string(&result).map_err(failure)?);
    if args.len() == 6 {
        crate::server::command(vec![
            "serve".into(),
            "--config".into(),
            result.configuration.to_string_lossy().into_owned(),
            "--state".into(),
            result.state.to_string_lossy().into_owned(),
        ])?;
    }
    Ok(true)
}

fn task_operation(
    request: &EnrolmentRequest,
    identity: &ExecutionIdentity,
    shell: &str,
    shell_hash: &str,
) -> Result<Operation, Refusal> {
    serde_json::from_value(serde_json::json!({
        "description":"Untrusted task code within the operator-selected native boundary.",
        "resources":["task:workspace"],"arguments":{},
        "execution":{"broader":request.plan.broader,"executable":shell,"executable_sha256":shell_hash,
            "dependencies":{},"argv":[{"kind":"literal","value":"-c"},{"kind":"literal","value":"pwd"}],
            "environment":{},"working_directory":request.plan.root,"identity":identity,
            "filesystem":{"read":request.plan.read_paths,"write":[request.plan.root]},"network":request.plan.network,
            "resources":request.plan.execution_limits,"delegated_services":[]},
        "effects":{"task_code":{"description":"Arbitrary code can read the selected files, change the workspace, create permitted child processes and use the represented network authority. Written files and disclosures can persist after authority ends.","persists_after_access":true,"evidence":["package"]}},
        "enforcement":{"enforced":["The native target qualifies and enforces the represented bounds before execution."],
            "adopted":["Code is untrusted. Explicit broader modes and the target account's ambient exposure remain part of the selected authority."],"unresolved":[]},"required_checks":[]
    })).map_err(failure)
}
