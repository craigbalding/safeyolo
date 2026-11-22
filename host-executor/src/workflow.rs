//! Package preparation uses the existing target configuration. It creates no
//! policy database, live authority or target-side dependency installer.
use crate::{server::Configuration, *};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
};

fn failure(error: impl std::fmt::Display) -> Refusal {
    native::unavailable(error)
}
fn read<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Refusal> {
    serde_json::from_reader(fs::File::open(path).map_err(failure)?).map_err(failure)
}
fn hash(path: &Path) -> Result<String, Refusal> {
    let mut file = fs::File::open(path).map_err(failure)?;
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(failure)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
fn save(path: &str, value: &impl serde::Serialize) -> Result<(), Refusal> {
    crate::https::private_file(
        Path::new(path),
        &serde_json::to_vec_pretty(value).map_err(failure)?,
    )
}
fn private_directory(path: &Path) -> Result<(), Refusal> {
    #[cfg(unix)]
    server::protected(path, true)?;
    #[cfg(windows)]
    crate::windows::security::protected(path, true)?;
    Ok(())
}

fn identity(credential: Option<&str>) -> Result<ExecutionIdentity, Refusal> {
    #[cfg(windows)]
    {
        let credential = credential.ok_or_else(|| {
            failure("Windows starter needs the configured workload credential name")
        })?;
        crate::windows::security::identity(&crate::windows::security::workload(credential)?)
    }
    #[cfg(unix)]
    {
        let _ = credential;
        // SAFETY: getgroups receives the buffer length from its size query.
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if count < 0 {
            return Err(failure(std::io::Error::last_os_error()));
        }
        let mut groups = vec![0; count as usize];
        let count = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
        if count < 0 {
            return Err(failure(std::io::Error::last_os_error()));
        }
        groups.truncate(count as usize);
        groups.sort_unstable();
        groups.dedup();
        Ok(ExecutionIdentity {
            principal: unsafe { libc::geteuid() }.to_string(),
            groups: groups.iter().map(ToString::to_string).collect(),
        })
    }
}

struct Starter {
    root: PathBuf,
    service: String,
    credential: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeSelection {
    resources: BTreeSet<String>,
    arguments: BTreeMap<String, Vec<Value>>,
    budgets: Budgets,
    #[serde(default)]
    checks: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerPreparation {
    issuer_id: String,
    key_id: String,
    public_key_file: PathBuf,
    grant_id: String,
    principal: Principal,
    operations: PathBuf,
    verbs: BTreeSet<Verb>,
    not_before: u64,
    expires_at: u64,
    authority_valid_until: u64,
    assessment_revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preparation {
    target_id: String,
    package: PathBuf,
    native: NativeRuntime,
    ledger: LedgerLimits,
    connections: u16,
    connection_timeout_seconds: u64,
    max_authority_age_seconds: u64,
    allowed_verbs: BTreeSet<Verb>,
    issuers: PathBuf,
    ceiling: PathBuf,
    https: Option<crate::https::Listener>,
}

#[cfg(any(windows, test))]
fn windows_starter_package(settings: &Starter) -> Result<Package, Refusal> {
    let mut document: Value =
        serde_json::from_str(include_str!("../examples/windows-starter.json")).map_err(failure)?;
    fn replace(value: &mut Value, settings: &Starter) {
        match value {
            Value::String(text) if text == "Demo" || text == "demo" => {
                *text = settings.service.clone()
            }
            Value::String(text)
                if text
                    .get(.."C:\\SafeYolo\\Demo".len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("C:\\SafeYolo\\Demo")) =>
            {
                let root = settings.root.to_string_lossy();
                let root = if text.starts_with("C:\\SafeYolo\\Demo") {
                    root.into_owned()
                } else {
                    root.to_ascii_lowercase()
                };
                *text = format!("{root}{}", &text["C:\\SafeYolo\\Demo".len()..]);
            }
            Value::Array(values) => values.iter_mut().for_each(|v| replace(v, settings)),
            Value::Object(values) => values.values_mut().for_each(|v| replace(v, settings)),
            _ => (),
        }
    }
    replace(&mut document, settings);
    serde_json::from_value(document).map_err(failure)
}

#[cfg(windows)]
fn starter(settings: &Starter, identity: ExecutionIdentity) -> Result<Package, Refusal> {
    let mut package = windows_starter_package(settings)?;
    let system =
        std::env::var_os("SystemRoot").ok_or_else(|| failure("SystemRoot is unavailable"))?;
    let system = Path::new(&system).join("System32");
    for operation in package.operations.values_mut() {
        let e = &mut operation.execution;
        e.identity = identity.clone();
        e.executable = if e.executable.ends_with("whoami.exe") {
            system.join("whoami.exe")
        } else {
            system.join("WindowsPowerShell/v1.0/powershell.exe")
        }
        .to_string_lossy()
        .into_owned();
        e.executable_sha256 = hash(Path::new(&e.executable))?;
        e.working_directory = settings.root.to_string_lossy().into_owned();
        e.environment.insert(
            "SystemRoot".into(),
            Word::Literal {
                value: Path::new(&system)
                    .parent()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            },
        );
    }
    // The generated package is bound to the selected target; the source file
    // remains the authoring example. Pinning does not qualify ambient modules.
    package.semantics.as_mut().unwrap().gaps = vec![
        "Executable hashes and workload identity were observed during preparation. Inbox modules, object ACLs, service definitions and dependencies still require target review and native qualification.".into(),
        "Windows Job Objects enforce process lifetime and resource bounds. The adopted workload account retains its separately declared filesystem, registry, network/IPC and service permissions.".into(),
    ];
    add_inspection(&mut package, settings, identity)?;
    Ok(package)
}

#[cfg(unix)]
fn starter(settings: &Starter, identity: ExecutionIdentity) -> Result<Package, Refusal> {
    let mut package = Package {
        format: VERSION.into(),
        name: "host-starter".into(),
        version: 1,
        source: Source {
            location: "SafeYolo packaged starter; hostctl fixed-command examples".into(),
            version: "1".into(),
        },
        operations: BTreeMap::new(),
        semantics: None,
    };
    add_inspection(&mut package, settings, identity.clone())?;
    for action in ["status", "start", "stop", "restart"] {
        let mut operation = package.operations["bundle-metadata"].clone();
        operation.arguments.clear();
        let e = &mut operation.execution;
        #[cfg(target_os = "linux")]
        {
            let socket = format!("/run/user/{}/systemd/private", identity.principal);
            e.executable = "/usr/bin/systemctl".into();
            let mut argv = vec!["--user", "--no-pager", "--no-ask-password"];
            if action == "status" {
                argv.extend(["show", "--property=ActiveState", "--property=MainPID"]);
            } else {
                argv.push(action);
            }
            argv.extend(["--", &settings.service]);
            e.argv = argv
                .into_iter()
                .map(|value| Word::Literal {
                    value: value.into(),
                })
                .collect();
            e.environment = BTreeMap::from([
                (
                    "XDG_RUNTIME_DIR".into(),
                    Word::Literal {
                        value: format!("/run/user/{}", identity.principal),
                    },
                ),
                (
                    "SYSTEMD_OFFLINE".into(),
                    Word::Literal { value: "0".into() },
                ),
            ]);
            e.network.ipc = vec![IpcEndpoint::UnixSocket { path: socket }];
            e.broader = [
                BroaderBound::DelegatedServices,
                BroaderBound::ProcessVisibility,
            ]
            .into();
            e.delegated_services = vec![DelegatedService {
                service: "systemd-user".into(),
                capability: action.into(),
                resources: vec![settings.service.clone()],
            }];
        }
        #[cfg(target_os = "macos")]
        {
            e.executable = "/bin/launchctl".into();
            // launchd's restart throttle can outlast the inspection deadline.
            // The issuer grant and local ceiling still select the actual bound.
            if matches!(action, "start" | "restart") {
                e.resources.timeout_seconds = 30;
            }
            let command: Vec<&str> = match action {
                "status" => vec!["print", &settings.service],
                "start" => vec!["kickstart", &settings.service],
                "stop" => vec!["kill", "SIGTERM", &settings.service],
                _ => vec!["kickstart", "-k", &settings.service],
            };
            e.argv = command
                .into_iter()
                .map(|value| Word::Literal {
                    value: value.into(),
                })
                .collect();
            e.environment.clear();
            e.broader
                .extend([BroaderBound::NetworkIpc, BroaderBound::DelegatedServices]);
            e.delegated_services = vec![DelegatedService {
                service: "launchd-user".into(),
                capability: action.into(),
                resources: vec![settings.service.clone()],
            }];
        }
        e.executable_sha256 = hash(Path::new(&e.executable))?;
        e.working_directory = "/".into();
        operation.resources = ["service:demo".into()].into();
        operation.description = format!(
            "{action} the fixed {} service. Service definitions, accounts, executable/configuration changes and dependent service effects remain separately governed. Native service stdout is retained inside the structured receipt.",
            settings.service
        );
        let effects: &[&str] = match action {
            "status" => &["disclosure"],
            "start" => &["service_start", "execute"],
            "stop" => &["service_stop"],
            _ => &["service_stop", "service_start", "execute"],
        };
        operation.effects = effects
            .iter()
            .map(|name| {
                let effect = if *name == "disclosure" {
                    package.operations["bundle-metadata"].effects["disclosure"].clone()
                } else {
                    NamedEffect {
                        description: match *name {
                            "service_start" => "Can start the selected fixed service.",
                            "service_stop" => "Can stop or signal the selected fixed service; configured restart and dependent effects remain separately governed.",
                            _ => "Can execute the service's current configured program with its service-account authority. Service code, configuration and dependencies are not pinned by the helper hash.",
                        }.into(),
                        persists_after_access: true,
                        evidence: vec!["package".into()],
                    }
                };
                ((*name).into(), effect)
            })
            .collect();
        operation.enforcement.unresolved.push("Service effects and service processes outlive the helper and its process bounds. macOS stop signals the existing service; launchd KeepAlive can restart it. Disabling or changing the definition is separate authority.".into());
        package
            .operations
            .insert(format!("service-{action}"), operation);
    }
    package.semantics = Some(HostSemantics {
        sources: BTreeMap::new(),
        resources: ["service", "evidence"]
            .into_iter()
            .map(|name| (name.into(), crate::effects::Resource {
                description: format!("Selected target {name}"),
                identity: vec!["target".into(), "id".into()],
            }))
            .collect(),
        rules: BTreeMap::new(),
        alternatives: BTreeMap::new(),
        gaps: vec!["Only these packaged fixed recipes are characterized. Ambient service/dependency changes and missing historical evidence remain unobserved. No model inference or execution permission follows from these annotations.".into()],
    });
    for (name, operation) in &mut package.operations {
        let resource = if name.starts_with("service-") {
            "service"
        } else {
            "evidence"
        };
        let id = if resource == "service" {
            HostIdentity::Fixed {
                value: settings.service.clone(),
            }
        } else {
            HostIdentity::Resource {
                aliases: BTreeMap::new(),
            }
        };
        operation.semantics = Some(HostOperationSemantics {
            resources: BTreeMap::from([(
                resource.into(),
                BTreeMap::from([("target".into(), HostIdentity::Target), ("id".into(), id)]),
            )]),
            effects: operation
                .effects
                .keys()
                .map(|effect| crate::effects::EffectUse {
                    effect: effect.clone(),
                    resource: resource.into(),
                    when: crate::effects::Condition::Always,
                    evidence: vec!["package".into()],
                })
                .collect(),
            prerequisites: operation.enforcement.adopted.clone(),
            limitations: operation.enforcement.unresolved.clone(),
            evidence: vec!["package".into()],
        });
    }
    Ok(package)
}

fn add_inspection(
    package: &mut Package,
    settings: &Starter,
    identity: ExecutionIdentity,
) -> Result<(), Refusal> {
    let executable = std::env::current_exe()
        .map_err(failure)?
        .canonicalize()
        .map_err(failure)?;
    let disclosure = package
        .operations
        .values()
        .find_map(|operation| operation.effects.get("disclosure"))
        .cloned()
        .unwrap_or_else(|| NamedEffect {
            description:
                "Disclose selected target observations into the agent sandbox for analysis.".into(),
            persists_after_access: true,
            evidence: vec!["package".into()],
        });
    for (name, directory, mode) in [
        ("bundle-metadata", "relocated", "directory"),
        ("application-log", "logs/application.jsonl", "content"),
        ("system-log", "logs/system.jsonl", "content"),
        ("snapshot-list", "snapshots", "directory"),
    ] {
        let path = settings.root.join(directory);
        let mut read: Vec<String> = if cfg!(target_os = "macos") {
            vec![
                "/usr/lib",
                "/System/Library",
                "/Library/Apple/System/Library",
            ]
        } else if cfg!(unix) {
            vec!["/usr", "/lib", "/lib64"]
        } else {
            Vec::new()
        }
        .into_iter()
        .filter(|p| Path::new(p).exists())
        .map(String::from)
        .collect();
        read.push(settings.root.to_string_lossy().into_owned());
        let broader = if cfg!(windows) {
            [
                BroaderBound::Filesystem,
                BroaderBound::Registry,
                BroaderBound::NetworkIpc,
                BroaderBound::DelegatedServices,
            ]
            .into()
        } else if cfg!(target_os = "macos") {
            [BroaderBound::Memory, BroaderBound::ExecutorRestart].into()
        } else {
            BTreeSet::new()
        };
        let operation = Operation {
            description: format!("Read bounded {name} evidence from the selected root. JSON retains observation time, byte/count bounds and completeness. No earlier snapshot/log availability or original cause is inferred."),
            resources: [format!("evidence:{name}")].into(),
            arguments: BTreeMap::from([("limit".into(), Argument { kind: ArgumentType::Integer, required: false, default: Some(json!(if mode == "content" {32768} else {50})), options: Vec::new() })]),
            execution: Execution { broader, executable: executable.to_string_lossy().into_owned(), executable_sha256: hash(&executable)?, dependencies: BTreeMap::new(),
                argv: vec![Word::Literal { value: "inspect".into() }, Word::Literal { value: "--root".into() }, Word::Literal { value: path.to_string_lossy().into_owned() },
                    Word::Literal { value: "--kind".into() }, Word::Literal { value: mode.into() }, Word::Literal { value: "--limit".into() }, Word::Argument { name: "limit".into() }],
                environment: BTreeMap::new(), working_directory: settings.root.to_string_lossy().into_owned(), identity: identity.clone(),
                filesystem: Filesystem { read, write: Vec::new() }, network: Network { destinations: Vec::new(), ipc: Vec::new() },
                resources: ExecutionLimits { timeout_seconds: 10, output_bytes: 65536, memory_bytes: 268435456, processes: 1 }, delegated_services: Vec::new() },
            effects: BTreeMap::from([("disclosure".into(), disclosure.clone())]),
            enforcement: Enforcement { enforced: vec!["Typed inputs, exact executable identity, finite native resource and output bounds.".into()],
                adopted: vec!["Operator-selected root, workload account, platform dependencies and explicitly broader permissions.".into()],
                unresolved: vec!["Absent historical evidence remains a gap. A current observation or reinstall does not establish an earlier cause.".into()] },
            semantics: None, required_checks: BTreeSet::new(),
        };
        package.operations.insert(name.into(), operation);
    }
    Ok(())
}

fn inspect(root: &Path, kind: &str, limit: usize) -> Result<Value, Refusal> {
    require(
        limit > 0,
        RefusalCode::Budget,
        "inspection limit must be positive",
    )?;
    let path = root.canonicalize().map_err(failure)?;
    // Windows canonicalize returns an extended-length path for ordinary drive
    // paths. Keep the supported local spellings and report the resolved source.
    #[cfg(windows)]
    crate::windows::security::absolute_local(root)?;
    #[cfg(unix)]
    require(
        root.is_absolute() && *root == path,
        RefusalCode::Arguments,
        "inspection root must be canonical and absolute",
    )?;
    let mut partial = false;
    let data = match kind {
        "directory" => {
            let mut entries = Vec::new();
            for entry in fs::read_dir(&path)
                .map_err(failure)?
                .take(limit.saturating_add(1))
            {
                let entry = entry.map_err(failure)?;
                if entries.len() == limit {
                    partial = true;
                    break;
                }
                let metadata = fs::symlink_metadata(entry.path()).map_err(failure)?;
                entries.push(json!({"name":entry.file_name().to_string_lossy(),"bytes":metadata.len(),"directory":metadata.is_dir(),
                    "symlink":metadata.file_type().is_symlink(),"modified_unix_seconds":metadata.modified().ok().and_then(|t|t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d|d.as_secs())}));
            }
            json!(entries)
        }
        "content" => {
            let mut bytes = Vec::new();
            fs::File::open(&path)
                .map_err(failure)?
                .take(limit.saturating_add(1) as u64)
                .read_to_end(&mut bytes)
                .map_err(failure)?;
            partial = bytes.len() > limit;
            bytes.truncate(limit);
            json!({"encoding":"base64","bytes":STANDARD.encode(bytes)})
        }
        _ => return Err(failure("inspection kind must be directory or content")),
    };
    Ok(
        json!({"source":path,"observed_at_unix_seconds":now(),"time_zone":"UTC","limit":limit,
        "limit_unit":if kind=="content"{"bytes"}else{"entries"},"complete":!partial,"status":if partial{"partial"}else{"ok"},"data":data}),
    )
}

pub(crate) fn command(args: &[String]) -> Result<bool, Refusal> {
    match args {
        [command, a, package, b, selection, c, output]
            if command == "scopes" && a == "--package" && b == "--selection" && c == "--output" =>
        {
            let package: Package = read(package)?;
            package.validate().map_err(failure)?;
            let selections: BTreeMap<String, ScopeSelection> = read(selection)?;
            let mut scopes = BTreeMap::new();
            for (id, selected) in selections {
                let operation = package
                    .operations
                    .get(&id)
                    .ok_or_else(|| failure(format!("operation {id} is absent")))?;
                require(
                    !selected.resources.is_empty()
                        && selected.resources.is_subset(&operation.resources),
                    RefusalCode::Selector,
                    "scope resources must belong to the selected operation",
                )?;
                for (name, values) in &selected.arguments {
                    let argument = operation
                        .arguments
                        .get(name)
                        .ok_or_else(|| failure(format!("unknown argument {name}")))?;
                    require(
                        !values.is_empty() && values.iter().all(|v| argument.accepts(v)),
                        RefusalCode::Arguments,
                        "scope needs complete typed argument choices",
                    )?;
                }
                scopes.insert(
                    id,
                    OperationScope {
                        implementation_sha256: operation.implementation_sha256(),
                        resources: selected.resources,
                        arguments: selected.arguments,
                        budgets: selected.budgets,
                        checks: selected.checks,
                        updates: None,
                    },
                );
            }
            save(output, &scopes)?;
            println!(
                "{}",
                json!({"scopes":output,"permission_granted":false,"next_action":"Review the complete scopes, then select them explicitly as issuer grant and target ceiling inputs."})
            );
        }
        [command] if command == "identity" => {
            println!(
                "{}",
                serde_json::to_string(&identity(None)?).map_err(failure)?
            );
        }
        [command, flag, directory] if command == "key-create" && flag == "--directory" => {
            let directory = Path::new(directory);
            private_directory(directory)?;
            let key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .map_err(failure)?;
            let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).map_err(failure)?;
            let private = zeroize::Zeroizing::new(STANDARD.encode(key.as_ref()));
            crate::https::private_file(&directory.join("issuer-key.base64"), private.as_bytes())?;
            crate::https::private_file(
                &directory.join("issuer-public.base64"),
                STANDARD.encode(pair.public_key().as_ref()).as_bytes(),
            )?;
            println!(
                "{}",
                json!({"public_key":STANDARD.encode(pair.public_key().as_ref()),"private_key_file":directory.join("issuer-key.base64"),"permission_granted":false})
            );
        }
        [command, a, root, b, service, c, output, rest @ ..]
            if command == "starter" && a == "--root" && b == "--service" && c == "--output" =>
        {
            require(
                rest.is_empty() || rest.len() == 2 && rest[0] == "--credential",
                RefusalCode::Arguments,
                "starter --root ABSOLUTE_DIRECTORY --service FIXED_SERVICE --output NEW_PACKAGE_JSON [--credential WINDOWS_WORKLOAD_CREDENTIAL]",
            )?;
            let settings = Starter {
                root: root.into(),
                service: service.clone(),
                credential: rest.get(1).cloned(),
            };
            #[cfg(windows)]
            crate::windows::security::absolute_local(&settings.root)?;
            #[cfg(unix)]
            require(
                settings.root.is_absolute()
                    && settings.root.canonicalize().map_err(failure)? == settings.root,
                RefusalCode::Arguments,
                "starter root must be an existing canonical absolute directory",
            )?;
            require(
                fs::metadata(&settings.root).map_err(failure)?.is_dir(),
                RefusalCode::Arguments,
                "starter root must be an existing directory",
            )?;
            let package = starter(&settings, identity(settings.credential.as_deref())?)?;
            package.validate().map_err(failure)?;
            save(output, &package)?;
            println!(
                "{}",
                json!({"package":output,"package_sha256":revision(&package),"permission_granted":false,"native_qualified":false})
            );
        }
        [command, a, input, b, output]
            if command == "prepare-issuer" && a == "--settings" && b == "--output" =>
        {
            let plan: IssuerPreparation = read(input)?;
            let public_key = fs::read_to_string(plan.public_key_file)
                .map_err(failure)?
                .trim()
                .to_owned();
            require(
                selector(&plan.issuer_id)
                    && selector(&plan.key_id)
                    && selector(&plan.grant_id)
                    && STANDARD.decode(&public_key).map_err(failure)?.len() == 32,
                RefusalCode::Issuer,
                "issuer, key, grant and public key must have their native identities",
            )?;
            let operations =
                serde_json::from_reader(fs::File::open(plan.operations).map_err(failure)?)
                    .map_err(failure)?;
            let grant = Grant {
                principal: plan.principal,
                not_before: plan.not_before,
                expires_at: plan.expires_at,
                verbs: plan.verbs,
                operations,
                families: Vec::new(),
            };
            let observed_at = now();
            require(
                grant.expires_at > grant.not_before && plan.authority_valid_until > observed_at,
                RefusalCode::Expired,
                "grant and authority must have finite future validity",
            )?;
            let keys = BTreeMap::from([(plan.key_id, public_key)]);
            let grants = BTreeMap::from([(plan.grant_id, grant)]);
            let trust = IssuerTrust {
                revision: revision(&keys),
                public_keys: keys,
                authority: IssuerAuthority {
                    revision: revision(&grants),
                    assessment_revision: plan.assessment_revision,
                    observed_at,
                    valid_until: plan.authority_valid_until,
                    grants,
                },
            };
            save(output, &BTreeMap::from([(plan.issuer_id, trust)]))?;
            println!(
                "{}",
                json!({"issuer_configuration":output,"activated":false,"next_action":"Adopt this exact configuration through the target owner and the issuing instance policy owner."})
            );
        }
        [command, a, input, b, output]
            if command == "prepare" && a == "--settings" && b == "--output" =>
        {
            let plan: Preparation = read(input)?;
            let package: Package =
                serde_json::from_reader(fs::File::open(plan.package).map_err(failure)?)
                    .map_err(failure)?;
            let issuers = serde_json::from_reader(fs::File::open(plan.issuers).map_err(failure)?)
                .map_err(failure)?;
            let ceiling = serde_json::from_reader(fs::File::open(plan.ceiling).map_err(failure)?)
                .map_err(failure)?;
            let configuration = Configuration {
                target: Target {
                    target_id: plan.target_id,
                    package,
                    ceiling_revision: "1".into(),
                    allowed_verbs: plan.allowed_verbs,
                    max_authority_age_seconds: plan.max_authority_age_seconds,
                    issuers,
                    ceiling,
                    families: Vec::new(),
                    catalogue: None,
                },
                native: plan.native,
                ledger: plan.ledger,
                connections: plan.connections,
                connection_timeout_seconds: plan.connection_timeout_seconds,
                catalogue: None,
                https: plan.https,
            };
            configuration.target.validate().map_err(failure)?;
            configuration
                .ledger
                .validate(&configuration.target.target_id)?;
            save(output, &configuration)?;
            println!(
                "{}",
                json!({"configuration":output,"target":configuration.target.target_id,"saved":true,"activated":false,"native_qualified":false})
            );
        }
        [command, a, config, b, state]
            if command == "status" && a == "--config" && b == "--state" =>
        {
            let configuration: Configuration = read(config)?;
            let validation = server::load(Path::new(config), Path::new(state));
            println!(
                "{}",
                json!({"target":configuration.target.target_id,"desired_package_sha256":revision(&configuration.target.package),
                "catalogue":configuration.catalogue,"configuration_valid":validation.is_ok(),"validation_error":validation.err().map(|e|e.to_string()),
                "running_target_observed":false,"next_action":"Use authenticated discovery to observe active target revisions; status reads saved configuration and validates local inputs only."})
            );
        }
        [command, a, root, b, kind, c, limit]
            if command == "inspect" && a == "--root" && b == "--kind" && c == "--limit" =>
        {
            let result = inspect(Path::new(root), kind, limit.parse().map_err(failure)?)?;
            println!("{result}");
        }
        [command, flag, directory] if command == "demo" && flag == "--directory" => {
            let root = Path::new(directory);
            fs::create_dir(root).map_err(failure)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(failure)?;
            }
            for directory in ["relocated", "logs", "snapshots"] {
                fs::create_dir(root.join(directory)).map_err(failure)?;
            }
            crate::https::private_file(&root.join("relocated/DemoApp.txt"), b"Synthetic relocated application. Current presence does not establish the earlier disappearance cause.\n")?;
            crate::https::private_file(&root.join("logs/application.jsonl"), b"{\"time\":\"2026-11-01T10:00:00Z\",\"zone\":\"UTC\",\"source\":\"synthetic-application\",\"event\":\"application observed at relocated path\"}\n")?;
            crate::https::private_file(&root.join("logs/system.jsonl"), b"{\"time\":\"2026-11-01T10:01:00Z\",\"zone\":\"UTC\",\"source\":\"synthetic-system\",\"event\":\"no earlier removal record retained\"}\n")?;
            println!(
                "{}",
                json!({"synthetic_root":root,"snapshots":0,"limit":"No earlier snapshot or removal log was supplied. Do not infer an original cause or treat reinstall as proof."})
            );
        }
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_starter_includes_native_inspection_without_conflicting_effects() {
        let settings = Starter {
            root: std::env::current_dir().unwrap().canonicalize().unwrap(),
            service: "CaseService".into(),
            credential: None,
        };
        let mut package = windows_starter_package(&settings).unwrap();
        let identity = package.operations["service-status"]
            .execution
            .identity
            .clone();
        let disclosure = revision(&package.operations["service-status"].effects["disclosure"]);
        add_inspection(&mut package, &settings, identity).unwrap();
        package.validate().unwrap();
        assert_eq!(
            revision(&package.operations["bundle-metadata"].effects["disclosure"]),
            disclosure
        );
    }

    #[test]
    fn windows_starter_paths_follow_the_selected_root_as_data() {
        for root in [r"C:\SafeYolo\Case", r"D:\Cases\O'Brien $(whoami); café"] {
            let package = windows_starter_package(&Starter {
                root: root.into(),
                service: "CaseService".into(),
                credential: None,
            })
            .unwrap();
            package.validate().unwrap();
            let config = format!(r"{root}\config.json");
            for name in ["file-inspect", "file-hash"] {
                let operation = &package.operations[name];
                let paths = &operation.arguments["path"];
                assert_eq!(
                    paths.options,
                    vec![json!(config), json!(config.to_ascii_lowercase())]
                );
                assert_eq!(
                    operation.command(&BTreeMap::new()).unwrap().environment["SY_PATH"],
                    config
                );
                for path in &paths.options {
                    let command = operation
                        .command(&BTreeMap::from([("path".into(), path.clone())]))
                        .unwrap();
                    assert!(command.environment["SY_PATH"].eq_ignore_ascii_case(&config));
                    assert!(!command.argv.iter().any(|word| word.contains(root)));
                }
                assert!(
                    operation
                        .arguments(&BTreeMap::from([(
                            "path".into(),
                            json!(r"C:\SafeYolo\Demo\config.json")
                        )]))
                        .is_err()
                );
            }
            let directory = package.operations["directory-list"]
                .command(&BTreeMap::new())
                .unwrap();
            assert_eq!(directory.environment["SY_PATH"], root);
            for name in ["write-service-config", "transmit-data"] {
                let supplied = if name == "write-service-config" {
                    BTreeMap::from([("content".into(), json!("complete configuration"))])
                } else {
                    BTreeMap::new()
                };
                let command = package.operations[name].command(&supplied).unwrap();
                assert_eq!(command.environment["SY_PATH"], config);
                assert!(command.argv.last().unwrap().contains("$env:SY_PATH"));
                assert!(!command.argv.iter().any(|word| word.contains(root)));
            }
            assert_eq!(
                package.operations["service-status"]
                    .command(&BTreeMap::new())
                    .unwrap()
                    .environment["SY_SERVICE"],
                "CaseService"
            );
            let document = serde_json::to_value(&package).unwrap();
            assert_eq!(
                document["semantics"]["alternatives"]["file-metadata-before-content"]["steps"][0]["arguments"]
                    ["path"],
                config
            );
        }
    }

    #[test]
    fn bounded_observations_distinguish_complete_partial_and_missing_evidence() {
        let root = std::env::temp_dir().join(format!("workflow-{}-{}", std::process::id(), now()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("evidence"), b"longer evidence").unwrap();
        let selected = root.join("evidence").canonicalize().unwrap();
        let short = inspect(&selected, "content", 3).unwrap();
        assert_eq!(short["status"], "partial");
        assert_eq!(
            STANDARD
                .decode(short["data"]["bytes"].as_str().unwrap())
                .unwrap(),
            b"lon"
        );
        assert_eq!(
            inspect(&selected, "content", 100).unwrap()["complete"],
            true
        );
        assert!(inspect(&root.join("absent"), "directory", 50).is_err());
        assert_eq!(
            inspect(&root.canonicalize().unwrap(), "directory", 1).unwrap()["data"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }
}
