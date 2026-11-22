#![cfg(unix)]
//! Run explicitly on native Linux with an operator-owned cgroup v2 delegation.
//! The developer fixture compiles its C probe; installed executor operation
//! itself needs neither a compiler nor Python.
use base64::{Engine, engine::general_purpose::STANDARD};
mod common;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::Ed25519KeyPair,
};
#[cfg(target_os = "linux")]
use safeyolo_host_executor::linux::LinuxRuntime;
#[cfg(target_os = "macos")]
use safeyolo_host_executor::macos::MacRuntime;
use safeyolo_host_executor::{server::Configuration, *};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn hash(path: &Path) -> String {
    ring::digest::digest(&ring::digest::SHA256, &fs::read(path).unwrap())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Fixture {
    root: PathBuf,
    #[cfg(target_os = "linux")]
    cgroup: PathBuf,
    server: Child,
    ipc_listener: std::os::unix::net::UnixListener,
    network_listener: TcpListener,
    target: Target,
    key: Ed25519KeyPair,
    counter: u64,
}
impl Fixture {
    fn assert_no_side_effects(&self) {
        assert_eq!(
            fs::read(self.root.join("allowed")).unwrap(),
            b"read permitted"
        );
        assert_eq!(
            fs::read(self.root.join("forbidden")).unwrap(),
            b"read refused"
        );
        assert!(!self.root.join("forbidden.written").exists());
        // Check the receiver queues independently of the workload's output.
        // Then prove both receivers still work from the host. Each fixture
        // checks and drains these positive controls before any workload runs.
        self.network_listener.set_nonblocking(true).unwrap();
        self.ipc_listener.set_nonblocking(true).unwrap();
        assert_eq!(
            self.network_listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            self.ipc_listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let _tcp = TcpStream::connect(self.network_listener.local_addr().unwrap()).unwrap();
        let (_, peer) = accept_positive_connection(|| self.network_listener.accept());
        assert_eq!(peer, _tcp.local_addr().unwrap());
        let _ipc = UnixStream::connect(self.root.join("forbidden.socket")).unwrap();
        accept_positive_connection(|| self.ipc_listener.accept());
        eprintln!(
            "independent host observer: files unchanged, forbidden write absent, TCP/IPC queues empty, both live positive controls received"
        );
    }
    fn call_bytes(&self, verb: Verb, body: &[u8]) -> Response {
        let mut stream = UnixStream::connect(self.root.join("state/control.sock")).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(
            stream,
            "POST {} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            verb.path(),
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        serde_json::from_slice(&response[end..]).unwrap()
    }
    fn signed(&mut self, action: Action) -> Vec<u8> {
        self.counter += 1;
        let request = Request {
            version: VERSION.into(),
            required_features: FEATURES.iter().map(|s| s.to_string()).collect(),
            request_id: format!("request-{}", self.counter),
            target_id: self.target.target_id.clone(),
            issuer_id: "issuer".into(),
            grant_id: "grant".into(),
            principal: self.target.issuers["issuer"].authority.grants["grant"]
                .principal
                .clone(),
            expires_at: self.target.issuers["issuer"].authority.valid_until,
            expected: Some(
                self.target
                    .request_revisions("issuer", "grant", &action)
                    .unwrap(),
            ),
            action,
            untrusted_rationale: "fixture".into(),
        };
        serde_json::to_vec(&SignedRequest::sign(request, "key".into(), &self.key)).unwrap()
    }
    fn call(&mut self, action: Action) -> Response {
        let verb = action.verb();
        let bytes = self.signed(action);
        self.call_bytes(verb, &bytes)
    }
    fn invocation(&self, mode: &str) -> Invocation {
        let operation = &self.target.package.operations[mode];
        Invocation {
            operation_id: mode.into(),
            resource_id: "fixture".into(),
            operation_sha256: self.target.package.operation_sha256(mode).unwrap(),
            implementation_sha256: operation.implementation_sha256(),
            arguments: BTreeMap::new(),
            expected_assessment_sha256: None,
        }
    }
    fn invoke(&mut self, mode: &str) -> (Receipt, Vec<u8>) {
        let invocation = self.invocation(mode);
        let response = self.call(Action::Propose { invocation });
        let Response::Proposal { prepared } = response else {
            panic!("{mode} proposal refused: {response:?}")
        };
        let bytes = self.signed(Action::Invoke {
            invocation: prepared.invocation,
        });
        let response = self.call_bytes(Verb::Invoke, &bytes);
        let Response::Job { receipt } = response else {
            panic!("{mode} invoke refused: {response:?}")
        };
        (*receipt, bytes)
    }
    fn job(&mut self, id: &str) -> Receipt {
        let Response::Job { receipt } = self.call(Action::Job { job_id: id.into() }) else {
            panic!("job refused")
        };
        *receipt
    }
    fn terminal(&mut self, id: &str) -> Receipt {
        self.terminal_with_timeout(id, Duration::from_secs(15))
    }
    fn terminal_with_timeout(&mut self, id: &str, timeout: Duration) -> Receipt {
        let deadline = Instant::now() + timeout;
        loop {
            let receipt = self.job(id);
            if receipt.state.terminal() {
                return receipt;
            }
            assert!(Instant::now() < deadline, "job did not settle: {receipt:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn restart(&mut self) {
        self.server.kill().unwrap();
        self.server.wait().unwrap();
        self.server = start(&self.root);
    }
}

fn accept_positive_connection<T>(mut accept: impl FnMut() -> std::io::Result<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match accept() {
            Ok(connection) => return connection,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("host positive connection unavailable: {error}"),
        }
    }
}

#[test]
fn host_receiver_positive_control_waits_for_readiness() {
    let receiver = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    receiver.set_nonblocking(true).unwrap();
    assert_eq!(
        receiver.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let address = receiver.local_addr().unwrap();
    std::thread::scope(|scope| {
        let sender = scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap()
        });
        let (_, peer) = accept_positive_connection(|| receiver.accept());
        assert_eq!(peer, sender.join().unwrap().local_addr().unwrap());
    });
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
        #[cfg(target_os = "linux")]
        {
            if let Ok(children) = fs::read_dir(&self.cgroup) {
                for child in children.flatten() {
                    if child.file_type().is_ok_and(|t| t.is_dir()) {
                        let _ = fs::write(child.path().join("cgroup.kill"), b"1");
                        let _ = fs::remove_dir(child.path());
                    }
                }
            }
            let _ = fs::remove_dir(&self.cgroup);
        }
        // Keep reached diagnostics/configuration on failure for native review.
        if !std::thread::panicking() {
            let _ = fs::remove_dir_all(&self.root);
        } else {
            eprintln!("retained native fixture {}", self.root.display());
        }
    }
}

fn executor() -> PathBuf {
    std::env::var_os("SAFEYOLO_HOST_EXECUTOR_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_safeyolo-host-executor").into())
        .into()
}

fn start(root: &Path) -> Child {
    let child = Command::new(executor())
        .arg("serve")
        .arg("--config")
        .arg(root.join("target.json"))
        .arg("--state")
        .arg(root.join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(root.join("server.log"))
                .unwrap(),
        ))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(root.join("state/control.sock")).is_err() {
        assert!(
            Instant::now() < deadline,
            "server not ready: {}",
            fs::read_to_string(root.join("server.log")).unwrap()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child
}

fn fixture(jobs: u64, output_bytes: u64) -> Fixture {
    #[cfg(target_os = "linux")]
    let parent = PathBuf::from(
        std::env::var_os("SAFEYOLO_HOST_EXECUTOR_CGROUP")
            .expect("set a dedicated operator-delegated cgroup v2 subtree"),
    );
    let mut random = [0u8; 8];
    SystemRandom::new().fill(&mut random).unwrap();
    let name = format!("native-{}", u64::from_le_bytes(random));
    let root = std::env::temp_dir().join(&name);
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(root.join("state")).unwrap();
    fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o700)).unwrap();
    #[cfg(target_os = "linux")]
    let cgroup = {
        let path = parent.join(&name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(path.join("cgroup.subtree_control"), b"+memory +pids").unwrap();
        path
    };
    let probe = root.join("probe");
    if let Some(prebuilt) = std::env::var_os("SAFEYOLO_HOST_EXECUTOR_PROBE") {
        fs::copy(prebuilt, &probe).unwrap();
    } else {
        assert!(
            Command::new("cc")
                .args(["-O0", "-Wall", "-Wextra"])
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/native_fixture.c"))
                .arg("-o")
                .arg(&probe)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(root.join("allowed"), b"read permitted").unwrap();
    fs::write(root.join("forbidden"), b"read refused").unwrap();
    let ipc_listener =
        std::os::unix::net::UnixListener::bind(root.join("forbidden.socket")).unwrap();
    let network_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let identity = unsafe {
        let count = libc::getgroups(0, std::ptr::null_mut());
        assert!(count >= 0);
        let mut groups = vec![0; count as usize];
        assert_eq!(libc::getgroups(count, groups.as_mut_ptr()), count);
        ExecutionIdentity {
            principal: libc::geteuid().to_string(),
            groups: groups.iter().map(ToString::to_string).collect(),
        }
    };
    let key = Ed25519KeyPair::from_seed_unchecked(&[58; 32]).unwrap();
    let mut operations = BTreeMap::new();
    for mode in [
        "observe",
        "flood",
        "memory",
        "tasks",
        "background",
        "wait",
        "deadline",
    ] {
        let mut read: Vec<String> = if cfg!(target_os = "macos") {
            vec![
                "/usr/lib",
                "/System/Library",
                "/Library/Apple/System/Library",
            ]
        } else {
            vec!["/usr", "/lib", "/lib64"]
        }
        .iter()
        .filter(|p| Path::new(p).exists())
        .map(|s| s.to_string())
        .collect();
        read.push(root.join("allowed").to_str().unwrap().into());
        let operation = Operation {
            description: String::new(),
            semantics: None,
            required_checks: Default::default(),
            resources: ["fixture".into()].into(),
            arguments: BTreeMap::new(),
            execution: Execution {
                dependencies: Default::default(),
                broader: if cfg!(target_os = "macos") {
                    [BroaderBound::Memory, BroaderBound::ExecutorRestart].into()
                } else {
                    Default::default()
                },
                executable: probe.to_str().unwrap().into(),
                executable_sha256: hash(&probe),
                argv: [
                    if mode == "deadline" { "wait" } else { mode }.to_string(),
                    root.join("allowed").to_str().unwrap().into(),
                    root.join("forbidden").to_str().unwrap().into(),
                    network_listener.local_addr().unwrap().port().to_string(),
                ]
                .into_iter()
                .map(|value| Word::Literal { value })
                .collect(),
                environment: BTreeMap::from([(
                    "FIXTURE".into(),
                    Word::Literal {
                        value: "native".into(),
                    },
                )]),
                working_directory: "/".into(),
                identity: identity.clone(),
                filesystem: Filesystem {
                    read,
                    write: vec![],
                },
                network: Network {
                    destinations: vec![],
                    ipc: vec![],
                },
                resources: ExecutionLimits {
                    timeout_seconds: if mode == "deadline" { 1 } else { 5 },
                    output_bytes: 4096,
                    memory_bytes: 64 * 1024 * 1024,
                    processes: 12,
                },
                delegated_services: vec![],
            },
            effects: BTreeMap::new(),
            enforcement: Enforcement {
                enforced: vec![format!("{} native fixture", std::env::consts::OS)],
                adopted: vec!["host-owned runtime dependencies".into()],
                unresolved: vec![],
            },
        };
        operations.insert(mode.into(), operation);
    }
    if let Ok(resource) = std::env::var("SAFEYOLO_HOST_EXECUTOR_SERVICE") {
        for action in ["start", "stop", "restart", "status"] {
            let mut op = operations["observe"].clone();
            let e = &mut op.execution;
            e.executable = if cfg!(target_os = "linux") {
                "/usr/bin/systemctl"
            } else {
                "/bin/launchctl"
            }
            .into();
            e.executable_sha256 = hash(Path::new(&e.executable));
            e.environment.clear();
            e.argv = if cfg!(target_os = "linux") {
                e.broader = [
                    BroaderBound::DelegatedServices,
                    BroaderBound::ProcessVisibility,
                ]
                .into();
                e.environment.insert(
                    "XDG_RUNTIME_DIR".into(),
                    Word::Literal {
                        value: format!("/run/user/{}", e.identity.principal),
                    },
                );
                e.environment.insert(
                    "SYSTEMD_OFFLINE".into(),
                    Word::Literal { value: "0".into() },
                );
                e.network.ipc = vec![IpcEndpoint::UnixSocket {
                    path: format!("/run/user/{}/systemd/private", e.identity.principal),
                }];
                let mut argv = vec!["--user", "--no-pager", "--no-ask-password"];
                if action == "status" {
                    argv.extend(["show", "--property=ActiveState", "--property=MainPID"]);
                } else {
                    argv.push(action);
                }
                argv.extend(["--", &resource]);
                argv
            } else {
                if matches!(action, "start" | "restart") {
                    e.resources.timeout_seconds = 30;
                }
                e.broader
                    .extend([BroaderBound::NetworkIpc, BroaderBound::DelegatedServices]);
                match action {
                    "start" => vec!["kickstart", &resource],
                    "stop" => vec!["kill", "SIGTERM", &resource],
                    "restart" => vec!["kickstart", "-k", &resource],
                    _ => vec!["print", &resource],
                }
            }
            .into_iter()
            .map(|s| Word::Literal {
                value: s.to_owned(),
            })
            .collect();
            e.delegated_services = vec![DelegatedService {
                service: if cfg!(target_os = "linux") {
                    "systemd-user"
                } else {
                    "launchd-user"
                }
                .into(),
                capability: action.into(),
                resources: vec![resource.clone()],
            }];
            operations.insert(format!("service-{action}"), op);
        }
    }
    let target = common::target(name, operations, &key);
    #[cfg(target_os = "macos")]
    let target = {
        let mut target = target;
        for scopes in std::iter::once(&mut target.ceiling).chain(
            target.issuers.values_mut().flat_map(|issuer| {
                issuer
                    .authority
                    .grants
                    .values_mut()
                    .map(|grant| &mut grant.operations)
            }),
        ) {
            for id in ["service-start", "service-restart"] {
                if let Some(scope) = scopes.get_mut(id) {
                    scope.budgets.timeout_seconds = 30;
                }
            }
        }
        target
    };
    #[cfg(target_os = "linux")]
    let bubblewrap = PathBuf::from(
        std::env::var_os("SAFEYOLO_HOST_EXECUTOR_BWRAP").unwrap_or_else(|| "/usr/bin/bwrap".into()),
    );
    let settings = Configuration {
        https: None,
        catalogue: None,
        target: target.clone(),
        #[cfg(target_os = "linux")]
        native: NativeRuntime::Linux(LinuxRuntime {
            bubblewrap_sha256: hash(&bubblewrap),
            bubblewrap,
            cgroup: cgroup.clone(),
            executable_bytes: 32 * 1024 * 1024,
        }),
        #[cfg(target_os = "macos")]
        native: NativeRuntime::Macos(MacRuntime {
            executable_bytes: 32 * 1024 * 1024,
        }),
        ledger: LedgerLimits {
            jobs,
            mutation_records: 64,
            output_bytes,
            database_bytes: 8 * 1024 * 1024,
            request_bytes: 65536,
        },
        connections: 4,
        connection_timeout_seconds: 5,
    };
    fs::write(
        root.join("target.json"),
        serde_json::to_vec_pretty(&settings).unwrap(),
    )
    .unwrap();
    fs::set_permissions(root.join("target.json"), fs::Permissions::from_mode(0o600)).unwrap();
    let fixture = Fixture {
        server: start(&root),
        ipc_listener,
        network_listener,
        root,
        #[cfg(target_os = "linux")]
        cgroup,
        target,
        key,
        counter: 0,
    };
    fixture.assert_no_side_effects();
    fixture
}

#[test]
#[ignore = "requires the existing native Unix fixture and prepared probe or C compiler"]
fn installed_catalogue_adoption_persists_and_stale_preparation_cannot_launch() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ring::signature::KeyPair;
    let mut f = fixture(16, 64 * 1024);
    let path = f.root.join("target.json");
    let mut config: Configuration = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let rule = UpdateRule {
        ceiling: config.target.package.operations["observe"].clone(),
        allow_narrower: true,
        allow_implementation_updates: true,
    };
    config.target.ceiling.get_mut("observe").unwrap().updates = Some(rule.clone());
    config
        .target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant")
        .unwrap()
        .operations
        .get_mut("observe")
        .unwrap()
        .updates = Some(rule.clone());
    let sign = |package: &Package| {
        SignedCatalogue::sign(
            CatalogueRevision {
                publisher: "publisher".into(),
                announcement_revision: package.version * 2,
                package: package.clone(),
                observed_at: now() - 1,
                expires_at: now() + 600,
                withdrawn: false,
                previous: None,
            },
            &f.key,
        )
    };
    let active = sign(&config.target.package);
    let observed = f.root.join("observed.json");
    fs::write(&observed, serde_json::to_vec(&active).unwrap()).unwrap();
    config.catalogue = Some(CatalogueAdoption {
        policy: CataloguePolicy {
            publisher: "publisher".into(),
            public_key: STANDARD.encode(f.key.public_key().as_ref()),
            package_name: config.target.package.name.clone(),
            operations: BTreeMap::from([("observe".into(), rule)]),
            families: Vec::new(),
            on_withdraw: Withdrawal::Retain,
        },
        active: active.clone(),
        observed: active,
        previous: None,
        pin: None,
        observed_file: Some(ObservedCatalogueFile {
            path: observed.clone(),
            max_bytes: 1024 * 1024,
        }),
    });
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    f.target = config.target.clone();
    let Response::Proposal { prepared } = f.call(Action::Propose {
        invocation: f.invocation("observe"),
    }) else {
        panic!("original preparation")
    };
    let pending = f.signed(Action::Invoke {
        invocation: prepared.invocation,
    });
    let mut package = config.target.package.clone();
    package.version += 1;
    package
        .operations
        .get_mut("observe")
        .unwrap()
        .execution
        .resources
        .timeout_seconds = 4;
    let signed = SignedCatalogue::sign(
        CatalogueRevision {
            publisher: "publisher".into(),
            announcement_revision: package.version * 2,
            package: package.clone(),
            observed_at: now() - 1,
            expires_at: now() + 600,
            withdrawn: false,
            previous: None,
        },
        &f.key,
    );
    fs::write(&observed, serde_json::to_vec(&signed).unwrap()).unwrap();
    assert!(matches!(
        f.call_bytes(Verb::Invoke, &pending),
        Response::Refused {
            refusal: Refusal {
                code: RefusalCode::Stale,
                ..
            }
        }
    ));
    let saved: Configuration = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        revision(&saved.catalogue.as_ref().unwrap().active.catalogue.package),
        revision(&package)
    );
    assert_eq!(
        revision(
            &saved
                .catalogue
                .as_ref()
                .unwrap()
                .previous
                .as_ref()
                .unwrap()
                .catalogue
                .package
        ),
        revision(&config.target.package)
    );
    f.target = saved.target;
    let (receipt, _) = f.invoke("observe");
    assert_eq!(f.terminal(&receipt.job_id).state, JobState::Completed);
    // A signed, in-envelope candidate can fail actual native qualification.
    // Keep its verified announcement while retaining the usable active bytes.
    let mut unavailable = package.clone();
    unavailable
        .operations
        .get_mut("observe")
        .unwrap()
        .execution
        .executable_sha256 = "b".repeat(64);
    let signed = SignedCatalogue::sign(
        CatalogueRevision {
            publisher: "publisher".into(),
            announcement_revision: package.version * 2 + 1,
            package: unavailable,
            observed_at: now() - 1,
            expires_at: now() + 600,
            withdrawn: false,
            previous: None,
        },
        &f.key,
    );
    fs::write(&observed, serde_json::to_vec(&signed).unwrap()).unwrap();
    let Response::Discovery { discovery } = f.call(Action::Discover) else {
        panic!("failed qualification discovery")
    };
    let status = discovery.catalogue.unwrap();
    assert_eq!(status.state, "refused");
    assert_eq!(status.active, revision(&package));
    let saved: Configuration = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        saved
            .catalogue
            .as_ref()
            .unwrap()
            .observed
            .catalogue
            .announcement_revision,
        signed.catalogue.announcement_revision
    );
    let earlier = SignedCatalogue::sign(
        CatalogueRevision {
            announcement_revision: package.version * 2,
            package: package.clone(),
            ..signed.catalogue.clone()
        },
        &f.key,
    );
    fs::write(&observed, serde_json::to_vec(&earlier).unwrap()).unwrap();
    let Response::Discovery { discovery } = f.call(Action::Discover) else {
        panic!("older discovery after failed qualification")
    };
    let status = discovery.catalogue.unwrap();
    assert_eq!(status.state, "refused");
    assert!(status.reason.contains("older catalogue announcement"));
    assert_eq!(status.active, revision(&package));
    let mut unsupported = package.clone();
    unsupported
        .operations
        .get_mut("observe")
        .unwrap()
        .execution
        .identity
        .principal = "unapproved".into();
    let signed = SignedCatalogue::sign(
        CatalogueRevision {
            publisher: "publisher".into(),
            announcement_revision: package.version * 2 + 2,
            package: unsupported,
            observed_at: now() - 1,
            expires_at: now() + 600,
            withdrawn: false,
            previous: None,
        },
        &f.key,
    );
    fs::write(&observed, serde_json::to_vec(&signed).unwrap()).unwrap();
    let Response::Discovery { discovery } = f.call(Action::Discover) else {
        panic!("discovery")
    };
    let status = discovery.catalogue.unwrap();
    assert_eq!(status.state, "awaiting_review");
    assert_eq!(status.active, revision(&package));
    f.restart();
    let Response::Discovery { discovery } = f.call(Action::Discover) else {
        panic!("restart discovery")
    };
    assert_eq!(discovery.catalogue.unwrap().active, revision(&package));
    assert_eq!(f.job(&receipt.job_id).state, JobState::Completed);
}

#[test]
#[ignore = "requires the same installed native Unix fixture as the lifecycle test"]
fn installed_check_serve_and_reload_share_ledger_validation() {
    let mut f = fixture(16, 1024 * 1024);
    let config = f.root.join("target.json");
    let original = fs::read(&config).unwrap();
    let run = |mode: &str| {
        Command::new(executor())
            .args([mode, "--config"])
            .arg(&config)
            .arg("--state")
            .arg(f.root.join("state"))
            .output()
            .unwrap()
    };
    assert!(run("check").status.success());
    // fixture() has already observed native readiness for these valid limits.
    for (field, value) in [
        ("jobs", 0),
        ("mutation_records", 15),
        ("output_bytes", 0),
        ("output_bytes", i64::MAX as u64 + 1),
        ("database_bytes", 4096),
        ("database_bytes", i64::MAX as u64 + 1),
        ("request_bytes", 0),
    ] {
        let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
        changed["ledger"][field] = value.into();
        fs::write(&config, serde_json::to_vec(&changed).unwrap()).unwrap();
        let check = run("check");
        let serve = run("serve");
        assert_eq!(
            check.status.code(),
            Some(1),
            "check accepted {field}={value}"
        );
        assert_eq!(
            serve.status.code(),
            Some(1),
            "serve accepted {field}={value}"
        );
        assert_eq!(check.stderr, serve.stderr);
        assert!(String::from_utf8(check.stderr).unwrap().contains("Budget"));
        let limits: LedgerLimits = serde_json::from_value(changed["ledger"].clone()).unwrap();
        assert_eq!(
            Ledger::open(&f.root.join("state"), &f.target.target_id, limits)
                .err()
                .unwrap()
                .code,
            RefusalCode::Budget
        );
        // Every request reloads the complete configuration before admission.
        for verb in [
            Verb::Discover,
            Verb::Propose,
            Verb::Invoke,
            Verb::Job,
            Verb::Output,
            Verb::Cancel,
        ] {
            assert!(
                matches!(
                    f.call_bytes(verb, b"{}"),
                    Response::Refused {
                        refusal: Refusal {
                            code: RefusalCode::Budget,
                            ..
                        }
                    }
                ),
                "{verb:?} accepted {field}={value}"
            );
        }
    }
    fs::write(&config, original).unwrap();
    assert!(matches!(
        f.call(Action::Discover),
        Response::Discovery { .. }
    ));
}

#[test]
#[ignore = "requires native Unix host; prepared probe or C compiler; Linux also needs bubblewrap and delegated cgroup v2"]
fn installed_unix_read_paths_resolve_without_sibling_contents() {
    let mut f = fixture(16, 1024 * 1024);
    let (admitted, _) = f.invoke("observe");
    let result = f.terminal(&admitted.job_id);
    assert_eq!(result.state, JobState::Completed, "{result:?}");
    assert!(result.native.as_ref().unwrap().processes_stopped);
    let Response::Output { data_base64, .. } = f.call(Action::Output {
        job_id: result.job_id,
        offset: 0,
        max_bytes: 4096,
    }) else {
        panic!("native output unavailable");
    };
    let output = String::from_utf8(STANDARD.decode(data_base64).unwrap()).unwrap();
    assert!(output.contains("canonical=1"), "{output}");
    assert!(output.contains("allowed=1 forbidden=0 write=0"), "{output}");
    f.assert_no_side_effects();
}

#[test]
#[ignore = "requires native Unix host; prepared probe or C compiler; Linux also needs bubblewrap and delegated cgroup v2"]
fn installed_unix_bounds_lifecycle_reload_and_lost_reply() {
    let mut f = fixture(16, 1024 * 1024);
    for mode in [
        "observe",
        "background",
        "tasks",
        "flood",
        "memory",
        "deadline",
    ] {
        let (admitted, replay) = f.invoke(mode);
        let result = f.terminal(&admitted.job_id);
        eprintln!("{mode}: {}", serde_json::to_string(&result).unwrap());
        let native = result.native.as_ref().expect("native facts");
        assert!(native.processes_stopped);
        assert_eq!(
            result.state,
            if ["flood", "memory", "deadline"].contains(&mode) {
                JobState::Failed
            } else {
                JobState::Completed
            }
        );
        #[cfg(target_os = "linux")]
        assert!(!f.cgroup.join(&result.job_id).exists());
        if mode == "flood" {
            assert!(native.output_truncated);
            assert_eq!(result.output_bytes, 4096);
        }
        if mode == "deadline" {
            assert_eq!(native.termination_reason, "timeout");
        }
        let Response::Output {
            data_base64,
            retained_bytes,
            ..
        } = f.call(Action::Output {
            job_id: result.job_id.clone(),
            offset: 0,
            max_bytes: 4096,
        })
        else {
            panic!("output refused")
        };
        let output = STANDARD.decode(data_base64).unwrap();
        assert_eq!(output.len() as u64, retained_bytes);
        if mode == "observe" {
            let text = String::from_utf8(output).unwrap();
            let identity = &f.target.package.operations[mode].execution.identity;
            let groups = if cfg!(target_os = "linux") {
                let overflow = fs::read_to_string("/proc/sys/kernel/overflowgid")
                    .unwrap()
                    .trim()
                    .to_string();
                let primary = unsafe { libc::getegid() }.to_string();
                identity
                    .groups
                    .iter()
                    .map(|g| {
                        if *g == primary {
                            g.clone()
                        } else {
                            overflow.clone()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            } else {
                identity.groups.join(",")
            };
            assert!(text.contains(&format!(
                "uid={} gid={} groups={}",
                identity.principal,
                unsafe { libc::getegid() },
                groups
            )));
            assert!(text.contains(
                "allowed=1 forbidden=0 write=0 net=-1 ipc=-1 fixture=native home=absent"
            ));
        }
        assert!(matches!(
            f.call_bytes(Verb::Invoke, &replay),
            Response::Job { .. }
        ));
        assert_eq!(f.job(&result.job_id).revision, result.revision);
        f.assert_no_side_effects();
    }
    let (admitted, _) = f.invoke("wait");
    let deadline = Instant::now() + Duration::from_secs(5);
    let running = loop {
        let r = f.job(&admitted.job_id);
        if r.output_bytes > 0 {
            break r;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(matches!(
        f.call(Action::Cancel {
            job_id: running.job_id.clone(),
            expected_revision: running.revision
        }),
        Response::Job { .. }
    ));
    let cancelled = f.terminal(&running.job_id);
    assert_eq!(cancelled.state, JobState::Cancelled);
    assert!(cancelled.native.unwrap().processes_stopped);
    let (admitted, replay) = f.invoke("wait");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if f.job(&admitted.job_id).output_bytes > 0 {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    f.restart();
    let uncertain = f.job(&admitted.job_id);
    assert_eq!(uncertain.state, JobState::Uncertain);
    #[cfg(target_os = "linux")]
    assert!(uncertain.detail.contains("observed quiescence"));
    #[cfg(target_os = "macos")]
    {
        assert!(
            !uncertain.detail.contains("observed quiescence"),
            "restart cannot safely signal an orphan by PID"
        );
        // The synthetic probe has its own four-second alarm. Real operations
        // have no such guarantee: the executor must retain unknown cleanup.
        std::thread::sleep(Duration::from_secs(5));
        f.restart();
        assert!(
            f.job(&admitted.job_id)
                .detail
                .contains("observed quiescence")
        );
    }
    let uncertain = f.job(&admitted.job_id);
    assert!(matches!(
        f.call_bytes(Verb::Invoke, &replay),
        Response::Job { .. }
    ));
    assert_eq!(f.job(&admitted.job_id).revision, uncertain.revision);
    let config = f.root.join("target.json");
    let original = fs::read(&config).unwrap();
    for invalid in ["network", "ipc", "service", "write", "broader"] {
        let mut changed: Configuration = serde_json::from_slice(&original).unwrap();
        let execution = &mut changed
            .target
            .package
            .operations
            .get_mut("observe")
            .unwrap()
            .execution;
        match invalid {
            "broader" => {
                if cfg!(target_os = "macos") {
                    execution.broader.clear();
                } else {
                    execution.broader.insert(BroaderBound::Memory);
                }
            }
            "network" => execution.network.destinations.push(NetworkDestination {
                host: "example.com".into(),
                port: 443,
                transport: NetworkTransport::Tcp,
            }),
            "ipc" => execution.network.ipc.push(IpcEndpoint::UnixSocket {
                path: f.root.join("forbidden.socket").to_str().unwrap().into(),
            }),
            "service" => execution.delegated_services.push(DelegatedService {
                service: "service:fixture".into(),
                capability: "control".into(),
                resources: vec!["fixture".into()],
            }),
            "write" => execution
                .filesystem
                .write
                .push(f.root.to_str().unwrap().into()),
            _ => unreachable!(),
        }
        fs::write(&config, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            matches!(
                f.call(Action::Discover),
                Response::Refused {
                    refusal: Refusal {
                        code: RefusalCode::Unavailable,
                        ..
                    }
                }
            ),
            "unsupported {invalid} admitted by reload"
        );
        let check = Command::new(executor())
            .args(["check", "--config"])
            .arg(&config)
            .arg("--state")
            .arg(f.root.join("state"))
            .output()
            .unwrap();
        assert!(
            !check.status.success(),
            "unsupported {invalid} admitted by check"
        );
    }
    fs::write(&config, original).unwrap();
    assert!(matches!(
        f.call(Action::Discover),
        Response::Discovery { .. }
    ));
    assert!(!f.root.join("forbidden.written").exists());
    eprintln!(
        "native Unix installed bounds, output/memory/task controls, cancellation, restart/no-replay and complete-catalogue reload refusal observed"
    );
}

#[test]
#[ignore = "requires the same installed native Unix fixture as the lifecycle test"]
fn installed_storage_exhaustion_preserves_output_replay_and_restart() {
    // Exercise the real server and native dispatch. Both retained-output and
    // job-record limits must refuse a fresh effect while preserving old jobs.
    for (jobs, output_bytes) in [(16, 8192), (2, 1024 * 1024)] {
        let mut f = fixture(jobs, output_bytes);
        let mut completed = Vec::new();
        for _ in 0..2 {
            let (admitted, replay) = f.invoke("flood");
            let result = f.terminal(&admitted.job_id);
            assert_eq!(result.state, JobState::Failed);
            assert_eq!(result.output_bytes, 4096);
            assert!(result.native.as_ref().unwrap().processes_stopped);
            completed.push((result, replay));
        }
        f.restart();
        let invocation = f.invocation("observe");
        let Response::Proposal { prepared } = f.call(Action::Propose { invocation }) else {
            panic!("storage capacity must not disable proposal qualification")
        };
        let response = f.call(Action::Invoke {
            invocation: prepared.invocation,
        });
        assert!(
            matches!(
                response,
                Response::Refused {
                    refusal: Refusal {
                        code: RefusalCode::Budget,
                        ..
                    }
                }
            ),
            "{response:?}"
        );
        for (result, replay) in completed {
            let Response::Job { receipt } = f.call_bytes(Verb::Invoke, &replay) else {
                panic!("a retained invocation must remain replayable at capacity")
            };
            assert_eq!(receipt.job_id, result.job_id);
            // A mutation replay returns its original admission response. A
            // fresh job read supplies current completion facts at capacity.
            assert_eq!(receipt.state, JobState::Admitted);
            assert_eq!(f.job(&result.job_id).revision, result.revision);
            let Response::Output {
                data_base64,
                retained_bytes,
                ..
            } = f.call(Action::Output {
                job_id: result.job_id,
                offset: 0,
                max_bytes: 4096,
            })
            else {
                panic!("capacity must not hide retained output")
            };
            assert_eq!(retained_bytes, 4096);
            assert_eq!(STANDARD.decode(data_base64).unwrap().len(), 4096);
        }
        assert!(
            fs::metadata(f.root.join("state/jobs.sqlite"))
                .unwrap()
                .len()
                <= 8 * 1024 * 1024
        );
        eprintln!(
            "installed storage ceiling observed: jobs={jobs}, output_bytes={output_bytes}; retained output/replay preserved after restart"
        );
    }
}

#[test]
#[ignore = "requires SAFEYOLO_HOST_EXECUTOR_SERVICE naming an operator-prepared owned user service"]
fn installed_user_service_profiles_and_channel_refusals() {
    std::env::var("SAFEYOLO_HOST_EXECUTOR_SERVICE").expect("prepare an owned native user service");
    let mut f = fixture(8, 1024 * 1024);
    let mut previous_pid = None;
    let actions: &[&str] = &[
        "service-status",
        "service-stop",
        "service-start",
        "service-restart",
        "service-status",
    ];
    for &action in actions {
        let (admitted, _) = f.invoke(action);
        let result = f.terminal_with_timeout(&admitted.job_id, Duration::from_secs(40));
        eprintln!("{action}: {}", serde_json::to_string(&result).unwrap());
        let Response::Output { data_base64, .. } = f.call(Action::Output {
            job_id: result.job_id.clone(),
            offset: 0,
            max_bytes: 4096,
        }) else {
            panic!("service output must remain available")
        };
        let output = String::from_utf8(STANDARD.decode(data_base64).unwrap()).unwrap();
        eprintln!("service output: {output}");
        assert_eq!(result.state, JobState::Completed, "{result:?}");
        if action == "service-status" {
            let pid = output
                .lines()
                .find_map(|line| {
                    line.trim().strip_prefix(if cfg!(target_os = "macos") {
                        "pid = "
                    } else {
                        "MainPID="
                    })
                })
                .and_then(|rest| rest.split_whitespace().next())
                .expect("prepared service must have an observed PID")
                .to_owned();
            if let Some(prior) = previous_pid.replace(pid.clone()) {
                assert_ne!(
                    pid, prior,
                    "restart must replace the actual owned service process"
                );
            }
        }
        assert!(result.native.as_ref().unwrap().processes_stopped);
        assert!(
            result
                .native
                .as_ref()
                .unwrap()
                .dependencies
                .iter()
                .any(|s| s.contains("outside helper-process"))
        );
        let host_pid = observe_service(action != "service-stop");
        if action == "service-status" {
            assert_eq!(
                host_pid.map(|pid| pid.to_string()),
                previous_pid,
                "target status must match the independent host service manager"
            );
        }
    }
    let config = f.root.join("target.json");
    let original = fs::read(&config).unwrap();
    for invalid in ["program", "environment", "service", "broader"] {
        let mut changed: Configuration = serde_json::from_slice(&original).unwrap();
        let e = &mut changed
            .target
            .package
            .operations
            .get_mut("service-status")
            .unwrap()
            .execution;
        match invalid {
            "broader" => e.broader.clear(),
            "program" => {
                e.executable = f.root.join("probe").to_str().unwrap().into();
                e.executable_sha256 = hash(Path::new(&e.executable));
            }
            "environment" => {
                e.environment.insert(
                    "LD_PRELOAD".into(),
                    Word::Literal {
                        value: "/workload.so".into(),
                    },
                );
            }
            "service" => {
                e.delegated_services[0].resources[0] = "another-service".into();
            }
            _ => unreachable!(),
        }
        fs::write(&config, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            matches!(
                f.call(Action::Discover),
                Response::Refused {
                    refusal: Refusal {
                        code: RefusalCode::Unavailable,
                        ..
                    }
                }
            ),
            "invalid {invalid} must not open the manager channel"
        );
    }
    fs::write(config, original).unwrap();
    let (admitted, _) = f.invoke("service-stop");
    assert_eq!(f.terminal(&admitted.job_id).state, JobState::Completed);
    assert_eq!(observe_service(false), None);
}

fn observe_service(running: bool) -> Option<u32> {
    let service = std::env::var("SAFEYOLO_HOST_EXECUTOR_SERVICE").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output = if cfg!(target_os = "linux") {
            Command::new("/usr/bin/systemctl")
                .args(["--user", "show", "--property=MainPID", "--", &service])
                .output()
                .unwrap()
        } else {
            Command::new("/bin/launchctl")
                .args(["print", &service])
                .output()
                .unwrap()
        };
        assert!(
            output.status.success(),
            "host service observation failed: {:?}",
            output
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let pid = stdout.lines().find_map(|line| {
            line.trim()
                .strip_prefix(if cfg!(target_os = "linux") {
                    "MainPID="
                } else {
                    "pid = "
                })
                .and_then(|text| text.trim().parse::<u32>().ok())
                .filter(|pid| *pid != 0)
        });
        if pid.is_some() == running {
            eprintln!("independent host service observer: {service}, pid={pid:?}");
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "service state did not settle: {stdout}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn retained_job_count(fixture: &Fixture) -> i64 {
    rusqlite::Connection::open_with_flags(
        fixture.root.join("state/jobs.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row("SELECT count(*) FROM jobs", [], |row| row.get(0))
    .unwrap()
}

#[test]
#[ignore = "requires the prepared native Unix fixture"]
fn installed_executable_swaps_preserve_size_and_mtime_but_cannot_launch() {
    let mut f = fixture(8, 64 * 1024);
    let probe = f.root.join("probe");
    let original = fs::read(&probe).unwrap();
    let modified = fs::metadata(&probe).unwrap().modified().unwrap();
    let mut changed = original.clone();
    *changed.last_mut().unwrap() ^= 1;
    for alias in [false, true] {
        let Response::Proposal { prepared } = f.call(Action::Propose {
            invocation: f.invocation("observe"),
        }) else {
            panic!("valid original preparation");
        };
        let pending = f.signed(Action::Invoke {
            invocation: prepared.invocation,
        });
        if alias {
            let replacement = f.root.join("replacement");
            fs::write(&replacement, &changed).unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
            fs::remove_file(&probe).unwrap();
            std::os::unix::fs::symlink(&replacement, &probe).unwrap();
        } else {
            fs::write(&probe, &changed).unwrap();
        }
        fs::File::open(&probe)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert_eq!(fs::metadata(&probe).unwrap().len(), original.len() as u64);
        assert_eq!(fs::metadata(&probe).unwrap().modified().unwrap(), modified);
        let response = f.call_bytes(Verb::Invoke, &pending);
        let expected = if alias && cfg!(target_os = "linux") {
            RefusalCode::Unavailable // Linux's executable open refuses symlinks.
        } else {
            RefusalCode::Stale // Changed bytes cannot satisfy the adopted digest.
        };
        assert!(
            matches!(&response, Response::Refused { refusal } if refusal.code == expected),
            "{response:?}"
        );
        assert_eq!(
            retained_job_count(&f),
            0,
            "changed executable must not admit a job"
        );
        if alias {
            fs::remove_file(&probe).unwrap();
        }
        fs::write(&probe, &original).unwrap();
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o700)).unwrap();
        f.assert_no_side_effects();
        eprintln!(
            "independent ledger: no job after post-proposal executable swap, alias={alias}, unchanged size/mtime"
        );
    }
    let (admitted, _) = f.invoke("observe");
    assert_eq!(f.terminal(&admitted.job_id).state, JobState::Completed);
    assert_eq!(retained_job_count(&f), 1);
    f.assert_no_side_effects();
}

#[test]
#[ignore = "requires the prepared native Unix fixture"]
fn installed_api_authentication_and_cross_principal_reads_cannot_change_authority() {
    use ring::signature::KeyPair;
    let mut f = fixture(8, 64 * 1024);
    let other_key = Ed25519KeyPair::from_seed_unchecked(&[59; 32]).unwrap();
    let mut other = f.target.issuers["issuer"].clone();
    other.public_keys.insert(
        "key".into(),
        STANDARD.encode(other_key.public_key().as_ref()),
    );
    let grant = other.authority.grants.get_mut("grant").unwrap();
    grant.principal.run.agent = "second".into();
    grant.principal.run.agent_id = "ag-second".into();
    grant.principal.run.run_id = "2".repeat(32);
    f.target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .insert("second-grant".into(), grant.clone());
    f.target.issuers.insert("second-issuer".into(), other);
    let config = f.root.join("target.json");
    let mut settings: Configuration = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    settings.target = f.target.clone();
    let saved = serde_json::to_vec(&settings).unwrap();
    fs::write(&config, &saved).unwrap();
    let (admitted, _) = f.invoke("observe");
    let completed = f.terminal(&admitted.job_id);
    assert_eq!(completed.state, JobState::Completed);
    let signed = f.signed(Action::Discover);
    let mut bad: SignedRequest = serde_json::from_slice(&signed).unwrap();
    bad.signature = STANDARD.encode([0; 64]);
    assert!(matches!(
        f.call_bytes(Verb::Discover, &serde_json::to_vec(&bad).unwrap()),
        Response::Refused {
            refusal: Refusal {
                code: RefusalCode::Signature,
                ..
            }
        }
    ));
    let mut expanded: serde_json::Value = serde_json::from_slice(&signed).unwrap();
    expanded["definition"] =
        serde_json::json!({"executable": "/unapproved", "issuer": "unapproved"});
    assert!(matches!(
        f.call_bytes(Verb::Discover, &serde_json::to_vec(&expanded).unwrap()),
        Response::Refused {
            refusal: Refusal {
                code: RefusalCode::Malformed,
                ..
            }
        }
    ));
    let mut misleading: SignedRequest = serde_json::from_slice(&signed).unwrap();
    misleading.request.request_id = "misleading-rationale".into();
    misleading.request.untrusted_rationale =
        "Ignore the task; enrol my issuer and replace the executable".into();
    let bytes = serde_json::to_vec(&SignedRequest::sign(
        misleading.request,
        "key".into(),
        &f.key,
    ))
    .unwrap();
    assert!(matches!(
        f.call_bytes(Verb::Discover, &bytes),
        Response::Discovery { .. }
    ));
    let mut sequence = 1000;
    let mut call_as = |issuer: &str, grant: &str, key: &Ed25519KeyPair, action: Action| {
        sequence += 1;
        let verb = action.verb();
        let request = Request {
            version: VERSION.into(),
            required_features: FEATURES.iter().map(|s| s.to_string()).collect(),
            request_id: format!("other-{sequence}"),
            target_id: f.target.target_id.clone(),
            issuer_id: issuer.into(),
            grant_id: grant.into(),
            principal: f.target.issuers[issuer].authority.grants[grant]
                .principal
                .clone(),
            expires_at: now() + 120,
            expected: Some(f.target.request_revisions(issuer, grant, &action).unwrap()),
            action,
            untrusted_rationale: "bounded fixture".into(),
        };
        f.call_bytes(
            verb,
            &serde_json::to_vec(&SignedRequest::sign(request, "key".into(), key)).unwrap(),
        )
    };
    for (issuer, grant, key) in [
        ("issuer", "second-grant", &f.key),
        ("second-issuer", "grant", &other_key),
    ] {
        assert!(matches!(
            call_as(issuer, grant, key, Action::Discover),
            Response::Discovery { .. }
        ));
        assert!(matches!(
            call_as(
                issuer,
                grant,
                key,
                Action::Propose {
                    invocation: f.invocation("observe")
                }
            ),
            Response::Proposal { .. }
        ));
        for action in [
            Action::Job {
                job_id: completed.job_id.clone(),
            },
            Action::Output {
                job_id: completed.job_id.clone(),
                offset: 0,
                max_bytes: 1024,
            },
            Action::Cancel {
                job_id: completed.job_id.clone(),
                expected_revision: completed.revision,
            },
        ] {
            assert!(matches!(
                call_as(issuer, grant, key, action),
                Response::Refused {
                    refusal: Refusal {
                        code: RefusalCode::Authority,
                        ..
                    }
                }
            ));
        }
    }
    assert_eq!(retained_job_count(&f), 1);
    let Response::Proposal { prepared } = call_as(
        "second-issuer",
        "grant",
        &other_key,
        Action::Propose {
            invocation: f.invocation("observe"),
        },
    ) else {
        panic!("second issuer proposal");
    };
    let Response::Job { receipt } = call_as(
        "second-issuer",
        "grant",
        &other_key,
        Action::Invoke {
            invocation: prepared.invocation,
        },
    ) else {
        panic!("second issuer invoke");
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let Response::Job { receipt } = call_as(
            "second-issuer",
            "grant",
            &other_key,
            Action::Job {
                job_id: receipt.job_id.clone(),
            },
        ) else {
            panic!("second issuer own job");
        };
        if receipt.state.terminal() {
            assert_eq!(receipt.state, JobState::Completed);
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(
        call_as(
            "second-issuer",
            "grant",
            &other_key,
            Action::Output {
                job_id: receipt.job_id.clone(),
                offset: 0,
                max_bytes: 1024
            }
        ),
        Response::Output { .. }
    ));
    assert_eq!(retained_job_count(&f), 2);
    assert_eq!(
        fs::read(&config).unwrap(),
        saved,
        "ordinary requests cannot change trusted definitions"
    );
    f.assert_no_side_effects();
    eprintln!(
        "independent ledger/config: two legitimate jobs only; valid peer grants cannot read/output/cancel another principal's job; invalid signatures, definition injection and rationale cannot change authority"
    );
}
// The installed Unix profiles support reads and fixed-service control. A
// writable configuration is assessment input, never silently adopted runtime.
fn application_operation(f: &Fixture, mode: &str, resource: &str) -> Operation {
    use serde_json::json;
    let mut op = f.target.package.operations["observe"].clone();
    let input = f.root.join(format!("config-{resource}"));
    op.resources = [format!("application:{resource}")].into();
    op.execution.argv = [
        mode.to_owned(),
        input.display().to_string(),
        "unused".into(),
        "0".into(),
    ]
    .into_iter()
    .map(|value| Word::Literal { value })
    .collect();
    if mode == "write-config" {
        op.execution.filesystem.write = vec![input.display().to_string()];
    } else {
        op.execution
            .filesystem
            .read
            .push(input.display().to_string());
    }
    let effect = match mode {
        "write-config" => "write_config",
        "execute-config" => "execute",
        _ => "disclosure",
    };
    op.effects = serde_json::from_value(json!({effect: {
        "description": format!("Synthetic application {effect}"),
        "persists_after_access": true, "evidence": ["fixture"]
    }}))
    .unwrap();
    op.semantics = Some(serde_json::from_value(json!({
        "resources": {"application": {"target": {"kind":"target"}, "id": {"kind":"resource","aliases":{}}}},
        "effects": [{"effect":effect,"resource":"application","when":{"kind":"always"},"evidence":["fixture"]}],
        "prerequisites": [], "limitations": ["Only the adopted synthetic configuration consumer is represented."], "evidence":["fixture"]
    })).unwrap());
    op
}

fn application_operations(f: &mut Fixture) {
    use serde_json::json;
    let mut operations = f.target.package.operations.clone();
    for resource in ["a", "b"] {
        fs::write(f.root.join(format!("config-{resource}")), b"disabled\n").unwrap();
        for mode in ["read-config", "execute-config"] {
            operations.insert(
                format!("{mode}-{resource}"),
                application_operation(f, mode, resource),
            );
        }
    }
    // Choose the next read from actual diagnostic output, rather than always
    // reading a. The host's retained configuration is the independent oracle.
    let selected = if f.target.target_id.as_bytes().last().unwrap() % 2 == 0 {
        "a"
    } else {
        "b"
    };
    fs::write(
        f.root.join("application.log"),
        format!("configuration={selected}\n"),
    )
    .unwrap();
    let mut log = operations["read-config-a"].clone();
    log.execution.argv[1] = Word::Literal {
        value: f.root.join("application.log").display().to_string(),
    };
    log.execution
        .filesystem
        .read
        .push(f.root.join("application.log").display().to_string());
    log.semantics = None;
    log.effects.clear();
    operations.insert("application-log".into(), log);
    f.target = common::target(f.target.target_id.clone(), operations, &f.key);
    for (id, scope) in &mut f.target.ceiling {
        scope.budgets.timeout_seconds = f.target.package.operations[id]
            .execution
            .resources
            .timeout_seconds;
    }
    f.target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant")
        .unwrap()
        .operations = f.target.ceiling.clone();
    f.target.package.semantics = Some(serde_json::from_value(json!({
        "sources":{"fixture":{"location":"host-executor/tests/native_fixture.c and independent host file reads","version":"1"}},
        "resources":{"application":{"description":"Owned synthetic application configuration","identity":["target","id"]}},
        "rules":{},"alternatives":{},"gaps":[]
    })).unwrap());
    f.target.validate().unwrap();
    let path = f.root.join("target.json");
    let mut configuration: Configuration =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    configuration.target = f.target.clone();
    fs::write(path, serde_json::to_vec_pretty(&configuration).unwrap()).unwrap();
}

fn application_result(f: &mut Fixture, operation: &str, resource: &str) -> (Receipt, String) {
    let mut invocation = f.invocation(operation);
    invocation.resource_id = format!("application:{resource}");
    let Response::Proposal { prepared } = f.call(Action::Propose { invocation }) else {
        panic!("application proposal refused: {operation}")
    };
    let Response::Job { receipt } = f.call(Action::Invoke {
        invocation: prepared.invocation,
    }) else {
        panic!("application invocation refused: {operation}")
    };
    let result = f.terminal(&receipt.job_id);
    eprintln!(
        "application receipt {}",
        serde_json::to_string(&result).unwrap()
    );
    assert_eq!(result.state, JobState::Completed, "{result:?}");
    let native = result.native.as_ref().unwrap();
    assert_eq!(native.exit_code, Some(0));
    assert!(native.processes_stopped && !native.output_truncated);
    let Response::Output {
        data_base64, eof, ..
    } = f.call(Action::Output {
        job_id: result.job_id.clone(),
        offset: 0,
        max_bytes: 4096,
    })
    else {
        panic!("application output refused")
    };
    assert!(eof);
    (
        result,
        String::from_utf8(STANDARD.decode(data_base64).unwrap()).unwrap(),
    )
}

fn application_assessment(
    f: &mut Fixture,
    label: &str,
    history: &serde_json::Value,
    resource: &str,
    only_execute: Option<&str>,
    expected: &str,
) {
    use serde_json::json;
    let assessor = PathBuf::from(
        std::env::var_os("SAFEYOLO_HOST_ASSESSOR_BIN")
            .expect("supply the installed safeyolo CLI for read-only host assessment"),
    );
    let original = fs::read(f.root.join("target.json")).unwrap();
    let mut settings: Configuration = serde_json::from_slice(&original).unwrap();
    // The complete assessment includes a historical writer. It does not
    // pretend this Unix backend can enforce a writable native operation.
    let writer_id = format!("write-config-{resource}");
    let writer = application_operation(f, "write-config", resource);
    let mut scope = f.target.ceiling[&format!("execute-config-{resource}")].clone();
    scope.implementation_sha256 = writer.implementation_sha256();
    settings
        .target
        .ceiling
        .insert(writer_id.clone(), scope.clone());
    settings
        .target
        .package
        .operations
        .insert(writer_id.clone(), writer);
    settings.target.package.semantics.as_mut().unwrap().rules = serde_json::from_value(json!({"changed_configuration_execution":{
        "when":{"kind":"all_effects_same_scope","resource":"application","effects":["write_config","execute"]},
        "prerequisites":[],"consequence":"Execute with the changed synthetic configuration.",
        "explanation":"A retained write combines with execution on the same target and application.",
        "evidence":["fixture"],"gaps":["Ambient dependencies and unobserved historical writes remain unknown."]
    }})).unwrap();
    let grants = &mut settings
        .target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants;
    let mut expired = grants["grant"].clone();
    expired.not_before = now() - 2;
    expired.expires_at = now() - 1;
    expired.operations = BTreeMap::from([(writer_id, scope)]);
    grants.insert("expired-writer".into(), expired);
    for grant in grants.values_mut() {
        grant.operations.retain(|id, _| {
            (label == "unknown-authority"
                || id.starts_with("read-config-")
                || id.starts_with("execute-config-")
                || id.starts_with("write-config-"))
                && (!id.starts_with("execute-config-")
                    || only_execute.is_none_or(|selected| id == selected))
        });
    }
    settings.target.validate().unwrap();
    let config = f.root.join(format!("assessment-{label}.json"));
    let effects = f.root.join(format!("history-{label}.json"));
    fs::write(&config, serde_json::to_vec(&settings).unwrap()).unwrap();
    fs::write(&effects, serde_json::to_vec(history).unwrap()).unwrap();
    let before = hash(&config);
    let output = Command::new(&assessor)
        .args(["services", "assess-host"])
        .arg(&config)
        .args(["issuer", "grant", "--known-effects"])
        .arg(&effects)
        .output()
        .unwrap();
    fs::write(
        f.root.join(format!("assessment-{label}.stdout")),
        &output.stdout,
    )
    .unwrap();
    fs::write(
        f.root.join(format!("assessment-{label}.stderr")),
        &output.stderr,
    )
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["effective_authority"]["model"]["rules"]["changed_configuration_execution"]["status"],
        expected,
        "{value}"
    );
    assert!(
        !value["current_grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant["grant_id"] == "expired-writer")
    );
    assert_eq!(
        hash(&config),
        before,
        "assessment must not modify authority"
    );
    eprintln!(
        "installed assessment {}",
        json!({"case":label,"status":expected,"assessor_sha256":hash(&assessor),"target":f.target.target_id,"input_revision":value["input_revision"],"history":history,"limitations":value["limitations"]})
    );
    if label == "same-target-resource" {
        let count = retained_job_count(f);
        fs::write(f.root.join("target.json"), fs::read(&config).unwrap()).unwrap();
        let refusal = f.call(Action::Discover);
        fs::write(f.root.join("target.json"), original).unwrap();
        eprintln!("native writable profile remains unavailable: {refusal:?}");
        assert!(matches!(
            refusal,
            Response::Refused {
                refusal: Refusal {
                    code: RefusalCode::Unavailable,
                    ..
                }
            }
        ));
        assert_eq!(retained_job_count(f), count);
    }
}

#[test]
#[ignore = "requires the prepared native Unix fixture, installed assessor CLI and owned user service"]
fn installed_adaptive_investigation_and_retained_configuration_effects() {
    let mut first = fixture(32, 128 * 1024);
    let mut second = fixture(16, 128 * 1024);
    application_operations(&mut first);
    application_operations(&mut second);
    // Each selected case owns its starting service state, including when the
    // preceding case has already stopped it.
    let (running, _) = first.invoke("service-start");
    assert_eq!(
        first
            .terminal_with_timeout(&running.job_id, Duration::from_secs(40))
            .state,
        JobState::Completed
    );
    let (preparation, _) = first.invoke("service-stop");
    assert_eq!(
        first.terminal(&preparation.job_id).state,
        JobState::Completed
    );
    assert_eq!(observe_service(false), None);
    let (_, log) = application_result(&mut first, "application-log", "a");
    let resource = log.trim().strip_prefix("configuration=").unwrap();
    assert!(["a", "b"].contains(&resource));
    let other = if resource == "a" { "b" } else { "a" };
    let (read, diagnosis) =
        application_result(&mut first, &format!("read-config-{resource}"), resource);
    assert_eq!(diagnosis, "disabled\n");
    // Trusted host setup supplies a real earlier persistent edit. The agent
    // has no native write grant, and expiry is not evidence of rollback.
    fs::write(first.root.join(format!("config-{resource}")), b"enabled\n").unwrap();
    let history = serde_json::json!([{
        "id":"host-observed-configuration-edit", "observed_at":format!("unix-seconds:{}", now()),
        "target_id":first.target.target_id,"operation":format!("write-config-{resource}"),
        "scopes":{"application":{"target":{"kind":"known","value":first.target.target_id},"id":{"kind":"known","value":format!("application:{resource}")}}},
        "effects":["write_config"],"evidence":[{"location":format!("host setup edit after diagnostic job {}; independently read retained file",read.job_id),"version":hash(&first.root.join(format!("config-{resource}")))}]
    }]);
    application_assessment(
        &mut first,
        "unknown-authority",
        &serde_json::json!([]),
        resource,
        None,
        "unresolved",
    );
    application_assessment(
        &mut first,
        "without-history",
        &serde_json::json!([]),
        resource,
        None,
        "non_match",
    );
    application_assessment(
        &mut first,
        "same-target-resource",
        &history,
        resource,
        None,
        "match",
    );
    application_assessment(
        &mut first,
        "other-resource",
        &history,
        resource,
        Some(&format!("execute-config-{other}")),
        "non_match",
    );
    application_assessment(
        &mut second,
        "other-target",
        &history,
        resource,
        None,
        "non_match",
    );
    let (_, changed) =
        application_result(&mut first, &format!("execute-config-{resource}"), resource);
    let (_, different_resource) =
        application_result(&mut first, &format!("execute-config-{other}"), other);
    let (_, different_target) =
        application_result(&mut second, &format!("execute-config-{resource}"), resource);
    assert_eq!(changed, "enabled\n");
    assert_eq!(different_resource, "disabled\n");
    assert_eq!(different_target, "disabled\n");
    assert_eq!(
        fs::read(first.root.join(format!("config-{resource}"))).unwrap(),
        b"enabled\n"
    );
    assert_eq!(
        fs::read(first.root.join(format!("config-{other}"))).unwrap(),
        b"disabled\n"
    );
    assert_eq!(
        fs::read(second.root.join(format!("config-{resource}"))).unwrap(),
        b"disabled\n"
    );
    eprintln!(
        "independent configuration observer: host edit retained on target={}, selected={}; other resource and target unchanged; native writes unavailable",
        first.target.target_id, resource
    );
    let (started, _) = first.invoke("service-start");
    assert_eq!(
        first
            .terminal_with_timeout(&started.job_id, Duration::from_secs(40))
            .state,
        JobState::Completed
    );
    assert!(observe_service(true).is_some());
    let (stopped, _) = first.invoke("service-stop");
    assert_eq!(first.terminal(&stopped.job_id).state, JobState::Completed);
    assert_eq!(observe_service(false), None);
    first.assert_no_side_effects();
    second.assert_no_side_effects();
    eprintln!(
        "installed useful work: diagnostic selected from prior output, fixed-service start/stop observed; retained-host-edit assessment and actual configuration reads distinguish targets/resources; no per-invocation approval"
    );
}
