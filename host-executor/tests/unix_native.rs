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
    _ipc_listener: std::os::unix::net::UnixListener,
    target: Target,
    key: Ed25519KeyPair,
    counter: u64,
}
impl Fixture {
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
            expires_at: now() + 300,
            expected: Some(self.target.revisions("issuer").unwrap()),
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
    fn invoke(&mut self, mode: &str) -> (Receipt, Vec<u8>) {
        let operation = &self.target.package.operations[mode];
        let invocation = Invocation {
            operation_id: mode.into(),
            resource_id: "fixture".into(),
            package_sha256: revision(&self.target.package),
            implementation_sha256: operation.implementation_sha256(),
            arguments: BTreeMap::new(),
            expected_assessment_sha256: None,
        };
        let Response::Proposal { prepared } = self.call(Action::Propose { invocation }) else {
            panic!("proposal refused")
        };
        let bytes = self.signed(Action::Invoke {
            invocation: prepared.invocation,
        });
        let Response::Job { receipt } = self.call_bytes(Verb::Invoke, &bytes) else {
            panic!("invoke refused")
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
        let deadline = Instant::now() + Duration::from_secs(15);
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

fn fixture() -> Fixture {
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
    for mode in ["observe", "flood", "memory", "tasks", "background", "wait"] {
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
            resources: ["fixture".into()].into(),
            arguments: BTreeMap::new(),
            execution: Execution {
                broader: if cfg!(target_os = "macos") {
                    [BroaderBound::Memory, BroaderBound::ExecutorRestart].into()
                } else {
                    Default::default()
                },
                executable: probe.to_str().unwrap().into(),
                executable_sha256: hash(&probe),
                argv: [
                    mode.to_string(),
                    root.join("allowed").to_str().unwrap().into(),
                    root.join("forbidden").to_str().unwrap().into(),
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
                    timeout_seconds: 5,
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
    let target = common::target(name, operations, &key);
    #[cfg(target_os = "linux")]
    let bubblewrap = PathBuf::from(
        std::env::var_os("SAFEYOLO_HOST_EXECUTOR_BWRAP").unwrap_or_else(|| "/usr/bin/bwrap".into()),
    );
    let settings = Configuration {
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
            jobs: 16,
            mutation_records: 64,
            output_bytes: 1024 * 1024,
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
    Fixture {
        server: start(&root),
        _ipc_listener: ipc_listener,
        root,
        #[cfg(target_os = "linux")]
        cgroup,
        target,
        key,
        counter: 0,
    }
}

#[test]
#[ignore = "requires native Unix host; prepared probe or C compiler; Linux also needs bubblewrap and delegated cgroup v2"]
fn installed_unix_bounds_lifecycle_reload_and_lost_reply() {
    let mut f = fixture();
    for mode in ["observe", "background", "tasks", "flood", "memory"] {
        let (admitted, replay) = f.invoke(mode);
        let result = f.terminal(&admitted.job_id);
        eprintln!("{mode}: {}", serde_json::to_string(&result).unwrap());
        let native = result.native.as_ref().expect("native facts");
        assert!(native.processes_stopped);
        assert_eq!(
            result.state,
            if ["flood", "memory"].contains(&mode) {
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
