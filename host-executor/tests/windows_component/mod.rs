use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::Ed25519KeyPair;
use safeyolo_host_executor::{server::Configuration, windows::WindowsRuntime, *};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    process::{Child, Command as Process, Stdio},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{
        JobObjects::*, Pipes::GetNamedPipeServerProcessId, Services::*,
        SystemServices::JOB_OBJECT_QUERY, Threading::*,
    },
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn server_identity(pipe: &std::fs::File) -> std::io::Result<()> {
    // Identify the selected executor before sending a signed request. SQOS on
    // the client handle also prevents a squatting pipe from impersonating us.
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let process = Handle(process);
    let mut own = null_mut();
    let mut server = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut own) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let own = Handle(own);
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut server) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let server = Handle(server);
    let mut users = Vec::new();
    for token in [own.0, server.0] {
        let mut bytes = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut bytes);
        }
        let mut user = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                user.as_mut_ptr().cast(),
                bytes,
                &mut bytes,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        users.push(user);
    }
    let a = unsafe { (*users[0].as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let b = unsafe { (*users[1].as_ptr().cast::<TOKEN_USER>()).User.Sid };
    if unsafe { EqualSid(a, b) } == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "pipe server is not the selected executor account",
        ));
    }
    Ok(())
}

fn executor() -> PathBuf {
    std::env::var_os("SAFEYOLO_HOST_EXECUTOR_BIN")
        .expect("set prebuilt executor path")
        .into()
}
fn hash(path: &Path) -> String {
    ring::digest::digest(&ring::digest::SHA256, &fs::read(path).unwrap())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
fn literal(value: &str) -> Word {
    Word::Literal {
        value: value.into(),
    }
}
fn probe_path(root: &Path) -> PathBuf {
    root.join("programs with spaces/probe.exe")
}
fn config_path(root: &Path) -> PathBuf {
    root.join("control/target.json")
}
fn load(root: &Path) -> Configuration {
    serde_json::from_slice(&fs::read(config_path(root)).unwrap()).unwrap()
}

fn operation(
    program: PathBuf,
    argv: Vec<String>,
    identity: &ExecutionIdentity,
    root: &Path,
) -> Operation {
    Operation {
        resources: ["fixture".into()].into(), arguments: BTreeMap::new(),
        execution: Execution {
            broader: [BroaderBound::Filesystem, BroaderBound::Registry, BroaderBound::NetworkIpc, BroaderBound::DelegatedServices].into(),
            executable_sha256: hash(&program), executable: program.to_str().unwrap().into(),
            argv: argv.into_iter().map(|value| Word::Literal { value }).collect(),
            environment: BTreeMap::from([("FIXTURE".into(), literal("native")), ("SystemRoot".into(), literal("C:\\Windows"))]),
            working_directory: root.join("work").to_str().unwrap().into(), identity: identity.clone(),
            filesystem: Filesystem { read: vec![], write: vec![] }, network: Network { destinations: vec![], ipc: vec![] },
            resources: ExecutionLimits { timeout_seconds: 30, output_bytes: 64 * 1024, memory_bytes: 128 * 1024 * 1024, processes: 12 },
            delegated_services: vec![],
        }, effects: BTreeMap::new(),
        enforcement: Enforcement { enforced: vec!["Windows Job Object, protected executor, separate ordinary workload account".into()],
            adopted: vec!["explicit broader account filesystem/registry/network/delegated service access; mutable OS runtime dependencies; fixed PowerShell script is an interpreter capability".into()], unresolved: vec![] },
    }
}
fn prepare(root: &Path, credential: &str) {
    let output = Process::new(executor())
        .args(["identity", "--credential", credential])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let identity: ExecutionIdentity = serde_json::from_slice(&output.stdout).unwrap();
    fs::copy(std::env::current_exe().unwrap(), probe_path(root)).unwrap();
    let mut operations = BTreeMap::new();
    for mode in ["observe", "flood", "memory", "tasks", "background", "wait"] {
        let mut argv = vec![
            "--probe".into(),
            mode.into(),
            root.to_str().unwrap().into(),
            identity.principal.clone(),
        ];
        if mode == "observe" {
            argv.extend([
                "".into(),
                "spaces and ünicode".into(),
                "quote\"here".into(),
                "C:\\trailing\\".into(),
            ]);
        }
        let mut op = operation(probe_path(root), argv, &identity, root);
        if mode == "memory" {
            op.execution.resources.memory_bytes = 32 * 1024 * 1024;
        }
        if mode == "wait" {
            op.execution.resources.timeout_seconds = 3;
        }
        operations.insert(mode.into(), op);
    }
    let system = PathBuf::from("C:\\Windows\\System32");
    for (name, exe, args) in [
        (
            "service-status",
            "sc.exe",
            vec!["query", "SafeYolo1671Fixture"],
        ),
        (
            "service-start",
            "sc.exe",
            vec!["start", "SafeYolo1671Fixture"],
        ),
        (
            "service-stop",
            "sc.exe",
            vec!["stop", "SafeYolo1671Fixture"],
        ),
        (
            "event-log",
            "wevtutil.exe",
            vec!["qe", "System", "/c:1", "/rd:true", "/f:text"],
        ),
        (
            "registry",
            "reg.exe",
            vec![
                "query",
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                "/v",
                "ProductName",
            ],
        ),
        ("processes", "tasklist.exe", vec!["/FO", "CSV", "/NH"]),
        ("system", "systeminfo.exe", vec!["/FO", "CSV", "/NH"]),
        ("network", "netstat.exe", vec!["-ano"]),
        ("tasks-query", "schtasks.exe", vec!["/Query", "/FO", "LIST"]),
        ("fixed", "whoami.exe", vec!["/user"]),
    ] {
        let mut op = operation(
            system.join(exe),
            args.iter().map(|s| s.to_string()).collect(),
            &identity,
            root,
        );
        if name.starts_with("service-") {
            op.execution.delegated_services.push(DelegatedService {
                service: "Windows SCM".into(),
                capability: "fixed service start/stop/status".into(),
                resources: vec!["SafeYolo1671Fixture".into()],
            });
        }
        operations.insert(name.into(), op);
    }
    operations.insert(
        "files".into(),
        operation(
            system.join("attrib.exe"),
            vec![probe_path(root).to_str().unwrap().into()],
            &identity,
            root,
        ),
    );
    let mut restart = operation(
        system.join("WindowsPowerShell/v1.0/powershell.exe"),
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Restart-Service -Name SafeYolo1671Fixture -ErrorAction Stop",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        &identity,
        root,
    );
    restart.execution.resources.memory_bytes = 512 * 1024 * 1024;
    restart.execution.delegated_services.push(DelegatedService {
        service: "Windows SCM".into(),
        capability: "fixed service restart".into(),
        resources: vec!["SafeYolo1671Fixture".into()],
    });
    operations.insert("service-restart".into(), restart);
    let key = Ed25519KeyPair::from_seed_unchecked(&[58; 32]).unwrap();
    let mut target = super::common::target("windows-native1671".into(), operations, &key);
    for scope in target.ceiling.values_mut() {
        scope.budgets.timeout_seconds = 30;
        scope.budgets.output_bytes = 64 * 1024;
    }
    target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant")
        .unwrap()
        .operations = target.ceiling.clone();
    let configuration = Configuration {
        target,
        ledger: LedgerLimits {
            jobs: 128,
            mutation_records: 256,
            output_bytes: 8 * 1024 * 1024,
            database_bytes: 32 * 1024 * 1024,
            request_bytes: 64 * 1024,
        },
        native: NativeRuntime::Windows(WindowsRuntime {
            credential: credential.into(),
            executable_bytes: 32 * 1024 * 1024,
        }),
        connections: 8,
        connection_timeout_seconds: 5,
    };
    fs::write(
        config_path(root),
        serde_json::to_vec_pretty(&configuration).unwrap(),
    )
    .unwrap();
    println!(
        "prepared complete Windows native catalogue; identity {}",
        identity.principal
    );
}

struct Fixture {
    root: PathBuf,
    target: Target,
    counter: u64,
    server: Option<Child>,
    phase: String,
}
impl Fixture {
    fn new(root: PathBuf, service: bool) -> Self {
        let target = load(&root).target;
        let mut fixture = Self {
            root,
            target,
            counter: 0,
            server: None,
            phase: if service {
                "service".into()
            } else {
                "foreground".into()
            },
        };
        if !service {
            fixture.start();
        }
        fixture
    }
    fn start(&mut self) {
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("control/server.log"))
            .unwrap();
        self.server = Some(
            Process::new(executor())
                .arg("serve")
                .arg("--config")
                .arg(config_path(&self.root))
                .arg("--state")
                .arg(self.root.join("control/state"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        );
        let start = Instant::now();
        loop {
            let response = self.try_bytes(Verb::Discover.path(), &[]);
            if response.is_ok() {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "server readiness: {}",
                fs::read_to_string(self.root.join("control/server.log")).unwrap()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn signed(&mut self, action: Action) -> Vec<u8> {
        self.counter += 1;
        let request = Request {
            version: VERSION.into(),
            required_features: FEATURES.iter().map(|s| s.to_string()).collect(),
            request_id: format!("{}-{}", self.phase, self.counter),
            target_id: self.target.target_id.clone(),
            issuer_id: "issuer".into(),
            grant_id: "grant".into(),
            principal: self.target.issuers["issuer"].authority.grants["grant"]
                .principal
                .clone(),
            expires_at: self.target.issuers["issuer"].authority.valid_until,
            expected: Some(self.target.revisions("issuer").unwrap()),
            action,
            untrusted_rationale: "Windows component fixture".into(),
        };
        serde_json::to_vec(&SignedRequest::sign(
            request,
            "key".into(),
            &Ed25519KeyPair::from_seed_unchecked(&[58; 32]).unwrap(),
        ))
        .unwrap()
    }
    fn try_bytes(&self, path: &str, body: &[u8]) -> std::io::Result<Response> {
        let mut pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
            .open(format!(
                "\\\\.\\pipe\\safeyolo-host-{}",
                self.target.target_id
            ))?;
        server_identity(&pipe)?;
        write!(
            pipe,
            "POST {path} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )?;
        pipe.write_all(body)?;
        let mut reader = BufReader::new(pipe);
        let mut length = None;
        let mut total = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            total += line.len();
            assert!(total < 8192);
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.strip_prefix("Content-Length: ") {
                length = Some(value.trim().parse::<usize>().unwrap());
            }
            if line.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "HTTP pipe closed",
                ));
            }
        }
        let length = length.expect("HTTP response length");
        assert!(length < 1024 * 1024);
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes)?;
        Ok(serde_json::from_slice(&bytes).unwrap())
    }
    fn bytes(&self, verb: Verb, bytes: &[u8]) -> Response {
        self.try_bytes(verb.path(), bytes).unwrap()
    }
    fn call(&mut self, action: Action) -> Response {
        let verb = action.verb();
        let body = self.signed(action);
        self.bytes(verb, &body)
    }
    fn invoke(&mut self, name: &str) -> (Receipt, Vec<u8>) {
        let operation = &self.target.package.operations[name];
        let invocation = Invocation {
            operation_id: name.into(),
            resource_id: "fixture".into(),
            package_sha256: revision(&self.target.package),
            implementation_sha256: operation.implementation_sha256(),
            arguments: BTreeMap::new(),
            expected_assessment_sha256: None,
        };
        let Response::Proposal { prepared } = self.call(Action::Propose { invocation }) else {
            panic!("proposal {name} refused");
        };
        let bytes = self.signed(Action::Invoke {
            invocation: prepared.invocation,
        });
        let Response::Job { receipt } = self.bytes(Verb::Invoke, &bytes) else {
            panic!("invoke {name} refused");
        };
        (*receipt, bytes)
    }
    fn job(&mut self, id: &str) -> Receipt {
        let Response::Job { receipt } = self.call(Action::Job { job_id: id.into() }) else {
            panic!("job refused");
        };
        *receipt
    }
    fn terminal(&mut self, id: &str) -> Receipt {
        let end = Instant::now() + Duration::from_secs(45);
        loop {
            let receipt = self.job(id);
            if receipt.state.terminal() {
                println!(
                    "{}: {:?}; {:?}",
                    receipt.prepared.invocation.operation_id, receipt.state, receipt.native
                );
                return receipt;
            }
            assert!(Instant::now() < end, "job did not settle {receipt:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn output(&mut self, id: &str) -> Vec<u8> {
        let Response::Output { data_base64, .. } = self.call(Action::Output {
            job_id: id.into(),
            offset: 0,
            max_bytes: 64 * 1024,
        }) else {
            panic!("output refused");
        };
        STANDARD.decode(data_base64).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = self.server.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn native(root: PathBuf, service: bool) {
    let mut fixture = Fixture::new(root, service);
    for mode in ["observe", "memory", "tasks", "background"] {
        let (receipt, _) = fixture.invoke(mode);
        let result = fixture.terminal(&receipt.job_id);
        assert_eq!(result.state, JobState::Completed, "{result:?}");
        assert!(result.native.as_ref().unwrap().processes_stopped);
        let output = String::from_utf8(fixture.output(&receipt.job_id)).unwrap();
        println!("{mode}: {output}");
        if mode == "memory" {
            assert!(output.contains("allocation_refused"));
        }
        if mode == "tasks" {
            assert!(output.contains("process_limit_reached"));
        }
    }
    let (receipt, _) = fixture.invoke("flood");
    let result = fixture.terminal(&receipt.job_id);
    assert_eq!(
        result.native.as_ref().unwrap().termination_reason,
        "output_limit"
    );
    assert!(result.native.unwrap().processes_stopped);
    assert!(fixture.output(&receipt.job_id).len() <= 64 * 1024);
    let (receipt, _) = fixture.invoke("wait");
    let result = fixture.terminal(&receipt.job_id);
    assert_eq!(
        result.native.as_ref().unwrap().termination_reason,
        "timeout"
    );
    let (receipt, _) = fixture.invoke("wait");
    let deadline = Instant::now() + Duration::from_secs(2);
    let running = loop {
        let running = fixture.job(&receipt.job_id);
        if running.output_bytes > 0 {
            break running;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    };
    fixture.call(Action::Cancel {
        job_id: receipt.job_id.clone(),
        expected_revision: running.revision,
    });
    assert_eq!(fixture.terminal(&receipt.job_id).state, JobState::Cancelled);
    for mode in [
        "service-status",
        "service-start",
        "service-status",
        "service-restart",
        "service-stop",
        "service-status",
        "event-log",
        "registry",
        "processes",
        "system",
        "files",
        "network",
        "tasks-query",
        "fixed",
    ] {
        let (receipt, _) = fixture.invoke(mode);
        let result = fixture.terminal(&receipt.job_id);
        assert_eq!(
            result.state,
            JobState::Completed,
            "starter {mode}: {result:?}; {}",
            String::from_utf8_lossy(&fixture.output(&receipt.job_id))
        );
        println!("starter {mode}: {} bytes", result.output_bytes);
        if mode == "service-start" || mode == "service-stop" {
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    // A complete-catalogue edit must be refused even for discovery; no candidate
    // program is invoked to qualify it. Restore the exact operator-owned input.
    let original = fs::read(config_path(&fixture.root)).unwrap();
    let mut bad: Configuration = serde_json::from_slice(&original).unwrap();
    bad.target
        .package
        .operations
        .get_mut("observe")
        .unwrap()
        .execution
        .broader
        .remove(&BroaderBound::Registry);
    let changed = bad.target.package.operations["observe"].implementation_sha256();
    bad.target
        .ceiling
        .get_mut("observe")
        .unwrap()
        .implementation_sha256 = changed.clone();
    bad.target
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
        .implementation_sha256 = changed;
    fs::write(
        config_path(&fixture.root),
        serde_json::to_vec(&bad).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        fixture.call(Action::Discover),
        Response::Refused { refusal } if refusal.code == RefusalCode::Unavailable
    ));
    fs::write(config_path(&fixture.root), &original).unwrap();
    if !service {
        recover_controller(&mut fixture);
    }
    println!(
        "Windows {} native observations, broader profile, lifecycle, reload and starter commands passed",
        fixture.phase
    );
}

fn restart(fixture: &mut Fixture) {
    fixture.server.as_mut().unwrap().kill().unwrap();
    fixture.server.as_mut().unwrap().wait().unwrap();
    fixture.start();
}

fn recover_controller(fixture: &mut Fixture) {
    let (receipt, signed) = fixture.invoke("wait");
    println!("crash check admitted job {}", receipt.job_id);
    let end = Instant::now() + Duration::from_secs(2);
    while fixture.job(&receipt.job_id).output_bytes == 0 {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(10));
    }
    // Observe the exact process handle before the crash; PID reuse cannot make
    // this check mistake another process for the original workload. Close our
    // temporary Job handle before killing the executor so kill-on-close applies.
    let job_name = wide(&format!(
        "Local\\SafeYolo-host-{}-{}",
        fixture.target.target_id, receipt.job_id
    ));
    let job = Handle(unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, job_name.as_ptr()) });
    assert!(!job.0.is_null());
    #[repr(C)]
    struct ProcessIds {
        assigned: u32,
        listed: u32,
        // The prepared wait operation admits at most twelve Job processes.
        pids: [usize; 12],
    }
    let mut ids = ProcessIds {
        assigned: 0,
        listed: 0,
        pids: [0; 12],
    };
    assert_ne!(
        unsafe {
            QueryInformationJobObject(
                job.0,
                JobObjectBasicProcessIdList,
                (&mut ids as *mut ProcessIds).cast(),
                std::mem::size_of_val(&ids) as u32,
                null_mut(),
            )
        },
        0,
        "Job process list: {}; assigned={}, listed={}",
        std::io::Error::last_os_error(),
        ids.assigned,
        ids.listed
    );
    assert!(ids.listed > 0 && ids.listed as usize <= ids.pids.len());
    let processes: Vec<_> = ids.pids[..ids.listed as usize]
        .iter()
        .map(|pid| {
            let process = Handle(unsafe { OpenProcess(SYNCHRONIZE, 0, *pid as u32) });
            assert!(
                !process.0.is_null(),
                "open original Job process: {}",
                std::io::Error::last_os_error()
            );
            process
        })
        .collect();
    drop(job);
    restart(fixture);
    for process in &processes {
        assert_eq!(
            unsafe { WaitForSingleObject(process.0, 5000) },
            WAIT_OBJECT_0
        );
    }
    assert_eq!(fixture.job(&receipt.job_id).state, JobState::Uncertain);
    let Response::Job { receipt: replay } = fixture.bytes(Verb::Invoke, &signed) else {
        panic!("lost-reply replay refused");
    };
    assert_eq!(replay.job_id, receipt.job_id);
    assert_eq!(fixture.job(&receipt.job_id).state, JobState::Uncertain);
    println!(
        "original {} Job processes stopped after controller crash; uncertain receipt and exact replay retained without redispatch",
        processes.len()
    );
}

fn storage_exhaustion(fixture: &mut Fixture) {
    let (receipt, signed) = fixture.invoke("flood");
    let completed = fixture.terminal(&receipt.job_id);
    assert!(completed.native.as_ref().unwrap().processes_stopped);
    assert_eq!(
        completed.native.as_ref().unwrap().termination_reason,
        "output_limit"
    );
    let output = fixture.output(&receipt.job_id);
    assert!(!output.is_empty());
    let path = config_path(&fixture.root);
    let original = fs::read(&path).unwrap();
    for (jobs, retained_output) in [(1, 8 * 1024 * 1024), (128, 1)] {
        let mut config: Configuration = serde_json::from_slice(&original).unwrap();
        config.ledger.jobs = jobs;
        config.ledger.output_bytes = retained_output;
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        restart(fixture);
        let operation = &fixture.target.package.operations["observe"];
        let invocation = Invocation {
            operation_id: "observe".into(),
            resource_id: "fixture".into(),
            package_sha256: revision(&fixture.target.package),
            implementation_sha256: operation.implementation_sha256(),
            arguments: BTreeMap::new(),
            expected_assessment_sha256: None,
        };
        let Response::Proposal { prepared } = fixture.call(Action::Propose { invocation }) else {
            panic!("storage exhaustion disabled proposal")
        };
        assert!(
            matches!(fixture.call(Action::Invoke { invocation: prepared.invocation }), Response::Refused { refusal } if refusal.code == RefusalCode::Budget)
        );
        let Response::Job { receipt: replay } = fixture.bytes(Verb::Invoke, &signed) else {
            panic!("storage exhaustion lost replay")
        };
        assert_eq!(replay.job_id, receipt.job_id);
        assert_eq!(fixture.output(&receipt.job_id), output);
        println!(
            "storage ceiling jobs={jobs}, output_bytes={retained_output}: fresh effect refused; old replay and output retained after restart"
        );
    }
    fs::write(path, original).unwrap();
    restart(fixture);
}

fn probe(args: &[String]) {
    let mode = &args[0];
    let root = Path::new(&args[1]);
    if mode == "observe" {
        assert_eq!(
            &args[3..],
            ["", "spaces and ünicode", "quote\"here", "C:\\trailing\\"]
        );
        assert_eq!(std::env::current_dir().unwrap(), root.join("work"));
        assert_eq!(std::env::var("FIXTURE").unwrap(), "native");
        assert!(std::env::var_os("SAFEYOLO_HOST_EXECUTOR_BIN").is_none());
        assert!(fs::read(root.join("control/target.json")).is_err());
        assert!(
            OpenOptions::new()
                .write(true)
                .open(root.join("control/target.json"))
                .is_err()
        );
        fs::write(
            root.join("work/allowed.txt"),
            b"workload write under explicit broader account filesystem permission",
        )
        .unwrap();
        let mut token = null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
            0
        );
        let mut bytes = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut bytes);
        }
        let mut data = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    data.as_mut_ptr().cast(),
                    bytes,
                    &mut bytes,
                )
            },
            0
        );
        let sid = unsafe { (*data.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut text = null_mut();
        assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut text) }, 0);
        let mut length = 0;
        unsafe {
            while *text.add(length) != 0 {
                length += 1;
            }
        }
        let actual = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        assert_eq!(actual, args[2]);
        unsafe {
            LocalFree(text.cast());
            CloseHandle(token);
        }
        println!("arguments_identity_protected_files_environment_ok");
    } else if mode == "memory" {
        let mut bytes = Vec::<u8>::new();
        if bytes.try_reserve_exact(96 * 1024 * 1024).is_err() {
            println!("allocation_refused");
        } else {
            bytes.resize(96 * 1024 * 1024, 58);
            println!(
                "unexpected_allocation {}",
                bytes.iter().map(|x| *x as u64).sum::<u64>()
            );
        }
    } else if mode == "flood" {
        loop {
            std::io::stdout().write_all(&[b'x'; 4096]).unwrap();
        }
    } else if mode == "wait" || mode == "sleep" {
        println!("started {}", std::process::id());
        std::io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_secs(60));
    } else if mode == "background" || mode == "tasks" {
        let mut children = Vec::new();
        for _ in 0..if mode == "tasks" { 32 } else { 1 } {
            match Process::new(std::env::current_exe().unwrap())
                .args(["--probe", "sleep", args[1].as_str(), args[2].as_str()])
                .spawn()
            {
                Ok(child) => children.push(child),
                Err(_) => {
                    println!("process_limit_reached {}", children.len());
                    break;
                }
            }
        }
        assert!(!children.is_empty());
        println!(
            "background_pids {:?}",
            children.iter().map(Child::id).collect::<Vec<_>>()
        );
    } else {
        panic!("unknown probe mode");
    }
}

static SERVICE_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
unsafe extern "system" fn service_control(
    code: u32,
    _: u32,
    _: *mut std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> u32 {
    if code == SERVICE_CONTROL_STOP {
        SERVICE_STOP.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    0
}
unsafe extern "system" fn dummy_service(_: u32, _: *mut *mut u16) {
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            wide("SafeYolo1671Fixture").as_ptr(),
            Some(service_control),
            null(),
        )
    };
    assert!(!handle.is_null());
    let mut status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_RUNNING,
        dwControlsAccepted: SERVICE_ACCEPT_STOP,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    assert_ne!(unsafe { SetServiceStatus(handle, &status) }, 0);
    while !SERVICE_STOP.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(10));
    }
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    unsafe {
        SetServiceStatus(handle, &status);
    }
}
pub fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--probe") => probe(&args[1..]),
        Some("--prepare") if args.len() == 3 => prepare(Path::new(&args[1]), &args[2]),
        Some("--native") if args.len() == 2 || args.len() == 3 => native(
            PathBuf::from(&args[1]),
            args.get(2).is_some_and(|s| s == "--service"),
        ),
        Some(mode @ ("--recover" | "--storage")) if args.len() == 3 => {
            let mut fixture = Fixture::new(PathBuf::from(&args[1]), false);
            fixture.phase = format!("{}-{}", mode.trim_start_matches("--"), args[2]);
            if mode == "--recover" {
                recover_controller(&mut fixture);
            } else {
                storage_exhaustion(&mut fixture);
            }
        }
        Some("--dummy-service") => {
            let mut name = wide("SafeYolo1671Fixture");
            let table = [
                SERVICE_TABLE_ENTRYW {
                    lpServiceName: name.as_mut_ptr(),
                    lpServiceProc: Some(dummy_service),
                },
                SERVICE_TABLE_ENTRYW {
                    lpServiceName: null_mut(),
                    lpServiceProc: None,
                },
            ];
            assert_ne!(unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }, 0);
        }
        _ => println!(
            "Windows native fixture skipped: explicitly select --prepare/--native with the owned prepared inputs"
        ),
    }
}
