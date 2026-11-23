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
        description: String::new(),
        semantics: None,
        required_checks: Default::default(),
        resources: ["fixture".into()].into(), arguments: BTreeMap::new(),
        execution: Execution {
                dependencies: Default::default(),
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
    for mode in [
        "observe",
        "flood",
        "memory",
        "tasks",
        "background",
        "wait",
        "handles",
    ] {
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
    save_target(root, credential, target);
    println!(
        "prepared complete Windows native catalogue; identity {}",
        identity.principal
    );
}

fn save_target(root: &Path, credential: &str, target: Target) {
    let configuration = Configuration {
        https: None,
        catalogue: None,
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
}

struct Fixture {
    root: PathBuf,
    target: Target,
    counter: u64,
    server: Option<Child>,
    phase: String,
    server_pid: std::cell::Cell<u32>,
}
impl Fixture {
    fn new(root: PathBuf, service: bool) -> Self {
        let target = load(&root).target;
        let mut fixture = Self {
            root,
            target,
            counter: 0,
            server: None,
            server_pid: std::cell::Cell::new(0),
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
            expected: Some(
                self.target
                    .request_revisions("issuer", "grant", &action)
                    .unwrap(),
            ),
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
        let mut pid = 0;
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.server_pid.set(pid);
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
    fn signed_as(&mut self, action: Action, issuer: &str, grant: &str) -> Vec<u8> {
        let mut signed: SignedRequest = serde_json::from_slice(&self.signed(action)).unwrap();
        signed.request.issuer_id = issuer.into();
        signed.request.grant_id = grant.into();
        signed.request.principal = self.target.issuers[issuer].authority.grants[grant]
            .principal
            .clone();
        signed.request.expected = Some(
            self.target
                .request_revisions(issuer, grant, &signed.request.action)
                .unwrap(),
        );
        let seed = if issuer == "other" { 59 } else { 58 };
        serde_json::to_vec(&SignedRequest::sign(
            signed.request,
            "key".into(),
            &Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap(),
        ))
        .unwrap()
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
        self.invoke_arguments(name, "fixture", BTreeMap::new())
    }
    fn invoke_arguments(
        &mut self,
        name: &str,
        resource: &str,
        arguments: BTreeMap<String, serde_json::Value>,
    ) -> (Receipt, Vec<u8>) {
        let operation = &self.target.package.operations[name];
        let invocation = Invocation {
            operation_id: name.into(),
            resource_id: resource.into(),
            operation_sha256: self.target.package.operation_sha256(name).unwrap(),
            implementation_sha256: operation.implementation_sha256(),
            arguments,
            expected_assessment_sha256: None,
        };
        let response = self.call(Action::Propose { invocation });
        let Response::Proposal { prepared } = response else {
            panic!("proposal {name} refused: {response:?}");
        };
        let bytes = self.signed(Action::Invoke {
            invocation: prepared.invocation,
        });
        let response = self.bytes(Verb::Invoke, &bytes);
        let Response::Job { receipt } = response else {
            panic!("invoke {name} refused: {response:?}");
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

const STARTER_READS: &[&str] = &[
    "service-enumerate",
    "event-log-query",
    "registry-query-machine",
    "registry-query-user",
    "process-inspect",
    "system-inventory",
    "software-inventory",
    "update-inventory",
    "file-inspect",
    "network-diagnostics",
    "scheduled-task-inspect",
    "fixed-executable",
    "file-hash",
    "directory-list",
    "network-inspect",
    "scheduled-task-enumerate",
    "bundle-metadata",
    "application-log",
    "system-log",
    "snapshot-list",
];

fn prepare_starters(root: &Path, credential: &str) {
    let case = root.join("case with spaces ünicode");
    let package_path = root.join("control/starter.json");
    for args in [
        vec!["demo", "--directory", case.to_str().unwrap()],
        vec![
            "starter",
            "--root",
            case.to_str().unwrap(),
            "--service",
            "SafeYolo1671Fixture",
            "--output",
            package_path.to_str().unwrap(),
            "--credential",
            credential,
        ],
    ] {
        let output = Process::new(executor()).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
    fs::write(
        case.join("config.json"),
        b"{\"mode\":\"owned-native-fixture\"}\n",
    )
    .unwrap();
    let mut package: Package = serde_json::from_slice(&fs::read(&package_path).unwrap()).unwrap();
    let temp = case.join("Temp");
    fs::create_dir(&temp).unwrap();
    let output = Process::new(r"C:\Windows\System32\icacls.exe")
        .arg(&temp)
        .arg("/grant")
        .arg(format!(
            "*{}:(OI)(CI)(M)",
            package.operations["fixed-executable"]
                .execution
                .identity
                .principal
        ))
        .output()
        .unwrap();
    assert!(output.status.success(), "temporary storage ACL: {output:?}");
    // Select a real receiver inside this owned, network-disabled Sandbox. The
    // packaged typed recipe is unchanged; these are its explicit target inputs.
    let diagnostic = package.operations.get_mut("network-diagnostics").unwrap();
    for (name, value) in [
        ("destination", serde_json::json!("127.0.0.1")),
        ("port", serde_json::json!(19477)),
    ] {
        let argument = diagnostic.arguments.get_mut(name).unwrap();
        argument.options = vec![value.clone()];
        argument.default = Some(value);
    }
    fs::write(&package_path, serde_json::to_vec_pretty(&package).unwrap()).unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&[58; 32]).unwrap();
    let mut target = super::common::target(
        "windows-starters1677".into(),
        package.operations.clone(),
        &key,
    );
    target.package = package;
    target.ceiling.retain(|name, _| {
        STARTER_READS.contains(&name.as_str())
            || [
                "service-status",
                "service-start",
                "service-restart",
                "service-stop",
            ]
            .contains(&name.as_str())
    });
    for (name, scope) in &mut target.ceiling {
        let operation = &target.package.operations[name];
        scope.budgets.calls = 64;
        scope.budgets.timeout_seconds = operation.execution.resources.timeout_seconds;
        scope.budgets.output_bytes = operation.execution.resources.output_bytes;
        scope.arguments = operation
            .arguments
            .iter()
            .map(|(name, argument)| {
                let mut values = argument.options.clone();
                if let Some(default) = &argument.default
                    && !values.contains(default)
                {
                    values.push(default.clone());
                }
                (name.clone(), values)
            })
            .collect();
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
    println!(
        "{}",
        serde_json::json!({"package_sha256":revision(&target.package),
        "target":target.target_id,"selected":target.ceiling.keys().collect::<Vec<_>>(),
        "credential":credential,"identity":target.package.operations["fixed-executable"].execution.identity})
    );
    save_target(root, credential, target);
}

fn observed_service() -> (u32, u32) {
    unsafe {
        let manager = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        assert!(!manager.is_null());
        let service = OpenServiceW(
            manager,
            wide("SafeYolo1671Fixture").as_ptr(),
            SERVICE_QUERY_STATUS,
        );
        if service.is_null() {
            CloseServiceHandle(manager);
            panic!("owned service unavailable");
        }
        let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut bytes = 0;
        let result = QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes,
        );
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        assert_ne!(result, 0);
        (status.dwCurrentState, status.dwProcessId)
    }
}

fn starter_result(fixture: &mut Fixture, name: &str) -> bool {
    starter_result_arguments(fixture, name, BTreeMap::new())
}

fn starter_result_arguments(
    fixture: &mut Fixture,
    name: &str,
    arguments: BTreeMap<String, serde_json::Value>,
) -> bool {
    let resource = fixture.target.package.operations[name]
        .resources
        .iter()
        .next()
        .unwrap()
        .clone();
    let (receipt, _) = fixture.invoke_arguments(name, &resource, arguments);
    let result = fixture.terminal(&receipt.job_id);
    let Response::Output {
        data_base64, eof, ..
    } = fixture.call(Action::Output {
        job_id: receipt.job_id,
        offset: 0,
        max_bytes: fixture.target.package.operations[name]
            .execution
            .resources
            .output_bytes,
    })
    else {
        panic!("starter output unavailable")
    };
    assert!(eof, "starter output is incomplete");
    let bytes = STANDARD.decode(data_base64).unwrap();
    assert_eq!(bytes.len() as u64, result.output_bytes);
    // Keep the original bytes even when a native Windows command emits its
    // console code page instead of UTF-8. The native API carries binary output;
    // undecoded text must not discard its receipt or stop unrelated cases.
    let text = String::from_utf8(bytes.clone()).ok();
    let observation = text
        .as_deref()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok());
    println!(
        "{}",
        serde_json::json!({"case":name,"receipt":result,"output":text,
            "output_base64":STANDARD.encode(&bytes),"observation":observation})
    );
    assert!(result.native.as_ref().unwrap().processes_stopped);
    assert!(!result.native.as_ref().unwrap().output_truncated);
    if result.state == JobState::Completed
        && fixture.target.package.operations[name]
            .execution
            .executable
            .to_ascii_lowercase()
            .ends_with("powershell.exe")
    {
        assert!(
            observation.is_some(),
            "completed PowerShell recipe did not return UTF-8 JSON"
        );
    }
    if name == "software-inventory" && result.state == JobState::Completed {
        let observation = observation.as_ref().expect("software inventory JSON");
        let data = observation["data"]
            .as_array()
            .expect("software inventory rows");
        assert_eq!(observation["count"].as_u64(), Some(data.len() as u64));
        assert!(data.iter().all(|row| row["registryKey"].is_string()));
    }
    result.state == JobState::Completed
}

fn starters(root: PathBuf, service: bool, selected: Option<&str>, attempt: Option<&str>) {
    let service_operations = [
        "service-status",
        "service-start",
        "service-status",
        "service-restart",
        "service-stop",
        "service-status",
    ];
    assert!(
        selected
            .is_none_or(|name| STARTER_READS.contains(&name) || service_operations.contains(&name)),
        "unknown starter operation; no case executed"
    );
    let mut fixture = Fixture::new(root, service);
    // Distinct phase IDs retain foreground/service results and make an explicit
    // one-operation continuation possible after inspecting an earlier failure.
    fixture.phase = format!("starters-{}-{}", fixture.phase, selected.unwrap_or("all"));
    if let Some(attempt) = attempt {
        fixture.phase.push_str(&format!("-{attempt}"));
    }
    let receiver = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 19477)).unwrap();
    receiver.set_nonblocking(true).unwrap();
    let mut failed = Vec::new();
    let operations: Vec<_> = if let Some(name) = selected {
        vec![name]
    } else {
        service_operations
            .into_iter()
            .chain(STARTER_READS.iter().copied())
            .collect()
    };
    let mut started = None;
    for name in operations {
        if !starter_result(&mut fixture, name) {
            failed.push(name);
        }
        if ["service-start", "service-restart", "service-stop"].contains(&name) {
            let deadline = Instant::now() + Duration::from_secs(5);
            let state = loop {
                let observed = observed_service();
                if observed.0
                    == if name == "service-stop" {
                        SERVICE_STOPPED
                    } else {
                        SERVICE_RUNNING
                    }
                {
                    break observed;
                }
                assert!(
                    Instant::now() < deadline,
                    "owned service did not settle: {observed:?}"
                );
                std::thread::sleep(Duration::from_millis(20));
            };
            if name == "service-start" {
                started = Some(state.1);
            }
            if name == "service-restart"
                && let Some(previous) = started
            {
                assert_ne!(state.1, previous);
            }
            println!(
                "{}",
                serde_json::json!({"host_service_observer":name,"state":state.0,"pid":state.1})
            );
        }
        if name == "network-diagnostics" {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match receiver.accept() {
                    Ok((_, peer)) => {
                        println!("host TCP observer received {peer}");
                        break;
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => {
                        panic!("legitimate diagnostic did not reach owned receiver: {error}")
                    }
                }
            }
        }
    }
    if selected.is_none() {
        starter_refusals(&mut fixture);
    }
    assert!(
        failed.is_empty(),
        "starter jobs failed; inspect retained receipts/output before any continuation: {failed:?}"
    );
}

fn starter_refusals(fixture: &mut Fixture) {
    for (name, field, value) in [
        ("service-status", "service", "WinDefend"),
        ("event-log-query", "channel", "Security"),
        ("registry-query-machine", "hive", "HKCU"),
        ("registry-query-user", "hive", "HKLM"),
        ("registry-query-machine", "key", "SOFTWARE\\Other"),
        ("registry-query-machine", "view", "128"),
        ("file-inspect", "path", "C:\\Windows\\win.ini"),
    ] {
        let operation = &fixture.target.package.operations[name];
        let invocation = Invocation {
            operation_id: name.into(),
            resource_id: operation.resources.iter().next().unwrap().clone(),
            operation_sha256: fixture.target.package.operation_sha256(name).unwrap(),
            implementation_sha256: operation.implementation_sha256(),
            arguments: BTreeMap::from([(field.into(), serde_json::json!(value))]),
            expected_assessment_sha256: None,
        };
        let response = fixture.call(Action::Propose { invocation });
        assert!(
            matches!(&response, Response::Refused { refusal } if matches!(refusal.code, RefusalCode::Arguments | RefusalCode::Authority)),
            "{name}/{field}: {response:?}"
        );
        println!(
            "{}",
            serde_json::json!({"negative":name,"field":field,"value":value,"response":response})
        );
    }
}

fn bound_result(fixture: &mut Fixture, id: &str) -> (Receipt, Vec<u8>) {
    let result = fixture.terminal(id);
    let output = fixture.output(id);
    println!(
        "{}",
        serde_json::json!({"case":result.prepared.invocation.operation_id,
            "receipt":result,"output_base64":STANDARD.encode(&output)})
    );
    assert_eq!(output.len() as u64, result.output_bytes);
    assert!(result.native.as_ref().unwrap().processes_stopped);
    (result, output)
}

fn started_job(fixture: &mut Fixture, id: &str) -> Receipt {
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        let running = fixture.job(id);
        if running.output_bytes > 0 {
            return running;
        }
        assert!(
            Instant::now() < end,
            "workload did not produce its start marker: {running:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn bounds(fixture: &mut Fixture) {
    for mode in ["observe", "memory", "tasks", "background"] {
        let (receipt, _) = fixture.invoke(mode);
        let (result, output) = bound_result(fixture, &receipt.job_id);
        assert_eq!(result.state, JobState::Completed, "{result:?}");
        let output = String::from_utf8(output).unwrap();
        println!("{mode}: {output}");
        if mode == "memory" {
            assert!(output.contains("allocation_refused"));
        }
        if mode == "tasks" {
            assert!(output.contains("process_limit_reached"));
        }
    }
    let (receipt, _) = fixture.invoke("flood");
    let (result, output) = bound_result(fixture, &receipt.job_id);
    assert_eq!(
        result.native.as_ref().unwrap().termination_reason,
        "output_limit"
    );
    assert!(result.native.unwrap().processes_stopped);
    assert!(output.len() <= 64 * 1024);
    let (receipt, _) = fixture.invoke("wait");
    started_job(fixture, &receipt.job_id);
    let processes = observe_job_processes(fixture, &receipt);
    let (result, _) = bound_result(fixture, &receipt.job_id);
    assert_eq!(
        result.native.as_ref().unwrap().termination_reason,
        "timeout"
    );
    for process in processes {
        assert_eq!(
            unsafe { WaitForSingleObject(process.0, 5000) },
            WAIT_OBJECT_0
        );
    }
    let (receipt, _) = fixture.invoke("wait");
    let running = started_job(fixture, &receipt.job_id);
    let processes = observe_job_processes(fixture, &receipt);
    fixture.call(Action::Cancel {
        job_id: receipt.job_id.clone(),
        expected_revision: running.revision,
    });
    assert_eq!(
        bound_result(fixture, &receipt.job_id).0.state,
        JobState::Cancelled
    );
    for process in processes {
        assert_eq!(
            unsafe { WaitForSingleObject(process.0, 5000) },
            WAIT_OBJECT_0
        );
    }
}

fn native(root: PathBuf, service: bool) {
    let mut fixture = Fixture::new(root, service);
    bounds(&mut fixture);
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

fn path_boundaries(root: &Path) {
    let original = load(root);
    let program = probe_path(root);
    let file_link = root.join("programs with spaces/probe-link.exe");
    let directory_link = root.join("program-link");
    std::os::windows::fs::symlink_file(&program, &file_link).unwrap();
    std::os::windows::fs::symlink_dir(program.parent().unwrap(), &directory_link).unwrap();
    let paths = [
        ("absolute", program.to_str().unwrap().to_owned(), true),
        (
            "verbatim-local",
            format!("\\\\?\\{}", program.display()),
            false,
        ),
        ("trailing-dot", format!("{}.", program.display()), false),
        ("trailing-space", format!("{} ", program.display()), false),
        (
            "alternate-stream",
            format!("{}:stream", program.display()),
            false,
        ),
        (
            "parent-component",
            format!(
                "{}\\..\\programs with spaces\\probe.exe",
                program.parent().unwrap().display()
            ),
            false,
        ),
        ("drive-relative", "C:probe.exe".into(), false),
        (
            "unc",
            "\\\\localhost\\C$\\Windows\\System32\\whoami.exe".into(),
            false,
        ),
        (
            "device",
            "\\\\.\\C:\\Windows\\System32\\whoami.exe".into(),
            false,
        ),
        ("file-reparse", file_link.to_str().unwrap().into(), false),
        (
            "ancestor-reparse",
            directory_link.join("probe.exe").to_str().unwrap().into(),
            false,
        ),
    ];
    for (name, path, allowed) in paths {
        let mut candidate = original.clone();
        candidate
            .target
            .package
            .operations
            .get_mut("observe")
            .unwrap()
            .execution
            .executable = path;
        let pin = candidate.target.package.operations["observe"].implementation_sha256();
        candidate
            .target
            .ceiling
            .get_mut("observe")
            .unwrap()
            .implementation_sha256 = pin.clone();
        candidate
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
            .implementation_sha256 = pin;
        let config = root.join(format!("control/path-{name}.json"));
        assert!(!config.exists());
        fs::write(&config, serde_json::to_vec_pretty(&candidate).unwrap()).unwrap();
        let output = Process::new(executor())
            .arg("check")
            .arg("--config")
            .arg(&config)
            .arg("--state")
            .arg(root.join("control/state"))
            .output()
            .unwrap();
        println!(
            "{}",
            serde_json::json!({"path_case":name,"allowed":allowed,
            "exit":output.status.code(),"stdout":String::from_utf8_lossy(&output.stdout),
            "stderr":String::from_utf8_lossy(&output.stderr)})
        );
        assert_eq!(output.status.success(), allowed, "path case {name}");
        if !allowed {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("Unavailable"),
                "wrong refusal for {name}"
            );
        }
        fs::remove_file(config).unwrap();
    }
    fs::remove_file(file_link).unwrap();
    fs::remove_dir(directory_link).unwrap();
}

fn inherited_handles(fixture: &mut Fixture) {
    let sentinel = fixture.root.join("control/handle-sentinel.txt");
    assert!(!sentinel.exists());
    fs::write(&sentinel, b"private handle sentinel").unwrap();
    let file = OpenOptions::new().read(true).open(&sentinel).unwrap();
    let handle = file.as_raw_handle();
    assert_ne!(
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
        0
    );
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    assert_ne!(unsafe { GetFileInformationByHandle(handle, &mut info) }, 0);
    let input = |value: HANDLE| {
        serde_json::json!({"handle":value as usize,
        "volume":info.dwVolumeSerialNumber,"high":info.nFileIndexHigh,"low":info.nFileIndexLow})
    };
    fs::write(
        fixture.root.join("work/handle-control-input.json"),
        input(handle).to_string(),
    )
    .unwrap();
    // A positive control uses ordinary Win32 inheritance. This must expose the
    // sentinel to the same sensor that checks the actual executor's child.
    let mut command = wide(&format!(
        "\"{}\" --probe handles-control \"{}\" unused",
        probe_path(&fixture.root).display(),
        fixture.root.display()
    ));
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    assert_ne!(
        unsafe {
            CreateProcessW(
                wide(probe_path(&fixture.root).to_str().unwrap()).as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                0,
                null(),
                null(),
                &startup,
                &mut process,
            )
        },
        0
    );
    let child = Handle(process.hProcess);
    let _thread = Handle(process.hThread);
    let waited = unsafe { WaitForSingleObject(child.0, 10000) };
    if waited != WAIT_OBJECT_0 {
        unsafe {
            TerminateProcess(child.0, 1);
        }
    }
    assert_eq!(
        waited, WAIT_OBJECT_0,
        "inheritance sensor control did not exit"
    );
    let control: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.root.join("work/handle-control-observation.json")).unwrap(),
    )
    .unwrap();
    println!(
        "{}",
        serde_json::json!({"inherited_handle_control":control})
    );
    assert_eq!(control["sentinel_inherited"], true);
    assert!(!matches!(
        fixture.call(Action::Discover),
        Response::Refused { .. }
    ));
    let pid = fixture.server_pid.get();
    assert_ne!(pid, 0);
    let server = Handle(unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) });
    assert!(!server.0.is_null());
    let mut remote = null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                server.0,
                &mut remote,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        },
        0
    );
    fs::write(
        fixture.root.join("work/handle-input.json"),
        input(remote).to_string(),
    )
    .unwrap();
    let (receipt, _) = fixture.invoke("handles");
    let result = fixture.terminal(&receipt.job_id);
    let bytes = fixture.output(&receipt.job_id);
    println!(
        "{}",
        serde_json::json!({"case":"inherited-handles","receipt":result,"output_base64":STANDARD.encode(&bytes),"executor_pid":pid,"inheritable_handle":remote as usize})
    );
    assert_eq!(result.state, JobState::Completed);
    let observed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(observed["sentinel_inherited"], false);
    let host: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.root.join("work/handle-observation.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(host, observed);
    assert_eq!(fs::read(&sentinel).unwrap(), b"private handle sentinel");
    let mut closed = null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                server.0,
                remote,
                GetCurrentProcess(),
                &mut closed,
                0,
                0,
                DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            )
        },
        0
    );
    drop(Handle(closed));
    drop(file);
    fs::remove_file(sentinel).unwrap();
}

fn api_authority(fixture: &mut Fixture) {
    use ring::signature::KeyPair;
    let original = fs::read(config_path(&fixture.root)).unwrap();
    let backup = fixture
        .root
        .join(format!("control/{}-before.json", fixture.phase));
    assert!(!backup.exists());
    fs::write(backup, &original).unwrap();
    let mut config = load(&fixture.root);
    let mut other_grant = config.target.issuers["issuer"].authority.grants["grant"].clone();
    other_grant.principal.run.agent = "other".into();
    other_grant.principal.run.agent_id = "ag-other".into();
    other_grant.principal.run.run_id = "22222222222222222222222222222222".into();
    config
        .target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .insert("other".into(), other_grant);
    let mut other_issuer = config.target.issuers["issuer"].clone();
    let key = Ed25519KeyPair::from_seed_unchecked(&[59; 32]).unwrap();
    other_issuer
        .public_keys
        .insert("key".into(), STANDARD.encode(key.public_key().as_ref()));
    config.target.issuers.insert("other".into(), other_issuer);
    fs::write(
        config_path(&fixture.root),
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
    fixture.target = config.target;
    assert!(matches!(
        fixture.call(Action::Discover),
        Response::Discovery { .. }
    ));
    let (receipt, invoke) = fixture.invoke("observe");
    let result = fixture.terminal(&receipt.job_id);
    let output = fixture.output(&receipt.job_id);
    println!(
        "{}",
        serde_json::json!({"case":"authority-useful","receipt":result,"output_base64":STANDARD.encode(&output)})
    );
    assert_eq!(result.state, JobState::Completed);
    assert_eq!(
        fs::read(fixture.root.join("work/allowed.txt")).unwrap(),
        b"workload write under explicit broader account filesystem permission"
    );
    let Response::Job { receipt: replay } = fixture.bytes(Verb::Invoke, &invoke) else {
        panic!("same-request replay refused")
    };
    assert_eq!(replay.job_id, receipt.job_id);
    let mut invocation = receipt.prepared.invocation.clone();
    invocation.expected_assessment_sha256 = None;
    let actions = vec![
        Action::Discover,
        Action::Propose {
            invocation: invocation.clone(),
        },
        Action::Invoke {
            invocation: invocation.clone(),
        },
        Action::Job {
            job_id: receipt.job_id.clone(),
        },
        Action::Output {
            job_id: receipt.job_id.clone(),
            offset: 0,
            max_bytes: 1024,
        },
        Action::Cancel {
            job_id: receipt.job_id.clone(),
            expected_revision: result.revision,
        },
    ];
    for action in &actions {
        let mut signed: SignedRequest =
            serde_json::from_slice(&fixture.signed(action.clone())).unwrap();
        signed.signature = STANDARD.encode([0; 64]);
        let response = fixture.bytes(action.verb(), &serde_json::to_vec(&signed).unwrap());
        println!(
            "{}",
            serde_json::json!({"authority_case":"bad-signature","verb":action.verb(),"response":response})
        );
        assert!(
            matches!(response, Response::Refused { refusal } if refusal.code == RefusalCode::Signature)
        );
    }
    for (issuer, grant) in [("issuer", "other"), ("other", "grant")] {
        for action in &actions {
            // Proposals and discovery are legitimate for each independently
            // granted actor. Only the original actor may access the saved job.
            if matches!(action, Action::Invoke { .. }) {
                continue;
            }
            let signed = fixture.signed_as(action.clone(), issuer, grant);
            let response = fixture.bytes(action.verb(), &signed);
            println!(
                "{}",
                serde_json::json!({"authority_case":"other-actor","issuer":issuer,"grant":grant,"verb":action.verb(),"response":response})
            );
            match action {
                Action::Discover => assert!(matches!(response, Response::Discovery { .. })),
                Action::Propose { .. } => assert!(matches!(response, Response::Proposal { .. })),
                _ => assert!(
                    matches!(response, Response::Refused { refusal } if refusal.code == RefusalCode::Authority)
                ),
            }
        }
    }
    for (case, expected) in [
        ("wrong-principal", RefusalCode::Principal),
        ("expired", RefusalCode::Expired),
        ("wrong-target", RefusalCode::Target),
    ] {
        let mut signed: SignedRequest =
            serde_json::from_slice(&fixture.signed(Action::Discover)).unwrap();
        match case {
            "wrong-principal" => signed.request.principal.run.agent_id = "ag-forged".into(),
            "expired" => signed.request.expires_at = now() - 1,
            _ => signed.request.target_id = "unselected-target".into(),
        }
        let signed = SignedRequest::sign(
            signed.request,
            "key".into(),
            &Ed25519KeyPair::from_seed_unchecked(&[58; 32]).unwrap(),
        );
        let response = fixture.bytes(Verb::Discover, &serde_json::to_vec(&signed).unwrap());
        println!(
            "{}",
            serde_json::json!({"authority_case":case,"response":response})
        );
        assert!(matches!(response, Response::Refused { refusal } if refusal.code == expected));
    }
    let mut expanded = invocation.clone();
    expanded.resource_id = "ungranted-resource".into();
    let response = fixture.call(Action::Propose {
        invocation: expanded,
    });
    println!(
        "{}",
        serde_json::json!({"authority_case":"resource-expansion","response":response})
    );
    assert!(
        matches!(response, Response::Refused { refusal } if refusal.code == RefusalCode::Authority)
    );
    let mut definitions: serde_json::Value =
        serde_json::from_slice(&fixture.signed(Action::Invoke { invocation })).unwrap();
    definitions["request"]["definitions"] = serde_json::json!({"operation":"caller replacement"});
    let response = fixture.bytes(Verb::Invoke, &serde_json::to_vec(&definitions).unwrap());
    println!(
        "{}",
        serde_json::json!({"authority_case":"caller-definitions","response":response})
    );
    assert!(
        matches!(response, Response::Refused { refusal } if refusal.code == RefusalCode::Malformed)
    );
    assert_eq!(fixture.job(&receipt.job_id).state, JobState::Completed);
    assert_eq!(fixture.output(&receipt.job_id), output);
    fs::write(config_path(&fixture.root), original).unwrap();
    fixture.target = load(&fixture.root).target;
}

fn job_count(fixture: &Fixture) -> i64 {
    rusqlite::Connection::open_with_flags(
        fixture.root.join("control/state/jobs.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row("SELECT count(*) FROM jobs", [], |row| row.get(0))
    .unwrap()
}

fn catalogue_updates(fixture: &mut Fixture, resume: bool) {
    use ring::signature::KeyPair;
    let path = config_path(&fixture.root);
    let original = fs::read(if resume {
        fixture.root.join("control/updates-original.json")
    } else {
        path.clone()
    })
    .unwrap();
    let observed = fixture.root.join("control/update-observed.json");
    let program = fixture.root.join("programs with spaces/update-probe.exe");
    let mut config = load(&fixture.root);
    let key = Ed25519KeyPair::from_seed_unchecked(&[58; 32]).unwrap();
    let sign = |package: &Package, withdrawn| {
        SignedCatalogue::sign(
            CatalogueRevision {
                publisher: "publisher".into(),
                announcement_revision: package.version,
                package: package.clone(),
                observed_at: now() - 1,
                expires_at: now() + 600,
                withdrawn,
                previous: None,
            },
            &key,
        )
    };
    if !resume {
        assert!(
            !observed.exists() && !program.exists(),
            "inspect a previous update attempt before resuming"
        );
        fs::copy(probe_path(&fixture.root), &program).unwrap();
        let op = config.target.package.operations.get_mut("observe").unwrap();
        op.execution.executable = program.to_str().unwrap().into();
        let rule = UpdateRule {
            ceiling: op.clone(),
            allow_narrower: true,
            allow_implementation_updates: true,
        };
        let pin = op.implementation_sha256();
        for scope in [
            config.target.ceiling.get_mut("observe").unwrap(),
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
                .unwrap(),
        ] {
            scope.implementation_sha256 = pin.clone();
            scope.updates = Some(rule.clone());
        }
        let active = sign(&config.target.package, false);
        fs::write(&observed, serde_json::to_vec(&active).unwrap()).unwrap();
        config.catalogue = Some(CatalogueAdoption {
            policy: CataloguePolicy {
                publisher: "publisher".into(),
                public_key: STANDARD.encode(key.public_key().as_ref()),
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
    } else {
        assert!(
            observed.exists() && program.exists() && config.catalogue.is_some(),
            "resume requires retained adopted update input"
        );
    }
    let authority = revision(&(&config.target.ceiling, &config.target.issuers));
    let policy = revision(&config.catalogue.as_ref().unwrap().policy);
    fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    fixture.target = config.target;
    let announce = |fixture: &mut Fixture, package: &Package, withdrawn| {
        fs::write(
            &observed,
            serde_json::to_vec(&sign(package, withdrawn)).unwrap(),
        )
        .unwrap();
        let Response::Discovery { discovery } = fixture.call(Action::Discover) else {
            panic!("catalogue discovery refused")
        };
        let saved = load(&fixture.root);
        assert_eq!(
            revision(&(&saved.target.ceiling, &saved.target.issuers)),
            authority
        );
        assert_eq!(revision(&saved.catalogue.as_ref().unwrap().policy), policy);
        fixture.target = saved.target;
        let status = discovery.catalogue.unwrap();
        println!(
            "{}",
            serde_json::json!({"catalogue_observation":status,"job_count":job_count(fixture)})
        );
        status
    };
    let execute = |fixture: &mut Fixture, expected: &str| {
        let (receipt, _) = fixture.invoke("observe");
        let result = fixture.terminal(&receipt.job_id);
        let bytes = fixture.output(&receipt.job_id);
        println!(
            "{}",
            serde_json::json!({"case":"catalogue-useful","receipt":result,"output_base64":STANDARD.encode(&bytes)})
        );
        assert_eq!(result.state, JobState::Completed);
        assert!(String::from_utf8(bytes).unwrap().contains(expected));
        assert_eq!(
            fs::read(fixture.root.join("work/allowed.txt")).unwrap(),
            b"workload write under explicit broader account filesystem permission"
        );
    };
    let needle = b"safeyolo-windows-probe-revision=1".as_slice();
    let marker1 = std::str::from_utf8(needle).unwrap();
    let count = job_count(fixture);
    let mut package = fixture.target.package.clone();
    if !resume {
        execute(fixture, marker1);
        package.version += 1;
        package.source.version = "cosmetic metadata".into();
        package.operations.get_mut("observe").unwrap().description =
            "Current diagnostic description".into();
        let status = announce(fixture, &package, false);
        assert_eq!(status.state, "active");
        assert_eq!(status.changes["observe"].comparison, Comparison::Equivalent);
        execute(fixture, marker1);
        package.version += 1;
        package
            .operations
            .get_mut("observe")
            .unwrap()
            .execution
            .resources
            .timeout_seconds = 4;
        let status = announce(fixture, &package, false);
        assert_eq!(status.state, "active");
        assert_eq!(status.changes["observe"].comparison, Comparison::Narrower);
        execute(fixture, marker1);
    }
    let mut bytes = fs::read(&program).unwrap();
    let positions = bytes
        .windows(needle.len())
        .enumerate()
        .filter_map(|(i, b)| (b == needle).then_some(i))
        .collect::<Vec<_>>();
    assert!(!positions.is_empty(), "probe revision marker is absent");
    println!(
        "{}",
        serde_json::json!({"patched_marker_copies":positions.len(),"resume":resume})
    );
    for position in positions {
        bytes[position + needle.len() - 1] = b'2';
    }
    let modified = fs::metadata(&program).unwrap().modified().unwrap();
    let length = bytes.len();
    fs::write(&program, bytes).unwrap();
    OpenOptions::new()
        .write(true)
        .open(&program)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(fs::metadata(&program).unwrap().len() as usize, length);
    assert_eq!(
        fs::metadata(&program).unwrap().modified().unwrap(),
        modified
    );
    package.version += 1;
    package
        .operations
        .get_mut("observe")
        .unwrap()
        .execution
        .executable_sha256 = hash(&program);
    assert_eq!(announce(fixture, &package, false).state, "active");
    let marker2 = marker1.strip_suffix('1').unwrap().to_owned() + "2";
    execute(fixture, &marker2);
    let active = package.clone();
    for label in ["recipe", "default", "alias", "selector", "enforcement"] {
        let mut candidate = active.clone();
        package.version += 1;
        candidate.version = package.version;
        let op = candidate.operations.get_mut("observe").unwrap();
        match label {
            "recipe" => op.execution.argv[1] = literal("flood"),
            "default" => {
                op.arguments.insert(
                    "new-default".into(),
                    Argument {
                        kind: ArgumentType::Integer,
                        required: false,
                        default: Some(1.into()),
                        options: Vec::new(),
                    },
                );
            }
            "alias" => {
                let op = op.clone();
                candidate.operations.insert("observe-alias".into(), op);
            }
            "selector" => {
                op.resources.insert("other-resource".into());
            }
            _ => op
                .enforcement
                .unresolved
                .push("required containment unavailable".into()),
        }
        let status = announce(fixture, &candidate, false);
        println!(
            "{}",
            serde_json::json!({"catalogue_case":label,"state":status.state})
        );
        assert_eq!(status.state, "awaiting_review");
        assert_eq!(revision(&fixture.target.package), revision(&active));
        assert_eq!(job_count(fixture), count + if resume { 1 } else { 4 });
    }
    package.operations = active.operations;
    package.version += 1;
    assert_eq!(announce(fixture, &package, false).state, "active");
    package.version += 1;
    let status = announce(fixture, &package, true);
    assert_eq!(status.state, "withdrawn");
    assert_eq!(status.active, revision(&fixture.target.package));
    assert_eq!(job_count(fixture), count + if resume { 1 } else { 4 });
    println!(
        "{}",
        serde_json::json!({"catalogue_case":"withdraw-retain","state":status.state,"persistent_file_present":fixture.root.join("work/allowed.txt").exists()})
    );
    fs::write(&path, original).unwrap();
    fixture.target = load(&fixture.root).target;
    fs::remove_file(observed).unwrap();
    fs::remove_file(program).unwrap();
}

fn lifecycle_authority(fixture: &mut Fixture) {
    let path = config_path(&fixture.root);
    let original = fs::read(&path).unwrap();
    let (receipt, _) = fixture.invoke("observe");
    let result = fixture.terminal(&receipt.job_id);
    let bytes = fixture.output(&receipt.job_id);
    println!(
        "{}",
        serde_json::json!({"case":"lifecycle-useful","receipt":result,"output_base64":STANDARD.encode(&bytes)})
    );
    assert_eq!(result.state, JobState::Completed);
    let persisted = fixture.root.join("work/allowed.txt");
    let effect = fs::read(&persisted).unwrap();
    for (case, expected) in [
        ("revoked", RefusalCode::Authority),
        ("expired", RefusalCode::Expired),
        ("missing-configuration", RefusalCode::Unavailable),
    ] {
        let signed = fixture.signed(Action::Output {
            job_id: receipt.job_id.clone(),
            offset: 0,
            max_bytes: 1024,
        });
        let mut config = load(&fixture.root);
        match case {
            "revoked" => {
                config
                    .target
                    .issuers
                    .get_mut("issuer")
                    .unwrap()
                    .authority
                    .grants
                    .remove("grant");
            }
            "expired" => {
                config
                    .target
                    .issuers
                    .get_mut("issuer")
                    .unwrap()
                    .authority
                    .grants
                    .get_mut("grant")
                    .unwrap()
                    .expires_at = now()
            }
            _ => (),
        }
        if case == "missing-configuration" {
            fs::remove_file(&path).unwrap();
        } else {
            fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        }
        let response = fixture.bytes(Verb::Output, &signed);
        println!(
            "{}",
            serde_json::json!({"lifecycle_case":case,"response":response,"persistent_file_sha256":hash(&persisted)})
        );
        assert!(matches!(response, Response::Refused { refusal } if refusal.code == expected));
        assert_eq!(
            fs::read(&persisted).unwrap(),
            effect,
            "ending permission does not erase an earlier effect"
        );
        fs::write(&path, &original).unwrap();
        assert_eq!(
            fixture.output(&receipt.job_id),
            bytes,
            "restored configuration must recover retained output"
        );
    }
    assert_eq!(fixture.job(&receipt.job_id).state, JobState::Completed);
}

fn recover_controller(fixture: &mut Fixture) {
    let (receipt, signed) = fixture.invoke("wait");
    println!("crash check admitted job {}", receipt.job_id);
    started_job(fixture, &receipt.job_id);
    let processes = observe_job_processes(fixture, &receipt);
    restart(fixture);
    for process in &processes {
        assert_eq!(
            unsafe { WaitForSingleObject(process.0, 5000) },
            WAIT_OBJECT_0
        );
    }
    let uncertain = fixture.job(&receipt.job_id);
    println!("{}", serde_json::json!({"crash_receipt":uncertain}));
    assert_eq!(uncertain.state, JobState::Uncertain);
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

fn observe_job_processes(fixture: &Fixture, receipt: &Receipt) -> Vec<Handle> {
    // Observe each exact process handle before termination; PID reuse cannot make
    // this check mistake another process for the original workload. Close our
    // temporary Job handle before killing the executor so kill-on-close applies.
    let job_name = wide(&format!(
        "Local\\SafeYolo-host-{}-{}",
        fixture.target.target_id, receipt.job_id
    ));
    let job = Handle(unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, job_name.as_ptr()) });
    assert!(!job.0.is_null());
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    assert_ne!(
        unsafe {
            QueryInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
                null_mut(),
            )
        },
        0
    );
    let expected = &fixture.target.package.operations[&receipt.prepared.invocation.operation_id]
        .execution
        .resources;
    let flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_JOB_MEMORY;
    assert_eq!(limits.BasicLimitInformation.LimitFlags & flags, flags);
    assert_eq!(
        limits.BasicLimitInformation.ActiveProcessLimit,
        expected.processes
    );
    assert_eq!(limits.JobMemoryLimit as u64, expected.memory_bytes);
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
    println!(
        "{}",
        serde_json::json!({"job_observer":receipt.job_id,
        "pids":&ids.pids[..ids.listed as usize],"memory_limit":limits.JobMemoryLimit,
        "process_limit":limits.BasicLimitInformation.ActiveProcessLimit,
        "limit_flags":limits.BasicLimitInformation.LimitFlags})
    );
    ids.pids[..ids.listed as usize]
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
        .collect()
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
            operation_sha256: fixture.target.package.operation_sha256("observe").unwrap(),
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
    if mode == "handles" || mode == "handles-control" {
        let prefix = if mode == "handles-control" {
            "handle-control"
        } else {
            "handle"
        };
        let input: serde_json::Value = serde_json::from_slice(
            &fs::read(root.join(format!("work/{prefix}-input.json"))).unwrap(),
        )
        .unwrap();
        let handle = input["handle"].as_u64().unwrap() as usize as HANDLE;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let queried = unsafe { GetFileInformationByHandle(handle, &mut info) } != 0;
        let observed = serde_json::json!({"handle":input["handle"],"handle_query_succeeded":queried,
            "sentinel_inherited":queried && input["volume"] == info.dwVolumeSerialNumber
                && input["high"] == info.nFileIndexHigh && input["low"] == info.nFileIndexLow});
        fs::write(
            root.join(format!("work/{prefix}-observation.json")),
            observed.to_string(),
        )
        .unwrap();
        println!("{observed}");
    } else if mode == "observe" {
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
        println!("safeyolo-windows-probe-revision=1");
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
        Some("--starter-prepare") if args.len() == 3 => {
            prepare_starters(Path::new(&args[1]), &args[2])
        }
        Some("--starters") if args.len() == 2 || args.len() == 3 => starters(
            PathBuf::from(&args[1]),
            args.get(2).is_some_and(|s| s == "--service"),
            None,
            None,
        ),
        Some("--starter") if args.len() == 3 || args.len() == 4 => starters(
            PathBuf::from(&args[1]),
            args.get(3).is_some_and(|s| s == "--service"),
            Some(&args[2]),
            None,
        ),
        Some("--starter-attempt") if args.len() == 4 || args.len() == 5 => starters(
            PathBuf::from(&args[1]),
            args.get(4).is_some_and(|s| s == "--service"),
            Some(&args[2]),
            Some(&args[3]),
        ),
        Some("--starter-refusals") if args.len() == 2 || args.len() == 3 => {
            let mut fixture = Fixture::new(
                PathBuf::from(&args[1]),
                args.get(2).is_some_and(|s| s == "--service"),
            );
            fixture.phase = format!("starter-refusals-{}", fixture.phase);
            starter_refusals(&mut fixture);
        }
        Some("--native") if args.len() == 2 || args.len() == 3 => native(
            PathBuf::from(&args[1]),
            args.get(2).is_some_and(|s| s == "--service"),
        ),
        Some("--bounds") if args.len() == 3 || args.len() == 4 => {
            let mut fixture = Fixture::new(
                PathBuf::from(&args[1]),
                args.get(3).is_some_and(|s| s == "--service"),
            );
            fixture.phase = format!("bounds-{}-{}", fixture.phase, args[2]);
            bounds(&mut fixture);
        }
        Some("--paths") if args.len() == 2 => path_boundaries(Path::new(&args[1])),
        Some("--handles") if args.len() == 3 || args.len() == 4 => {
            let mut fixture = Fixture::new(
                PathBuf::from(&args[1]),
                args.get(3).is_some_and(|s| s == "--service"),
            );
            fixture.phase = format!("handles-{}-{}", fixture.phase, args[2]);
            inherited_handles(&mut fixture);
        }
        Some("--authority") if args.len() == 3 || args.len() == 4 => {
            let mut fixture = Fixture::new(
                PathBuf::from(&args[1]),
                args.get(3).is_some_and(|s| s == "--service"),
            );
            fixture.phase = format!("authority-{}-{}", fixture.phase, args[2]);
            api_authority(&mut fixture);
        }
        Some(mode @ ("--updates" | "--updates-resume")) if args.len() == 3 || args.len() == 4 => {
            let mut fixture = Fixture::new(
                PathBuf::from(&args[1]),
                args.get(3).is_some_and(|s| s == "--service"),
            );
            fixture.phase = format!("updates-{}-{}", fixture.phase, args[2]);
            catalogue_updates(&mut fixture, mode == "--updates-resume");
        }
        Some("--lifecycle") if args.len() == 3 || args.len() == 4 => {
            let mut fixture = Fixture::new(
                PathBuf::from(&args[1]),
                args.get(3).is_some_and(|s| s == "--service"),
            );
            fixture.phase = format!("lifecycle-{}-{}", fixture.phase, args[2]);
            lifecycle_authority(&mut fixture);
        }
        Some(mode @ ("--registry" | "--registry-user")) if args.len() == 3 || args.len() == 4 => {
            let mut fixture = Fixture::new(
                PathBuf::from(&args[1]),
                args.get(3).is_some_and(|s| s == "--service"),
            );
            fixture.phase = format!("registry-{}-{}", fixture.phase, args[2]);
            for view in ["32", "64"] {
                assert!(starter_result_arguments(
                    &mut fixture,
                    if mode == "--registry-user" {
                        "registry-query-user"
                    } else {
                        "registry-query-machine"
                    },
                    BTreeMap::from([("view".into(), serde_json::json!(view))])
                ));
            }
        }
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
