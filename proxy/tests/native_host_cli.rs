//! Native operator configuration and instance isolation at the installed CLI.

use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::{Command, Output},
    time::Duration,
};

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(root)
        .args(args)
        .output()
        .unwrap()
}
fn value(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn initialize(root: &Path) {
    let output = cli(root, &["init"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::create_dir(root.join("bin")).unwrap();
    symlink(env!("CARGO_BIN_EXE_safeyolo"), root.join("bin/safeyolo")).unwrap();
    symlink(
        env!("CARGO_BIN_EXE_safeyolo-proxy"),
        root.join("bin/safeyolo-proxy"),
    )
    .unwrap();
}

fn initialize_tmux_launcher(root: &Path) {
    initialize(root);
    let paths = std::env::var_os("PATH").expect("native launcher fixtures require PATH");
    let tmux = std::env::split_paths(&paths)
        .map(|directory| directory.join("tmux"))
        .find(|path| {
            path.is_file() && fs::metadata(path).unwrap().permissions().mode() & 0o111 != 0
        })
        .expect("native launcher fixtures require an installed tmux executable");
    symlink(fs::canonicalize(tmux).unwrap(), root.join("bin/tmux")).unwrap();
}

struct StopOnDrop<'a>(&'a Path);
impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        let _ = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--config")
            .arg(self.0)
            .arg("stop")
            .output();
    }
}

#[test]
fn conflicting_ids_are_reported_by_admin_without_changing_agents() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let hook = temp.path().join("launcher.sh");
    let markers = temp.path().join("markers");
    fs::write(&markers, b"").unwrap();
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\nprintf '%s:%s\\n' \"$SAFEYOLO_AGENT_NAME\" \"$1\" >> '{}'\n",
            markers.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    let mut ids = Vec::new();
    for name in ["alpha", "beta", "gamma"] {
        let created = value(cli(
            &root,
            &[
                "agent",
                "create",
                name,
                "--workspace",
                workspace.to_str().unwrap(),
                "--launcher",
                "supervisor",
            ],
        ));
        ids.push(created["configuration"]["id"].as_str().unwrap().to_owned());
        let directory = root.join("agents").join(name);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("current-launch.json"),
            serde_json::to_vec(&serde_json::json!({
                "name":name,"agent_id":ids.last().unwrap(),"launch_id":format!("launch-{name}"),
                "state":"unknown","launcher":{"kind":"script","script":hook}
            }))
            .unwrap(),
        )
        .unwrap();
    }
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[0], ids[2]);
    assert_ne!(ids[1], ids[2]);
    let config = root.join("config.toml");
    let mut document: toml_edit::DocumentMut =
        fs::read_to_string(&config).unwrap().parse().unwrap();
    document["admin_port"] = toml_edit::value(0);
    fs::write(&config, document.to_string()).unwrap();
    let _stop = StopOnDrop(&config);
    value(cli(&root, &["start"]));
    let ready: Value =
        serde_json::from_slice(&fs::read(root.join("data/ready.json")).unwrap()).unwrap();
    let address = (
        std::net::Ipv4Addr::LOCALHOST,
        ready["admin_port"].as_u64().unwrap() as u16,
    );
    let token = fs::read_to_string(root.join("data/admin_token")).unwrap();
    let post = |id: &str, operation: &str| -> (u16, Value) {
        let mut stream =
            TcpStream::connect_timeout(&address.into(), Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "POST /admin/agents/{id}/{operation} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnull",
            token.trim()
        ).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let header_end = response
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap()
            + 4;
        let status = std::str::from_utf8(&response[..header_end])
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (
            status,
            serde_json::from_slice(&response[header_end..]).unwrap(),
        )
    };
    let policy = root.join("policy.toml");
    let mut document: toml_edit::DocumentMut =
        fs::read_to_string(&policy).unwrap().parse().unwrap();
    document["agents"]["beta"]["agent_id"] = toml_edit::value(&ids[0]);
    fs::write(&policy, document.to_string()).unwrap();
    let paths = [
        config.clone(),
        policy,
        root.join("agents/alpha/current-launch.json"),
        root.join("agents/beta/current-launch.json"),
        root.join("agents/gamma/current-launch.json"),
        markers.clone(),
    ];
    let before: Vec<_> = paths.iter().map(|path| fs::read(path).unwrap()).collect();
    let missing = post("ag-00000000000000000000000000000000", "stop");
    assert_eq!(missing.0, 404, "{}", missing.1);
    assert_eq!(missing.1["error"], "Agent not found");
    for operation in ["start", "start-interactive", "stop"] {
        let (status, refused) = post(&ids[0], operation);
        let error = refused["error"].as_str().unwrap();
        assert_eq!(status, 500, "{operation}: {refused}");
        assert!(
            error.contains("alpha") && error.contains("beta") && error.contains(&ids[0]),
            "{error}"
        );
        assert_eq!(
            paths
                .iter()
                .map(|path| fs::read(path).unwrap())
                .collect::<Vec<_>>(),
            before
        );
    }
    let (status, stopped) = post(&ids[2], "stop");
    assert_eq!(status, 200, "{stopped}");
    assert_eq!(stopped["name"], "gamma");
    assert_eq!(fs::read_to_string(&markers).unwrap(), "gamma:stop\n");
    for index in [1, 2, 3] {
        assert_eq!(fs::read(&paths[index]).unwrap(), before[index]);
    }
    value(cli(&root, &["stop"]));
    assert!(!root.join("data/ready.json").exists());
}

#[test]
fn conflicting_ids_reject_named_operations_without_touching_either_agent() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let hook = temp.path().join("launcher.sh");
    let markers = temp.path().join("markers");
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\nprintf '%s:%s\\n' \"$SAFEYOLO_AGENT_NAME\" \"$1\" >> '{}'\n",
            markers.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    let mut ids = Vec::new();
    for name in ["alpha", "beta"] {
        let created = value(cli(
            &root,
            &[
                "agent",
                "create",
                name,
                "--workspace",
                workspace.to_str().unwrap(),
                "--launcher",
                "supervisor",
            ],
        ));
        ids.push(created["configuration"]["id"].as_str().unwrap().to_owned());
        let directory = root.join("agents").join(name);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("current-launch.json"),
            serde_json::to_vec(&serde_json::json!({
                "name":name,"agent_id":ids.last().unwrap(),"launch_id":format!("launch-{name}"),
                "state":"unknown","launcher":{"kind":"script","script":hook}
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(value(cli(&root, &["agent", "stop", name]))["name"], name);
    }
    assert_ne!(ids[0], ids[1]);
    assert_eq!(
        fs::read_to_string(&markers).unwrap(),
        "alpha:stop\nbeta:stop\n"
    );
    let policy = root.join("policy.toml");
    let mut document: toml_edit::DocumentMut =
        fs::read_to_string(&policy).unwrap().parse().unwrap();
    document["agents"]["beta"]["agent_id"] = toml_edit::value(&ids[0]);
    document["agents"]["policy-only"]["hosts"]["example.com"]["egress"] = toml_edit::value("allow");
    fs::write(&policy, document.to_string()).unwrap();
    assert!(
        cli(&root, &["policy", "check", policy.to_str().unwrap()])
            .status
            .success()
    );
    let paths = [
        policy,
        root.join("config.toml"),
        root.join("agents/alpha/current-launch.json"),
        root.join("agents/beta/current-launch.json"),
        markers,
    ];
    let before: Vec<_> = paths.iter().map(|path| fs::read(path).unwrap()).collect();
    for name in ["alpha", "beta"] {
        for operation in [
            "stop", "start", "cleanup", "status", "attach", "shell", "present",
        ] {
            let rejected = cli(&root, &["agent", operation, name]);
            assert!(!rejected.status.success(), "{operation} {name}");
            let error = String::from_utf8_lossy(&rejected.stderr);
            assert!(
                error.contains("alpha")
                    && error.contains("beta")
                    && error.contains("durable identity"),
                "{error}"
            );
            assert_eq!(
                paths
                    .iter()
                    .map(|path| fs::read(path).unwrap())
                    .collect::<Vec<_>>(),
                before
            );
            assert!(!root.join("data/proxy-process.json").exists());
        }
    }
}

#[test]
fn rejected_launcher_selection_precedes_config_setup_and_proxy_or_backend_effects() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let unsafe_script = workspace.join("unsafe.sh");
    fs::write(&unsafe_script, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&unsafe_script, fs::Permissions::from_mode(0o755)).unwrap();
    let setup = temp.path().join("setup.sh");
    let setup_marker = temp.path().join("setup-ran");
    fs::write(
        &setup,
        format!("#!/bin/sh\ntouch '{}'\n", setup_marker.display()),
    )
    .unwrap();
    fs::set_permissions(&setup, fs::Permissions::from_mode(0o755)).unwrap();
    value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            workspace.to_str().unwrap(),
        ],
    ));
    let policy = fs::read(root.join("policy.toml")).unwrap();
    let original_config = fs::read_to_string(root.join("config.toml")).unwrap();
    let invalid = [
        "unsupported-review-launcher".to_owned(),
        "manager:/missing-817-manager".to_owned(),
        "manager:relative-script.sh".to_owned(),
        format!("manager:{}", unsafe_script.display()),
        "/missing-817-script".to_owned(),
    ];
    for launcher in invalid {
        for (operation, name) in [("create", "new"), ("configure", "marker")] {
            assert!(
                !cli(
                    &root,
                    &[
                        "agent",
                        operation,
                        name,
                        "--workspace",
                        workspace.to_str().unwrap(),
                        "--host-script",
                        setup.to_str().unwrap(),
                        "--launcher",
                        &launcher
                    ]
                )
                .status
                .success()
            );
            assert_eq!(fs::read(root.join("policy.toml")).unwrap(), policy);
            assert!(!setup_marker.exists());
        }
        let config = format!(
            "{original_config}\n[agent_launcher]\ndefault = {}\n",
            toml_edit::Value::from(launcher)
        );
        fs::write(root.join("config.toml"), &config).unwrap();
        let rejected = cli(&root, &["agent", "start", "marker"]);
        assert!(!rejected.status.success());
        assert_eq!(
            fs::read(root.join("config.toml")).unwrap(),
            config.as_bytes()
        );
        assert_eq!(fs::read(root.join("policy.toml")).unwrap(), policy);
        for path in [
            "logs/proxy.log",
            "data/proxy-process.json",
            "data/agent-map.json",
            "agents/marker/runtime.json",
            "agents/marker/config-share",
        ] {
            assert!(
                !root.join(path).exists(),
                "rejected launcher created {path}"
            );
        }
        fs::write(root.join("config.toml"), &original_config).unwrap();
    }
    let valid_script = temp.path().join("launcher.sh");
    fs::write(&valid_script, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&valid_script, fs::Permissions::from_mode(0o755)).unwrap();
    for launcher in [
        "tmux-window".to_owned(),
        "tmux-pane".to_owned(),
        "supervisor".to_owned(),
        valid_script.to_str().unwrap().to_owned(),
        format!("manager:{}", valid_script.display()),
    ] {
        value(cli(
            &root,
            &["agent", "configure", "marker", "--launcher", &launcher],
        ));
    }
}

#[test]
fn workflow_stop_inherits_the_selected_lock_without_releasing_the_parent_barrier() {
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    for name in ["marker", "other"] {
        value(cli(
            &root,
            &[
                "agent",
                "create",
                name,
                "--workspace",
                temp.path().to_str().unwrap(),
            ],
        ));
    }
    let directory = root.join("agents/marker");
    fs::create_dir_all(&directory).unwrap();
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("host-setup.lock"))
        .unwrap();
    let descriptor = lock.as_raw_fd();
    assert_eq!(unsafe { libc::flock(descriptor, libc::LOCK_EX) }, 0);
    let run = |name| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_safeyolo"));
        command
            .arg("--root")
            .arg(&root)
            .args(["agent", "stop", name])
            .env("SAFEYOLO_HOST_SETUP_LOCK_FD", descriptor.to_string());
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(descriptor, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.output().unwrap()
    };
    assert_eq!(value(run("marker"))["runtime_state"], "stopped");
    let contender = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.join("host-setup.lock"))
        .unwrap();
    assert_ne!(
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let rejected = run("other");
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("does not belong to the selected agent")
    );
    drop(lock);
    assert_eq!(
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
}

#[test]
fn invalid_local_start_selection_cannot_start_proxy_or_change_agent_state() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            temp.path().to_str().unwrap(),
        ],
    ));
    let policy = fs::read(root.join("policy.toml")).unwrap();
    for arguments in [
        vec!["agent", "start", "marker", "--foreground", "--sandbox-only"],
        vec![
            "agent",
            "start",
            "marker",
            "--sandbox-only",
            "--",
            "fixture argument",
        ],
        vec!["agent", "start", "marker", "--host-executable", "/fixture"],
    ] {
        assert!(!cli(&root, &arguments).status.success());
        assert_eq!(fs::read(root.join("policy.toml")).unwrap(), policy);
        assert!(!root.join("data/proxy-process.json").exists());
        assert!(!root.join("agents/marker/current-launch.json").exists());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn dead_vz_handle_and_stale_socket_can_be_cleaned_without_signalling_a_live_pid() {
    use std::os::unix::net::UnixListener;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            temp.path().to_str().unwrap(),
        ],
    ));
    let directory = root.join("agents/marker");
    fs::create_dir_all(&directory).unwrap();
    fs::create_dir_all(root.join("data/vm-control")).unwrap();
    let socket = root.join("data/vm-control/marker.sock");
    drop(UnixListener::bind(&socket).unwrap());
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    assert_eq!(
        unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        },
        size
    );
    let info = unsafe { info.assume_init() };
    assert_eq!(info.pbi_pid, child.id());
    assert!(info.pbi_start_tvsec > 0 && info.pbi_start_tvusec < 1_000_000);
    let backend_token = format!(
        "darwin:{pid}:{}:{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    );
    let record = directory.join("runtime.json");
    let mut run = serde_json::json!({
        "run_id":"0123456789abcdef0123456789abcdef",
        "backend_pid":child.id(), "backend_token":backend_token
    });
    fs::write(&record, serde_json::to_vec(&run).unwrap()).unwrap();
    let live = value(cli(&root, &["agent", "status", "marker"]));
    let stop = cli(&root, &["agent", "stop", "marker"]);
    let survived = child.try_wait().unwrap().is_none();
    let socket_preserved = socket.exists();
    fs::remove_file(&socket).unwrap();
    let without_control = cli(&root, &["agent", "status", "marker"]);
    drop(UnixListener::bind(&socket).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(live["runtime_state"], "unknown");
    assert!(!stop.status.success());
    assert!(survived, "an unrelated live PID was signalled");
    assert!(socket_preserved);
    let without_control = value(without_control);
    assert_eq!(without_control["runtime_state"], "unknown");
    assert!(without_control["next_action"].as_str().is_some());
    run["backend_token"] = "unrelated-fixture".into();
    let malformed_record = serde_json::to_vec(&run).unwrap();
    fs::write(&record, &malformed_record).unwrap();
    let unidentified_dead = value(cli(&root, &["agent", "status", "marker"]));
    assert_eq!(unidentified_dead["runtime_state"], "unknown");
    for operation in ["stop", "cleanup"] {
        assert!(!cli(&root, &["agent", operation, "marker"]).status.success());
        assert_eq!(fs::read(&record).unwrap(), malformed_record);
        assert!(socket.exists());
    }
    run["backend_token"] = backend_token.into();
    fs::write(&record, serde_json::to_vec(&run).unwrap()).unwrap();
    let dead = value(cli(&root, &["agent", "status", "marker"]));
    assert_eq!(dead["runtime_state"], "stopped");
    fs::create_dir_all(root.join("data/shell-sockets")).unwrap();
    let shell_path = root.join("data/shell-sockets/marker.sock");
    let listener = UnixListener::bind(&shell_path).unwrap();
    assert!(!cli(&root, &["agent", "cleanup", "marker"]).status.success());
    assert!(socket.exists());
    assert!(directory.join("runtime.json").exists());
    drop(listener);
    let cleaned = value(cli(&root, &["agent", "cleanup", "marker"]));
    assert_eq!(cleaned["runtime_state"], "stopped");
    assert!(!socket.exists());
    assert!(!shell_path.exists());
    assert!(!directory.join("runtime.json").exists());
}

#[test]
fn incomplete_launcher_stop_can_be_repeated_and_cleaned_without_a_new_launch() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    initialize(&root);
    value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            workspace.to_str().unwrap(),
        ],
    ));
    let agent_id = value(cli(&root, &["agent", "status", "marker"]))["agent_id"].clone();
    let script = temp.path().join("launcher.sh");
    let actions = temp.path().join("actions");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{}'\n",
            actions.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let launch = root.join("agents/marker/current-launch.json");
    fs::write(
        &launch,
        serde_json::to_vec(&serde_json::json!({
            "name":"marker", "agent_id":agent_id, "launch_id":"launch-incomplete",
            "state":"unknown", "launcher":{"kind":"script","script":script}
        }))
        .unwrap(),
    )
    .unwrap();
    for _ in 0..2 {
        let stopped = value(cli(&root, &["agent", "stop", "marker"]));
        assert_eq!(stopped["runtime_state"], "stopped");
        assert_eq!(stopped["agent_id"], agent_id);
    }
    assert_eq!(fs::read_to_string(&actions).unwrap(), "stop\nstop\n");
    let saved: Value = serde_json::from_slice(&fs::read(&launch).unwrap()).unwrap();
    assert_eq!(saved["launch_id"], "launch-incomplete");
    assert_eq!(saved["state"], "stopping");
    value(cli(&root, &["agent", "cleanup", "marker"]));
    assert!(!launch.exists());
    assert_eq!(fs::read_to_string(&actions).unwrap(), "stop\nstop\nstop\n");
    let mut wrong_agent = saved;
    wrong_agent["agent_id"] = "another-agent".into();
    fs::write(&launch, serde_json::to_vec(&wrong_agent).unwrap()).unwrap();
    assert!(!cli(&root, &["agent", "stop", "marker"]).status.success());
    assert_eq!(fs::read_to_string(&actions).unwrap(), "stop\nstop\nstop\n");
}

#[cfg(target_os = "linux")]
#[test]
fn runsc_state_without_a_runtime_record_holds_native_and_admin_start() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            temp.path().to_str().unwrap(),
            "--launcher",
            "supervisor",
        ],
    ));
    let directory = root.join("agents/marker");
    let share = directory.join("config-share");
    fs::create_dir_all(&share).unwrap();
    let generation = "0123456789abcdef0123456789abcdef";
    let context = serde_json::to_vec(&serde_json::json!({"generation":generation})).unwrap();
    fs::write(share.join("host-launch-context.json"), &context).unwrap();
    let runsc = root.join("run");
    fs::create_dir(&runsc).unwrap();
    let state = runsc.join(format!(
        "safeyolo-{generation}_sandbox:safeyolo-{generation}.state"
    ));
    fs::write(&state, b"unreconciled backend state").unwrap();

    let config = root.join("config.toml");
    let document = fs::read_to_string(&config)
        .unwrap()
        .replace("admin_port = 9090", "admin_port = 0");
    fs::write(&config, document).unwrap();
    let _stop = StopOnDrop(&config);
    value(cli(&root, &["start"]));
    for args in [
        ["agent", "status", "marker"],
        ["agent", "diagnostics", "marker"],
    ] {
        let observed = value(cli(&root, &args));
        assert_eq!(observed["runtime_state"], "unknown");
        assert_eq!(observed["sandbox_state"], "unknown");
        assert_eq!(observed["exec"], false);
        assert_eq!(observed["port_forward"], false);
    }
    assert_eq!(
        value(cli(&root, &["doctor"]))["agents"][0]["runtime_state"],
        "unknown"
    );
    // Ordinary start goes through the authenticated Admin caller. The explicit
    // sandbox-only mode reaches the same owner through the native CLI.
    let admin = cli(&root, &["agent", "start", "marker"]);
    assert!(!admin.status.success());
    assert!(String::from_utf8_lossy(&admin.stderr).contains("API 409"));
    assert!(
        !cli(&root, &["agent", "start", "marker", "--sandbox-only"])
            .status
            .success()
    );
    for operation in ["stop", "cleanup"] {
        assert!(!cli(&root, &["agent", operation, "marker"]).status.success());
    }
    assert!(!directory.join("runtime.json").exists());
    assert!(!directory.join("current-launch.json").exists());
    assert_eq!(fs::read(&state).unwrap(), b"unreconciled backend state");
    assert_eq!(
        fs::read(share.join("host-launch-context.json")).unwrap(),
        context
    );

    // A dangling or inaccessible backend path cannot establish absence.
    fs::remove_file(&state).unwrap();
    symlink(runsc.join("absent"), &state).unwrap();
    assert_eq!(
        value(cli(&root, &["agent", "status", "marker"]))["runtime_state"],
        "unknown"
    );
    fs::remove_file(&state).unwrap();
    let blocked_parent = root.join("blocked");
    fs::create_dir(&blocked_parent).unwrap();
    fs::set_permissions(&blocked_parent, fs::Permissions::from_mode(0o000)).unwrap();
    let denied = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(&root)
        .args(["agent", "status", "marker"])
        .env("SAFEYOLO_RUNSC_ROOT", blocked_parent.join("run"))
        .output()
        .unwrap();
    fs::set_permissions(&blocked_parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(value(denied)["runtime_state"], "unknown");
    assert_eq!(
        value(cli(&root, &["agent", "status", "marker"]))["runtime_state"],
        "stopped"
    );

    // Corrupt launch context must not disappear into an absent identity.
    fs::write(share.join("host-launch-context.json"), b"corrupt").unwrap();
    assert_eq!(
        value(cli(&root, &["agent", "status", "marker"]))["runtime_state"],
        "unknown"
    );
    assert_eq!(
        fs::read(share.join("host-launch-context.json")).unwrap(),
        b"corrupt"
    );
}

#[test]
fn missing_runtime_record_does_not_make_unverified_pid_files_stopped() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            temp.path().to_str().unwrap(),
        ],
    ));
    let directory = root.join("agents/marker");
    let share = directory.join("config-share");
    fs::create_dir_all(&share).unwrap();
    fs::write(
        share.join("host-launch-context.json"),
        b"{\"generation\":\"0123456789abcdef0123456789abcdef\"}",
    )
    .unwrap();
    #[cfg(target_os = "linux")]
    let handles = ["userns.pid", "container.pid"];
    #[cfg(target_os = "macos")]
    let handles = ["vm.pid", "vm.token"];
    for handle in handles {
        let path = directory.join(handle);
        fs::write(&path, b"unverified handle").unwrap();
        let observed = value(cli(&root, &["agent", "status", "marker"]));
        assert_eq!(observed["runtime_state"], "unknown", "{handle}: {observed}");
        assert_eq!(observed["exec"], false);
        assert!(!cli(&root, &["agent", "stop", "marker"]).status.success());
        assert!(!cli(&root, &["agent", "cleanup", "marker"]).status.success());
        assert_eq!(fs::read(&path).unwrap(), b"unverified handle");
        assert!(!directory.join("runtime.json").exists());
        fs::remove_file(path).unwrap();
    }
    assert_eq!(
        value(cli(&root, &["agent", "status", "marker"]))["runtime_state"],
        "stopped"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn an_exited_backend_with_or_without_runsc_state_can_be_cleaned() {
    use std::os::unix::process::CommandExt;

    for retain_state in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("instance");
        initialize(&root);
        value(cli(
            &root,
            &[
                "agent",
                "create",
                "marker",
                "--workspace",
                temp.path().to_str().unwrap(),
            ],
        ));
        let directory = root.join("agents/marker");
        fs::create_dir_all(directory.join("config-share")).unwrap();
        let generation = "0123456789abcdef0123456789abcdef";
        let id = format!("safeyolo-{generation}");
        fs::write(
            directory.join("config-share/host-launch-context.json"),
            serde_json::to_vec(&serde_json::json!({"generation":generation})).unwrap(),
        )
        .unwrap();
        // Reach the native backend identity path without giving this harmless
        // fixture the operator's namespace or any product signal authority.
        let mut backend = Command::new("/bin/sh")
            .arg0("runsc-sandbox")
            .args(["-c", "read line"])
            .arg(format!("--root={}", root.join("run").display()))
            .args(["boot", &id])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = backend.id();
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let started = stat
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap();
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let saved = serde_json::to_vec(&serde_json::json!({"run_id":generation,"backend_pid":pid,"backend_token":format!("linux:{}:{pid}:{started}",boot.trim())})).unwrap();
        fs::write(directory.join("runtime.json"), &saved).unwrap();
        let state = root.join("run").join(format!("{id}_sandbox:{id}.state"));
        let lock = state.with_extension("lock");
        let metadata = serde_json::to_vec(&serde_json::json!({
            "id":id,"sandbox":{"id":id,"pid":pid}
        }))
        .unwrap();
        let other_state = root.join("run/safeyolo-fedcba9876543210fedcba9876543210_sandbox:safeyolo-fedcba9876543210fedcba9876543210.state");
        if retain_state {
            fs::create_dir_all(root.join("run")).unwrap();
            fs::write(&state, &metadata).unwrap();
            fs::write(&lock, b"").unwrap();
            fs::write(&other_state, b"another retained incarnation").unwrap();
            fs::write(other_state.with_extension("lock"), b"").unwrap();
        }
        let live = cli(&root, &["agent", "status", "marker"]);
        let live_stop = cli(&root, &["agent", "stop", "marker"]);
        let live_record_unchanged = fs::read(directory.join("runtime.json")).unwrap() == saved;
        backend.kill().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while fs::read_to_string(format!("/proc/{pid}/stat"))
            .unwrap()
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .next()
            != Some("Z")
        {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let zombie = cli(&root, &["agent", "status", "marker"]);
        let mut wrong_birth: Value = serde_json::from_slice(&saved).unwrap();
        wrong_birth["backend_token"] = format!(
            "linux:{}:{pid}:{}",
            boot.trim(),
            started.parse::<u64>().unwrap() + 1
        )
        .into();
        let wrong_birth = serde_json::to_vec(&wrong_birth).unwrap();
        fs::write(directory.join("runtime.json"), &wrong_birth).unwrap();
        let other_zombie = cli(&root, &["agent", "status", "marker"]);
        let zombie_stop = cli(&root, &["agent", "stop", "marker"]);
        let zombie_preserved = fs::read(directory.join("runtime.json")).unwrap() == wrong_birth;
        fs::write(directory.join("runtime.json"), &saved).unwrap();
        backend.wait().unwrap();
        let live = value(live);
        assert_eq!(live["runtime_state"], "degraded");
        assert_eq!(live["run_id"], generation);
        assert_eq!(live["exec"], false);
        assert_eq!(live["port_forward"], false);
        assert!(!live_stop.status.success());
        assert!(live_record_unchanged);
        assert_eq!(value(zombie)["runtime_state"], "stopped");
        assert_eq!(value(other_zombie)["runtime_state"], "unknown");
        assert!(!zombie_stop.status.success());
        assert!(zombie_preserved);
        assert_eq!(
            value(cli(&root, &["agent", "status", "marker"]))["runtime_state"],
            "stopped"
        );
        assert_eq!(fs::read(directory.join("runtime.json")).unwrap(), saved);
        // A dead numeric PID with an empty, malformed or conflicting birth
        // token cannot authorize reconciliation or deletion through any caller.
        let mut unrelated = Command::new("sleep").arg("120").spawn().unwrap();
        let other_pid = unrelated.id();
        let other_stat = fs::read_to_string(format!("/proc/{other_pid}/stat")).unwrap();
        let other_started = other_stat
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap();
        let context_path = directory.join("config-share/host-launch-context.json");
        let context = fs::read(&context_path).unwrap();
        let mut results = Vec::new();
        for token in [
            Value::Null,
            serde_json::json!(""),
            serde_json::json!(format!("linux:{}:{other_pid}:{other_started}", boot.trim())),
            serde_json::json!(format!("linux::{pid}:{started}")),
            serde_json::json!(format!("linux:not-a-boot-id:{pid}:{started}")),
            serde_json::json!(format!("linux:{}:{pid}", boot.trim())),
            serde_json::json!(format!("linux:{}:{pid}:bad", boot.trim())),
            serde_json::json!(format!("linux:{}:{pid}:{started}:extra", boot.trim())),
            serde_json::json!(format!("darwin:{pid}:1:0")),
        ] {
            let mut record: Value = serde_json::from_slice(&saved).unwrap();
            record["backend_token"] = token;
            let bytes = serde_json::to_vec(&record).unwrap();
            fs::write(directory.join("runtime.json"), &bytes).unwrap();
            results.push((
                cli(&root, &["agent", "status", "marker"]),
                cli(&root, &["doctor"]),
                cli(&root, &["agent", "stop", "marker"]),
                cli(&root, &["agent", "cleanup", "marker"]),
                fs::read(directory.join("runtime.json")).unwrap() == bytes
                    && fs::read(&context_path).unwrap() == context
                    && (!retain_state || (fs::read(&state).unwrap() == metadata && lock.exists())),
            ));
        }
        let other_survived = unrelated.try_wait().unwrap().is_none()
            && fs::read_to_string(format!("/proc/{other_pid}/stat"))
                .unwrap()
                .rsplit_once(')')
                .unwrap()
                .1
                .split_whitespace()
                .nth(19)
                == Some(other_started);
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
        assert!(other_survived, "unrelated process birth was not preserved");
        for (status, doctor, stop, cleanup, preserved) in results {
            assert_eq!(value(status)["runtime_state"], "unknown");
            assert_eq!(value(doctor)["agents"][0]["runtime_state"], "unknown");
            assert!(!stop.status.success());
            assert!(!cleanup.status.success());
            assert!(preserved);
        }
        fs::write(directory.join("runtime.json"), &saved).unwrap();
        let mut wrong_run: Value = serde_json::from_slice(&saved).unwrap();
        wrong_run["run_id"] = "fedcba9876543210fedcba9876543210".into();
        let wrong_run = serde_json::to_vec(&wrong_run).unwrap();
        fs::write(directory.join("runtime.json"), &wrong_run).unwrap();
        assert_eq!(
            value(cli(&root, &["agent", "status", "marker"]))["runtime_state"],
            "unknown"
        );
        assert!(!cli(&root, &["agent", "stop", "marker"]).status.success());
        assert!(!cli(&root, &["agent", "cleanup", "marker"]).status.success());
        assert_eq!(fs::read(directory.join("runtime.json")).unwrap(), wrong_run);
        fs::write(directory.join("runtime.json"), &saved).unwrap();
        if retain_state {
            assert_eq!(fs::read(&state).unwrap(), metadata);
            assert!(lock.exists());
            // Production runsc writes mode 0640 as subordinate UID/GID 100000.
            // Matching dead metadata must not require host-readable contents.
            fs::set_permissions(&state, fs::Permissions::from_mode(0o0)).unwrap();
            if unsafe { libc::geteuid() } != 0 {
                assert_eq!(
                    fs::read(&state).unwrap_err().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
            }
            assert_eq!(
                value(cli(&root, &["agent", "status", "marker"]))["runtime_state"],
                "stopped"
            );
        }
        assert_eq!(
            value(cli(&root, &["agent", "stop", "marker"]))["runtime_state"],
            "stopped"
        );
        assert!(!state.exists());
        assert!(!lock.exists());
        if retain_state {
            // Retry must also retire a lock left after the state file was
            // removed; its saved birth/generation still identifies the owner.
            fs::write(&lock, b"").unwrap();
        }
        for operation in ["stop", "cleanup", "cleanup", "stop"] {
            assert_eq!(
                value(cli(&root, &["agent", operation, "marker"]))["runtime_state"],
                "stopped"
            );
            assert!(!state.exists());
            assert!(!lock.exists());
            if retain_state {
                assert_eq!(
                    fs::read(&other_state).unwrap(),
                    b"another retained incarnation"
                );
                assert!(other_state.with_extension("lock").exists());
            }
        }
        assert!(!directory.join("runtime.json").exists());
        assert_eq!(
            value(cli(&root, &["agent", "status", "marker"]))["runtime_state"],
            "stopped"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn an_unrelated_live_pid_is_not_a_backend_or_signal_authority() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            temp.path().to_str().unwrap(),
        ],
    ));
    let directory = root.join("agents/marker");
    fs::create_dir_all(directory.join("config-share")).unwrap();
    let run_id = "0123456789abcdef0123456789abcdef";
    fs::write(
        directory.join("config-share/host-launch-context.json"),
        serde_json::to_vec(&serde_json::json!({"generation":run_id})).unwrap(),
    )
    .unwrap();
    let mut unrelated = Command::new("sleep").arg("30").spawn().unwrap();
    let pid = unrelated.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let started = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let token = format!("linux:{}:{pid}:{started}", boot.trim());
    let mut results = Vec::new();
    for record in [
        serde_json::json!({"run_id":run_id,"backend_pid":pid,"backend_token":token}),
        serde_json::json!({"run_id":run_id,"backend_pid":pid,"backend_token":"different-birth"}),
        serde_json::json!({"run_id":run_id,"backend_pid":pid}),
        serde_json::json!({"run_id":run_id,"backend_pid":"bad","backend_token":token}),
        serde_json::json!({"run_id":run_id}),
    ] {
        let saved = serde_json::to_vec(&record).unwrap();
        fs::write(directory.join("runtime.json"), &saved).unwrap();
        results.push((
            cli(&root, &["agent", "status", "marker"]),
            cli(&root, &["agent", "stop", "marker"]),
            fs::read(directory.join("runtime.json")).unwrap() == saved,
        ));
    }
    let survived = unrelated.try_wait().unwrap().is_none();
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
    for (status, stop, state_preserved) in results {
        let observed = value(status);
        assert_eq!(observed["runtime_state"], "unknown");
        assert!(
            observed["runtime_error"]
                .as_str()
                .unwrap()
                .contains("unrelated process")
        );
        assert!(!stop.status.success());
        assert!(state_preserved);
    }
    assert!(survived, "the unrelated process was signalled");
}

#[cfg(target_os = "linux")]
#[test]
fn sentry_arguments_do_not_replace_birth_run_and_namespace_validation() {
    use std::os::unix::process::CommandExt;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            temp.path().to_str().unwrap(),
        ],
    ));
    let directory = root.join("agents/marker");
    fs::create_dir_all(directory.join("config-share")).unwrap();
    let run_id = "0123456789abcdef0123456789abcdef";
    let id = format!("safeyolo-{run_id}");
    // An ordinary host process can carry the sentry's argument form.
    // Its argv must not grant signal authority when birth/run disagree or
    // when it shares the operator's namespaces instead of the sandbox's.
    let mut unrelated = Command::new("/bin/sh")
        .arg0("runsc-sandbox")
        .args(["-c", "read line"])
        .arg(format!("--root={}", root.join("run").display()))
        .args(["boot", &id])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = unrelated.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let started = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let token = format!("linux:{}:{pid}:{started}", boot.trim());
    fs::create_dir_all(root.join("run")).unwrap();
    fs::write(
        root.join("run").join(format!("{id}_sandbox:{id}.state")),
        b"unreconciled backend state",
    )
    .unwrap();
    let saved = serde_json::json!({"run_id":run_id,"backend_pid":pid,"backend_token":token});
    let mut results = Vec::new();
    for (field, replacement, generation, expected_state) in [
        (
            "backend_token",
            "different-process-birth",
            run_id,
            "unknown",
        ),
        (
            "run_id",
            "fedcba9876543210fedcba9876543210",
            run_id,
            "unknown",
        ),
        (
            "run_id",
            run_id,
            "fedcba9876543210fedcba9876543210",
            "unknown",
        ),
        ("backend_token", token.as_str(), run_id, "degraded"),
    ] {
        let mut run = saved.clone();
        run[field] = replacement.into();
        fs::write(
            directory.join("runtime.json"),
            serde_json::to_vec(&run).unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join("config-share/host-launch-context.json"),
            serde_json::to_vec(&serde_json::json!({"generation":generation})).unwrap(),
        )
        .unwrap();
        results.push((
            cli(&root, &["agent", "status", "marker"]),
            cli(&root, &["agent", "stop", "marker"]),
            unrelated.try_wait().unwrap().is_none(),
            fs::read(directory.join("runtime.json")).unwrap() == serde_json::to_vec(&run).unwrap(),
            expected_state,
        ));
    }
    if unrelated.try_wait().unwrap().is_none() {
        unrelated.kill().unwrap();
    }
    unrelated.wait().unwrap();
    for (status, stop, survived, state_preserved, expected_state) in results {
        assert_eq!(value(status)["runtime_state"], expected_state);
        assert!(!stop.status.success());
        assert!(
            state_preserved,
            "unverified stop changed the runtime record"
        );
        assert!(
            survived,
            "a process with mismatched birth/run/namespace evidence was signalled"
        );
    }
}

#[test]
fn configuration_rejection_is_atomic_and_current_run_is_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let first = temp.path().join("first");
    let next = temp.path().join("next");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&next).unwrap();
    let created = value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            first.to_str().unwrap(),
            "--memory",
            "512",
            "--command",
            "printf marker",
        ],
    ));
    let id = created["configuration"]["id"].clone();
    let directory = root.join("agents/marker");
    fs::create_dir_all(&directory).unwrap();
    let runtime =
        br#"{"run_id":"0123456789abcdef0123456789abcdef","state":"running","workspace":"old"}"#;
    fs::write(directory.join("runtime.json"), runtime).unwrap();
    let policy = fs::read(root.join("policy.toml")).unwrap();
    for args in [
        vec!["--memory", "0"],
        vec!["--memory", "true"],
        vec!["--workspace", "/missing-817-workspace"],
        vec!["--mount", "/:/safeyolo"],
        vec!["--mount", "/://"],
        vec!["--mount", "/:/workspace:rw"],
    ] {
        let mut command = vec!["agent", "configure", "marker"];
        command.extend(args);
        assert!(!cli(&root, &command).status.success());
        assert_eq!(fs::read(root.join("policy.toml")).unwrap(), policy);
        assert_eq!(fs::read(directory.join("runtime.json")).unwrap(), runtime);
    }
    let changed = value(cli(
        &root,
        &[
            "agent",
            "configure",
            "marker",
            "--workspace",
            next.to_str().unwrap(),
            "--memory",
            "768",
        ],
    ));
    assert_eq!(changed["configuration"]["id"], id);
    assert_eq!(changed["configuration"]["folder"], next.to_str().unwrap());
    assert_eq!(
        changed["scope"],
        "next sandbox start; current run is unchanged"
    );
    assert_eq!(fs::read(directory.join("runtime.json")).unwrap(), runtime);
    let output = cli(&root, &["agent", "create", "unowned", "--workspace", "/"]);
    if unsafe { libc::geteuid() } != 0 {
        assert!(!output.status.success());
        let allowed = cli(
            &root,
            &[
                "agent",
                "create",
                "unowned",
                "--workspace",
                "/",
                "--dangerously-allow-unowned",
            ],
        );
        assert!(
            allowed.status.success(),
            "{}",
            String::from_utf8_lossy(&allowed.stderr)
        );
    }
}

#[test]
fn host_scripts_cannot_execute_from_the_proposed_writable_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let script = workspace.join("hook");
    fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let policy = fs::read(root.join("policy.toml")).unwrap();
    for setting in ["--host-script", "--launcher"] {
        let output = cli(
            &root,
            &[
                "agent",
                "create",
                "unsafe",
                "--workspace",
                workspace.to_str().unwrap(),
                setting,
                script.to_str().unwrap(),
            ],
        );
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("agent-writable"));
        assert_eq!(fs::read(root.join("policy.toml")).unwrap(), policy);
    }
}

#[test]
fn host_setup_keeps_the_explicit_config_and_failed_setup_does_not_publish() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let selected = root.join("selected.toml");
    fs::copy(root.join("config.toml"), &selected).unwrap();
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let hook = temp.path().join("setup-hook.sh");
    fs::write(&hook, b"#!/bin/sh\nprintf '%s\\n' \"$SAFEYOLO_NATIVE_CONFIG_PATH\" > \"$SAFEYOLO_AGENT_HOME/source\"\nexit 41\n").unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    let call = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--config")
            .arg(&selected)
            .args(args)
            .output()
            .unwrap()
    };
    value(call(&[
        "agent",
        "create",
        "marker",
        "--workspace",
        workspace.to_str().unwrap(),
    ]));
    let saved = fs::read(root.join("policy.toml")).unwrap();
    let failed = call(&[
        "agent",
        "configure",
        "marker",
        "--host-script",
        hook.to_str().unwrap(),
    ]);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("saved configuration is unchanged"));
    assert_eq!(fs::read(root.join("policy.toml")).unwrap(), saved);
    assert_eq!(
        fs::read_to_string(root.join("agents/marker/home/source"))
            .unwrap()
            .trim(),
        selected.to_str().unwrap()
    );
}

#[test]
fn same_named_agents_have_separate_native_state_and_read_only_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    initialize(&a);
    initialize(&b);
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    for root in [&a, &b] {
        value(cli(
            root,
            &[
                "agent",
                "create",
                "marker",
                "--workspace",
                workspace.to_str().unwrap(),
            ],
        ));
    }
    let a_id = value(cli(&a, &["agent", "status", "marker"]))["agent_id"].clone();
    let b_id = value(cli(&b, &["agent", "status", "marker"]))["agent_id"].clone();
    assert_ne!(a_id, b_id);
    let b_policy = fs::read(b.join("policy.toml")).unwrap();
    let b_instance = fs::read(b.join("data/instance_id")).unwrap();
    let dir = a.join("agents/marker");
    fs::create_dir_all(&dir).unwrap();
    for record in [
        "corrupt",
        "null",
        "[]",
        "{}",
        "{\"run_id\":42}",
        "{\"run_id\":\"bad\"}",
    ] {
        fs::write(dir.join("runtime.json"), record).unwrap();
        let observed = value(cli(&a, &["agent", "status", "marker"]));
        assert_eq!(observed["runtime_state"], "unknown", "{record}: {observed}");
        let doctor = value(cli(&a, &["doctor"]));
        assert_eq!(doctor["agents"][0]["runtime_state"], "unknown");
        assert_eq!(
            fs::read(dir.join("runtime.json")).unwrap(),
            record.as_bytes()
        );
    }
    assert_eq!(fs::read(b.join("policy.toml")).unwrap(), b_policy);
    assert_eq!(fs::read(b.join("data/instance_id")).unwrap(), b_instance);
    assert_eq!(
        value(cli(&b, &["agent", "status", "marker"]))["runtime_state"],
        "stopped"
    );
    assert!(!cli(&b, &["agent", "attach", "marker"]).status.success());
    assert!(!dir.join("launch.json").exists());
}

#[test]
fn help_uses_native_lifecycle_and_has_no_old_aliases() {
    let root = tempfile::tempdir().unwrap();
    initialize(root.path());
    let output = cli(root.path(), &["agent", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for required in [
        "create|configure",
        "start NAME",
        "attach",
        "diagnostics",
        "--foreground",
        "--sandbox-only",
    ] {
        assert!(help.contains(required));
    }
    for alias in [
        "agent up",
        "agent down",
        "agent check",
        "python -m",
        "hostPython",
    ] {
        assert!(!help.contains(alias));
    }
}

#[test]
fn fresh_proxy_uses_the_explicit_toml_and_keeps_the_other_instance_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    initialize(&a);
    initialize(&b);
    let selected = a.join("selected.toml");
    let source = fs::read_to_string(a.join("config.toml"))
        .unwrap()
        .replace("admin_port = 9090", "admin_port = 0");
    fs::write(&selected, source).unwrap();
    let a_default = fs::read(a.join("config.toml")).unwrap();
    let b_default = fs::read(b.join("config.toml")).unwrap();
    let selected_cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .env("SAFEYOLO_NATIVE_CONFIG_PATH", &selected)
            .env("SAFEYOLO_CONFIG_DIR", &b)
            .args(args)
            .output()
            .unwrap()
    };
    let _stop = StopOnDrop(&selected);
    value(selected_cli(&["start"]));
    assert!(a.join("data/ready.json").is_file());
    assert!(!b.join("data/ready.json").exists());
    assert!(fs::read_to_string(&selected).unwrap().contains("reload_id"));
    assert_eq!(fs::read(a.join("config.toml")).unwrap(), a_default);
    assert_eq!(fs::read(b.join("config.toml")).unwrap(), b_default);
    value(selected_cli(&[
        "agent",
        "create",
        "marker",
        "--workspace",
        temp.path().to_str().unwrap(),
    ]));
    assert_eq!(
        value(selected_cli(&["agent", "status", "marker"]))["name"],
        "marker"
    );
    assert!(
        !fs::read_to_string(b.join("policy.toml"))
            .unwrap()
            .contains("[agents.marker]")
    );
    value(selected_cli(&["stop"]));
    fs::write(&selected, "agent_launcher = false\n").unwrap();
    let failed = selected_cli(&["agent", "status", "marker"]);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("config.toml settings"));
    assert_eq!(fs::read(a.join("config.toml")).unwrap(), a_default);
    assert_eq!(fs::read(b.join("config.toml")).unwrap(), b_default);
}

#[cfg(target_os = "linux")]
#[test]
fn native_tmux_launch_uses_current_environment_on_the_owned_socket() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("a");
    initialize_tmux_launcher(&root);
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let created = value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            workspace.to_str().unwrap(),
        ],
    ));
    let dir = root.join("agents/marker");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("current-launch.json"),
        serde_json::to_vec(&serde_json::json!({
            "name":"marker", "agent_id":created["configuration"]["id"], "launch_id":"launch-env",
            "launcher":{"kind":"tmux-window"}, "state":"starting", "tmux_session":"fixture"
        }))
        .unwrap(),
    )
    .unwrap();
    let socket = root.join("data/tmux.sock");
    struct OwnedServer<'a>(&'a Path);
    impl Drop for OwnedServer<'_> {
        fn drop(&mut self) {
            let _ = Command::new("tmux")
                .arg("-S")
                .arg(self.0)
                .arg("kill-server")
                .output();
        }
    }
    let _server = OwnedServer(&socket);
    let old = Command::new("tmux")
        .arg("-S")
        .arg(&socket)
        .env("SAFEYOLO_RUNSC_ROOT", "old-server-root")
        .env("SAFEYOLO_CONFIG_DIR", "old-server-config")
        .args(["new-session", "-d", "-s", "control", "sleep", "30"])
        .output()
        .unwrap();
    assert!(
        old.status.success(),
        "{}",
        String::from_utf8_lossy(&old.stderr)
    );
    // This harmless terminal fixture records selected nonsecret values. It
    // supplies no sandbox or coding-agent acceptance.
    fs::remove_file(root.join("bin/safeyolo")).unwrap();
    fs::write(root.join("bin/safeyolo"), b"#!/bin/sh\nprintf '%s\\n' \"$SAFEYOLO_CONFIG_DIR\" \"${SAFEYOLO_RUNSC_ROOT-unset}\" > \"$SAFEYOLO_CONFIG_DIR/environment-marker\"\nexec sleep 30\n").unwrap();
    fs::set_permissions(root.join("bin/safeyolo"), fs::Permissions::from_mode(0o755)).unwrap();
    let started = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(&root)
        .args(["agent", "launcher-session", "marker", "launch-env"])
        .env("SAFEYOLO_CONFIG_DIR", &root)
        .env_remove("SAFEYOLO_RUNSC_ROOT")
        .output()
        .unwrap();
    let target = value(started);
    assert_eq!(target["tmux_socket"], socket.to_str().unwrap());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while !root.join("environment-marker").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(
        fs::read_to_string(root.join("environment-marker")).unwrap(),
        format!("{}\nunset\n", root.display())
    );
    assert!(
        Command::new("tmux")
            .arg("-S")
            .arg(&socket)
            .args(["has-session", "-t", "=control"])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn custom_launchers_can_delegate_to_the_shipped_tmux_presets() {
    for (kind, preset) in [("script", "tmux-window"), ("manager", "tmux-pane")] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("instance");
        initialize_tmux_launcher(&root);
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let created = value(cli(
            &root,
            &[
                "agent",
                "create",
                "marker",
                "--workspace",
                workspace.to_str().unwrap(),
            ],
        ));
        let directory = root.join("agents/marker");
        fs::create_dir_all(&directory).unwrap();
        let record = serde_json::json!({
            "name":"marker", "agent_id":created["configuration"]["id"],
            "launch_id":"launch-custom", "launcher":{"kind":kind},
            "state":"starting", "tmux_session":"custom"
        });
        fs::write(
            directory.join("current-launch.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        // A terminal-only control records entry. The real preset and native
        // CLI arrange it; this fixture does not claim guest/runtime proof.
        fs::remove_file(root.join("bin/safeyolo")).unwrap();
        fs::write(
            root.join("bin/safeyolo"),
            b"#!/bin/sh\nprintf entered > \"$SAFEYOLO_CONFIG_DIR/custom-entry\"\nexec sleep 30\n",
        )
        .unwrap();
        fs::set_permissions(root.join("bin/safeyolo"), fs::Permissions::from_mode(0o755)).unwrap();
        let socket = root.join("data/tmux.sock");
        struct OwnedServer<'a>(&'a Path);
        impl Drop for OwnedServer<'_> {
            fn drop(&mut self) {
                let _ = Command::new("tmux")
                    .arg("-S")
                    .arg(self.0)
                    .arg("kill-server")
                    .output();
            }
        }
        let _server = OwnedServer(&socket);
        let invalid = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(&root)
            .args(["agent", "launcher-session", "marker", "launch-custom"])
            .env("SAFEYOLO_TMUX_LAYOUT", "invalid")
            .output()
            .unwrap();
        assert!(!invalid.status.success());
        assert!(!root.join("custom-entry").exists());
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../cli/src/safeyolo/launchers")
            .join(format!("{preset}.sh"));
        let launch_preset = || {
            Command::new("bash")
                .arg(&script)
                .arg("launch")
                .env("SAFEYOLO_EXECUTABLE", env!("CARGO_BIN_EXE_safeyolo"))
                .env("SAFEYOLO_NATIVE_CONFIG_PATH", root.join("config.toml"))
                .env("SAFEYOLO_CONFIG_DIR", &root)
                .env("SAFEYOLO_AGENT_NAME", "marker")
                .env("SAFEYOLO_LAUNCH_ID", "launch-custom")
                .env("SAFEYOLO_TMUX_SESSION", "custom")
                .env("SAFEYOLO_TMUX_SOCKET", &socket)
                .output()
                .unwrap()
        };
        let installed_tmux = root.join("bin/tmux");
        let held_tmux = root.join("bin/tmux-held");
        fs::rename(&installed_tmux, &held_tmux).unwrap();
        let missing = launch_preset();
        assert!(!missing.status.success());
        assert!(
            String::from_utf8_lossy(&missing.stderr).contains("Installed tmux runtime is missing")
        );
        assert!(!root.join("custom-entry").exists());
        assert!(!socket.exists());
        fs::rename(&held_tmux, &installed_tmux).unwrap();
        let started = launch_preset();
        assert!(
            started.status.success(),
            "{kind} / {preset}: {}",
            String::from_utf8_lossy(&started.stderr)
        );
        let target: Value = serde_json::from_slice(&started.stdout).unwrap();
        assert_eq!(target["tmux_socket"], socket.to_str().unwrap());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !root.join("custom-entry").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(fs::read(root.join("custom-entry")).unwrap(), b"entered");
        let saved: Value =
            serde_json::from_slice(&fs::read(directory.join("current-launch.json")).unwrap())
                .unwrap();
        assert_eq!(
            saved, record,
            "delegation replaced the custom hook identity"
        );
    }
}
