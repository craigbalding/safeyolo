//! Prepare the installed guest inputs for one stopped sandbox incarnation.

use crate::{Error, host_agents::Agent, host_platform::config_dir};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub(crate) fn workspace(path: &Path, allow_unowned: bool) -> Result<PathBuf, Error> {
    let path = path.canonicalize()?;
    let metadata = path.metadata()?;
    if !metadata.is_dir() {
        return Err("workspace must be a directory".into());
    }
    if !allow_unowned && metadata.uid() != unsafe { libc::geteuid() } {
        return Err("workspace is not owned by the operator; use --dangerously-allow-unowned to allow this explicit share".into());
    }
    Ok(path)
}

pub(crate) fn mount(spec: &str) -> Result<(PathBuf, String, bool), Error> {
    let parts: Vec<_> = spec.split(':').collect();
    if !(parts.len() == 2 || parts.len() == 3 && parts[2] == "ro") {
        return Err("mount requires /host/path:/guest/path[:ro]".into());
    }
    let host = Path::new(parts[0]).canonicalize()?;
    let source_type = host.metadata()?.file_type();
    if !source_type.is_dir() {
        let kind = if source_type.is_file() {
            "regular file"
        } else if source_type.is_fifo() {
            "FIFO"
        } else if source_type.is_socket() {
            "socket"
        } else if source_type.is_char_device() {
            "character device"
        } else if source_type.is_block_device() {
            "block device"
        } else {
            "non-directory filesystem entry"
        };
        return Err(format!(
            "mount source {} is a {kind}; host mounts require a directory. Put files in a dedicated directory and mount that directory instead.",
            host.display()
        )
        .into());
    }
    let guest = Path::new(parts[1]);
    if !guest.is_absolute()
        || guest
            .components()
            .any(|part| part == std::path::Component::ParentDir)
        || ["/home/agent", "/workspace"]
            .iter()
            .any(|root| Path::new(root).starts_with(guest))
        || ["/dev", "/proc", "/sys", "/safeyolo", "/safeyolo-status"]
            .iter()
            .any(|root| guest.starts_with(root))
    {
        return Err("mount destination is invalid or reserved".into());
    }
    let read_only = parts.len() == 3;
    if !read_only
        && let Some(protected) = crate::native_config::host_settings()?
            .protected_host_directories
            .iter()
            .find(|directory| host.starts_with(directory))
    {
        return Err(format!(
            "mount source {} is protected by {}; writable extra mounts are refused. Use an explicit :ro mount: {spec}:ro",
            host.display(), protected.display()
        ).into());
    }
    Ok((
        host,
        guest
            .components()
            .collect::<PathBuf>()
            .to_string_lossy()
            .into_owned(),
        read_only,
    ))
}

pub(crate) fn validate(agent: &Agent) -> Result<(), Error> {
    validate_sandbox(agent)?;
    if agent.launcher.is_some() {
        let launcher = crate::host_lifecycle::selected_launcher(agent)?;
        if matches!(launcher["kind"].as_str(), Some("script" | "manager"))
            && let Some(script) = launcher.get("script").and_then(Value::as_str)
        {
            validate_script_for_agent(agent, script)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_sandbox(agent: &Agent) -> Result<(), Error> {
    workspace(
        Path::new(
            agent
                .folder
                .as_deref()
                .ok_or("agent workspace is not configured")?,
        ),
        agent.dangerously_allow_unowned,
    )?;
    if agent.memory_mb.unwrap_or(4096) <= 0 {
        return Err("agent memory_mb must be positive".into());
    }
    for spec in &agent.mounts {
        mount(spec)?;
    }
    if let Some(script) = &agent.host_script {
        validate_script_for_agent(agent, script)?;
    }
    Ok(())
}

pub(crate) fn validate_script_for_agent(agent: &Agent, script: &str) -> Result<(), Error> {
    let path = Path::new(script).canonicalize()?;
    crate::host_lifecycle::validate_host_script(&path)?;
    let mut writable = vec![workspace(
        Path::new(agent.folder.as_deref().ok_or("missing workspace")?),
        agent.dangerously_allow_unowned,
    )?];
    for spec in &agent.mounts {
        let (host, _, ro) = mount(spec)?;
        if !ro {
            writable.push(host);
        }
    }
    if writable.iter().any(|root| path.starts_with(root)) {
        return Err("host script is inside an agent-writable mount".into());
    }
    Ok(())
}

/// Host setup is an explicit operator configuration action, never a start hook.
/// The caller holds the agent's setup lock and has proved its backend stopped.
pub(crate) async fn setup(
    agent: &Agent,
    factory: Option<(&Path, &str, bool)>,
    copy_host_state: Option<bool>,
) -> Result<(), Error> {
    let root = config_dir();
    let home = root.join("agents").join(&agent.name).join("home");
    fs::create_dir_all(&home)?;
    let script = Path::new(
        agent
            .host_script
            .as_deref()
            .ok_or("host script is missing")?,
    )
    .canonicalize()?;
    validate_script_for_agent(agent, script.to_str().ok_or("invalid host script path")?)?;
    let mut command = tokio::process::Command::new(script);
    command
        .env("SAFEYOLO_AGENT_NAME", &agent.name)
        .env("SAFEYOLO_AGENT_HOME", &home)
        .env(
            "SAFEYOLO_AGENT_FOLDER",
            agent.folder.as_deref().ok_or("missing workspace")?,
        )
        .env(
            "SAFEYOLO_WORKSPACE",
            agent.folder.as_deref().ok_or("missing workspace")?,
        )
        .env("SAFEYOLO_CONFIG_DIR", &root)
        .env(
            "SAFEYOLO_NATIVE_CONFIG_PATH",
            crate::host_platform::config_path(),
        )
        .env("SAFEYOLO_EXECUTABLE", root.join("bin/safeyolo"))
        .env("SAFEYOLO_COORD_EXECUTABLE", root.join("bin/safeyolo-coord"))
        .env(
            "SAFEYOLO_COORD_GUEST_BINARY",
            root.join("assets/guest/safeyolo-coord"),
        );
    if let Some(copy) = copy_host_state {
        command.env(
            "SAFEYOLO_CLAUDE_COPY_HOST_STATE",
            if copy { "1" } else { "0" },
        );
    }
    // Bind only this setup invocation. Process-global environment changes
    // would race another instance or another role's approved snapshot.
    if let Some((snapshot, role, preparing)) = factory {
        command
            .env("SAFEYOLO_FACTORY_SNAPSHOT", snapshot)
            .env("SAFEYOLO_FACTORY_ROLE", role)
            .env(
                "SAFEYOLO_FACTORY_PREPARE_ONLY",
                if preparing { "1" } else { "0" },
            );
    }
    let result = command.status().await?;
    if !result.success() {
        return Err(format!(
            "host setup script failed ({result}); saved configuration is unchanged"
        )
        .into());
    }
    Ok(())
}

pub(crate) async fn stage(agent: &Agent, ip: &str, run_id: &str) -> Result<Value, Error> {
    validate_sandbox(agent)?;
    let root = config_dir();
    let (host_package, guest_inputs) = crate::guest_acquisition::selected_boot_inputs(&root)?;
    let directory = root.join("agents").join(&agent.name);
    let home = directory.join("home");
    let share = directory.join("config-share");
    let status = directory.join("status");
    for path in [&directory, &home, &share, &status] {
        fs::create_dir_all(path)?;
    }
    let workspace = workspace(
        Path::new(agent.folder.as_deref().ok_or("missing workspace")?),
        agent.dangerously_allow_unowned,
    )?;
    #[cfg(target_os = "macos")]
    {
        let lock = root.join("data/vm-ssh-key.lock");
        let _lock =
            tokio::task::spawn_blocking(move || crate::host_platform::lock_host_state(&lock))
                .await??;
        let key = root.join("data/vm_ssh_key");
        if !key.is_file() {
            let generated = tokio::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .status()
                .await?;
            if !generated.success() {
                return Err(
                    "could not generate the instance's guest SSH key; no sandbox was started"
                        .into(),
                );
            }
            fs::set_permissions(key, fs::Permissions::from_mode(0o600))?;
        }
    }
    let mut shares = Vec::new();
    for spec in &agent.mounts {
        let entry = mount(spec)?;
        shares.retain(|(_, guest, _)| guest != &entry.1);
        shares.push(entry);
    }
    let previous = crate::guest_commands::read_state(&share.join("host-launch-context.json"))?
        .unwrap_or(Value::Null);
    let context = json!({"generation":run_id,"agent_id":agent.id,"ip":ip,"workspace":workspace,"memory_mb":agent.memory_mb.unwrap_or(4096),
        "guest_inputs":guest_inputs,"host_package":host_package,
        "extra_shares":shares.iter().map(|(host,guest,ro)| json!({"host_path":host,"guest_path":guest,"read_only":ro})).collect::<Vec<_>>(),
        "writable_mounts":shares.iter().filter(|(_,_,ro)| !ro).map(|(host,_,_)| host).collect::<Vec<_>>(),
        "command_payloads":previous.get("command_payloads").cloned().unwrap_or_else(|| json!({}))});
    crate::guest_commands::stage(
        &home,
        &share,
        &host_package.join("assets/guest"),
        context.clone(),
    )?;
    stage_skills(&host_package.join("assets/skills"), &share).await?;
    for name in ["agent_token", "authorized_keys"] {
        let source = if name == "agent_token" {
            crate::native_config::read(&crate::host_platform::config_path())?
                .data_dir()
                .join("agent_token")
        } else {
            root.join("data/vm_ssh_key.pub")
        };
        if source.is_file() {
            fs::copy(source, share.join(name))?;
            fs::set_permissions(share.join(name), fs::Permissions::from_mode(0o644))?;
        }
    }
    fs::copy(
        root.join("certs/mitmproxy-ca-cert.pem"),
        share.join("mitmproxy-ca-cert.pem"),
    )?;
    if host_package.join("assets/guest/guest-sudo").is_file() {
        fs::copy(
            host_package.join("assets/guest/guest-sudo"),
            share.join("guest-sudo"),
        )?;
    }
    fs::write(share.join("agent-name"), &agent.name)?;
    fs::write(
        share.join("agent.env"),
        b"export SAFEYOLO_YOLO_MODE=1\nexport SAFEYOLO_DETACH=1\n",
    )?;
    fs::write(
        share.join("network.env"),
        format!("GUEST_IP=127.0.0.1\nGATEWAY_IP=127.0.0.1\nAGENT_IP={ip}\nNETMASK=255.255.255.0\n"),
    )?;
    // Both shells and sudo read this file after guest-init copies it to
    // /etc/environment. Sudo does not expand shell variable references.
    fs::write(
        share.join("proxy.env"),
        "export HTTP_PROXY=http://127.0.0.1:8080\nexport HTTPS_PROXY=http://127.0.0.1:8080\nexport http_proxy=http://127.0.0.1:8080\nexport https_proxy=http://127.0.0.1:8080\nexport NO_PROXY=localhost,127.0.0.1\nexport no_proxy=localhost,127.0.0.1\nexport SSL_CERT_FILE=/usr/local/share/ca-certificates/safeyolo.crt\nexport REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/safeyolo.crt\nexport NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/safeyolo.crt\nexport HOME=/home/agent\n",
    )?;
    fs::write(
        share.join("host-mounts"),
        shares
            .iter()
            .enumerate()
            .map(|(i, (_, guest, _))| format!("extra{i}:{guest}\n"))
            .collect::<String>(),
    )?;
    fs::create_dir_all(share.join("proxy"))?;
    fs::create_dir_all(share.join("extra-mounts"))?;
    #[cfg(target_os = "linux")]
    {
        let rootfs = if directory.join("rootfs").is_dir() {
            directory.join("rootfs")
        } else {
            guest_inputs.join("rootfs-tree")
        };
        if !rootfs.is_dir() {
            return Err(format!("installed rootfs tree is missing: {}", rootfs.display()).into());
        }
        let mapping = crate::linux_host::selected_mapping()?;
        if rootfs.metadata()?.uid() != mapping.uid_base
            || rootfs.metadata()?.gid() != mapping.gid_base
        {
            return Err(format!(
                "rootfs tree must be owned by sandbox root {}:{}: {}",
                mapping.uid_base,
                mapping.gid_base,
                rootfs.display()
            )
            .into());
        }
        for target in [
            "etc",
            "workspace",
            "safeyolo",
            "safeyolo-status",
            "home/agent",
        ] {
            if !rootfs.join(target).is_dir() {
                return Err(format!("rootfs is missing a host-traversable bind target: {target}; rebuild with guest/install-guest-common.sh").into());
            }
        }
        if !rootfs
            .join("usr/local/share/ca-certificates/safeyolo.crt")
            .is_file()
        {
            return Err("rootfs is missing the public CA bind target; rebuild with guest/install-guest-common.sh".into());
        }
        let rootfs = rootfs.canonicalize()?;
        let spec = oci(
            &root,
            &directory,
            &rootfs,
            &guest_inputs,
            &workspace,
            &shares,
        )?;
        crate::guest_commands::write_json(&directory.join("config.json"), &spec)?;
    }
    Ok(context)
}

async fn stage_skills(source: &Path, share: &Path) -> Result<(), Error> {
    if !source.join("safeyolo/SKILL.md").is_file() {
        return Err(format!(
            "installed SafeYolo skills are missing: {}",
            source.display()
        )
        .into());
    }
    // Replace the stopped guest's whole skill tree so removed files cannot
    // survive an artifact refresh. Keep the prior tree if staging fails.
    let temporary = tempfile::TempDir::new_in(share)?;
    let staged = temporary.path().join("skills");
    let copied = tokio::process::Command::new("cp")
        .arg("-R")
        .arg(source)
        .arg(&staged)
        .status()
        .await?;
    if !copied.success() {
        return Err("could not stage installed SafeYolo skills; prior skills remain intact".into());
    }
    let destination = share.join("skills");
    let backup = temporary.path().join("previous");
    let previous = destination.try_exists()?;
    if previous {
        fs::rename(&destination, &backup)?;
    }
    if let Err(error) = fs::rename(&staged, &destination) {
        if previous {
            fs::rename(&backup, &destination)?;
        }
        return Err(error.into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn oci(
    root: &Path,
    directory: &Path,
    rootfs: &Path,
    guest_inputs: &Path,
    workspace: &Path,
    shares: &[(PathBuf, String, bool)],
) -> Result<Value, Error> {
    let name = directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("agent directory has no name")?;
    let bind = |host: &Path, guest: &str, ro: bool| json!({"destination":guest,"type":"bind","source":host,"options":if ro {vec!["rbind","ro","nosuid","nodev"]} else {vec!["rbind","rw","nosuid","nodev","dcache=0"]}});
    let mut mounts = vec![
        json!({"destination":"/proc","type":"proc","source":"proc"}),
        json!({"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","strictatime","mode=755","size=65536k"]}),
        json!({"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]}),
        json!({"destination":"/tmp","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","mode=1777"]}),
        bind(workspace, "/workspace", false),
        bind(&directory.join("config-share"), "/safeyolo", true),
        bind(&directory.join("status"), "/safeyolo-status", false),
        bind(&directory.join("home"), "/home/agent", false),
        bind(
            &root.join("certs/mitmproxy-ca-cert.pem"),
            "/usr/local/share/ca-certificates/safeyolo.crt",
            true,
        ),
        bind(&directory.join("proxy"), "/safeyolo/proxy", true),
    ];
    // Extra sources are served by isolated Gofers after runsc start. Their
    // guest targets are prepared inside the sentry, not through host home
    // paths. An OCI bind would leave the source in the root Gofer tree.
    let caches = directory.join("cache-paths.txt");
    let caches = if caches.is_file() {
        caches
    } else {
        guest_inputs.join("cache-paths.txt")
    };
    if caches.is_file() {
        for guest in fs::read_to_string(caches)?
            .lines()
            .filter(|line| !line.is_empty())
        {
            if shares.iter().any(|(_, selected, _)| selected == guest) {
                continue;
            }
            if !Path::new(guest).is_absolute()
                || Path::new(guest)
                    .components()
                    .any(|part| part == std::path::Component::ParentDir)
            {
                return Err("invalid rootfs cache path".into());
            }
            let host = directory.join("cache").join(guest.trim_start_matches('/'));
            fs::create_dir_all(&host)?;
            fs::set_permissions(&host, fs::Permissions::from_mode(0o755))?;
            mounts.push(bind(&host, guest, false));
        }
    }
    let caps = [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_NET_ADMIN",
        "CAP_MKNOD",
        "CAP_AUDIT_WRITE",
        "CAP_SETFCAP",
        "CAP_SYS_PTRACE",
    ];
    Ok(
        json!({"ociVersion":"1.0.0","root":{"path":rootfs,"readonly":false},"hostname":format!("safeyolo-{name}"),
        "process":{"terminal":false,"user":{"uid":0,"gid":0},"cwd":"/",
            "args":["/bin/bash","-c","while [ ! -f /safeyolo/per-run-go ]; do /bin/sleep 0.1; done; export BASH_ENV=/etc/mise-activate.sh; mkdir -p /var/log /safeyolo-status && : > /safeyolo-status/boot.log && ln -sf /safeyolo-status/boot.log /var/log/safeyolo-boot.log && exec /safeyolo/guest-init >> /safeyolo-status/boot.log 2>&1"],
            "env":["PATH=/home/agent/.mise/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","HOME=/home/agent","USER=agent","TERM=xterm-256color","BASH_ENV=","MISE_DATA_DIR=/home/agent/.mise","MISE_CONFIG_DIR=/home/agent/.mise","MISE_CACHE_DIR=/home/agent/.mise/cache","MISE_OVERRIDE_CONFIG_FILENAMES=/etc/safeyolo/mise-project-config-disabled.toml","MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES=none"],
            "capabilities":{"bounding":caps,"effective":caps,"permitted":caps,"ambient":caps},"rlimits":[{"type":"RLIMIT_NOFILE","hard":65536,"soft":65536}],"noNewPrivileges":false},
        "mounts":mounts,"linux":{"namespaces":[{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"mount"}],"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_AARCH64"],"syscalls":[{"names":["unshare"],"action":"SCMP_ACT_ERRNO","errnoRet":1}]}}}),
    )
}

#[cfg(test)]
mod mount_tests {
    use super::*;
    use std::{ffi::CString, os::unix::fs::symlink, os::unix::net::UnixListener};

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_extra_sources_are_absent_from_the_root_gofer_spec() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        let directory = root.join("agents/alice");
        fs::create_dir_all(directory.join("home")).unwrap();
        fs::create_dir(root.join("outside")).unwrap();
        symlink(root.join("outside"), directory.join("home/reference")).unwrap();
        let shares = vec![
            (root.join("writable"), "/mnt/shared".into(), false),
            (
                root.join("readonly"),
                "/home/agent/reference/nested".into(),
                true,
            ),
        ];
        let spec = oci(
            root,
            &directory,
            &root.join("rootfs"),
            root,
            &root.join("workspace"),
            &shares,
        )
        .unwrap();
        let mounts = spec["mounts"].as_array().unwrap();
        let proxy = mounts
            .iter()
            .find(|mount| mount["destination"] == "/safeyolo/proxy")
            .unwrap();
        assert_eq!(proxy["source"], json!(directory.join("proxy")));
        assert!(
            proxy["options"]
                .as_array()
                .unwrap()
                .iter()
                .any(|option| option == "ro")
        );

        for (source, target, _) in shares {
            assert!(!mounts.iter().any(|mount| mount["source"] == json!(source) || mount["destination"] == target));
        }
        for target in [
            "/workspace",
            "/home/agent",
            "/safeyolo",
            "/safeyolo-status",
            "/safeyolo/proxy",
        ] {
            assert!(mounts.iter().any(|mount| mount["destination"] == target));
        }
        assert!(
            !root.join("outside/nested").exists(),
            "OCI preparation must not follow guest home links on the host"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn oci_entry_waits_for_shares_before_guest_setup() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        let directory = root.join("agents/alice");
        fs::create_dir_all(&directory).unwrap();
        let spec = oci(root, &directory, root, root, root, &[]).unwrap();
        assert!(
            spec["process"]["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "BASH_ENV=")
        );
        let entry = spec["process"]["args"][2].as_str().unwrap();
        let prefix = entry.split_once("mkdir -p /var/log").unwrap().0;
        let gate = root.join("per-run-go");
        let started = root.join("guest-setup-started");
        let script = format!(
            "{} printf started > '{}'",
            prefix.replace("/safeyolo/per-run-go", gate.to_str().unwrap()),
            started.display()
        );
        let mut child = tokio::process::Command::new("/bin/bash")
            .args(["-c", &script])
            .env_remove("BASH_ENV")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(!started.exists());
        assert!(child.try_wait().unwrap().is_none());
        fs::write(&gate, "").unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(3), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        assert_eq!(fs::read_to_string(started).unwrap(), "started");
    }

    #[test]
    fn non_directory_sources_report_the_resolved_path_and_type() {
        let fixture = tempfile::tempdir().unwrap();
        let file = fixture.path().join("settings.json");
        fs::write(&file, "{}").unwrap();
        let link = fixture.path().join("file-link");
        symlink(&file, &link).unwrap();
        let fifo = fixture.path().join("fifo");
        let name = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let socket = fixture.path().join("socket");
        let _listener = UnixListener::bind(&socket).unwrap();
        for (source, kind) in [
            (file, "regular file"),
            (link, "regular file"),
            (fifo, "FIFO"),
            (socket, "socket"),
            (PathBuf::from("/dev/null"), "character device"),
        ] {
            let error = mount(&format!("{}:/opt/settings:ro", source.display()))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(source.canonicalize().unwrap().to_str().unwrap()),
                "{error}"
            );
            for expected in [kind, "directory", "dedicated directory"] {
                assert!(error.contains(expected), "{error}");
            }
        }
    }

    #[test]
    fn directories_and_directory_symlinks_preserve_read_only_and_destination_rules() {
        let fixture = tempfile::tempdir().unwrap();
        let link = fixture.path().join("directory-link");
        symlink(fixture.path(), &link).unwrap();
        for source in [fixture.path(), link.as_path()] {
            for (suffix, read_only) in [("", false), (":ro", true)] {
                let parsed = mount(&format!(
                    "{}:/opt//settings/./config{suffix}",
                    source.display()
                ))
                .unwrap();
                assert_eq!(
                    parsed,
                    (
                        fixture.path().canonicalize().unwrap(),
                        "/opt/settings/config".into(),
                        read_only
                    )
                );
            }
        }
        for guest in [
            "relative",
            "/",
            "/home",
            "/home/agent",
            "/workspace",
            "/dev/file",
            "/proc/file",
            "/sys/file",
            "/safeyolo/file",
            "/safeyolo-status/file",
            "/opt/../etc",
        ] {
            assert!(
                mount(&format!("{}:{guest}:ro", fixture.path().display()))
                    .unwrap_err()
                    .to_string()
                    .contains("mount destination is invalid or reserved")
            );
        }
        for suffix in [":rw", ":ro:ro"] {
            assert!(
                mount(&format!(
                    "{}:/opt/settings{suffix}",
                    fixture.path().display()
                ))
                .unwrap_err()
                .to_string()
                .contains("mount requires")
            );
        }
    }
}

#[cfg(test)]
mod package_tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn boot_stages_selected_rootfs_and_caches_together_without_discovery() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        fs::write(root.join("config.toml"), "").unwrap();
        let mapping = crate::linux_host::mapping_for_root(root).unwrap();
        let platform = if std::env::consts::ARCH == "aarch64" {
            "arm64"
        } else {
            "amd64"
        };
        fs::write(root.join("package-info"), format!(
            "source_commit={}\nprofile=debug\nplatform=linux-{platform}\nminimum_runtime=2.34\nguest_compatibility=v1\nguest_repository={}\nguest_discovery_tag=compat-v1\n",
            "a".repeat(40), crate::guest_oci::REPOSITORY,
        )).unwrap();
        fs::create_dir_all(root.join("assets/guest")).unwrap();
        for name in [
            "guest-init",
            "guest-init-static",
            "guest-init-per-run",
            "guest-proxy-forwarder",
            "guest-shell-bridge",
            "guest-desktop",
        ] {
            fs::write(root.join("assets/guest").join(name), "#!/bin/sh\n").unwrap();
        }
        fs::write(
            root.join("assets/guest/safeyolo-guest"),
            b"\x7fELF0000000000000000",
        )
        .unwrap();
        fs::create_dir_all(root.join("assets/skills/safeyolo")).unwrap();
        fs::write(root.join("assets/skills/safeyolo/SKILL.md"), "fixture").unwrap();
        fs::create_dir(root.join("certs")).unwrap();
        fs::write(root.join("certs/mitmproxy-ca-cert.pem"), "fixture CA").unwrap();
        for version in ["g1", "g2"] {
            let inputs = root.join(version);
            for path in [
                "etc",
                "workspace",
                "safeyolo",
                "safeyolo-status",
                "home/agent",
                "usr/local/share/ca-certificates",
            ] {
                fs::create_dir_all(inputs.join("rootfs-tree").join(path)).unwrap();
            }
            fs::write(
                inputs.join("rootfs-tree/usr/local/share/ca-certificates/safeyolo.crt"),
                "",
            )
            .unwrap();
            fs::write(
                inputs.join("cache-paths.txt"),
                format!("/var/cache/{version}\n"),
            )
            .unwrap();
            // Synthetic staging inputs use the selected host mapping.
            // Archive ownership is checked separately.
            let tree = inputs.join("rootfs-tree");
            fs::set_permissions(&tree, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(
                std::process::Command::new("sudo")
                    .args(["-n", "chown"])
                    .arg(format!("{}:{}", mapping.uid_base, mapping.gid_base))
                    .arg(&tree)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        fs::create_dir(root.join("share")).unwrap();
        std::os::unix::fs::symlink(root.join("g1/rootfs-tree"), root.join("share/rootfs-tree"))
            .unwrap();
        fs::copy(
            root.join("g1/cache-paths.txt"),
            root.join("share/cache-paths.txt"),
        )
        .unwrap();
        let selection = |version: &str, hex: &str| {
            json!({
                "version":"guest-2026-10-12.1", "repository":crate::guest_oci::REPOSITORY,
                "compatibility":"v1", "platform":format!("linux/{platform}"),
                "index":{"digest":format!("sha256:{}", hex.repeat(64)),"size":1},
                "manifest":{"digest":format!("sha256:{}", hex.repeat(64)),"size":1},
                "archive":{"digest":format!("sha256:{}", hex.repeat(64)),"size":1},
                "assets":root.join(version),
            })
        };
        let g1 = selection("g1", "a");
        let mut g2 = selection("g2", "b");
        g2["installed_assets"] = json!(root.join("g2"));
        g2["previous"] = g1.clone();
        let path = root.join("share/guest-selection.json");
        crate::coord_supervisor::atomic_write(&path, &serde_json::to_vec(&g1).unwrap(), 0o600)
            .unwrap();
        let agent = Agent {
            name: "alice".into(),
            id: uuid::Uuid::new_v4().to_string(),
            folder: Some(root.display().to_string()),
            launcher: None,
            host_script: None,
            memory_mb: None,
            rootfs_overlay: None,
            user_default_args: vec![],
            mounts: vec![],
            dangerously_allow_unowned: false,
        };
        crate::host_platform::in_instance(root.to_owned(), async {
            let old_context = stage(&agent, "10.200.0.1", &"1".repeat(32)).await.unwrap();
            let config = root.join("agents/alice/config.json");
            let old_spec: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
            crate::coord_supervisor::atomic_write(&path, &serde_json::to_vec(&g2).unwrap(), 0o600)
                .unwrap();
            assert_eq!(old_context["guest_inputs"], json!(root.join("share")));
            assert_eq!(old_spec["root"]["path"], json!(root.join("g1/rootfs-tree")));
            let new_context = stage(&agent, "10.200.0.1", &"2".repeat(32)).await.unwrap();
            let new_spec: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
            assert_eq!(new_context["guest_inputs"], json!(root.join("g2")));
            assert_eq!(new_spec["root"]["path"], json!(root.join("g2/rootfs-tree")));
            for (spec, expected, rejected) in [
                (&old_spec, "/var/cache/g1", "/var/cache/g2"),
                (&new_spec, "/var/cache/g2", "/var/cache/g1"),
            ] {
                let mounts = spec["mounts"].as_array().unwrap();
                assert!(mounts.iter().any(|mount| mount["destination"] == expected));
                assert!(mounts.iter().all(|mount| mount["destination"] != rejected));
            }
            // A custom profile with explicit inputs does not consume the default.
            let directory = root.join("agents/alice");
            std::os::unix::fs::symlink(root.join("g1/rootfs-tree"), directory.join("rootfs"))
                .unwrap();
            fs::write(directory.join("cache-paths.txt"), "/var/cache/custom\n").unwrap();
            fs::rename(root.join("g2"), root.join("unused-g2")).unwrap();
            stage(&agent, "10.200.0.1", &"4".repeat(32)).await.unwrap();
            let custom: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
            assert_eq!(custom["root"]["path"], json!(root.join("g1/rootfs-tree")));
            assert!(
                custom["mounts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|mount| mount["destination"] == "/var/cache/custom")
            );
            fs::rename(root.join("unused-g2"), root.join("g2")).unwrap();
            fs::remove_file(directory.join("rootfs")).unwrap();
            fs::remove_file(directory.join("cache-paths.txt")).unwrap();
            crate::coord_supervisor::atomic_write(&path, &serde_json::to_vec(&g1).unwrap(), 0o600)
                .unwrap();
            stage(&agent, "10.200.0.1", &"3".repeat(32)).await.unwrap();
            let restored: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
            assert_eq!(restored["root"]["path"], old_spec["root"]["path"]);

            // A complete host/guest switch must capture both from the same
            // retained pair, even when the old top-level receipt differs.
            for (name, compatibility, guest) in [("one", "v1", &g1), ("two", "v2", &g2)] {
                let pair = root.join("versions").join(name);
                fs::create_dir_all(pair.join("host/assets/guest")).unwrap();
                fs::create_dir(pair.join("share")).unwrap();
                fs::write(
                    pair.join("host/package-info"),
                    fs::read_to_string(root.join("package-info"))
                        .unwrap()
                        .replace("v1", compatibility),
                )
                .unwrap();
                for entry in fs::read_dir(root.join("assets/guest")).unwrap() {
                    let entry = entry.unwrap();
                    fs::copy(
                        entry.path(),
                        pair.join("host/assets/guest").join(entry.file_name()),
                    )
                    .unwrap();
                }
                fs::write(pair.join("host/assets/guest/guest-init"), compatibility).unwrap();
                std::os::unix::fs::symlink(
                    root.join("assets/skills"),
                    pair.join("host/assets/skills"),
                )
                .unwrap();
                std::os::unix::fs::symlink(
                    root.join("g1/rootfs-tree"),
                    pair.join("share/rootfs-tree"),
                )
                .unwrap();
                fs::copy(
                    root.join("g1/cache-paths.txt"),
                    pair.join("share/cache-paths.txt"),
                )
                .unwrap();
                let mut guest = guest.clone();
                guest["compatibility"] = json!(compatibility);
                fs::write(
                    pair.join("share/guest-selection.json"),
                    serde_json::to_vec(&guest).unwrap(),
                )
                .unwrap();
            }
            let one = root.join("versions/one");
            let two = root.join("versions/two");
            std::os::unix::fs::symlink(&one, root.join("current")).unwrap();
            let first = stage(&agent, "10.200.0.1", &"5".repeat(32)).await.unwrap();
            assert_eq!(first["host_package"], json!(one.join("host")));
            assert_eq!(first["guest_inputs"], json!(one.join("share")));
            assert_eq!(
                fs::read_to_string(root.join("agents/alice/config-share/guest-init")).unwrap(),
                "v1"
            );
            std::os::unix::fs::symlink(&two, root.join("next")).unwrap();
            fs::rename(root.join("next"), root.join("current")).unwrap();
            let second = stage(&agent, "10.200.0.1", &"6".repeat(32)).await.unwrap();
            assert_eq!(second["host_package"], json!(two.join("host")));
            assert_eq!(second["guest_inputs"], json!(root.join("g2")));
            assert_eq!(
                fs::read_to_string(root.join("agents/alice/config-share/guest-init")).unwrap(),
                "v2"
            );
            assert_eq!(first["host_package"], json!(one.join("host")));
        })
        .await;
    }

    #[tokio::test]
    async fn installed_skills_replace_stale_files_and_survive_missing_input() {
        let fixture = tempfile::tempdir().unwrap();
        let source = fixture.path().join("assets/skills");
        let share = fixture.path().join("share");
        fs::create_dir_all(source.join("safeyolo")).unwrap();
        fs::create_dir_all(share.join("skills")).unwrap();
        fs::write(source.join("safeyolo/SKILL.md"), "installed skill").unwrap();
        fs::write(share.join("skills/retired.py"), "old input").unwrap();
        stage_skills(&source, &share).await.unwrap();
        assert!(!share.join("skills/retired.py").exists());
        assert_eq!(
            fs::read_to_string(share.join("skills/safeyolo/SKILL.md")).unwrap(),
            "installed skill"
        );
        fs::remove_file(source.join("safeyolo/SKILL.md")).unwrap();
        assert!(stage_skills(&source, &share).await.is_err());
        assert!(share.join("skills/safeyolo/SKILL.md").is_file());
    }
}
