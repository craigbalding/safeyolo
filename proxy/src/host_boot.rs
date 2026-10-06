//! Prepare the installed guest inputs for one stopped sandbox incarnation.

use crate::{Error, host_agents::Agent, host_platform::config_dir};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
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
    let guest = Path::new(parts[1]);
    if !guest.is_absolute()
        || guest
            .components()
            .any(|part| part == std::path::Component::ParentDir)
        || ["/", "/home/agent", "/workspace"]
            .iter()
            .any(|root| guest == Path::new(root))
        || ["/dev", "/proc", "/sys", "/safeyolo", "/safeyolo-status"]
            .iter()
            .any(|root| guest.starts_with(root))
    {
        return Err("mount destination is invalid or reserved".into());
    }
    Ok((
        host,
        guest
            .components()
            .collect::<PathBuf>()
            .to_string_lossy()
            .into_owned(),
        parts.len() == 3,
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
pub(crate) async fn setup(agent: &Agent) -> Result<(), Error> {
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
    let result = tokio::process::Command::new(script)
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
        .status()
        .await?;
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
        "extra_shares":shares.iter().map(|(host,_,ro)| json!({"host_path":host,"read_only":ro})).collect::<Vec<_>>(),
        "writable_mounts":shares.iter().filter(|(_,_,ro)| !ro).map(|(host,_,_)| host).collect::<Vec<_>>(),
        "command_payloads":previous.get("command_payloads").cloned().unwrap_or_else(|| json!({}))});
    crate::guest_commands::stage(&home, &share, &root.join("assets/guest"), context.clone())?;
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
    if root.join("assets/guest/guest-sudo").is_file() {
        fs::copy(
            root.join("assets/guest/guest-sudo"),
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
    fs::write(
        share.join("proxy.env"),
        "export HTTP_PROXY=http://127.0.0.1:8080\nexport HTTPS_PROXY=$HTTP_PROXY\nexport http_proxy=$HTTP_PROXY\nexport https_proxy=$HTTP_PROXY\nexport NO_PROXY=localhost,127.0.0.1\nexport no_proxy=$NO_PROXY\nexport SSL_CERT_FILE=/usr/local/share/ca-certificates/safeyolo.crt\nexport REQUESTS_CA_BUNDLE=$SSL_CERT_FILE\nexport NODE_EXTRA_CA_CERTS=$SSL_CERT_FILE\nexport HOME=/home/agent\n",
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
    #[cfg(target_os = "linux")]
    {
        let rootfs = if directory.join("rootfs").is_dir() {
            directory.join("rootfs")
        } else {
            root.join("share/rootfs-tree")
        };
        if !rootfs.is_dir() {
            return Err(format!("installed rootfs tree is missing: {}", rootfs.display()).into());
        }
        if rootfs.metadata()?.uid() != 100000 {
            return Err(format!(
                "rootfs tree must be owned by sandbox root UID 100000: {}",
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
            &workspace,
            ip,
            &agent.name,
            &shares,
        )?;
        crate::guest_commands::write_json(&directory.join("config.json"), &spec)?;
    }
    Ok(context)
}

#[cfg(target_os = "linux")]
fn oci(
    root: &Path,
    directory: &Path,
    rootfs: &Path,
    workspace: &Path,
    ip: &str,
    name: &str,
    shares: &[(PathBuf, String, bool)],
) -> Result<Value, Error> {
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
        bind(
            &root.join("data/sockets").join(format!("{ip}_{name}")),
            "/safeyolo/proxy",
            true,
        ),
    ];
    for (host, guest, ro) in shares {
        if let Ok(relative) = Path::new(guest).strip_prefix("/home/agent") {
            fs::create_dir_all(directory.join("home").join(relative))?;
        }
        mounts.push(bind(host, guest, *ro));
    }
    let caches = directory.join("cache-paths.txt");
    let caches = if caches.is_file() {
        caches
    } else {
        root.join("share/cache-paths.txt")
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
            "args":["/bin/bash","-c","mkdir -p /var/log /safeyolo-status && : > /safeyolo-status/boot.log && ln -sf /safeyolo-status/boot.log /var/log/safeyolo-boot.log && exec /safeyolo/guest-init >> /safeyolo-status/boot.log 2>&1"],
            "env":["PATH=/home/agent/.mise/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","HOME=/home/agent","USER=agent","TERM=xterm-256color","BASH_ENV=/etc/mise-activate.sh","MISE_DATA_DIR=/home/agent/.mise","MISE_CONFIG_DIR=/home/agent/.mise","MISE_CACHE_DIR=/home/agent/.mise/cache","MISE_OVERRIDE_CONFIG_FILENAMES=/etc/safeyolo/mise-project-config-disabled.toml","MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES=none"],
            "capabilities":{"bounding":caps,"effective":caps,"permitted":caps,"ambient":caps},"rlimits":[{"type":"RLIMIT_NOFILE","hard":65536,"soft":65536}],"noNewPrivileges":false},
        "mounts":mounts,"linux":{"namespaces":[{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"mount"}],"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_AARCH64"],"syscalls":[{"names":["unshare"],"action":"SCMP_ACT_ERRNO","errnoRet":1}]}}}),
    )
}
