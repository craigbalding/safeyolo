//! Ordinary Linux extra directories, each served outside the root Gofer tree.
//!
//! Callers hold the agent's existing SetupLock across these operations. There
//! is deliberately no guest or operator API here. runtime.json owns the share
//! receipts along with the sandbox's other process receipts.

use crate::{Error, host_boot, host_platform, host_runs};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
};

const MODE: &str = "isolated-gofer-v1";

struct Run {
    name: String,
    receipt: Value,
    id: String,
}

impl Run {
    fn open(name: &str, expected: &str) -> Result<Self, Error> {
        if !host_platform::valid_agent_name(name) {
            return Err("invalid agent name".into());
        }
        let receipt = host_runs::read(name)?.ok_or("sandbox runtime record is missing")?;
        let id = host_runs::id(name)?;
        if receipt["run_id"] != expected || id != format!("safeyolo-{expected}") {
            return Err("sandbox incarnation changed; no share was changed".into());
        }
        let agents = crate::host_agents::list()?;
        let agent = receipt["agent_id"]
            .as_str()
            .map(|id| crate::host_agents::by_id(&agents, id))
            .transpose()?
            .flatten()
            .ok_or("share's agent identity is missing")?;
        if agent.name != name || host_platform::backend_pid(name).is_none() {
            return Err("share's sandbox process identity is unverified".into());
        }
        let run = Self {
            name: name.into(),
            receipt,
            id,
        };
        run.check()?;
        Ok(run)
    }

    fn check(&self) -> Result<Value, Error> {
        let current = host_runs::read(&self.name)?.ok_or("sandbox record disappeared")?;
        if ["run_id", "agent_id", "backend_pid", "backend_token"]
            .iter()
            .any(|key| current[key] != self.receipt[key])
            || host_runs::id(&self.name)? != self.id
            || host_platform::backend_pid(&self.name).is_none()
        {
            return Err("sandbox incarnation changed; share state was preserved".into());
        }
        Ok(current)
    }

    fn save_share(&self, share: &Value) -> Result<(), Error> {
        let mut current = self.check()?;
        let entries = current["linux"]["extra_shares"]
            .as_array_mut()
            .ok_or("isolated share receipts are missing")?;
        if let Some(entry) = entries.iter_mut().find(|entry| entry["id"] == share["id"]) {
            *entry = share.clone();
        } else {
            entries.push(share.clone());
        }
        host_runs::save(&self.name, &current)
    }
}

pub(crate) async fn attach_startup(name: &str) -> Result<(), Error> {
    let mut current = host_runs::read(name)?.ok_or("sandbox runtime record is missing")?;
    let generation = current["run_id"]
        .as_str()
        .ok_or("sandbox generation is missing")?
        .to_owned();
    let agents = crate::host_agents::list()?;
    let agent = crate::host_agents::by_id(
        &agents,
        current["agent_id"]
            .as_str()
            .ok_or("agent identity is missing")?,
    )?
    .ok_or("agent no longer exists")?;
    Run::open(name, &generation)?;
    if !current["linux"]["extra_share_mode"].is_null() {
        return Err("startup shares were already prepared; their receipts were preserved".into());
    }
    // Preserve the existing last-entry-wins configuration contract.
    let mut selected = Vec::new();
    for spec in &agent.mounts {
        let (_, target, _) = host_boot::mount(spec)?;
        selected.retain(|(_, previous)| previous != &target);
        selected.push((spec.clone(), target));
    }
    current["linux"]["extra_share_mode"] = MODE.into();
    current["linux"]["extra_shares"] = json!([]);
    host_runs::save(name, &current)?;
    for (spec, _) in selected {
        attach(name, &generation, &spec).await?;
    }
    Ok(())
}

fn check_target(spec: &Value, target: &str) -> Result<(), Error> {
    let target = Path::new(target);
    // Preserve home/workspace children, but never cover their roots, another
    // static mount, or the config/control trees. This also checks resolved
    // guest paths, rather than trusting the configured spelling.
    if !target.is_absolute()
        || target
            .components()
            .any(|part| part == std::path::Component::ParentDir)
        || ["/dev", "/proc", "/sys", "/safeyolo", "/safeyolo-status"]
            .iter()
            .any(|root| target.starts_with(root))
        || spec["mounts"]
            .as_array()
            .ok_or("OCI mounts are missing")?
            .iter()
            .filter_map(|mount| mount["destination"].as_str())
            .any(|mount| Path::new(mount).starts_with(target))
    {
        return Err("extra mount destination would conceal a reserved mount".into());
    }
    Ok(())
}

fn inherit(command: &mut Command, descriptors: Vec<RawFd>) {
    // Only these child descriptors survive exec. Their owners remain open
    // until spawn has completed; all other host descriptors stay CLOEXEC.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            for descriptor in &descriptors {
                if libc::fcntl(*descriptor, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

fn pipe() -> io::Result<(File, File)> {
    let mut pair = [0; 2];
    if unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (File::from_raw_fd(pair[0]), File::from_raw_fd(pair[1])) })
}

fn scoped_gofer_command(scope: &str, cgroup: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    // A login session is outside the user manager's delegated subtree. Only
    // systemd can move this child across that boundary. Attach to the existing
    // scope, then verify membership before nsenter or any Gofer work. The
    // shell execs the launcher, so its PID and inherited descriptors survive.
    command.args([
        "-eu",
        "-c",
        r#"busctl --user --timeout=10s --allow-interactive-authorization=no call \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager AttachProcessesToUnit ssau "$1" "" 1 "$$"
joined=no
while IFS= read -r actual; do
    if [ "$actual" = "$2" ]; then joined=yes; fi
done < /proc/self/cgroup
if [ "$joined" != yes ]; then
    printf '%s\n' "share Gofer did not join the sandbox's resource scope" >&2
    exit 1
fi
shift 2
exec "$@""#,
        "share-gofer",
        scope,
        cgroup,
    ]);
    command
}

fn gofer_command(run: &Run) -> Result<Command, Error> {
    let pid = run.receipt["backend_pid"]
        .as_u64()
        .ok_or("sandbox PID is missing")?;
    let selected = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    if selected == fs::read_to_string("/proc/self/cgroup")? {
        return Ok(Command::new("nsenter"));
    }
    // systemd-run places the original sentry and Gofer in one delegated
    // cgroup. Keep additional Gofers under those same MemoryMax/CPUQuota
    // limits. This changes membership, not the operator's resource policy.
    let path = selected
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("cannot retain sandbox resource limits: unified cgroup path is missing")?;
    let relative = Path::new(path).strip_prefix("/")?;
    if relative
        .components()
        .any(|part| part == std::path::Component::ParentDir)
    {
        return Err("invalid sandbox cgroup path".into());
    }
    let scope = relative
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| name.ends_with(".scope"))
        .ok_or("cannot retain sandbox resource limits: its systemd scope is missing")?;
    run.check()?;
    let mut command = scoped_gofer_command(scope, &format!("0::{path}"));
    command.arg("nsenter");
    Ok(command)
}

/// Connect as namespace root without changing credentials in a host thread.
/// The fixed child only connects the shared socket and execs /bin/true. The
/// host retains that connected socket; there is no host command/RPC service.
async fn connect_control(run: &Run) -> Result<std::os::unix::net::UnixStream, Error> {
    let filename = format!("runsc-{}.sock", run.id);
    let mapping = super::selected_mapping()?;
    let mut selected = None;
    // These are runsc's own fallback directories for long socket paths.
    for root in [
        host_platform::runsc_root(),
        PathBuf::from("/var/run"),
        PathBuf::from("/run"),
        PathBuf::from("/tmp"),
    ] {
        match fs::symlink_metadata(root.join(&filename)) {
            Ok(metadata) => {
                if !metadata.file_type().is_socket() || metadata.uid() != mapping.uid_base {
                    return Err("runsc control socket ownership is unverified".into());
                }
                selected = Some((File::open(&root)?, metadata));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let (directory, before) = selected.ok_or("runsc filesystem control socket is missing; use a runtime with Fs.Mount support (proved release-20261005.0)")?;
    let path = format!("/proc/self/fd/{}/{}", directory.as_raw_fd(), filename);
    let bytes = path.as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() {
        return Err("runsc control socket name is too long".into());
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (to, from) in address.sun_path.iter_mut().zip(bytes) {
        *to = *from as libc::c_char;
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let socket = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    socket.set_read_timeout(Some(Duration::from_secs(20)))?;
    let (user, net) = host_platform::pinned_namespaces(&run.name)?;
    let mut child = Command::new("/bin/true");
    child
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // After fork, use only async-signal-safe libc calls until exec.
    unsafe {
        child.as_std_mut().pre_exec(move || {
            if libc::setns(user.as_raw_fd(), libc::CLONE_NEWUSER) != 0
                || libc::setns(net.as_raw_fd(), libc::CLONE_NEWNET) != 0
                || libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(0) != 0
                || libc::setuid(0) != 0
                || libc::connect(
                    fd,
                    (&address as *const libc::sockaddr_un).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    run.check()?;
    if !child.status().await?.success() {
        return Err("could not enter the share's control namespace".into());
    }
    let after = fs::symlink_metadata(path)?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err("runsc control socket changed; no request was sent".into());
    }
    run.check()?;
    Ok(socket)
}

fn send_request(
    socket: &mut std::os::unix::net::UnixStream,
    request: &Value,
    descriptor: Option<RawFd>,
) -> Result<Value, Error> {
    let bytes = serde_json::to_vec(request)?;
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // usize storage gives cmsghdr its required alignment.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0_usize; space.div_ceil(std::mem::size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    if let Some(descriptor) = descriptor {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
            std::ptr::write(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor);
        }
    }
    let count = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
    if count < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if count == 0 {
        return Err("runsc control socket closed before request".into());
    }
    socket.write_all(&bytes[count as usize..])?;
    // urpc sends one JSON value, without a length header or final newline.
    let mut received = Vec::new();
    let mut buffer = [0; 4096];
    while received.len() < 65536 {
        let count = socket.read(&mut buffer)?;
        if count == 0 {
            return Err(
                "runsc closed before a complete share response; live state is uncertain".into(),
            );
        }
        received.extend_from_slice(&buffer[..count]);
        if received.len() > 65536 {
            return Err("runsc share response exceeds 64 KiB; live state is uncertain".into());
        }
        match serde_json::from_slice::<Value>(&received) {
            Ok(response) => return Ok(response),
            Err(error) if error.is_eof() => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err("runsc share response exceeds 64 KiB; live state is uncertain".into())
}

async fn rpc(run: &Run, request: Value, descriptor: Option<RawFd>) -> Result<Value, Error> {
    let mut socket = connect_control(run).await?;
    // The worker owns its duplicate even if its async caller is cancelled.
    let descriptor = descriptor
        .map(|fd| unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned())
        .transpose()?;
    let result = tokio::task::spawn_blocking(move || {
        send_request(
            &mut socket,
            &request,
            descriptor.as_ref().map(AsRawFd::as_raw_fd),
        )
    })
    .await??;
    run.check()?;
    Ok(result)
}

struct GuestTarget {
    child: Child,
    resolved: String,
    path: String,
}

impl GuestTarget {
    async fn open(run: &Run, target: &str, parent: bool) -> Result<Self, Error> {
        // Hold a guest directory descriptor while the host mounts. Fs.Mount
        // follows this pinned dentry, so a concurrent guest rename/symlink
        // replacement cannot redirect a validated target onto control mounts.
        const SCRIPT: &str = "set -eu; if [ \"$2\" = create ]; then mkdir -p -- \"$1\"; fi; exec 3<\"$1\"; printf '%s\\n%s\\n' \"$$\" \"$(readlink -f -- /proc/self/fd/3)\"; read -r release";
        let mut child = host_platform::runsc_command(&run.name)?
            .args([
                "exec",
                "--user",
                "0:0",
                "--cwd",
                "/",
                "--env",
                "BASH_ENV=",
                &run.id,
                "/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                SCRIPT,
                "share-target",
                target,
                if parent { "parent" } else { "create" },
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let output = async {
            let stdout = child
                .stdout
                .take()
                .ok_or("share target output is unavailable")?;
            let mut lines = tokio::io::BufReader::new(stdout.take(8192)).lines();
            let pid = lines
                .next_line()
                .await?
                .ok_or("could not open the guest share target")?;
            let pid: u32 = pid.parse()?;
            let resolved = lines
                .next_line()
                .await?
                .ok_or("could not resolve the guest share target")?;
            if pid == 0 || resolved.is_empty() {
                return Err("invalid guest share target".into());
            }
            Ok::<_, Error>((resolved, format!("/proc/{pid}/fd/3")))
        };
        let (resolved, path) = tokio::time::timeout(Duration::from_secs(10), output).await??;
        run.check()?;
        Ok(Self {
            child,
            resolved,
            path,
        })
    }

    async fn close(mut self) -> Result<(), Error> {
        self.child
            .stdin
            .take()
            .ok_or("share target input is unavailable")?
            .write_all(b"release\n")
            .await?;
        if !tokio::time::timeout(Duration::from_secs(5), self.child.wait())
            .await??
            .success()
        {
            return Err("could not release the guest share target descriptor".into());
        }
        Ok(())
    }
}

pub(crate) async fn attach(
    name: &str,
    expected: &str,
    specification: &str,
) -> Result<Value, Error> {
    let run = Run::open(name, expected)?;
    let (source, target, read_only) = host_boot::mount(specification)?;
    let directory = host_platform::config_dir().join("agents").join(name);
    let mut spec: Value = serde_json::from_slice(&fs::read(directory.join("config.json"))?)?;
    check_target(&spec, &target)?;
    let current = run.check()?;
    if current["linux"]["extra_share_mode"] != MODE {
        return Err("this sandbox uses baked-in startup binds; live removal is unsupported. An explicit future stop/start is required; this run was left intact".into());
    }
    if current["linux"]["extra_shares"]
        .as_array()
        .ok_or("share receipts are missing")?
        .iter()
        .any(|share| {
            share["state"] != "removed"
                && share["guest_path"]
                    .as_str()
                    .is_some_and(|other| Path::new(other).starts_with(&target))
        })
    {
        return Err("extra mount destination is already in use".into());
    }
    let source_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&source)?;
    let guest = GuestTarget::open(&run, &target, false)
        .await
        .map_err(|error| format!("could not prepare extra mount at {target}: {error}"))?;
    check_target(&spec, &guest.resolved)?;
    if current["linux"]["extra_shares"]
        .as_array()
        .ok_or("share receipts are missing")?
        .iter()
        .any(|share| {
            share["state"] != "removed"
                && share["resolved_path"]
                    .as_str()
                    .is_some_and(|other| Path::new(other).starts_with(&guest.resolved))
        })
    {
        return Err("resolved extra mount destination is already in use".into());
    }
    let id = uuid::Uuid::new_v4().simple().to_string();
    let bundle = directory.join("extra-shares").join(expected).join(&id);
    fs::create_dir_all(&bundle)?;
    spec["root"] =
        json!({"path":format!("/proc/self/fd/{}", source_fd.as_raw_fd()),"readonly":read_only});
    spec["mounts"] = json!([]);
    spec["hooks"] = json!({});
    crate::guest_commands::write_json(&bundle.join("config.json"), &spec)?;
    let config = File::open(bundle.join("config.json"))?;
    let log = File::create(bundle.join("gofer.log"))?;
    let (connection, gofer) = std::os::unix::net::UnixStream::pair()?;
    let (_rpc_host, rpc_gofer) = std::os::unix::net::UnixStream::pair()?;
    let (mounts, mounts_gofer) = pipe()?;
    let mut command = gofer_command(&run)?;
    host_platform::pin_namespace_arguments(name, &mut command)?;
    command
        .args([
            "unshare",
            "--mount",
            "--ipc",
            "--uts",
            "--pid",
            "--net",
            "--fork",
            "--kill-child=SIGKILL",
            "--",
        ])
        .arg(super::runtime_path()?)
        .args(["--host-uds=open", "gofer", "--bundle"])
        .arg(&bundle)
        .arg("--gofer-mount-confs=lisafs:none")
        .arg(format!("--spec-fd={}", config.as_raw_fd()))
        .arg(format!("--io-fds={}", gofer.as_raw_fd()))
        .arg(format!("--rpc-fd={}", rpc_gofer.as_raw_fd()))
        .arg(format!("--mounts-fd={}", mounts_gofer.as_raw_fd()))
        .arg(&run.id)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    inherit(
        &mut command,
        vec![
            config.as_raw_fd(),
            source_fd.as_raw_fd(),
            gofer.as_raw_fd(),
            rpc_gofer.as_raw_fd(),
            mounts_gofer.as_raw_fd(),
        ],
    );
    let mut child = command.spawn()?;
    let saved = (|| {
        let pid = child.id().ok_or("share Gofer has no PID")?;
        let share = json!({"id":id,"host_path":source,"guest_path":target,"resolved_path":guest.resolved,"read_only":read_only,
            "launcher_pid":pid,"launcher_token":crate::host_lifecycle::process_token(i64::from(pid)).ok_or("share Gofer launcher identity is unavailable")?,"state":"preparing"});
        run.save_share(&share)?;
        Ok::<_, Error>(share)
    })();
    let mut share = match saved {
        Ok(share) => share,
        Err(error) => {
            child.kill().await?;
            return Err(error);
        }
    };
    drop((config, gofer, rpc_gofer, mounts_gofer));
    let prepared = async {
        let mut mounts = tokio::fs::File::from_std(mounts);
        let mut bytes = [0; 32];
        let count = tokio::time::timeout(Duration::from_secs(15), mounts.read(&mut bytes)).await??;
        if count == 0 || child.try_wait()?.is_some() { return Err("isolated share Gofer failed during startup; inspect its gofer.log".into()); }
        let launcher = share["launcher_pid"].as_u64().ok_or("share launcher PID is missing")?;
        let children = fs::read_to_string(format!("/proc/{launcher}/task/{launcher}/children"))?;
        let children = children.split_whitespace().map(str::parse::<u32>).collect::<Result<Vec<_>, _>>()?;
        let [pid] = children.as_slice() else { return Err("share Gofer launcher did not identify one isolated child".into()); };
        share["gofer_pid"] = (*pid).into();
        share["gofer_token"] = crate::host_lifecycle::process_token(i64::from(*pid)).ok_or("share Gofer child identity is unavailable")?.into();
        share["state"] = "mounting".into();
        run.save_share(&share)?;
        let response = rpc(&run, json!({"method":"Fs.Mount","arg":{"container_id":run.id,"source":format!("safeyolo-share-{id}"),"target":guest.path,"fs_type":"gofer","flags":6 | u64::from(read_only),"data":"cache=remote_revalidating,directfs"}}), Some(connection.as_raw_fd())).await?;
        if response["success"] != true {
            share["state"] = "refused".into();
            return Err(format!("extra mount {target} failed: {}; requires Fs.Mount support (proved release-20261005.0)", response["err"]).into());
        }
        share["state"] = "mounted".into();
        Ok::<_, Error>(())
    }.await;
    drop(connection);
    let close = guest.close().await;
    run.save_share(&share)?;
    if let Err(error) = prepared {
        // An unknown RPC outcome may have mounted the share. Preserve that
        // receipt and Gofer until the caller stops this failed startup/run.
        if share["state"] != "mounting" {
            release_gofer(&share, &bundle).await?;
            share["state"] = "removed".into();
            share["error"] = error.to_string().into();
            run.save_share(&share)?;
        }
        return Err(error);
    }
    close?;
    Ok(share)
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Internal removal prerequisite; the public live-mount command is separate work"
    )
)]
pub(crate) async fn remove(name: &str, expected: &str, target: &str) -> Result<Value, Error> {
    let run = Run::open(name, expected)?;
    let current = run.check()?;
    if current["linux"]["extra_share_mode"] != MODE {
        return Err("this sandbox has baked-in startup binds; safe live removal is unsupported. Use an explicit future stop/start; this run was left intact".into());
    }
    let mut share = current["linux"]["extra_shares"]
        .as_array()
        .ok_or("share receipts are missing")?
        .iter()
        .find(|share| share["guest_path"] == target && share["state"] == "mounted")
        .cloned()
        .ok_or("this extra share is not recorded as mounted")?;
    let resolved = Path::new(
        share["resolved_path"]
            .as_str()
            .ok_or("share target is missing")?,
    );
    let parent = resolved.parent().ok_or("share parent is missing")?;
    let guest =
        GuestTarget::open(&run, parent.to_str().ok_or("invalid share parent")?, true).await?;
    if Path::new(&guest.resolved) != parent {
        return Err("share parent changed; removal was refused".into());
    }
    let pinned = format!(
        "{}/{}",
        guest.path,
        resolved
            .file_name()
            .ok_or("share target is missing")?
            .to_str()
            .ok_or("invalid share target")?
    );
    let response = rpc(
        &run,
        json!({"method":"Fs.Umount","arg":{"container_id":run.id,"target":pinned,"flags":0}}),
        None,
    )
    .await;
    let close = guest.close().await;
    let response = response?;
    if response["success"] != true {
        return Err(format!(
            "extra mount removal refused; share remains available: {}",
            response["err"]
        )
        .into());
    }
    // Ordinary Umount has succeeded before this share's Gofer is released.
    // No shared root Gofer, guest workload or unrelated share is signalled.
    share["state"] = "unmounted".into();
    run.save_share(&share)?;
    release_gofer(&share, &share_bundle(name, expected, &share)?).await?;
    share["state"] = "removed".into();
    run.save_share(&share)?;
    close?;
    Ok(share)
}

fn share_bundle(name: &str, generation: &str, share: &Value) -> Result<PathBuf, Error> {
    let id = share["id"].as_str().ok_or("share ID is missing")?;
    if ![generation, id]
        .iter()
        .all(|value| value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err("invalid share ownership receipt".into());
    }
    Ok(host_platform::config_dir()
        .join("agents")
        .join(name)
        .join("extra-shares")
        .join(generation)
        .join(id))
}

fn pin_share_process(share: &Value, kind: &str) -> Result<Option<OwnedFd>, Error> {
    let pid = share[format!("{kind}_pid")]
        .as_i64()
        .ok_or("share Gofer PID is missing")?;
    let token = share[format!("{kind}_token")]
        .as_str()
        .ok_or("share Gofer birth is missing")?;
    if host_runs::saved_process_is_dead(share, kind) {
        return Ok(None);
    }
    if crate::host_lifecycle::process_token(pid).as_deref() != Some(token) {
        return Err("share Gofer birth changed; no process was signalled".into());
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let process = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    if crate::host_lifecycle::process_token(pid).as_deref() != Some(token) {
        return Err("share Gofer identity changed; no process was signalled".into());
    }
    Ok(Some(process))
}

async fn release_gofer(share: &Value, bundle: &Path) -> Result<(), Error> {
    // Pin the actual Gofer as well as its unshare launcher. Observing only
    // the launcher exit would not establish that the file server exited.
    let gofer = if share["gofer_pid"].is_null() {
        None
    } else {
        pin_share_process(share, "gofer")?
    };
    release_launcher(share, bundle).await?;
    if let Some(gofer) = gofer {
        host_runs::wait_for_pidfd_exit(&gofer, Duration::from_secs(5)).await?;
    }
    Ok(())
}

async fn release_launcher(share: &Value, bundle: &Path) -> Result<(), Error> {
    let Some(process) = pin_share_process(share, "launcher")? else {
        return Ok(());
    };
    let pid = share["launcher_pid"]
        .as_i64()
        .ok_or("share launcher PID is missing")?;
    match host_runs::wait_for_pidfd_exit(&process, Duration::from_secs(2)).await {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
        Err(error) => return Err(error.into()),
    }
    let command = fs::read(format!("/proc/{pid}/cmdline"))?;
    let arguments = command.split(|byte| *byte == 0).collect::<Vec<_>>();
    if !arguments.first().is_some_and(|argument| {
        Path::new(std::ffi::OsStr::from_bytes(argument))
            .file_name()
            .is_some_and(|name| name == "unshare")
    }) || !arguments
        .windows(2)
        .any(|pair| pair[0] == b"--bundle" && pair[1] == bundle.as_os_str().as_bytes())
    {
        return Err("share Gofer command ownership is unverified; no process was signalled".into());
    }
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            process.as_raw_fd(),
            libc::SIGTERM,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    host_runs::wait_for_pidfd_exit(&process, Duration::from_secs(5)).await?;
    Ok(())
}

/// Called only after the selected sentry has stopped and closed its shares.
pub(crate) async fn cleanup_stopped(name: &str) -> Result<(), Error> {
    let Some(mut run) = host_runs::read(name)? else {
        return Ok(());
    };
    if run["linux"]["extra_shares"]
        .as_array()
        .is_none_or(|shares| shares.iter().all(|share| share["state"] == "removed"))
    {
        return Ok(());
    }
    if host_runs::id(name)?
        != format!(
            "safeyolo-{}",
            run["run_id"]
                .as_str()
                .ok_or("sandbox generation is missing")?
        )
        || !host_runs::saved_process_is_dead(&run, "backend")
    {
        return Err("sandbox death is unverified; share cleanup was refused".into());
    }
    let generation = run["run_id"]
        .as_str()
        .ok_or("sandbox generation is missing")?
        .to_owned();
    if let Some(shares) = run["linux"]["extra_shares"].as_array_mut() {
        for share in shares {
            if share["state"] == "removed" {
                continue;
            }
            release_gofer(share, &share_bundle(name, &generation, share)?).await?;
            share["state"] = "removed".into();
        }
        let current =
            host_runs::read(name)?.ok_or("sandbox receipt disappeared during share cleanup")?;
        if current["run_id"] != run["run_id"]
            || current["agent_id"] != run["agent_id"]
            || current["backend_token"] != run["backend_token"]
        {
            return Err("sandbox incarnation changed during share cleanup; replacement receipts were preserved".into());
        }
        host_runs::save(name, &run)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[tokio::test]
    async fn scope_join_checks_placement_before_exec_and_preserves_descriptors() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::tempdir().unwrap();
        let busctl = fixture.path().join("busctl");
        fs::write(
            &busctl,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CALL_RECORD\"\nexit \"$BUS_EXIT\"\n",
        )
        .unwrap();
        fs::set_permissions(&busctl, fs::Permissions::from_mode(0o755)).unwrap();
        let cgroups = fs::read_to_string("/proc/self/cgroup").unwrap();
        let cgroup = cgroups.lines().last().unwrap();
        let mut source = tempfile::tempfile().unwrap();
        source.write_all(b"inherited Gofer connection").unwrap();

        for (manager_exit, selected, success) in [
            (0, cgroup, true),
            (42, cgroup, false),
            (0, "0::/unjoined.scope", false),
        ] {
            let record = fixture.path().join("call");
            let mut command = scoped_gofer_command("selected.scope", selected);
            command
                .args([
                    "/bin/sh",
                    "-c",
                    "exec /bin/cat \"/proc/self/fd/$SOURCE_FD\"",
                ])
                .env("PATH", fixture.path())
                .env("CALL_RECORD", &record)
                .env("BUS_EXIT", manager_exit.to_string())
                .env("SOURCE_FD", source.as_raw_fd().to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            inherit(&mut command, vec![source.as_raw_fd()]);
            let child = command.spawn().unwrap();
            let pid = child.id().unwrap();
            let result = child.wait_with_output().await.unwrap();
            let arguments = fs::read_to_string(record).unwrap();
            let arguments: Vec<_> = arguments.lines().collect();
            assert_eq!(
                arguments[..10],
                [
                    "--user",
                    "--timeout=10s",
                    "--allow-interactive-authorization=no",
                    "call",
                    "org.freedesktop.systemd1",
                    "/org/freedesktop/systemd1",
                    "org.freedesktop.systemd1.Manager",
                    "AttachProcessesToUnit",
                    "ssau",
                    "selected.scope",
                ]
            );
            assert_eq!(arguments[10..], ["", "1", &pid.to_string()]);
            assert_eq!(result.status.success(), success, "{result:?}");
            if success {
                assert_eq!(result.stdout, b"inherited Gofer connection");
            } else {
                assert!(
                    result.stdout.is_empty(),
                    "Gofer command ran before placement"
                );
            }
            if manager_exit != 0 {
                assert_eq!(result.status.code(), Some(manager_exit));
            } else if !success {
                assert!(
                    String::from_utf8_lossy(&result.stderr)
                        .contains("did not join the sandbox's resource scope")
                );
            }
        }
    }

    #[test]
    fn destinations_preserve_static_mounts_and_valid_children() {
        let spec = json!({"mounts":[{"destination":"/workspace"},{"destination":"/home/agent"},{"destination":"/safeyolo"},{"destination":"/safeyolo-status"},{"destination":"/usr/local/share/ca-certificates/safeyolo.crt"},{"destination":"/var/cache/apt"}]});
        for target in [
            "/",
            "/home",
            "/home/agent",
            "/workspace",
            "/safeyolo/proxy",
            "/safeyolo-status/boot.log",
            "/proc/1",
            "/usr",
            "/var/cache",
            "/var/cache/apt",
            "relative",
            "/mnt/../workspace",
        ] {
            assert!(check_target(&spec, target).is_err(), "{target}");
        }
        for target in [
            "/mnt/reference",
            "/home/agent/reference",
            "/workspace/data",
            "/var/cache/other",
        ] {
            check_target(&spec, target).unwrap();
        }
    }

    #[test]
    fn urpc_donates_an_actual_descriptor_and_reads_a_fragmented_response() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"share connection marker").unwrap();
        let peer = std::thread::spawn(move || {
            let mut bytes = [0; 4096];
            let mut control = [0_usize; 8];
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = std::mem::size_of_val(&control);
            let count =
                unsafe { libc::recvmsg(server.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
            assert!(count > 0);
            let request: Value = serde_json::from_slice(&bytes[..count as usize]).unwrap();
            assert_eq!(request["method"], "Fs.Mount");
            let mut donated = unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                assert!(!header.is_null());
                assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
                File::from_raw_fd(std::ptr::read(libc::CMSG_DATA(header).cast::<RawFd>()))
            };
            use std::io::Seek;
            donated.rewind().unwrap();
            let mut marker = String::new();
            donated.read_to_string(&mut marker).unwrap();
            assert_eq!(marker, "share connection marker");
            server.write_all(b"{\"success\":").unwrap();
            std::thread::sleep(Duration::from_millis(10));
            server
                .write_all(b"true,\"err\":\"\",\"result\":{}}")
                .unwrap();
        });
        let result = send_request(
            &mut client,
            &json!({"method":"Fs.Mount","arg":{}}),
            Some(file.as_raw_fd()),
        )
        .unwrap();
        assert_eq!(result["success"], true);
        peer.join().unwrap();
    }

    #[test]
    fn urpc_preserves_refusal_and_rejects_incomplete_or_oversized_responses() {
        for response in [
            b"{\"success\":false,\"err\":\"resource busy\"}".to_vec(),
            b"{\"success\":".to_vec(),
            vec![b' '; 65536],
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let refused = response.starts_with(b"{\"success\":false");
            let peer = std::thread::spawn(move || {
                let mut request = [0; 1024];
                assert!(server.read(&mut request).unwrap() > 0);
                server.write_all(&response).unwrap();
            });
            let result = send_request(
                &mut client,
                &json!({"method":"Fs.Umount","arg":{"flags":0}}),
                None,
            );
            if refused {
                assert_eq!(result.unwrap()["success"], false);
            } else {
                assert!(result.is_err());
            }
            peer.join().unwrap();
        }
    }

    #[tokio::test]
    async fn gofer_cleanup_refuses_a_stale_birth_and_an_unrelated_command() {
        let mut child = Command::new("sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = i64::from(child.id().unwrap());
        let token = crate::host_lifecycle::process_token(pid).unwrap();
        let mut receipt = json!({"launcher_pid":pid, "launcher_token":format!("{token}-stale")});
        assert!(
            release_gofer(&receipt, Path::new("/absent/owned/bundle"))
                .await
                .unwrap_err()
                .to_string()
                .contains("birth changed")
        );
        assert!(child.try_wait().unwrap().is_none());
        receipt["launcher_token"] = token.into();
        assert!(
            release_gofer(&receipt, Path::new("/absent/owned/bundle"))
                .await
                .unwrap_err()
                .to_string()
                .contains("command ownership")
        );
        assert!(child.try_wait().unwrap().is_none());
        child.kill().await.unwrap();
        release_gofer(&receipt, Path::new("/absent/owned/bundle"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stale_incarnations_do_not_change_receipts_or_clean_a_live_process() {
        let fixture = tempfile::tempdir().unwrap();
        host_platform::in_instance(fixture.path().to_owned(), async {
            let generation = "1".repeat(32);
            let directory = fixture.path().join("agents/alice/config-share");
            fs::create_dir_all(&directory).unwrap();
            crate::guest_commands::write_json(&directory.join("host-launch-context.json"), &json!({"generation":generation})).unwrap();
            let current = json!({"run_id":generation,"agent_id":"alice-id","backend_pid":std::process::id(),"backend_token":crate::host_lifecycle::process_token(i64::from(std::process::id())).unwrap(),"linux":{"extra_shares":[{"state":"mounted"}]}});
            host_runs::save("alice", &current).unwrap();
            assert!(Run::open("alice", &"2".repeat(32)).err().unwrap().to_string().contains("incarnation changed"));
            assert!(cleanup_stopped("alice").await.unwrap_err().to_string().contains("death is unverified"));
            assert_eq!(host_runs::read("alice").unwrap().unwrap(), current);
            crate::guest_commands::write_json(&directory.join("host-launch-context.json"), &json!({"generation":"3".repeat(32)})).unwrap();
            assert!(cleanup_stopped("alice").await.is_err());
            assert_eq!(host_runs::read("alice").unwrap().unwrap(), current);
        }).await;
    }

    /// The existing installed Python driver uses this test-only typed entry to
    /// exercise the internal backend. No product add/remove command is added.
    #[tokio::test]
    #[ignore = "requires the owned real Linux fixture selected by the existing backend driver"]
    async fn installed_share_operation() {
        assert_eq!(
            std::env::var("SAFEYOLO_SHARE_TEST_REVISION").unwrap(),
            env!("SAFEYOLO_BUILD_REVISION")
        );
        assert_eq!(env!("SAFEYOLO_BUILD_PROFILE"), "production");
        let root = PathBuf::from(std::env::var_os("SAFEYOLO_SHARE_TEST_ROOT").unwrap());
        let name = std::env::var("SAFEYOLO_SHARE_TEST_AGENT").unwrap();
        let expected = std::env::var("SAFEYOLO_SHARE_TEST_GENERATION").unwrap();
        let operation = std::env::var("SAFEYOLO_SHARE_TEST_OPERATION").unwrap();
        let operand = std::env::var("SAFEYOLO_SHARE_TEST_OPERAND").unwrap();
        host_platform::in_instance(root.clone(), async {
            let directory = root.join("agents").join(&name);
            let _lock = tokio::task::spawn_blocking(move || {
                crate::host_lifecycle::SetupLock::acquire_in(
                    &directory,
                    Some(std::time::Instant::now() + Duration::from_secs(10)),
                )
            })
            .await
            .unwrap()
            .unwrap();
            let result = match operation.as_str() {
                "add" => attach(&name, &expected, &operand).await,
                "remove" => remove(&name, &expected, &operand).await,
                _ => panic!("unknown backend test operation"),
            };
            let mut result = match result {
                Ok(value) => json!({"success":true,"share":value}),
                Err(error) => json!({"success":false,"error":error.to_string()}),
            };
            result["commit"] = env!("SAFEYOLO_BUILD_REVISION").into();
            result["profile"] = env!("SAFEYOLO_BUILD_PROFILE").into();
            println!("\nSHARE_RESULT={result}");
        })
        .await;
    }
}
