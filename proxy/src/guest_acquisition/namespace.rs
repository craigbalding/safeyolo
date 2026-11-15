//! Import canonical archive IDs directly into the selected delegated host IDs.

use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use crate::{
    Error,
    linux_host::{ARCHIVE_BASE, ID_COUNT, Mapping},
};

pub(super) struct ImportNamespace {
    holder: Child,
}

fn entries(base: u32, operator: u32) -> [(u32, u32, u32); 4] {
    // Runtime guest 1000 uses the operator, leaving base+1000 available for
    // import root. Host root is absent; tar sees the archive's canonical IDs.
    [
        (0, base + 1000, 1),
        (ARCHIVE_BASE, base, 1000),
        (ARCHIVE_BASE + 1000, operator, 1),
        (ARCHIVE_BASE + 1001, base + 1001, ID_COUNT - 1001),
    ]
}

impl ImportNamespace {
    pub(super) fn start(root: &Path, mapping: Mapping) -> Result<Self, Error> {
        mapping.validate()?;
        if mapping.host_uid != unsafe { libc::getuid() }
            || mapping.host_gid != unsafe { libc::getgid() }
            || mapping.host_gid == 0
        {
            return Err("guest import requires the selected ordinary host UID/GID".into());
        }
        let mut errors = tempfile::tempfile()?;
        let mut command = crate::linux_host::namespace_command(root, "unshare")?;
        let holder = command
            .args(["-U", "tail", "-f", "/dev/null"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(errors.try_clone()?)
            .spawn()?;
        let mut namespace = Self { holder };
        let prepared = (|| -> Result<(), Error> {
            let parent = fs::metadata("/proc/self/ns/user")?.ino();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if namespace.holder.try_wait()?.is_some() {
                    use std::io::{Read, Seek};
                    errors.rewind()?;
                    let mut diagnostic = String::new();
                    errors.take(4096).read_to_string(&mut diagnostic)?;
                    return Err(format!("guest import namespace exited: {diagnostic}").into());
                }
                if fs::metadata(format!("/proc/{}/ns/user", namespace.holder.id()))
                    .is_ok_and(|metadata| metadata.ino() != parent)
                {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("guest import namespace did not become ready".into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            for (tool, base, operator) in [
                ("newuidmap", mapping.uid_base, mapping.host_uid),
                ("newgidmap", mapping.gid_base, mapping.host_gid),
            ] {
                let mut command = Command::new(tool);
                command.arg(namespace.holder.id().to_string());
                for (inside, outside, count) in entries(base, operator) {
                    command.args([inside.to_string(), outside.to_string(), count.to_string()]);
                }
                let result = command.output()?;
                if !result.status.success() {
                    return Err(format!(
                        "{tool} failed: {}",
                        String::from_utf8_lossy(&result.stderr)
                    )
                    .into());
                }
            }
            Ok(())
        })();
        prepared.map_err(|error| format!("{error}; run safeyolo --root {} host prepare to check namespace authorization and delegated IDs, then retry. No guest tree was published", root.display()))?;
        Ok(namespace)
    }

    pub(super) fn command(
        &mut self,
        program: impl AsRef<std::ffi::OsStr>,
    ) -> Result<Command, Error> {
        // This Child remains unreaped while commands use its namespace. An
        // exited holder fails here; its PID cannot be reused between this
        // check and nsenter because nobody else owns/waits on this Child.
        if self.holder.try_wait()?.is_some() {
            return Err("guest import namespace exited before preparation completed".into());
        }
        let mut command = Command::new("nsenter");
        command
            .arg(format!("--user=/proc/{}/ns/user", self.holder.id()))
            .args(["--setuid=0", "--setgid=0", "--"])
            .arg(program);
        Ok(command)
    }
}

impl Drop for ImportNamespace {
    fn drop(&mut self) {
        // Signal only our unreaped Child, never a saved or rediscovered PID.
        let _ = self.holder.kill();
        let _ = self.holder.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_mapping_covers_every_canonical_id_and_excludes_host_root() {
        for (base, operator) in [(100000, 1000), (231072, 1001), (296608, 2000)] {
            let map = entries(base, operator);
            assert_eq!(map[0], (0, base + 1000, 1));
            assert!(map.iter().all(|(_, host, _)| *host > 0));
            for guest in 0..ID_COUNT {
                let archive = ARCHIVE_BASE + guest;
                let rows: Vec<_> = map
                    .iter()
                    .filter(|(start, _, count)| (*start..*start + *count).contains(&archive))
                    .collect();
                assert_eq!(rows.len(), 1);
                let (start, host, _) = *rows[0];
                assert_eq!(
                    host + archive - start,
                    if guest == 1000 {
                        operator
                    } else {
                        base + guest
                    }
                );
            }
        }
    }
}
