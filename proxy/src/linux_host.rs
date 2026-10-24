//! Linux prerequisites and the mapping used by the existing rootless launcher.

use crate::Error;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
#[path = "linux_host/ownership.rs"]
mod ownership;
#[cfg(target_os = "linux")]
#[path = "linux_host/prepare.rs"]
mod prepare;
#[cfg(target_os = "linux")]
#[path = "linux_host/runsc.rs"]
mod runsc;
#[cfg(target_os = "linux")]
#[path = "linux_host/shares.rs"]
pub(crate) mod shares;

pub const HELP: &str = "safeyolo [--root ROOT] host prepare [--system-runsc PATH] [--yes]\nCheck and prepare the Ubuntu or Alpine host for rootless agents.\nReuse valid subordinate UID/GID ranges. Allocate missing ranges through shadow's locked allocator.\nInstall only missing host tools. Load a separate AppArmor profile for this installation when required.\nExplain host changes before asking for consent and sudo. --yes accepts the explained changes.\nThe agent and proxy continue to run as your host account. Repeat preserves existing instances.\n--system-runsc selects a complete tested system payload; the bundled runtime remains unchanged.";

pub const ID_COUNT: u32 = 65536;
pub const ARCHIVE_BASE: u32 = 100000;

/// Saved in config.toml. UID and GID allocations need not have the same base.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub host_uid: u32,
    pub host_gid: u32,
    pub uid_base: u32,
    pub gid_base: u32,
    pub runsc: PathBuf,
    pub runsc_origin: String,
    pub apparmor_profile: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Mapping {
    pub host_uid: u32,
    pub host_gid: u32,
    pub uid_base: u32,
    pub gid_base: u32,
}

impl Mapping {
    pub(crate) fn for_bases(uid_base: u32, gid_base: u32) -> Self {
        Self {
            uid_base,
            gid_base,
            host_uid: unsafe { libc::getuid() },
            host_gid: unsafe { libc::getgid() },
        }
    }
    pub(crate) fn validate(self) -> Result<Self, Error> {
        if self.host_uid == 0 {
            return Err(
                "Linux agent mappings require an ordinary host account, not host root".into(),
            );
        }
        for (base, host) in [
            (self.uid_base, self.host_uid),
            (self.gid_base, self.host_gid),
        ] {
            if base == 0 || base.checked_add(ID_COUNT).is_none() {
                return Err("subordinate ID range must fit 65536 IDs below 4294967295".into());
            }
            if (base..base + ID_COUNT).contains(&host) {
                return Err(
                    "host account ID overlaps the selected subordinate range; use an unused range"
                        .into(),
                );
            }
        }
        Ok(self)
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn entries(base: u32, operator: u32) -> [(u32, u32, u32); 3] {
        [
            (0, base, 1000),
            (1000, operator, 1),
            (1001, base + 1001, 64535),
        ]
    }

    pub(crate) fn tree_name(self, digest: &str) -> String {
        format!(
            "{digest}-uid{}-gid{}-user{}-group{}",
            self.uid_base, self.gid_base, self.host_uid, self.host_gid
        )
    }
}

impl Settings {
    pub(crate) fn mapping(&self) -> Result<Mapping, Error> {
        Mapping {
            host_uid: self.host_uid,
            host_gid: self.host_gid,
            uid_base: self.uid_base,
            gid_base: self.gid_base,
        }
        .validate()
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.mapping()?;
        if !self.runsc.is_absolute() || !matches!(self.runsc_origin.as_str(), "bundled" | "system")
        {
            return Err("linux.runsc must be an absolute executable path; linux.runsc_origin must be bundled or system".into());
        }
        if self.apparmor_profile.as_ref().is_some_and(|name| {
            name.is_empty()
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        }) {
            return Err("invalid Linux AppArmor profile name".into());
        }
        Ok(())
    }
}

pub(crate) fn mapping_from_settings(path: &Path) -> Result<Mapping, Error> {
    let document = crate::policy::parse_toml_document(&fs::read_to_string(path)?)?;
    let settings: Settings = serde_json::from_value(
        document
            .get("linux")
            .cloned()
            .ok_or("Linux preparation settings are missing")?,
    )?;
    settings.validate()?;
    let mapping = settings.mapping()?;
    #[cfg(target_os = "linux")]
    validate_current_mapping(mapping)?;
    Ok(mapping)
}

pub(crate) fn mapping_for_root(root: &Path) -> Result<Mapping, Error> {
    let path = root.join("config.toml");
    if path.try_exists()?
        && let Some(settings) = crate::native_config::read(&path)?
            .native_settings
            .and_then(|s| s.linux)
    {
        let mapping = settings.mapping()?;
        #[cfg(target_os = "linux")]
        validate_current_mapping(mapping)?;
        return Ok(mapping);
    }
    #[cfg(target_os = "linux")]
    {
        current_mapping()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(Mapping::for_bases(ARCHIVE_BASE, ARCHIVE_BASE))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn selected_mapping() -> Result<Mapping, Error> {
    let settings = crate::native_config::host_settings()?;
    let mapping = match settings.linux {
        Some(settings) => settings.mapping()?,
        None => current_mapping()?,
    };
    validate_current_mapping(mapping)?;
    Ok(mapping)
}

/// The caller holds the agent setup lock and has verified that its backend stopped.
#[cfg(target_os = "linux")]
pub(crate) async fn remove_scheduler_spool(directory: &Path) -> Result<(), Error> {
    let spool = directory.join("overlay/var/spool/cron");
    match fs::remove_dir_all(&spool) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => return Err(error.into()),
    }
    let mapping = selected_mapping()?;
    let settings = crate::native_config::host_settings()?;
    let mut command =
        if fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .is_ok_and(|value| value.trim() == "1")
        {
            let mut command = tokio::process::Command::new("aa-exec");
            command.args([
                "-p",
                settings
                    .linux
                    .as_ref()
                    .and_then(|linux| linux.apparmor_profile.as_deref())
                    .unwrap_or("safeyolo-runsc"),
                "--",
                "unshare",
            ]);
            command
        } else {
            tokio::process::Command::new("unshare")
        };
    // Namespace root is the operator. Map its allocated subordinate IDs too,
    // so DAC and sticky-directory checks can remove root/daemon-owned queues.
    // The comma syntax also works with the older supported util-linux tools.
    command.args([
        "--map-root-user".to_owned(),
        format!("--map-users={},1,{ID_COUNT}", mapping.uid_base),
        format!("--map-groups={},1,{ID_COUNT}", mapping.gid_base),
        "--".to_owned(),
    ]);
    remove_scheduler_spool_in(&spool, command).await
}

#[cfg(target_os = "linux")]
async fn remove_scheduler_spool_in(
    spool: &Path,
    mut command: tokio::process::Command,
) -> Result<(), Error> {
    // rm does not follow job-directory symlinks. Never elevate deletion of the
    // agent home, workspace, overlay parent, or another agent's files.
    let output = command
        .args(["rm", "-rf", "--"])
        .arg(spool)
        .output()
        .await?;
    if !output.status.success() {
        return Err(format!(
            "cannot remove stopped guest scheduler spool {}: {}",
            spool.display(),
            String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(2048)])
        )
        .into());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug)]
struct Allocation {
    owner: String,
    start: u32,
    count: u32,
}

#[cfg(any(target_os = "linux", test))]
fn allocations(text: &str, file: &str) -> Result<Vec<Allocation>, Error> {
    let mut ranges = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split(':').collect();
        let invalid = || {
            format!(
                "{file}: malformed subordinate allocation at line {}; repair the file with your host account tools",
                index + 1
            )
        };
        if fields.len() != 3
            || fields[0].is_empty()
            || fields.iter().any(|s| s.chars().any(char::is_whitespace))
        {
            return Err(invalid().into());
        }
        let start: u32 = fields[1].parse().map_err(|_| invalid())?;
        let count: u32 = fields[2].parse().map_err(|_| invalid())?;
        if count == 0 || start.checked_add(count).is_none() {
            return Err(invalid().into());
        }
        ranges.push(Allocation {
            owner: fields[0].into(),
            start,
            count,
        });
    }
    Ok(ranges)
}

#[cfg(any(target_os = "linux", test))]
fn check_overlaps(ranges: &[Allocation], file: &str) -> Result<(), Error> {
    let mut sorted: Vec<_> = ranges.iter().collect();
    sorted.sort_by_key(|r| r.start);
    for (index, range) in sorted.iter().enumerate() {
        for next in sorted[index + 1..]
            .iter()
            .take_while(|next| next.start < range.start + range.count)
        {
            if range.owner != next.owner {
                return Err(format!("{file}: allocations for {} and {} overlap; host allocation files were preserved", range.owner, next.owner).into());
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn owned_ranges(ranges: &[Allocation], owner: &str) -> Vec<(u32, u32)> {
    let mut owned: Vec<_> = ranges
        .iter()
        .filter(|r| r.owner == owner)
        .map(|r| (r.start, r.start + r.count))
        .collect();
    owned.sort_unstable();
    let mut joined: Vec<(u32, u32)> = Vec::new();
    for (start, end) in owned {
        if let Some(last) = joined.last_mut().filter(|last| start <= last.1) {
            last.1 = last.1.max(end);
        } else {
            joined.push((start, end));
        }
    }
    joined
}

#[cfg(any(target_os = "linux", test))]
fn existing_base(ranges: &[Allocation], owner: &str, occupied: &[u32]) -> Option<u32> {
    let suitable: Vec<_> = owned_ranges(ranges, owner)
        .into_iter()
        .filter(|(start, end)| end - start >= ID_COUNT)
        .collect();
    // Preserve the original mapping when the same account still owns it.
    suitable
        .iter()
        .find(|(start, end)| {
            *start <= ARCHIVE_BASE
                && *end >= ARCHIVE_BASE + ID_COUNT
                && !occupied
                    .iter()
                    .any(|id| (ARCHIVE_BASE..ARCHIVE_BASE + ID_COUNT).contains(id))
        })
        .map(|_| ARCHIVE_BASE)
        .or_else(|| {
            suitable
                .into_iter()
                .find_map(|(start, end)| free_base(&[], occupied, start, end - 1).ok())
        })
}

#[cfg(any(target_os = "linux", test))]
fn free_base(
    ranges: &[Allocation],
    occupied: &[u32],
    minimum: u32,
    maximum: u32,
) -> Result<u32, Error> {
    let mut used: Vec<_> = ranges
        .iter()
        .map(|r| (r.start, u64::from(r.start) + u64::from(r.count)))
        .collect();
    used.extend(occupied.iter().map(|id| (*id, u64::from(*id) + 1)));
    used.sort_unstable();
    let mut candidate = u64::from(minimum);
    let limit = u64::from(maximum) + 1;
    for (start, end) in used {
        if end <= candidate {
            continue;
        }
        if candidate + u64::from(ID_COUNT) <= u64::from(start) {
            break;
        }
        candidate = candidate.max(end);
    }
    if candidate == 0
        || candidate + u64::from(ID_COUNT) > limit
        || candidate + u64::from(ID_COUNT) > u64::from(u32::MAX)
    {
        return Err("no unused range of 65536 subordinate IDs is available within the host's allocation limits; ask the host administrator to provide an unused range".into());
    }
    Ok(candidate as u32)
}

#[cfg(target_os = "linux")]
fn occupied_ids(database: &str) -> Result<Vec<u32>, Error> {
    let output = std::process::Command::new("getent")
        .arg(database)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cannot enumerate host {database} IDs before subordinate-ID allocation"
        )
        .into());
    }
    std::str::from_utf8(&output.stdout)?
        .lines()
        .map(|line| {
            line.split(':')
                .nth(2)
                .ok_or("invalid host account record")?
                .parse::<u32>()
                .map_err(Into::into)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn login(uid: u32) -> Result<String, Error> {
    // Read the account through NSS, as shadow's account tools do.
    let output = std::process::Command::new("getent")
        .args(["passwd", &uid.to_string()])
        .output()?;
    if !output.status.success() {
        return Err(format!("cannot resolve host account for UID {uid}").into());
    }
    let text = std::str::from_utf8(&output.stdout)?;
    let fields: Vec<_> = text.trim_end().split(':').collect();
    if fields.len() != 7 || fields[2].parse::<u32>()? != uid || fields[0].is_empty() {
        return Err("host account lookup returned an invalid record".into());
    }
    Ok(fields[0].into())
}

#[cfg(target_os = "linux")]
fn host_ranges(file: &str, owner: &str, uid: u32) -> Result<Vec<Allocation>, Error> {
    let text = match fs::read_to_string(file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("cannot read {file}: {error}").into()),
    };
    let mut ranges = allocations(&text, file)?;
    for range in &mut ranges {
        if range.owner == uid.to_string() {
            range.owner = owner.into();
        }
    }
    check_overlaps(&ranges, file)?;
    Ok(ranges)
}

#[cfg(target_os = "linux")]
pub(crate) fn current_mapping() -> Result<Mapping, Error> {
    let uid = unsafe { libc::getuid() };
    let owner = login(uid)?;
    let uid_ranges = host_ranges("/etc/subuid", &owner, uid)?;
    let gid_ranges = host_ranges("/etc/subgid", &owner, uid)?;
    let uid_base = existing_base(&uid_ranges, &owner, &occupied_ids("passwd")?)
        .ok_or("host account needs 65536 unused subordinate UIDs; run safeyolo host prepare")?;
    let gid_base = existing_base(&gid_ranges, &owner, &occupied_ids("group")?)
        .ok_or("host account needs 65536 unused subordinate GIDs; run safeyolo host prepare")?;
    Mapping::for_bases(uid_base, gid_base).validate()
}

#[cfg(target_os = "linux")]
fn validate_current_mapping(mapping: Mapping) -> Result<(), Error> {
    mapping.validate()?;
    let uid = unsafe { libc::getuid() };
    if mapping.host_uid != uid || mapping.host_gid != unsafe { libc::getgid() } {
        return Err("this installation's Linux mapping belongs to another host UID/GID; use its original host account and group, or install in a separate root".into());
    }
    let owner = login(uid)?;
    for (file, base, operator) in [
        ("/etc/subuid", mapping.uid_base, uid),
        ("/etc/subgid", mapping.gid_base, unsafe { libc::getgid() }),
    ] {
        let ranges = host_ranges(file, &owner, uid)?;
        let database = if file == "/etc/subuid" {
            "passwd"
        } else {
            "group"
        };
        if let Some(id) = occupied_ids(database)?
            .into_iter()
            .find(|id| (base..base + ID_COUNT).contains(id))
        {
            return Err(format!("{file} selected range overlaps host {database} ID {id}; allocation files were preserved. Ask the host administrator to provide a range without host account IDs").into());
        }
        if (base..base + ID_COUNT).contains(&operator)
            || !owned_ranges(&ranges, &owner)
                .iter()
                .any(|(start, end)| *start <= base && *end >= base + ID_COUNT)
        {
            return Err(format!("{file} no longer grants this installation's {base}–{} range to {owner}; restore its allocation before starting the agent. Existing state was preserved", base + ID_COUNT - 1).into());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) use prepare::runsc_platform;
#[cfg(target_os = "linux")]
pub(crate) use runsc::report as runsc_report;
#[cfg(target_os = "linux")]
pub(crate) use runsc::verify_selected_runtime;
#[cfg(target_os = "linux")]
pub(crate) use runsc::{check_runtime, runtime_path};
#[cfg(target_os = "linux")]
pub fn run(root: &Path, args: &[String]) -> Result<(), Error> {
    prepare::run(root, args)
}
#[cfg(not(target_os = "linux"))]
pub fn run(_root: &Path, _args: &[String]) -> Result<(), Error> {
    Err("host preparation is for supported Ubuntu and Alpine Linux hosts".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn scheduler_spool_cleanup_handles_distinct_owners_and_preserves_peer_files() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        assert_ne!(unsafe { libc::geteuid() }, 0, "run as the operator account");
        let fixture = tempfile::tempdir().unwrap();
        let alice = fixture.path().join("alice");
        let spool = alice.join("overlay/var/spool/cron");
        let peer = fixture.path().join("bob");
        fs::create_dir_all(&peer).unwrap();
        let marker = peer.join("job");
        fs::write(&marker, "peer queue").unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        let before = marker.metadata().unwrap();
        for (name, owner, mode) in [
            ("crontabs", "0:0", "1730"),
            ("atjobs", "1:1", "1770"),
            ("atspool", "1:1", "1770"),
        ] {
            let directory = spool.join(name);
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("job"), "owned queue").unwrap();
            fs::set_permissions(directory.join("job"), fs::Permissions::from_mode(0o600)).unwrap();
            symlink(&peer, directory.join("peer-link")).unwrap();
            for args in [["chown", owner], ["chmod", mode]] {
                assert!(
                    std::process::Command::new("sudo")
                        .arg("-n")
                        .args(args)
                        .arg(&directory)
                        .status()
                        .unwrap()
                        .success()
                );
            }
        }
        fs::set_permissions(&spool, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            std::process::Command::new("sudo")
                .args(["-n", "chown", "0:0"])
                .arg(&spool)
                .status()
                .unwrap()
                .success()
        );
        // Real root/daemon IDs stand in for subordinate owners here. Guest
        // sudo supplies file capabilities for this filesystem probe; the
        // installed consumer exercises the rootless namespace separately.
        assert_eq!(
            fs::remove_dir_all(alice.join("overlay"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let owners = ["crontabs", "atjobs", "atspool"].map(|name| {
            let metadata = spool.join(name).metadata().unwrap();
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777)
        });
        assert_eq!(owners, [(0, 0, 0o1730), (1, 1, 0o1770), (1, 1, 0o1770)]);
        assert!(
            remove_scheduler_spool_in(&spool, tokio::process::Command::new("false"))
                .await
                .is_err()
        );
        for (name, expected) in ["crontabs", "atjobs", "atspool"].into_iter().zip(owners) {
            let metadata = spool.join(name).metadata().unwrap();
            assert_eq!(
                (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
                expected
            );
        }
        let mut command = tokio::process::Command::new("sudo");
        command.arg("-n");
        remove_scheduler_spool_in(&spool, command).await.unwrap();
        assert!(!spool.exists());
        fs::remove_dir_all(alice.join("overlay")).unwrap();
        let after = marker.metadata().unwrap();
        assert_eq!(fs::read_to_string(&marker).unwrap(), "peer queue");
        assert_eq!(
            (before.uid(), before.gid(), before.mode(), before.ino()),
            (after.uid(), after.gid(), after.mode(), after.ino())
        );
        // The next boot can create an empty spool at the reset location.
        fs::create_dir_all(&spool).unwrap();
        assert_eq!(fs::read_dir(&spool).unwrap().count(), 0);
    }

    #[test]
    fn allocation_selection_keeps_distinct_bases_and_skips_the_occupied_fixed_range() {
        let u = allocations("other:100000:65536\nalice:300000:65536\n", "subuid").unwrap();
        let g = allocations("other:100000:65536\nalice:500000:65536\n", "subgid").unwrap();
        check_overlaps(&u, "subuid").unwrap();
        assert_eq!(existing_base(&u, "alice", &[1000]), Some(300000));
        assert_eq!(existing_base(&g, "alice", &[1000]), Some(500000));
        assert_eq!(free_base(&u, &[165536], 100000, 600100000).unwrap(), 165537);
        assert_eq!(
            Mapping::entries(500000, 42),
            [(0, 500000, 1000), (1000, 42, 1), (1001, 501001, 64535)]
        );
    }
    #[test]
    fn malformed_overlap_and_exhaustion_are_refused() {
        for text in [
            "alice:100000:0",
            "alice:-1:65536",
            "alice:4294967290:65536",
            "alice:100000:65536:extra",
            "alice::65536",
            "alice:100000:x",
        ] {
            assert!(allocations(text, "subuid").is_err(), "{text}");
        }
        let ranges = allocations("alice:100000:65536\nother:150000:65536", "subuid").unwrap();
        assert!(check_overlaps(&ranges, "subuid").is_err());
        assert!(free_base(&ranges, &[], 100000, 165535).is_err());
        assert!(Mapping::for_bases(u32::MAX - 1, 100000).validate().is_err());
        let adjacent = allocations("alice:300000:32000\nalice:332000:33536", "subuid").unwrap();
        assert_eq!(existing_base(&adjacent, "alice", &[1000]), Some(300000));
        assert_eq!(existing_base(&adjacent, "alice", &[300001]), None);
    }
    #[test]
    fn prepared_reuse_distinguishes_both_mappings() {
        let a = Mapping::for_bases(300000, 500000);
        assert_ne!(
            a.tree_name("digest"),
            Mapping {
                gid_base: 600000,
                ..a
            }
            .tree_name("digest")
        );
        assert_ne!(
            a.tree_name("digest"),
            Mapping {
                host_gid: a.host_gid + 1,
                ..a
            }
            .tree_name("digest")
        );
        assert_ne!(
            a.tree_name("digest"),
            Mapping {
                uid_base: 400000,
                ..a
            }
            .tree_name("digest")
        );
    }
}
