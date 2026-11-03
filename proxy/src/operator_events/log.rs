//! One bounded host follower of the writer's effective destination/retention.
use bytes::Bytes;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

const BATCH: usize = 1024 * 1024;
// Preserve the replaced operator feed's 8 MiB message bound.
const RECORD: usize = 8 * 1024 * 1024;
// Bound filesystem lookups when retention is configured larger than a live
// reader can traverse in one turn. A skipped range is an explicit history gap.
const ROTATIONS: usize = 64;

pub(super) struct Readout {
    pub records: Vec<Bytes>,
    pub readable: bool,
    pub gap: Option<&'static str>,
    pub refresh_pending: bool,
}
pub(super) struct Follower {
    path: PathBuf,
    backups: usize,
    file: Option<File>,
    offset: u64,
    anchor: Vec<u8>,
    pending: Vec<u8>,
    skipping: bool,
}
fn identity(file: &File) -> std::io::Result<(u64, u64)> {
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}
fn backup(path: &Path, index: usize) -> PathBuf {
    if index == 0 {
        return path.to_owned();
    }
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}
impl Follower {
    pub fn new(path: PathBuf, settings: crate::audit::Settings) -> Self {
        let mut follower = Self {
            path,
            backups: settings
                .backups
                .to_string()
                .parse::<usize>()
                .unwrap_or(ROTATIONS)
                .min(ROTATIONS),
            file: None,
            offset: 0,
            anchor: Vec::new(),
            pending: Vec::new(),
            skipping: false,
        };
        // Fix the starting position before any client can receive its 101.
        // A missing file starts at zero when the writer creates it.
        let _ = follower.open(true);
        follower
    }
    fn open(&mut self, tail: bool) -> std::io::Result<()> {
        let mut file = File::open(&self.path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("audit source is not a file"));
        }
        self.offset = if tail { file.metadata()?.len() } else { 0 };
        if tail && self.offset > 0 {
            file.seek(SeekFrom::Start(self.offset - 1))?;
            let mut last = [0];
            file.read_exact(&mut last)?;
            self.skipping = last[0] != b'\n';
        }
        self.anchor.resize(self.offset.min(64) as usize, 0);
        let anchor_start = self.offset - self.anchor.len() as u64;
        file.read_exact_at(&mut self.anchor, anchor_start)?;
        file.seek(SeekFrom::Start(self.offset))?;
        self.file = Some(file);
        Ok(())
    }
    pub fn read(&mut self) -> Readout {
        let mut output = Readout {
            records: Vec::new(),
            readable: true,
            gap: None,
            refresh_pending: false,
        };
        if self.file.is_none() && self.open(false).is_err() {
            // No archive is still unavailable, even if pending state is readable.
            output.readable = false;
            return output;
        }
        let result = self.read_inner(&mut output);
        if result.is_err() {
            output.readable = false;
        }
        output
    }
    fn read_inner(&mut self, output: &mut Readout) -> std::io::Result<()> {
        let mut remaining = BATCH;
        let mut transitions = 0;
        loop {
            let file = self.file.as_mut().expect("opened source");
            let mut anchor = vec![0u8; self.anchor.len()];
            let replaced = file
                .read_exact_at(&mut anchor, self.offset - self.anchor.len() as u64)
                .is_err()
                || anchor != self.anchor;
            if file.metadata()?.len() < self.offset || replaced {
                output.gap = Some("audit log truncated; historical records may be missing");
                self.pending.zeroize();
                self.pending.clear();
                self.skipping = false;
                self.offset = 0;
                self.anchor.clear();
                file.seek(SeekFrom::Start(0))?;
            }
            let mut chunk = [0u8; 16 * 1024];
            let count = file.read(&mut chunk[..remaining.min(16 * 1024)])?;
            self.offset += count as u64;
            remaining -= count;
            for byte in &chunk[..count] {
                if self.skipping {
                    if *byte == b'\n' {
                        self.skipping = false;
                    }
                    continue;
                }
                if *byte == b'\n' {
                    if self.pending.last() == Some(&b'\r') {
                        self.pending.pop();
                    }
                    match std::str::from_utf8(&self.pending)
                        .ok()
                        .and_then(|line| crate::audit::parse_record(line).ok())
                    {
                        Some(mut event) => {
                            if super::is_operator_event(&event) {
                                output.refresh_pending |= super::refreshes_pending(&event);
                                output.records.push(Bytes::copy_from_slice(&self.pending));
                            }
                            crate::credentials::wipe_json(&mut event);
                        }
                        None => {
                            output.gap = Some(
                                "invalid audit record skipped; historical records may be missing",
                            )
                        }
                    }
                    self.pending.zeroize();
                    self.pending.clear();
                } else if self.pending.len() == RECORD {
                    self.pending.zeroize();
                    self.pending.clear();
                    self.skipping = true;
                    output.gap =
                        Some("oversized audit record skipped; historical records may be missing");
                } else {
                    self.pending.push(*byte);
                }
            }
            self.anchor.extend_from_slice(&chunk[..count]);
            if self.anchor.len() > 64 {
                self.anchor.drain(..self.anchor.len() - 64);
            }
            chunk.zeroize();
            if remaining == 0 {
                return Ok(());
            }
            if count > 0 {
                continue;
            }
            let current = File::open(&self.path)?;
            if !current.metadata()?.is_file() {
                return Err(std::io::Error::other("audit source is not a file"));
            }
            let old = identity(self.file.as_ref().expect("opened source"))?;
            if identity(&current)? == old {
                return Ok(());
            }
            // The old handle stays open across rename. Walk retained successors
            // in file order, including multiple rotations between host reads.
            let mut found = None;
            for index in 1..=self.backups {
                match File::open(backup(&self.path, index)) {
                    Ok(file) if identity(&file)? == old => {
                        found = Some(index);
                        break;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            let next = match found {
                Some(index) if index > 1 => File::open(backup(&self.path, index - 1))?,
                Some(_) => current,
                None => {
                    output.gap = Some("audit retention gap; historical records may be missing");
                    current
                }
            };
            if !self.pending.is_empty() || self.skipping {
                output.gap = Some(
                    "partial audit record lost at rotation; historical records may be missing",
                );
            }
            self.pending.zeroize();
            self.pending.clear();
            self.skipping = false;
            self.offset = 0;
            self.anchor.clear();
            self.file = Some(next);
            transitions += 1;
            if transitions > ROTATIONS {
                return Ok(());
            }
        }
    }
}
impl Drop for Follower {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    fn event(summary: &str) -> String {
        let root = tempfile::tempdir().unwrap();
        let writer =
            crate::audit::Writer::new(root.path().join("log"), crate::audit::Settings::default());
        writer
            .emit(crate::audit::Event::new(
                "agent.stopped",
                crate::audit::Kind::Agent,
                crate::audit::Severity::Low,
                summary,
            ))
            .unwrap();
        writer.shutdown(std::time::Duration::from_secs(2)).unwrap();
        fs::read_to_string(root.path().join("log")).unwrap()
    }
    #[test]
    fn partial_rotation_retention_and_read_failure_are_explicit() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit");
        fs::write(&path, event("before attachment")).unwrap();
        let mut follower = Follower::new(path.clone(), crate::audit::Settings::default());
        assert!(follower.read().records.is_empty());
        let line = event("partial then completed");
        let split = line.len() / 2;
        File::options()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&line.as_bytes()[..split])
            .unwrap();
        assert!(follower.read().records.is_empty());
        File::options()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&line.as_bytes()[split..])
            .unwrap();
        assert_eq!(follower.read().records.len(), 1);
        fs::rename(&path, backup(&path, 2)).unwrap();
        fs::write(backup(&path, 1), event("intermediate")).unwrap();
        fs::write(&path, event("current")).unwrap();
        let read = follower.read();
        assert_eq!(read.records.len(), 2);
        assert!(read.gap.is_none());
        fs::remove_file(&path).unwrap();
        assert!(!follower.read().readable);
        fs::write(&path, event("after gap")).unwrap();
        let read = follower.read();
        assert_eq!(read.records.len(), 1);
        assert!(!read.refresh_pending);
        assert!(read.gap.is_some());
    }

    #[test]
    fn recorded_approval_decisions_require_pending_reconciliation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit");
        fs::write(&path, []).unwrap();
        let mut follower = Follower::new(path.clone(), crate::audit::Settings::default());
        let writer = crate::audit::Writer::new(path, crate::audit::Settings::default());
        writer
            .emit(crate::audit::Event::new(
                "admin.approval_decided",
                crate::audit::Kind::Admin,
                crate::audit::Severity::High,
                "Canonical approval resolved",
            ))
            .unwrap();
        writer.shutdown(std::time::Duration::from_secs(2)).unwrap();
        let read = follower.read();
        assert_eq!(read.records.len(), 1);
        assert!(read.refresh_pending);
        assert!(read.gap.is_none());
    }
    #[test]
    fn first_file_and_rewritten_partial_tail_are_detected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit");
        let mut follower = Follower::new(path.clone(), crate::audit::Settings::default());
        assert!(!follower.read().readable);
        fs::write(&path, event("first file after startup")).unwrap();
        assert_eq!(follower.read().records.len(), 1);
        File::options()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"partial failed append")
            .unwrap();
        assert!(follower.read().records.is_empty());
        // A writer can truncate a failed append and replace it with more bytes
        // before the reader checks length again, without changing the inode.
        fs::write(&path, event(&"rewritten".repeat(100))).unwrap();
        let read = follower.read();
        assert_eq!(read.records.len(), 1);
        assert!(read.gap.is_some());
    }

    #[test]
    fn oversized_partial_is_bounded_and_never_parsed_as_a_suffix() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit");
        fs::write(&path, []).unwrap();
        let mut follower = Follower::new(path.clone(), crate::audit::Settings::default());
        let mut file = File::options().append(true).open(path).unwrap();
        file.write_all(&vec![b'x'; RECORD + 1]).unwrap();
        file.write_all(event("suffix is not a record").as_bytes())
            .unwrap();
        file.write_all(event("next complete record").as_bytes())
            .unwrap();
        for _ in 0..RECORD / BATCH {
            assert!(follower.read().records.is_empty());
        }
        let read = follower.read();
        assert_eq!(read.records.len(), 1);
        assert!(read.gap.is_some());
        assert!(follower.pending.len() <= RECORD);
    }
}
