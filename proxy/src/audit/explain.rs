//! Retained JSONL lookup for the concrete Agent API explain workflow.
//! File order, per-file tail and read/freshness failures follow AgentAPI.

use std::{
    collections::VecDeque,
    fmt,
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use num_bigint::BigInt;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Writer, wipe, writer};
use crate::{circuits::CircuitValue, policy::python_whitespace};

const MAX_LINES: usize = 10_000;
const DRAIN: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExplainErrorKind {
    Attribute,
    UnicodeDecode,
    Value,
    Permission,
    Io,
    /// Existing JSON scalar representation cannot express this source value.
    Compatibility,
}

/// Errors contain neither paths nor retained event data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExplainError(ExplainErrorKind);

impl ExplainError {
    pub fn kind(self) -> ExplainErrorKind {
        self.0
    }
}
impl fmt::Display for ExplainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            ExplainErrorKind::Attribute => "audit record is not an object",
            ExplainErrorKind::UnicodeDecode => "audit file text decoding failed",
            ExplainErrorKind::Value => "audit lookup value cannot be converted",
            ExplainErrorKind::Permission => "audit file metadata permission denied",
            ExplainErrorKind::Io => "audit file metadata unavailable",
            ExplainErrorKind::Compatibility => "audit JSON scalar representation unavailable",
        })
    }
}
impl std::error::Error for ExplainError {}
type Result<T> = std::result::Result<T, ExplainError>;

pub(super) fn explain(
    writer: &Writer,
    current: &Path,
    backups: &BigInt,
    request_id: &str,
    agent: &str,
) -> Result<CircuitValue> {
    // Failure to inspect/drain the queue does not prevent scanning retained
    // evidence. A successful timeout remains pending even if the queue drains
    // later, while the scan is running.
    let freshness = writer.pending_count().and_then(|count| {
        if count > 0 {
            writer.wait_for_drain(DRAIN).map(|drained| !drained)
        } else {
            Ok(false)
        }
    });
    let pending = freshness.unwrap_or_else(|_| {
        let _ = writeln!(
            std::io::stderr().lock(),
            "Audit explain freshness observation failed"
        );
        false
    });
    let files = retained(current, backups)?;
    let mut scan = scan(&files, request_id, agent)?;
    let status = if scan.read_error {
        "error"
    } else if pending {
        "pending"
    } else if scan.incomplete {
        "incomplete_search"
    } else {
        "complete"
    };
    let mut result = indexmap::IndexMap::from([
        ("request_id".into(), json!(request_id).into()),
        ("status".into(), json!(status).into()),
        (
            "events".into(),
            std::mem::replace(&mut scan.events, CircuitValue::Array(Vec::new())),
        ),
    ]);
    if scan.incomplete {
        result.insert("searched_lines_per_file".into(), json!(MAX_LINES).into());
    }
    Ok(CircuitValue::Object(result))
}

fn exists(path: &Path) -> Result<bool> {
    // Python Path.exists also suppresses a non-encodable (NUL) path ValueError.
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Ok(false);
    }
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::ENOTDIR | libc::EBADF | libc::ELOOP)
            ) =>
        {
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(ExplainError(ExplainErrorKind::Permission))
        }
        Err(_) => Err(ExplainError(ExplainErrorKind::Io)),
    }
}

fn retained(current: &Path, backups: &BigInt) -> Result<Vec<PathBuf>> {
    // pathlib.Path("") denotes the current directory, unlike metadata("").
    let current = if current.as_os_str().is_empty() {
        Path::new(".")
    } else {
        current
    };
    let mut files = Vec::new();
    if exists(current)? {
        files.push(current.into());
    }
    let mut index = BigInt::from(1);
    while &index <= backups {
        let rotated = match current.components().next_back() {
            Some(Component::Normal(_)) => writer::backup(current, &index),
            // Python preserves the '..' filename for with_suffix; Rust treats
            // it as a component instead. Do not change writer rotation here.
            Some(Component::ParentDir) => current
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .join(format!("...jsonl.{index}")),
            _ => return Err(ExplainError(ExplainErrorKind::Value)),
        };
        if exists(&rotated)? {
            files.push(rotated);
        }
        index += 1;
    }
    Ok(files)
}

struct Scan {
    events: CircuitValue,
    incomplete: bool,
    read_error: bool,
}
impl Drop for Scan {
    fn drop(&mut self) {
        wipe(&mut self.events);
    }
}

fn scan(files: &[PathBuf], request_id: &str, agent: &str) -> Result<Scan> {
    let mut result = Scan {
        events: CircuitValue::Array(Vec::new()),
        incomplete: false,
        read_error: false,
    };
    for path in files {
        let (lines, incomplete) = match tail_file(path) {
            Ok(tail) => tail,
            Err(ReadError::Io { incomplete }) => {
                result.incomplete |= incomplete;
                result.read_error = true;
                continue;
            }
            Err(ReadError::Unicode) => {
                return Err(ExplainError(ExplainErrorKind::UnicodeDecode));
            }
        };
        result.incomplete |= incomplete;
        for line in lines {
            // tail_file validates every input byte, including discarded lines.
            let text = std::str::from_utf8(&line)
                .expect("validated audit text")
                .trim_matches(python_whitespace);
            if text.is_empty() {
                continue;
            }
            let mut entry = match CircuitValue::parse_api_json(text) {
                Ok(entry) => entry,
                Err(error) => {
                    use crate::circuits::ErrorKind;
                    match error.kind() {
                        ErrorKind::Invalid => continue, // json.JSONDecodeError
                        ErrorKind::Value => return Err(ExplainError(ExplainErrorKind::Value)),
                        _ => return Err(ExplainError(ExplainErrorKind::Compatibility)),
                    }
                }
            };
            let Some(object) = entry.as_object() else {
                wipe(&mut entry);
                return Err(ExplainError(ExplainErrorKind::Attribute));
            };
            let matches = |key, expected: &str| matches!(object.get(key), Some(CircuitValue::Other(Value::String(value))) if value == expected);
            if matches("request_id", request_id) && matches("agent", agent) {
                let CircuitValue::Array(events) = &mut result.events else {
                    unreachable!()
                };
                events.push(entry);
            } else {
                wipe(&mut entry);
            }
        }
    }
    Ok(result)
}

enum ReadError {
    Io { incomplete: bool },
    Unicode,
}
type Lines = VecDeque<Zeroizing<Vec<u8>>>;

fn tail_file(path: &Path) -> std::result::Result<(Lines, bool), ReadError> {
    let mut file = File::open(path).map_err(|_| ReadError::Io { incomplete: false })?;
    let result = tail(&mut file);
    // As with Python's context manager, close failure takes precedence. The
    // shared helper consumes the descriptor once and never retries close.
    close_tail(result, writer::close(file))
}

fn close_tail(
    result: std::result::Result<(Lines, bool), ReadError>,
    closed: super::Result<()>,
) -> std::result::Result<(Lines, bool), ReadError> {
    // Source records retention truncation inside `with open`, before __exit__.
    // A close failure discards this file's events but keeps that reached flag.
    if closed.is_err() {
        return Err(ReadError::Io {
            incomplete: result.as_ref().is_ok_and(|(_, incomplete)| *incomplete),
        });
    }
    result
}

fn tail(input: &mut impl Read) -> std::result::Result<(Lines, bool), ReadError> {
    let mut lines = VecDeque::new();
    let mut incomplete = false;
    let mut line = Zeroizing::new(Vec::new());
    let mut skip_lf = false;
    let mut buffer = Zeroizing::new([0_u8; 8195]);
    let mut prefix = 0;
    loop {
        let count = match input.read(&mut buffer[prefix..prefix + 8192]) {
            Ok(count) => count,
            // CPython FileIO retries an interrupted syscall when no signal
            // handler raises. Closing a descriptor remains a separate once-only
            // operation and must not use this retry rule.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ReadError::Io { incomplete: false }),
        };
        if count == 0 {
            if prefix != 0 {
                return Err(ReadError::Unicode);
            }
            break;
        }
        let end = prefix + count;
        let valid = match std::str::from_utf8(&buffer[..end]) {
            Ok(_) => end,
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => return Err(ReadError::Unicode),
        };
        for byte in &buffer[..valid] {
            if skip_lf {
                skip_lf = false;
                if *byte == b'\n' {
                    continue;
                }
            }
            if matches!(*byte, b'\r' | b'\n') {
                push_line(&mut lines, std::mem::take(&mut line), &mut incomplete);
                skip_lf = *byte == b'\r';
            } else {
                line.push(*byte);
            }
        }
        prefix = end - valid;
        buffer.copy_within(valid..end, 0);
    }
    if !line.is_empty() {
        push_line(&mut lines, line, &mut incomplete);
    }
    Ok((lines, incomplete))
}

fn push_line(lines: &mut Lines, line: Zeroizing<Vec<u8>>, incomplete: &mut bool) {
    if lines.len() == MAX_LINES {
        lines.pop_front();
        *incomplete = true;
    }
    lines.push_back(line);
}

#[cfg(test)]
mod tests;
