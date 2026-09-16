//! Source baseline/addons/list observations owned by the accepted policy.
use std::{fs, io, os::unix::fs::MetadataExt, path::Path};

use serde_json::Value;
use zeroize::Zeroizing;

use super::{
    ErrorKind, Format, Policy, PolicyError, Result, TimestampPaths, decode_policy_value, invalid,
    normalize_toml,
};

#[derive(Clone, Copy, Default, PartialEq)]
pub(super) struct PolicyFileTimes {
    baseline: f64,
    addons: f64,
    lists: f64,
}

impl Policy {
    /// A watcher performs all three observations before deciding to reload.
    /// A later observation error can preempt an earlier changed flag.
    pub(crate) fn baseline_files_changed(&self) -> Result<bool> {
        let (Some(path), Some(previous)) = (&self.baseline_path, self.file_times) else {
            return Ok(false);
        };
        let mut changed = false;
        if exists(path)? && modified(path)? > previous.baseline {
            changed = true;
        }
        let addons = path.with_file_name("addons.yaml");
        if exists(&addons)? && modified(&addons)? > previous.addons {
            changed = true;
        }
        let lists = lists_max_mtime(path)?;
        Ok(changed || lists > previous.lists)
    }

    /// Runtime calls this only after successful candidate compilation, before
    /// publication. Failed observation leaves all current observations intact.
    pub(crate) fn observe_baseline_files(&mut self, previous: Option<&Policy>) -> Result<()> {
        let Some(path) = &self.baseline_path else {
            return Ok(());
        };
        let prior = previous
            .filter(|previous| previous.baseline_path.as_ref() == Some(path))
            .and_then(|previous| previous.file_times)
            .unwrap_or_default();
        let baseline = modified(path)?;
        let addons_path = path.with_file_name("addons.yaml");
        // Source retains an earlier addon watermark if the sibling is absent.
        let addons = if exists(&addons_path)? {
            modified(&addons_path)?
        } else {
            prior.addons
        };
        let lists = lists_max_mtime(path)?;
        self.file_times = Some(PolicyFileTimes {
            baseline,
            addons,
            lists,
        });
        Ok(())
    }
}

fn read_error(error: io::Error) -> PolicyError {
    PolicyError {
        kind: ErrorKind::Read,
        message: error.to_string(),
    }
}

fn exists(path: &Path) -> Result<bool> {
    // Source Path.exists catches ValueError for concrete NUL-bearing paths.
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
        Err(error) => Err(read_error(error)),
    }
}

fn modified(path: &Path) -> Result<f64> {
    fs::metadata(path)
        .map(|metadata| mtime(&metadata))
        .map_err(read_error)
}

fn mtime(metadata: &fs::Metadata) -> f64 {
    // Compare floating st_mtime, not the catalog's exact nanoseconds/size key.
    metadata.mtime() as f64 + metadata.mtime_nsec() as f64 * 1e-9
}

fn lists_max_mtime(path: &Path) -> Result<f64> {
    // _lists_max_mtime catches OSError/ValueError from _load_file; the source
    // file reader itself also catches decode/read failures and returns None.
    if !exists(path).unwrap_or(false) {
        return Ok(0.0);
    }
    let Ok(source) = fs::read_to_string(path).map(Zeroizing::new) else {
        return Ok(0.0);
    };
    let format = match path.extension().and_then(|value| value.to_str()) {
        Some("toml") => Format::Toml,
        Some("yaml" | "yml") => Format::Yaml,
        _ => Format::Json,
    };
    let Ok((mut raw, mut timestamps)) = decode_policy_value(&source, format) else {
        // The existing native decoder has documented representation gaps; this
        // preserves the file-decode failure boundary without another parser.
        return Ok(0.0);
    };
    if matches!(format, Format::Toml) {
        let Value::Object(document) = raw else {
            unreachable!("TOML decoder returns a table");
        };
        raw = match normalize_toml(document, &mut timestamps) {
            Ok(document) => Value::Object(document),
            Err(_) => return Ok(0.0),
        };
    }
    let result = raw_lists_max(path, &raw, &timestamps);
    crate::credentials::wipe_json(&mut raw);
    result
}

fn raw_lists_max(path: &Path, raw: &Value, timestamps: &TimestampPaths) -> Result<f64> {
    if timestamps.value_at(&[]).is_some() {
        return Err(invalid(
            "raw baseline is not a mapping for list observation",
        ));
    }
    let truthy = match raw {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    };
    if !truthy {
        return Ok(0.0);
    }
    let raw = raw
        .as_object()
        .ok_or_else(|| invalid("raw baseline is not a mapping for list observation"))?;
    let Some(lists) = raw.get("lists").and_then(Value::as_object) else {
        return Ok(0.0);
    };
    if timestamps.value_at(&["lists"]).is_some() {
        return Ok(0.0);
    }
    let mut maximum = 0.0;
    for (name, value) in lists {
        if timestamps.value_at(&["lists", name]).is_some() {
            continue;
        }
        let Some(value) = value.as_str() else {
            continue;
        };
        if value.as_bytes().contains(&0) {
            // Python stat raises ValueError here; the per-list handler catches
            // OSError only. Do not collapse this into an ignored read failure.
            return Err(invalid("list path contains a NUL byte"));
        }
        let list = Path::new(value);
        let list = if list.is_absolute() {
            list.to_owned()
        } else {
            path.parent().unwrap_or_else(|| Path::new("")).join(list)
        };
        if let Ok(metadata) = fs::metadata(list) {
            let current = mtime(&metadata);
            if current > maximum {
                maximum = current;
            }
        }
    }
    Ok(maximum)
}

#[cfg(test)]
mod tests;
