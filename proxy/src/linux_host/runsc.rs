//! Validate the complete pinned gVisor payload at the existing package boundary.

use crate::Error;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Error as IoError, Read},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

pub(super) const VERSION: &str = "release-20261005.0";
pub(super) const FILES: &[&str] = &[
    "runsc",
    "gvisor-bin/checkpointgofer",
    "gvisor-bin/gvisor-sentry-prewarmer",
    "gvisor-bin/gvisor_sentry",
    "gvisor-bin/runsc-fd-parking",
    "gvisor-bin/runsc-metric-server",
];

pub(crate) fn check_runtime(path: &Path) -> Result<String, Error> {
    if !path.is_absolute() {
        return Err("selected gVisor executable must be an absolute path; keep its gvisor-bin directory beside it".into());
    }
    let parent = path.parent().ok_or("selected runsc has no parent")?;
    for name in FILES {
        let file = if *name == "runsc" {
            path.to_owned()
        } else {
            parent.join(name)
        };
        let metadata = fs::metadata(&file).map_err(|error| format!("gVisor payload is incomplete: {}: {error}; reinstall the complete {VERSION} runtime", file.display()))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(format!("gVisor payload is not executable: {}", file.display()).into());
        }
        let mut header = [0_u8; 20];
        fs::File::open(&file)?.read_exact(&mut header).map_err(|error| format!("gVisor payload is corrupt: {}: {error}; reinstall the complete {VERSION} runtime",file.display()))?;
        let machine = if cfg!(target_arch = "aarch64") {
            183_u16
        } else {
            62_u16
        };
        if &header[..6] != b"\x7fELF\x02\x01"
            || u16::from_le_bytes([header[18], header[19]]) != machine
        {
            return Err(format!(
                "gVisor payload is corrupt or for another architecture: {}",
                file.display()
            )
            .into());
        }
    }
    let output = Command::new(path).arg("--version").output().map_err(|error| format!("cannot execute selected gVisor runtime {}: {error}; repair the complete {VERSION} payload",path.display()))?;
    let version = std::str::from_utf8(&output.stdout)?
        .lines()
        .next()
        .unwrap_or_default();
    if !output.status.success() || version != format!("runsc version {VERSION}") {
        return Err(format!("selected gVisor runtime is incompatible: expected {VERSION}, observed {version:?}; install the complete tested runtime or use the bundled runtime").into());
    }
    Ok(VERSION.into())
}

pub(super) fn verify_bundle_payload(package: &Path) -> Result<(), Error> {
    let sums = fs::read_to_string(package.join("SHA256SUMS"))?;
    for name in FILES {
        let file = format!("./libexec/{name}");
        let mut entries = sums
            .lines()
            .filter_map(|line| line.split_once("  "))
            .filter(|(_, path)| *path == file);
        let expected = entries
            .next()
            .ok_or_else(|| format!("gVisor payload is absent from package checksums: {file}"))?
            .0;
        if entries.next().is_some()
            || expected.len() != 64
            || !expected.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(format!("invalid gVisor checksum entry: {file}").into());
        }
        let mut input = fs::File::open(package.join(&file))?;
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        let mut bytes = [0_u8; 65536];
        loop {
            let count = input.read(&mut bytes)?;
            if count == 0 {
                break;
            }
            digest.update(&bytes[..count]);
        }
        let actual = digest
            .finish()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if expected != actual {
            return Err(format!(
                "gVisor payload checksum differs: {file}; repair this installation's host package"
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn verify_selected_runtime() -> Result<String, Error> {
    let settings = crate::native_config::host_settings()?.linux;
    let path = runtime_path()?;
    let packaged =
        crate::guest_acquisition::packaged_runsc_version(&crate::host_platform::config_dir())?
            .is_some();
    if settings
        .as_ref()
        .map_or(packaged, |s| s.runsc_origin == "bundled")
    {
        let package = path
            .parent()
            .and_then(Path::parent)
            .ok_or("bundled runtime has no package directory")?;
        verify_bundle_payload(package)?;
    }
    check_runtime(&path)
}

pub(crate) fn runtime_path() -> Result<PathBuf, IoError> {
    let settings = crate::native_config::host_settings().map_err(IoError::other)?;
    if let Some(settings) = settings.linux {
        if !settings.runsc.is_file() {
            return Err(IoError::other(format!(
                "selected gVisor executable is missing: {}; repair this installation's runtime; no other runtime was selected",
                settings.runsc.display()
            )));
        }
        return Ok(settings.runsc);
    }
    let root = crate::host_platform::config_dir();
    if crate::guest_acquisition::packaged_runsc_version(&root)
        .map_err(IoError::other)?
        .is_some()
    {
        let path = root.join("libexec/runsc");
        if !path.is_file() {
            return Err(IoError::other(format!(
                "bundled gVisor executable is missing: {}; repair this host package; no system runtime was selected",
                path.display()
            )));
        }
        return Ok(path);
    }
    // Existing contributor installations retain their explicit PATH runtime.
    // New installers always record a selected executable in config.toml.
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join("runsc"))
        .find(|path| path.is_file() && fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0))
        .ok_or_else(|| IoError::other("gVisor runtime is missing; run the SafeYolo installer or select a complete system runtime with --system-runsc PATH"))
}

pub(crate) fn report() -> Value {
    let mut unavailable =
        json!({"state":"unavailable","next_action":"run safeyolo host prepare, then retry doctor"});
    let result = (|| -> Result<Value, Error> {
        let settings = crate::native_config::host_settings()?.linux;
        if let Some(settings) = &settings {
            unavailable["path"] = json!(settings.runsc);
            unavailable["origin"] = json!(settings.runsc_origin);
            unavailable["uid_base"] = json!(settings.uid_base);
            unavailable["gid_base"] = json!(settings.gid_base);
        }
        let path = runtime_path()?;
        let packaged =
            crate::guest_acquisition::packaged_runsc_version(&crate::host_platform::config_dir())?
                .is_some();
        let origin = settings.as_ref().map_or(
            if packaged {
                "bundled"
            } else {
                "system (existing PATH selection)"
            },
            |s| s.runsc_origin.as_str(),
        );
        unavailable["path"] = json!(path);
        unavailable["origin"] = json!(origin);
        let version = if settings.is_some() || packaged {
            verify_selected_runtime()?
        } else {
            let output = Command::new(&path).arg("--version").output()?;
            if !output.status.success() {
                return Err("runsc --version failed".into());
            }
            std::str::from_utf8(&output.stdout)?
                .lines()
                .next()
                .unwrap_or_default()
                .into()
        };
        unavailable["version"] = json!(version);
        super::prepare::check_prerequisites(settings.as_ref())?;
        let mapping = super::selected_mapping()?;
        Ok(
            json!({"state":"ready", "path":path,"version":version,"origin":origin,
            "uid_base":mapping.uid_base,"gid_base":mapping.gid_base,
            "host_uid":mapping.host_uid,"host_gid":mapping.host_gid,
            "apparmor_profile":settings.and_then(|s| s.apparmor_profile)}),
        )
    })();
    match result {
        Ok(value) => value,
        Err(error) => {
            unavailable["error"] = json!(error.to_string());
            unavailable
        }
    }
}
