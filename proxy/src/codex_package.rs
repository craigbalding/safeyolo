//! Select and acquire the complete default first-launch package early.

use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{Error, guest_oci::Descriptor};

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    published_at: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    size: u64,
    digest: Option<String>,
    browser_download_url: String,
}

fn target() -> Result<&'static str, Error> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-musl"),
        ("linux" | "macos", "aarch64") => Ok("aarch64-unknown-linux-musl"),
        _ => Err("unsupported Codex guest platform".into()),
    }
}

fn candidate<'a>(
    release: &'a Release,
    target: &str,
    now: OffsetDateTime,
) -> Option<([u64; 3], &'a Asset)> {
    let version = release.tag_name.strip_prefix("rust-v")?;
    let numbers: Vec<_> = version.split('.').collect();
    if release.draft
        || release.prerelease
        || numbers.len() != 3
        || numbers
            .iter()
            .any(|n| n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()))
        || now - OffsetDateTime::parse(&release.published_at, &Rfc3339).ok()?
            < time::Duration::hours(24)
    {
        return None;
    }
    let numbers = numbers
        .iter()
        .map(|number| number.parse::<u64>())
        .collect::<Result<Vec<_>, _>>()
        .ok()?
        .try_into()
        .ok()?;
    let name = format!("codex-package-{target}.tar.zst");
    let mut matches = release.assets.iter().filter(|asset| asset.name == name);
    let asset = matches.next()?;
    if matches.next().is_some()
        || asset.browser_download_url
            != format!("https://github.com/openai/codex/releases/download/rust-v{version}/{name}")
        || crate::guest_oci::sha256_hex(asset.digest.as_deref()?).is_err()
    {
        return None;
    }
    Some((numbers, asset))
}

fn curl(url: &str) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("curl");
    command
        .args([
            "--fail",
            "--location",
            "--show-error",
            "--silent",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            url,
        ])
        .kill_on_drop(true);
    command
}

fn extract(archive: &Path, payload: &Path) -> Result<(), Error> {
    fs::create_dir(payload)?;
    // Keep tar's default refusal of absolute paths and directory-link traversal.
    // This runs as the host account, without guest extraction privileges.
    let mut child = Command::new("tar")
        .args(["-xpf", "-", "-C"])
        .arg(payload)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    let copy = (|| -> Result<(), Error> {
        let mut output = child.stdin.take().ok_or("Codex extraction has no input")?;
        let mut decoder = zstd::stream::read::Decoder::new(fs::File::open(archive)?)?;
        std::io::copy(&mut decoder, &mut output)?;
        Ok(())
    })();
    let status = child.wait()?;
    copy?;
    if !status.success() {
        return Err("cannot extract the complete Codex package".into());
    }
    for file in ["bin/codex", "bin/codex-code-mode-host", "codex-path/rg"] {
        let path = payload.join(file);
        let mut header = [0_u8; 20];
        fs::File::open(&path)?.read_exact(&mut header)?;
        let machine = if target()?.starts_with("x86_64") {
            62
        } else {
            183
        };
        if &header[..6] != b"\x7fELF\x02\x01"
            || header[18..20] != [machine, 0]
            || path.metadata()?.permissions().mode() & 0o111 == 0
        {
            return Err(format!("Codex package has an invalid guest executable: {file}").into());
        }
    }
    if !payload.join("codex-resources").is_dir() {
        return Err("Codex package lacks its adjacent resources".into());
    }
    Ok(())
}

pub async fn prefetch(output: &Path) -> Result<(), Error> {
    // Select only for the fresh default. Pins, custom age settings and healthy
    // installed selections retain the guest's ordinary mise path.
    if [
        "SAFEYOLO_CODEX_NATIVE_SPEC",
        "SAFEYOLO_CODEX_NPM_SPEC",
        "SAFEYOLO_CODEX_NPM_PACKAGE",
    ]
    .iter()
    .any(|key| std::env::var_os(key).is_some_and(|v| !v.is_empty()))
        || std::env::var("SAFEYOLO_MIN_RELEASE_AGE")
            .is_ok_and(|age| !age.is_empty() && age != "24h")
    {
        return Ok(());
    }
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let interrupted = || -> Error { "Codex prefetch interrupted; no package imported".into() };
    let response = tokio::select! {
        result = curl("https://api.github.com/repos/openai/codex/releases?per_page=30").output() => result?,
        _ = terminate.recv() => return Err(interrupted()),
        _ = interrupt.recv() => return Err(interrupted()),
    };
    if !response.status.success() {
        return Err("cannot read the upstream Codex release".into());
    }
    let metadata: Vec<&serde_json::value::RawValue> = serde_json::from_slice(&response.stdout)?;
    let releases = metadata
        .iter()
        .map(|json| serde_json::from_str::<Release>(json.get()))
        .collect::<Result<Vec<_>, _>>()?;
    let target = target()?;
    let now = OffsetDateTime::now_utc();
    // GitHub lists by creation time and includes prereleases. Pick the newest
    // eligible stable version. The guest reuses this selection only under the
    // matching default policy, after checking installed selections and payload.
    let Some((index, release, _, asset)) = releases
        .iter()
        .enumerate()
        .filter_map(|(index, release)| {
            candidate(release, target, now).map(|(numbers, asset)| (index, release, numbers, asset))
        })
        .max_by_key(|(_, _, numbers, _)| *numbers)
    else {
        // A bounded prefetch miss leaves installation to the guest resolver.
        return Ok(());
    };
    let version = release.tag_name.trim_start_matches("rust-v");
    let parent = output
        .parent()
        .ok_or("Codex prefetch needs an output parent")?;
    let stage = tempfile::Builder::new()
        .prefix("codex-")
        .tempdir_in(parent)?;
    let archive = stage.path().join("package.tar.zst");
    eprintln!(
        "SafeYolo: acquiring the complete Linux Codex {version} package while installing the host and guest."
    );
    let mut download = curl(&asset.browser_download_url);
    download.arg("--output").arg(&archive);
    let status = tokio::select! {
        result = download.status() => result?,
        _ = terminate.recv() => return Err(interrupted()),
        _ = interrupt.recv() => return Err(interrupted()),
    };
    if !status.success() {
        return Err("Codex package download failed; no partial package was imported".into());
    }
    let descriptor = Descriptor {
        digest: asset.digest.clone().ok_or("Codex asset lacks its digest")?,
        size: asset.size,
    };
    descriptor
        .verify(fs::File::open(&archive)?)
        .map_err(|error| format!("Codex package integrity check failed: {error}"))?;
    // Extraction finishes before an interruption is returned, so tar cannot
    // outlive cleanup of its private stage.
    let payload = stage.path().join("payload");
    let mut extraction = tokio::task::spawn_blocking(move || extract(&archive, &payload));
    tokio::select! {
        result = &mut extraction => result??,
        _ = terminate.recv() => { let _ = extraction.await; return Err(interrupted()); },
        _ = interrupt.recv() => { let _ = extraction.await; return Err(interrupted()); },
    }
    fs::remove_file(stage.path().join("package.tar.zst"))?;
    fs::write(stage.path().join("version"), format!("{version}\n"))?;
    fs::write(stage.path().join("target"), format!("{target}\n"))?;
    fs::write(
        stage.path().join("source"),
        format!("{}\n", env!("SAFEYOLO_BUILD_REVISION")),
    )?;
    fs::write(stage.path().join("upstream.json"), metadata[index].get())?;
    // Destination is caller-owned temporary staging, never an installed root.
    if output.try_exists()? {
        return Err("Codex prefetch destination already exists; preserved it".into());
    }
    fs::rename(stage.path(), output)?;
    Ok(())
}

pub async fn run(arguments: &[String]) -> Result<(), Error> {
    match arguments {
        [command, output] if command == "prefetch" => prefetch(Path::new(output)).await,
        [command, package, home] if command == "import" => stage(Path::new(package), Path::new(home)),
        _ => Err("Codex installer helpers: safeyolo codex prefetch DIRECTORY; safeyolo codex import DIRECTORY AGENT_HOME".into()),
    }
}

/// The host already verified and extracted these bytes. Import only into an
/// unused agent-home path, after the ordinary setup consent.
fn stage(package: &Path, home: &Path) -> Result<(), Error> {
    if fs::read_to_string(package.join("source"))?.trim() != env!("SAFEYOLO_BUILD_REVISION")
        || fs::read_to_string(package.join("target"))?.trim() != target()?
    {
        return Err("prefetched Codex source or guest platform differs from this launch".into());
    }
    let managed = home.join(".safeyolo");
    if !fs::symlink_metadata(&managed)?.is_dir() {
        return Err("Codex import needs the agent's ordinary SafeYolo directory".into());
    }
    let destination = managed.join("codex-package");
    fs::create_dir(&destination)?;
    // Keep the selected payload in its complete layout for the guest launcher.
    // This host never executes the Linux client.
    let status = Command::new("mv")
        .arg(package.join("payload"))
        .arg(&destination)
        .status()?;
    if !status.success() {
        return Err("cannot stage the prefetched Codex payload".into());
    }
    for name in ["target", "source", "upstream.json"] {
        fs::copy(package.join(name), destination.join(name))?;
    }
    // Publish the version last. The guest never imports an incomplete handoff.
    let mut version = fs::File::create(destination.join("version"))?;
    version.write_all(fs::read(package.join("version"))?.as_slice())?;
    Ok(())
}
