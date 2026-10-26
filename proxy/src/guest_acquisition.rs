//! Acquire a compatible guest and stage the existing backend installation inputs.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures_util::TryStreamExt;
use oci_client::{
    Client, Reference,
    client::{Certificate, CertificateEncoding, ClientConfig},
    secrets::RegistryAuth,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::{
    Error,
    guest_oci::{self, ConsumerPlatform, Descriptor, GuestIndex},
};

#[path = "guest_acquisition/archive.rs"]
mod archive;
#[path = "guest_acquisition/components.rs"]
mod components;
#[path = "guest_acquisition/download_timing.rs"]
mod download_timing;
#[path = "guest_acquisition/upgrade.rs"]
mod upgrade;

use download_timing::DownloadTiming;

/// Select a complete installed host/guest pair without initializing state.
pub async fn upgrade_components(root: &Path, arguments: &[OsString]) -> Result<(), Error> {
    components::run(root, arguments).await
}

pub const COMPONENT_UPGRADE_HELP: &str = components::HELP;

#[cfg(target_os = "linux")]
pub(crate) fn validate_prepared_linux_assets(
    path: &Path,
    mapping: crate::linux_host::Mapping,
) -> Result<(), Error> {
    archive::validate_assets(path, consumer_platform()?, mapping)
}

pub const HELP: &str = "safeyolo [--root ROOT] guest upgrade [--index sha256:DIGEST]\nsafeyolo [--root ROOT] guest rollback\nUpgrade the installed default guest, or restore its previous selection without a registry request.\nUpgrade resolves the installed host's compatibility tag once. --index pins an explicit OCI index.\nThe selected guest applies to the next sandbox boot. Running guests keep their existing inputs.\nStop and start an agent to use the selected guest. Host binaries and persistent state stay unchanged.\nPrint the selected guest and its previous selection as JSON.\n\nsafeyolo [--root ROOT] guest acquire --package-info FILE --write-selection FILE [--store DIRECTORY] [--index sha256:DIGEST]\nPrepare a compatible guest for the verified installer.\nWithout --index, resolve the package compatibility tag. --index pins the OCI index for first acquisition.\nPrint the prepared asset directory and write its OCI selection as JSON.\nExisting installed selections are retained even with --index; use guest upgrade to change them.\nDownloads and prepared trees stay in HOME/.local/share/safeyolo/guests by default.\nKeep this directory: installations and rollback selections reference its trees. --store selects another persistent directory.\n\nsafeyolo guest download --package-info FILE [--store DIRECTORY] [--index sha256:DIGEST] [--prepare]\nDownload and verify the compatible guest archive. By default, do not extract it.\n--prepare also attempts early cache extraction without changing host settings or asking for privilege.\nDuring download, --prepare decodes into a private temporary tar file. Extraction waits for archive size and digest verification. Temporary disk use includes the decoded archive.\nLinux uses existing validated UID/GID ranges and noninteractive sudo. Missing setup or extraction privilege defers preparation to the ordinary installer after host consent.\nThe installer checks its actual host settings and guest selection before activation.\nPrint its verified index digest. The installer can then acquire that exact index and reuse the archive.\nInterrupting the download removes its partial blob and retains completed verified blobs.\nDuring early extraction, interruption waits for extraction/remapping and private staging cleanup before exit. A completed verified tree remains reusable.\nExplicit platform inputs remain available through install.sh --platform-assets DIRECTORY.";

#[derive(Debug)]
struct PackageGuest {
    compatibility: String,
    repository: String,
    discovery_tag: String,
    platform: ConsumerPlatform,
    #[cfg(target_os = "linux")]
    runsc_version: Option<String>,
}

impl PackageGuest {
    fn read(path: &Path) -> Result<Self, Error> {
        let text = fs::read_to_string(path)?;
        let mut fields = BTreeMap::new();
        for line in text.split_terminator('\n') {
            let (key, value) = line.split_once('=').ok_or("invalid package-info field")?;
            if !matches!(
                key,
                "source_commit"
                    | "profile"
                    | "platform"
                    | "minimum_runtime"
                    | "libc"
                    | "guest_compatibility"
                    | "guest_repository"
                    | "guest_discovery_tag"
                    | "runsc_version"
                    | "runsc_source"
                    | "runsc_origin"
            ) {
                return Err(format!("unknown package field: {key}").into());
            }
            if fields.insert(key, value).is_some() {
                return Err(format!("duplicate package field: {key}").into());
            }
        }
        let field = |key| {
            fields
                .get(key)
                .copied()
                .ok_or_else(|| format!("missing package field: {key}"))
        };
        let source = field("source_commit")?;
        if source.len() != 40
            || !source
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || !matches!(field("profile")?, "debug" | "production")
        {
            return Err("invalid source/profile metadata".into());
        }
        let minimum = field("minimum_runtime")?;
        if fields
            .get("libc")
            .is_some_and(|value| !matches!(*value, "glibc" | "musl"))
        {
            return Err("invalid package libc".into());
        }
        let parts: Vec<_> = minimum.split('.').collect();
        if !(2..=3).contains(&parts.len())
            || parts
                .iter()
                .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err("invalid minimum runtime".into());
        }
        let platform = match field("platform")? {
            "darwin-arm64" => ConsumerPlatform::DarwinArm64,
            "linux-amd64" => ConsumerPlatform::LinuxAmd64,
            "linux-arm64" => ConsumerPlatform::LinuxArm64,
            _ => return Err("unsupported guest consumer platform".into()),
        };
        if fields.get("libc") == Some(&"musl") && platform == ConsumerPlatform::DarwinArm64 {
            return Err("musl requires a Linux package platform".into());
        }
        if ["runsc_version", "runsc_source", "runsc_origin"]
            .iter()
            .any(|key| fields.contains_key(key))
            && (platform == ConsumerPlatform::DarwinArm64
                || field("runsc_version")? != "release-20261005.0"
                || field("runsc_source")?
                    != "https://github.com/google/gvisor/releases/tag/release-20261005.0"
                || field("runsc_origin")? != "bundled")
        {
            return Err("invalid gVisor package metadata".into());
        }
        if platform != consumer_platform()? {
            return Err("package platform differs from this host".into());
        }
        let compatibility = field("guest_compatibility")?;
        let discovery_tag = field("guest_discovery_tag")?;
        if compatibility.is_empty()
            || compatibility.len() > 121
            || !compatibility
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || discovery_tag != format!("compat-{compatibility}")
        {
            return Err("invalid guest compatibility/discovery metadata".into());
        }
        let repository = field("guest_repository")?;
        if repository != guest_oci::REPOSITORY {
            return Err("untrusted guest repository".into());
        }
        Ok(Self {
            compatibility: compatibility.into(),
            repository: repository.into(),
            discovery_tag: discovery_tag.into(),
            platform,
            #[cfg(target_os = "linux")]
            runsc_version: fields.get("runsc_version").map(|value| value.to_string()),
        })
    }
}

/// Reuse the package's strict reader for Linux runtime selection and doctor.
#[cfg(target_os = "linux")]
pub(crate) fn packaged_runsc_version(root: &Path) -> Result<Option<String>, Error> {
    let path = root.join("package-info");
    if !path.try_exists()? {
        return Ok(None);
    }
    Ok(PackageGuest::read(&path)?.runsc_version)
}

fn consumer_platform() -> Result<ConsumerPlatform, Error> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok(ConsumerPlatform::DarwinArm64),
        ("linux", "x86_64") => Ok(ConsumerPlatform::LinuxAmd64),
        ("linux", "aarch64") => Ok(ConsumerPlatform::LinuxArm64),
        _ => Err("unsupported guest consumer platform".into()),
    }
}

fn registry_client() -> Result<Client, Error> {
    // oci-client's no-provider feature uses our existing ring implementation.
    // A previously installed provider is already usable by the same Rustls stack.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let native = rustls_native_certs::load_native_certs();
    let mut roots: Vec<_> = native
        .certs
        .into_iter()
        .map(|cert| Certificate {
            encoding: CertificateEncoding::Der,
            data: cert.to_vec(),
        })
        .collect();
    for error in native.errors {
        eprintln!("native TLS trust store: {error}");
    }
    if let Some(path) =
        std::env::var_os("SSL_CERT_FILE").or_else(|| std::env::var_os("REQUESTS_CA_BUNDLE"))
    {
        for cert in CertificateDer::pem_reader_iter(fs::File::open(path)?) {
            roots.push(Certificate {
                encoding: CertificateEncoding::Der,
                data: cert?.to_vec(),
            });
        }
    }
    if roots.is_empty() {
        return Err(
            "guest acquisition requires a usable system or configured CA trust store".into(),
        );
    }
    let proxy = |keys: &[&str]| {
        keys.iter()
            .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))
    };
    Client::try_from(ClientConfig {
        tls_certs_only: roots,
        platform_resolver: None,
        https_proxy: proxy(&["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]),
        http_proxy: proxy(&["HTTP_PROXY", "http_proxy"]),
        no_proxy: proxy(&["NO_PROXY", "no_proxy"]),
        connect_timeout: Some(Duration::from_secs(15)),
        read_timeout: Some(Duration::from_secs(60)),
        ..Default::default()
    })
    .map_err(Into::into)
}

/// The installed selection records standard OCI identities, independently of host source.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestSelection {
    version: String,
    repository: String,
    compatibility: String,
    platform: String,
    index: Descriptor,
    manifest: Descriptor,
    archive: Descriptor,
    assets: PathBuf,
    // Initial installations use share/. Upgrades retain a separate backend
    // installation, so an existing sandbox can keep using its original files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    installed_assets: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous: Option<Box<GuestSelection>>,
}

async fn blob(
    client: &Client,
    reference: &Reference,
    descriptor: &Descriptor,
    store: &Path,
    decoding: &mut Option<archive::DownloadDecoder>,
    mut timing: Option<&mut DownloadTiming>,
) -> Result<PathBuf, Error> {
    let directory = store.join("blobs/sha256");
    fs::create_dir_all(&directory)?;
    let destination = directory.join(guest_oci::sha256_hex(&descriptor.digest)?);
    if destination.try_exists()? {
        if let Some(timing) = timing.as_deref_mut() {
            timing.cache_hit = true;
            timing.decoder_status = "cached";
        }
        // Reuse the verified compressed cache without decoding it again here.
        *decoding = None;
        // A retained blob is reusable only after its bytes still verify.
        let metadata = destination.metadata()?;
        if !metadata.is_file() {
            return Err("retained guest blob must be a regular file".into());
        }
        descriptor.check_size(metadata.len())?;
        descriptor.verify(fs::File::open(&destination)?)?;
        if let Some(timing) = timing {
            timing.request_setup.finish();
            timing.archive_verified = true;
        }
        return Ok(destination);
    }
    let temporary = tempfile::NamedTempFile::new_in(&directory)?;
    // Batch network chunks instead of scheduling a blocking file write for each one.
    let mut output = tokio::io::BufWriter::with_capacity(
        1024 * 1024,
        tokio::fs::File::from_std(temporary.reopen()?),
    );
    let stream = client
        .pull_blob_stream(reference, descriptor.digest.as_str())
        .await;
    if let Some(timing) = timing.as_deref_mut() {
        timing.request_setup.finish();
    }
    let mut stream = stream?;
    if let Some(size) = stream.content_length {
        descriptor.check_size(size)?;
    }
    let mut size = 0_u64;
    // Reaching EOF consumes oci-client's streaming digest verification too.
    loop {
        if let Some(timing) = timing.as_deref_mut() {
            timing.stream_try_next.start();
        }
        // This boundary includes OCI digest work and task scheduling. It does
        // not measure time on the remote network.
        let next = stream.try_next().await;
        if let Some(timing) = timing.as_deref_mut() {
            timing.stream_try_next.finish();
        }
        let Some(bytes) = next? else {
            if let Some(timing) = timing.as_deref_mut() {
                timing.eof_at_s = Some(timing.started.elapsed().as_secs_f64());
            }
            break;
        };
        if let Some(timing) = timing.as_deref_mut() {
            let at = timing.started.elapsed().as_secs_f64();
            timing.first_chunk_at_s.get_or_insert(at);
            timing.last_chunk_at_s = Some(at);
            timing.chunks += 1;
            timing.bytes += bytes.len() as u64;
        }
        size = size
            .checked_add(bytes.len() as u64)
            .ok_or("guest content size overflow")?;
        if size > descriptor.size {
            return Err("guest descriptor size mismatch".into());
        }
        if let Some(timing) = timing.as_deref_mut() {
            timing.compressed_write.start();
        }
        let written = output.write_all(&bytes).await;
        if let Some(timing) = timing.as_deref_mut() {
            timing.compressed_write.finish();
        }
        written?;
        if let Some(decoder) = decoding {
            if let Some(timing) = timing.as_deref_mut() {
                timing.decoder_enqueue.start();
            }
            let decoded = decoder.write(bytes).await;
            if let Some(timing) = timing.as_deref_mut() {
                timing.decoder_enqueue.finish();
            }
            if let Err(error) = decoded {
                eprintln!("SafeYolo: guest download decoding deferred: {error}.");
                *decoding = None;
                if let Some(timing) = timing.as_deref_mut() {
                    timing.decoder_status = "write_failed";
                }
            }
        }
    }
    descriptor.check_size(size)?;
    if let Some(timing) = timing.as_deref_mut() {
        timing.compressed_flush.start();
    }
    let flushed = output.flush().await;
    if let Some(timing) = timing.as_deref_mut() {
        timing.compressed_flush.finish();
    }
    flushed?;
    if let Some(timing) = timing.as_deref_mut() {
        timing.compressed_sync.start();
    }
    let synced = output.get_ref().sync_all().await;
    if let Some(timing) = timing.as_deref_mut() {
        timing.compressed_sync.finish();
    }
    synced?;
    drop(output);
    temporary.persist_noclobber(&destination)?;
    fs::File::open(&directory)?.sync_all()?;
    if let Some(timing) = timing {
        timing.archive_verified = true;
    }
    Ok(destination)
}

async fn resolve_guest(
    client: &Client,
    package: &PackageGuest,
    store: &Path,
    index_digest: Option<&str>,
) -> Result<(GuestIndex, guest_oci::GuestChild), Error> {
    let reference: Reference = match index_digest {
        Some(digest) => {
            guest_oci::sha256_hex(digest)?;
            format!("{}@{digest}", package.repository).parse()?
        }
        None => format!("{}:{}", package.repository, package.discovery_tag).parse()?,
    };
    // Only an explicit immutable index can bypass discovery. Retained raw
    // metadata still goes through the same digest/descriptor/compatibility
    // validation as registry responses; its presence is not a receipt.
    let cached_index = match index_digest {
        Some(digest) => retained_manifest(store, digest)?.map(|bytes| (bytes, digest.to_owned())),
        None => None,
    };
    let fetched_index = cached_index.is_none();
    let (index_bytes, digest) = match cached_index {
        Some(cached) => cached,
        None => {
            client
                .pull_manifest_raw(
                    &reference,
                    &RegistryAuth::Anonymous,
                    &[guest_oci::INDEX_MEDIA_TYPE],
                )
                .await?
        }
    };
    let index = GuestIndex::parse(
        &index_bytes,
        index_digest.unwrap_or(&digest),
        &package.compatibility,
    )?;
    let manifest = index.manifest(package.platform).clone();
    let pinned: Reference = format!("{}@{}", package.repository, manifest.digest).parse()?;
    let cached_child = retained_manifest(store, &manifest.digest)?;
    let fetched_child = cached_child.is_none();
    let child_bytes = match cached_child {
        Some(bytes) => bytes,
        None => {
            client
                .pull_manifest_raw(
                    &pinned,
                    &RegistryAuth::Anonymous,
                    &[guest_oci::MANIFEST_MEDIA_TYPE],
                )
                .await?
                .0
        }
    };
    let child = index.validate_child(package.platform, &child_bytes)?;
    // Match publish_guest_oci.sh's exact bytes, not a canonical JSON encoding.
    // Only a full descriptor/platform match avoids the serial config request.
    let (os, architecture) = child.platform.os_architecture();
    let published_config = format!(r#"{{"os":"{os}","architecture":"{architecture}"}}"#);
    if child.validate_config(published_config.as_bytes()).is_err() {
        let config = blob(client, &pinned, &child.config, store, &mut None, None).await?;
        child.validate_config(&fs::read(config)?)?;
    }
    if fetched_index {
        retain_manifest(store, &index.identity.digest, &index_bytes)?;
    }
    if fetched_child {
        retain_manifest(store, &manifest.digest, &child_bytes)?;
    }
    Ok((index, child))
}

fn retained_manifest(store: &Path, digest: &str) -> Result<Option<bytes::Bytes>, Error> {
    let path = store
        .join("blobs/sha256")
        .join(guest_oci::sha256_hex(digest)?);
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes.into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn retain_manifest(store: &Path, digest: &str, bytes: &[u8]) -> Result<(), Error> {
    let directory = store.join("blobs/sha256");
    fs::create_dir_all(&directory)?;
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(directory.join(guest_oci::sha256_hex(digest)?))?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

async fn acquire(
    client: &Client,
    package: &PackageGuest,
    store: &Path,
    index_digest: Option<&str>,
    retained: Option<&GuestSelection>,
    mapping: crate::linux_host::Mapping,
) -> Result<GuestSelection, Error> {
    let (index, child) = resolve_guest(client, package, store, index_digest).await?;
    let manifest = index.manifest(package.platform).clone();
    let pinned: Reference = format!("{}@{}", package.repository, manifest.digest).parse()?;
    let trees = store.join("trees/sha256");
    fs::create_dir_all(&trees)?;
    let retained = retained.filter(|selected| selected.archive.digest == child.archive.digest);
    let assets = if let Some(selected) = retained {
        child.archive.check_size(selected.archive.size)?;
        selected.assets.clone()
    } else {
        prepared_tree(&trees, &child.archive, package.platform, mapping)?
    };
    // Verify a reusable archive's descriptor too. A changed index can declare
    // a wrong size even when its tree already exists from an earlier operation.
    let input = if retained.is_none() {
        Some(blob(client, &pinned, &child.archive, store, &mut None, None).await?)
    } else {
        None
    };
    if assets.try_exists()? {
        archive::validate_assets(&assets, package.platform, mapping)?;
    } else {
        let input = input.ok_or("retained guest inputs disappeared during acquisition")?;
        let destination = assets.clone();
        let platform = package.platform;
        tokio::task::spawn_blocking(move || {
            archive::prepare(&input, None, &destination, platform, mapping, None)
        })
        .await??;
    }
    let (os, architecture) = package.platform.os_architecture();
    Ok(GuestSelection {
        version: index.annotations.version,
        repository: package.repository.clone(),
        compatibility: package.compatibility.clone(),
        platform: format!("{os}/{architecture}"),
        index: index.identity,
        manifest,
        archive: child.archive,
        assets,
        installed_assets: None,
        previous: None,
    })
}

fn prepared_tree(
    trees: &Path,
    archive: &Descriptor,
    platform: ConsumerPlatform,
    mapping: crate::linux_host::Mapping,
) -> Result<PathBuf, Error> {
    let digest = guest_oci::sha256_hex(&archive.digest)?;
    Ok(if platform == ConsumerPlatform::DarwinArm64 {
        trees.join(digest)
    } else {
        trees.join(mapping.tree_name(digest))
    })
}

async fn prepare_downloaded_guest(
    input: PathBuf,
    decoded: Option<fs::File>,
    store: &Path,
    descriptor: &Descriptor,
    platform: ConsumerPlatform,
    terminate: &mut tokio::signal::unix::Signal,
    interrupt: &mut tokio::signal::unix::Signal,
) -> Result<(), Error> {
    // Only existing validated mappings are eligible. The ordinary installer
    // allocates missing ranges after consent and uses its saved host settings.
    #[cfg(target_os = "linux")]
    let mapping = crate::linux_host::current_mapping();
    #[cfg(not(target_os = "linux"))]
    let mapping = Ok::<_, Error>(crate::linux_host::Mapping::for_bases(
        crate::linux_host::ARCHIVE_BASE,
        crate::linux_host::ARCHIVE_BASE,
    ));
    let mapping = match mapping {
        Ok(mapping) => mapping,
        Err(error) => {
            eprintln!(
                "SafeYolo: early guest preparation needs host setup: {error}. The installer will prepare the verified archive after host consent."
            );
            return Ok(());
        }
    };
    let trees = store.join("trees/sha256");
    fs::create_dir_all(&trees)?;
    let assets = prepared_tree(&trees, descriptor, platform, mapping)?;
    if assets.try_exists()? {
        return archive::validate_assets(&assets, platform, mapping);
    }
    eprintln!("SafeYolo: preparing the verified guest cache while acquiring the host package.");
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = cancelled.clone();
    let mut preparation = tokio::task::spawn_blocking(move || {
        archive::prepare(
            &input,
            decoded,
            &assets,
            platform,
            mapping,
            Some(&worker_cancelled),
        )
    });
    tokio::select! {
        result = &mut preparation => return result?,
        _ = terminate.recv() => {},
        _ = interrupt.recv() => {},
    }
    cancelled.store(true, Ordering::Release);
    eprintln!(
        "SafeYolo: stopping early guest preparation; waiting for extraction and staging cleanup."
    );
    // Retain the store lock and helper until all privileged children have
    // finished and their private extraction has been removed.
    preparation.await??;
    Err("guest preparation interrupted; verified blobs remain reusable".into())
}

fn installed(root: &Path, package: &PackageGuest) -> Result<Option<GuestSelection>, Error> {
    let path = root.join("share/guest-selection.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    let selection: GuestSelection = serde_json::from_slice(&fs::read(path)?)?;
    selection.validate(package)?;
    selection.validate_inputs(root, package.platform)?;
    Ok(Some(selection))
}

impl GuestSelection {
    fn validate(&self, package: &PackageGuest) -> Result<(), Error> {
        let (os, architecture) = package.platform.os_architecture();
        if self.repository != package.repository
            || self.compatibility != package.compatibility
            || self.platform != format!("{os}/{architecture}")
        {
            return Err("installed guest selection differs from the host package's compatibility, repository or platform; selection was preserved".into());
        }
        for descriptor in [&self.index, &self.manifest, &self.archive] {
            guest_oci::sha256_hex(&descriptor.digest)?;
        }
        Ok(())
    }

    fn inputs(&self, root: &Path) -> PathBuf {
        self.installed_assets
            .clone()
            .unwrap_or_else(|| root.join("share"))
    }

    fn validate_inputs(&self, root: &Path, platform: ConsumerPlatform) -> Result<(), Error> {
        let mapping = crate::linux_host::mapping_for_root(root)?;
        archive::validate_assets(&self.assets, platform, mapping)?;
        let inputs = self.inputs(root);
        archive::validate_assets(&inputs, platform, mapping)?;
        if platform != ConsumerPlatform::DarwinArm64
            && inputs.join("rootfs-tree").canonicalize()?
                != self.assets.join("rootfs-tree").canonicalize()?
        {
            return Err("installed rootfs tree differs from the retained guest selection".into());
        }
        Ok(())
    }
}

/// Read one complete local selection. Boot never performs registry discovery.
pub(crate) fn selected_boot_inputs(root: &Path) -> Result<(PathBuf, PathBuf), Error> {
    let (host, share) = components::installed_paths(root)?;
    let guest = selected_inputs_at(&host, &share)?;
    Ok((host, guest))
}

pub(crate) fn retained_host_binaries(root: &Path, name: &str) -> Result<Vec<PathBuf>, Error> {
    components::retained_host_binaries(root, name)
}

fn selected_inputs_at(host: &Path, share: &Path) -> Result<PathBuf, Error> {
    if !share.join("guest-selection.json").try_exists()? {
        return Ok(share.to_path_buf());
    }
    let package = PackageGuest::read(&host.join("package-info"))?;
    let selection: GuestSelection =
        serde_json::from_slice(&fs::read(share.join("guest-selection.json"))?)?;
    selection.validate(&package)?;
    // Boot validates the inputs it consumes. Explicit per-agent files may
    // replace default files, and do not require unused cached inputs.
    Ok(selection
        .installed_assets
        .unwrap_or_else(|| share.to_path_buf()))
}

fn write_selection(selection: &GuestSelection, path: &Path) -> Result<(), Error> {
    crate::coord_supervisor::atomic_write(path, &serde_json::to_vec_pretty(selection)?, 0o600)?;
    eprintln!(
        "Prepared guest {} {}",
        selection.version, selection.archive.digest
    );
    println!("{}", selection.assets.display());
    Ok(())
}

fn guest_store_directory(store: Option<PathBuf>) -> Result<PathBuf, Error> {
    Ok(match store {
        Some(store) => store,
        None => PathBuf::from(
            std::env::var_os("HOME")
                .ok_or("HOME is required for the persistent guest directory")?,
        )
        .join(".local/share/safeyolo/guests"),
    })
}

pub async fn run(root: &Path, arguments: &[OsString]) -> Result<(), Error> {
    if matches!(arguments, [help] if help == "--help")
        || matches!(arguments, [command, help] if matches!(command.to_str(), Some("acquire" | "download" | "upgrade" | "rollback")) && help == "--help")
    {
        println!("{HELP}");
        return Ok(());
    }
    if arguments
        .first()
        .is_some_and(|value| value == "upgrade" || value == "rollback")
    {
        return upgrade::run(root, arguments).await;
    }
    let download_only = arguments.first().is_some_and(|value| value == "download");
    if !download_only && arguments.first().is_none_or(|value| value != "acquire") {
        return Err(format!("unknown guest command\n{HELP}").into());
    }
    let mut package_info = None;
    let mut store = None;
    let mut selection_file = None;
    let mut host_settings = None;
    let mut prepare_download = false;
    let mut index = None;
    let mut options = arguments[1..].iter();
    while let Some(option) = options.next() {
        if option == "--prepare" && download_only && !prepare_download {
            prepare_download = true;
            continue;
        }
        let value = options
            .next()
            .ok_or("guest acquire option requires a value")?;
        if option == "--package-info" && package_info.is_none() {
            package_info = Some(PathBuf::from(value));
        } else if option == "--store" && store.is_none() {
            store = Some(PathBuf::from(value));
        } else if option == "--write-selection" && selection_file.is_none() {
            selection_file = Some(PathBuf::from(value));
        } else if option == "--host-settings" && host_settings.is_none() {
            host_settings = Some(PathBuf::from(value));
        } else if option == "--index" && index.is_none() {
            let digest = value.to_str().ok_or("guest index digest must be UTF-8")?;
            guest_oci::sha256_hex(digest)?;
            index = Some(digest);
        } else {
            return Err("unknown or duplicate guest acquire option".into());
        }
    }
    let package = PackageGuest::read(&package_info.ok_or("--package-info is required")?)?;
    if download_only && (selection_file.is_some() || host_settings.is_some()) {
        return Err("guest download does not extract or write an installed selection".into());
    }
    if download_only {
        let mut timing = DownloadTiming::from_env();
        // Drop the streaming future on cancellation so its NamedTempFile is
        // removed. Only verified blobs persist; no tree or instance is created.
        let store = guest_store_directory(store)?;
        fs::create_dir_all(&store)?;
        let _store_lock = crate::host_platform::lock_host_state(&store.join("acquire.lock"))?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let client = registry_client()?;
        let (index, child) = tokio::select! {
            result = resolve_guest(&client, &package, &store, index) => result,
            _ = terminate.recv() => Err("guest download interrupted; verified blobs remain reusable".into()),
            _ = interrupt.recv() => Err("guest download interrupted; verified blobs remain reusable".into()),
        }?;
        // Decompression can overlap the network transfer, but tar (including
        // sudo tar) must not see bytes until the compressed descriptor verifies.
        // Anonymous temporary output disappears on cancellation or verification
        // failure. No extraction child exists during this part of the download.
        let mut decoding = if prepare_download {
            match tempfile::tempfile_in(&store)
                .map_err(Error::from)
                .and_then(archive::DownloadDecoder::new)
            {
                Ok(decoder) => Some(decoder),
                Err(error) => {
                    eprintln!("SafeYolo: guest download decoding deferred: {error}.");
                    None
                }
            }
        } else {
            None
        };
        if let Some(timing) = timing.as_mut() {
            timing.decoder_status = if decoding.is_some() {
                "streaming"
            } else if prepare_download {
                "unavailable"
            } else {
                "not_requested"
            };
        }
        let reference = format!(
            "{}@{}",
            package.repository,
            index.manifest(package.platform).digest
        )
        .parse()?;
        let input = tokio::select! {
            result = blob(&client, &reference, &child.archive, &store, &mut decoding, timing.as_mut()) => result,
            _ = terminate.recv() => Err("guest download interrupted; verified blobs remain reusable".into()),
            _ = interrupt.recv() => Err("guest download interrupted; verified blobs remain reusable".into()),
        }?;
        let decoded = if let Some(decoder) = decoding {
            if let Some(timing) = timing.as_mut() {
                timing.decoder_finish.start();
            }
            let finished = tokio::select! {
                result = decoder.finish() => result,
                _ = terminate.recv() => return Err("guest download interrupted; verified blobs remain reusable".into()),
                _ = interrupt.recv() => return Err("guest download interrupted; verified blobs remain reusable".into()),
            };
            if let Some(timing) = timing.as_mut() {
                timing.decoder_finish.finish();
                timing.decoder_status = if finished.is_ok() {
                    "complete"
                } else {
                    "finish_failed"
                };
            }
            match finished {
                Ok(output) => Some(output),
                Err(error) => {
                    eprintln!("SafeYolo: guest download decoding deferred: {error}.");
                    None
                }
            }
        } else {
            None
        };
        drop(timing);
        if prepare_download {
            prepare_downloaded_guest(
                input,
                decoded,
                &store,
                &child.archive,
                package.platform,
                &mut terminate,
                &mut interrupt,
            )
            .await?;
        }
        println!("{}", index.identity.digest);
        return Ok(());
    }
    let selection_file = selection_file.ok_or("--write-selection is required")?;
    fs::create_dir_all(root)?;
    let _install_lock = crate::host_platform::lock_host_state(&root.join("guest-install.lock"))?;
    if let Some(selection) = installed(root, &package)? {
        return write_selection(&selection, &selection_file);
    }
    if root.join("config.toml").try_exists()?
        || root.join("policy.toml").try_exists()?
        || root.join("data/admin_token").try_exists()?
    {
        return Err(
            "instance already has configuration; guest installation requires a fresh root".into(),
        );
    }
    if root.join("share").try_exists()? {
        return Err("guest inputs already exist; use --platform-assets for explicit inputs".into());
    }
    let store = guest_store_directory(store)?;
    fs::create_dir_all(&store)?;
    let store = store.canonicalize()?;
    let _store_lock = crate::host_platform::lock_host_state(&store.join("acquire.lock"))?;
    let mapping = match host_settings {
        Some(path) => crate::linux_host::mapping_from_settings(&path)?,
        None => crate::linux_host::mapping_for_root(root)?,
    };
    let selection = acquire(&registry_client()?, &package, &store, index, None, mapping).await?;
    // Acquisition can take time. Preserve an instance initialized meanwhile.
    if root.join("config.toml").try_exists()?
        || root.join("policy.toml").try_exists()?
        || root.join("data/admin_token").try_exists()?
    {
        return Err(
            "instance was initialized during acquisition; its guest inputs were preserved".into(),
        );
    }
    write_selection(&selection, &selection_file)
}

#[cfg(test)]
#[path = "guest_acquisition/tests.rs"]
mod tests;
