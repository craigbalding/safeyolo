//! Acquire a compatible guest and stage the existing backend installation inputs.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
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
#[path = "guest_acquisition/upgrade.rs"]
mod upgrade;

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

pub const HELP: &str = "safeyolo [--root ROOT] guest upgrade [--index sha256:DIGEST]\nsafeyolo [--root ROOT] guest rollback\nUpgrade the installed default guest, or restore its previous selection without a registry request.\nUpgrade resolves the installed host's compatibility tag once. --index pins an explicit OCI index.\nThe selected guest applies to the next sandbox boot. Running guests keep their existing inputs.\nStop and start an agent to use the selected guest. Host binaries and persistent state stay unchanged.\nPrint the selected guest and its previous selection as JSON.\n\nsafeyolo [--root ROOT] guest acquire --package-info FILE --write-selection FILE [--store DIRECTORY] [--index sha256:DIGEST]\nPrepare a compatible guest for the verified installer.\nWithout --index, resolve the package compatibility tag. --index pins the OCI index for first acquisition.\nPrint the prepared asset directory and write its OCI selection as JSON.\nExisting installed selections are retained even with --index; use guest upgrade to change them.\nDownloads and prepared trees stay in HOME/.local/share/safeyolo/guests by default.\nKeep this directory: installations and rollback selections reference its trees. --store selects another persistent directory.\nExplicit platform inputs remain available through install.sh --platform-assets DIRECTORY.";

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
) -> Result<PathBuf, Error> {
    let directory = store.join("blobs/sha256");
    fs::create_dir_all(&directory)?;
    let destination = directory.join(guest_oci::sha256_hex(&descriptor.digest)?);
    if destination.try_exists()? {
        // A retained blob is reusable only after its bytes still verify.
        let metadata = destination.metadata()?;
        if !metadata.is_file() {
            return Err("retained guest blob must be a regular file".into());
        }
        descriptor.check_size(metadata.len())?;
        descriptor.verify(fs::File::open(&destination)?)?;
        return Ok(destination);
    }
    let temporary = tempfile::NamedTempFile::new_in(&directory)?;
    let mut output = tokio::fs::File::from_std(temporary.reopen()?);
    let mut stream = client
        .pull_blob_stream(reference, descriptor.digest.as_str())
        .await?;
    if let Some(size) = stream.content_length {
        descriptor.check_size(size)?;
    }
    let mut size = 0_u64;
    // Reaching EOF consumes oci-client's streaming digest verification too.
    while let Some(bytes) = stream.try_next().await? {
        size = size
            .checked_add(bytes.len() as u64)
            .ok_or("guest content size overflow")?;
        if size > descriptor.size {
            return Err("guest descriptor size mismatch".into());
        }
        output.write_all(&bytes).await?;
    }
    descriptor.check_size(size)?;
    output.sync_all().await?;
    drop(output);
    temporary.persist_noclobber(&destination)?;
    fs::File::open(&directory)?.sync_all()?;
    Ok(destination)
}

async fn acquire(
    client: &Client,
    package: &PackageGuest,
    store: &Path,
    index_digest: Option<&str>,
    retained: Option<&GuestSelection>,
    mapping: crate::linux_host::Mapping,
) -> Result<GuestSelection, Error> {
    let reference: Reference = match index_digest {
        Some(digest) => {
            guest_oci::sha256_hex(digest)?;
            format!("{}@{digest}", package.repository).parse()?
        }
        None => format!("{}:{}", package.repository, package.discovery_tag).parse()?,
    };
    let (bytes, digest) = client
        .pull_manifest_raw(
            &reference,
            &RegistryAuth::Anonymous,
            &[guest_oci::INDEX_MEDIA_TYPE],
        )
        .await?;
    let index = GuestIndex::parse(
        &bytes,
        index_digest.unwrap_or(&digest),
        &package.compatibility,
    )?;
    let manifest = index.manifest(package.platform).clone();
    let pinned: Reference = format!("{}@{}", package.repository, manifest.digest).parse()?;
    let (bytes, _) = client
        .pull_manifest_raw(
            &pinned,
            &RegistryAuth::Anonymous,
            &[guest_oci::MANIFEST_MEDIA_TYPE],
        )
        .await?;
    let child = index.validate_child(package.platform, &bytes)?;
    let config = blob(client, &pinned, &child.config, store).await?;
    child.validate_config(&fs::read(config)?)?;
    let trees = store.join("trees/sha256");
    fs::create_dir_all(&trees)?;
    let retained = retained.filter(|selected| selected.archive.digest == child.archive.digest);
    let assets = if let Some(selected) = retained {
        child.archive.check_size(selected.archive.size)?;
        selected.assets.clone()
    } else {
        let digest = guest_oci::sha256_hex(&child.archive.digest)?;
        if package.platform == ConsumerPlatform::DarwinArm64 {
            trees.join(digest)
        } else {
            trees.join(mapping.tree_name(digest))
        }
    };
    // Verify a reusable archive's descriptor too. A changed index can declare
    // a wrong size even when its tree already exists from an earlier operation.
    let input = if retained.is_none() {
        Some(blob(client, &pinned, &child.archive, store).await?)
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
            archive::prepare(&input, &destination, platform, mapping)
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

pub async fn run(root: &Path, arguments: &[OsString]) -> Result<(), Error> {
    if matches!(arguments, [help] if help == "--help")
        || matches!(arguments, [command, help] if matches!(command.to_str(), Some("acquire" | "upgrade" | "rollback")) && help == "--help")
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
    if arguments.first().is_none_or(|value| value != "acquire") {
        return Err(format!("unknown guest command\n{HELP}").into());
    }
    let mut package_info = None;
    let mut store = None;
    let mut selection_file = None;
    let mut host_settings = None;
    let mut index = None;
    let mut options = arguments[1..].iter();
    while let Some(option) = options.next() {
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
    let selection_file = selection_file.ok_or("--write-selection is required")?;
    let package = PackageGuest::read(&package_info.ok_or("--package-info is required")?)?;
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
    let store = match store {
        Some(store) => store,
        None => PathBuf::from(
            std::env::var_os("HOME")
                .ok_or("HOME is required for the persistent guest directory")?,
        )
        .join(".local/share/safeyolo/guests"),
    };
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
