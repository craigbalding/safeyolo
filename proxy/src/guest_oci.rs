//! Shared OCI guest source contract. Registry transport and installation are separate.

use std::{collections::BTreeMap, io::Read};

use ring::digest::{Context, SHA256};
use serde::de::{self, DeserializeOwned, MapAccess, Visitor};
use serde_json::value::RawValue;

use crate::Error;

pub const REPOSITORY: &str = "ghcr.io/craigbalding/safeyolo-guest";
pub const SOURCE: &str = "https://github.com/craigbalding/safeyolo";
pub const INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const ARTIFACT_TYPE: &str = "application/vnd.safeyolo.guest.v1";
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.safeyolo.guest.platform.v1+json";
pub const ARCHIVE_MEDIA_TYPE: &str = "application/vnd.safeyolo.guest.v1.tar+zstd";
pub const VERSION: &str = "org.opencontainers.image.version";
pub const SOURCE_ANNOTATION: &str = "org.opencontainers.image.source";
pub const REVISION: &str = "org.opencontainers.image.revision";
pub const COMPATIBILITY: &str = "dev.safeyolo.guest.compatibility";
pub const BUILD_BASE: &str = "dev.safeyolo.guest.build-base";

// Keep fields as raw JSON until their declared OCI type is decoded. Value's
// private Number/RawValue representations must not reinterpret authored objects.
type JsonObject = BTreeMap<String, Box<RawValue>>;
type AnnotationMap = BTreeMap<String, String>;

/// The archive's consumer host, including the distinction between both arm64 payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumerPlatform {
    DarwinArm64,
    LinuxAmd64,
    LinuxArm64,
}

impl ConsumerPlatform {
    /// Complete release order, also used by `GuestIndex::validate_children`.
    pub const ALL: [Self; 3] = [Self::DarwinArm64, Self::LinuxAmd64, Self::LinuxArm64];

    pub fn from_oci(os: &str, architecture: &str) -> Result<Self, Error> {
        match (os, architecture) {
            ("darwin", "arm64") => Ok(Self::DarwinArm64),
            ("linux", "amd64") => Ok(Self::LinuxAmd64),
            ("linux", "arm64") => Ok(Self::LinuxArm64),
            _ => Err("unsupported guest consumer platform".into()),
        }
    }

    pub fn os_architecture(self) -> (&'static str, &'static str) {
        match self {
            Self::DarwinArm64 => ("darwin", "arm64"),
            Self::LinuxAmd64 => ("linux", "amd64"),
            Self::LinuxArm64 => ("linux", "arm64"),
        }
    }

    fn position(self) -> usize {
        match self {
            Self::DarwinArm64 => 0,
            Self::LinuxAmd64 => 1,
            Self::LinuxArm64 => 2,
        }
    }
}

/// Standard OCI content identity and raw byte size, not a separate checksum record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub digest: String,
    pub size: u64,
}

impl Descriptor {
    fn parse(value: &JsonObject, media_type: &str) -> Result<Self, Error> {
        if read_field::<String>(value, "mediaType")? != media_type {
            return Err("wrong guest descriptor mediaType".into());
        }
        let digest: String = read_field(value, "digest")?;
        sha256_hex(&digest)?;
        let size = integer_field(value, "size")?;
        if size < 0 {
            return Err("guest descriptor size must be a nonnegative int64".into());
        }
        if let Some(annotations) = value.get("annotations") {
            annotation_map(annotations)?;
        }
        Ok(Self {
            digest,
            size: size as u64,
        })
    }

    /// Check streamed content through EOF. No complete archive buffer is needed.
    /// The native OCI client can instead use its own hash check plus `check_size`.
    pub fn verify(&self, mut content: impl Read) -> Result<(), Error> {
        sha256_hex(&self.digest)?;
        let mut context = Context::new(&SHA256);
        let mut actual_size = 0_u64;
        let mut buffer = [0; 64 * 1024];
        loop {
            let read = match content.read(&mut buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if read == 0 {
                break;
            }
            actual_size = actual_size
                .checked_add(read as u64)
                .ok_or("guest content size overflow")?;
            if actual_size > self.size {
                return Err("guest descriptor size mismatch".into());
            }
            context.update(&buffer[..read]);
        }
        self.check_size(actual_size)?;
        if sha256_string(context.finish().as_ref()) != self.digest {
            return Err("guest descriptor SHA-256 mismatch".into());
        }
        Ok(())
    }

    pub fn check_size(&self, actual_size: u64) -> Result<(), Error> {
        if actual_size != self.size {
            return Err("guest descriptor size mismatch".into());
        }
        Ok(())
    }
}

/// Return the standard lowercase SHA-256 hexadecimal component of a digest.
pub fn sha256_hex(digest: &str) -> Result<&str, Error> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or("guest digest must use SHA-256")?;
    if hex.len() != 64 || !lower_hex(hex) {
        return Err("guest SHA-256 digest must have 64 lowercase hexadecimal characters".into());
    }
    Ok(hex)
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_string(bytes: &[u8]) -> String {
    let mut hex = String::from("sha256:");
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn raw_field<'a>(value: &'a JsonObject, key: &str) -> Result<&'a RawValue, Error> {
    value
        .get(key)
        .map(Box::as_ref)
        .ok_or_else(|| format!("missing guest {key}").into())
}

fn read_field<T: DeserializeOwned>(value: &JsonObject, key: &str) -> Result<T, Error> {
    serde_json::from_str(raw_field(value, key)?.get())
        .map_err(|error| format!("guest {key}: {error}").into())
}

fn integer_field(value: &JsonObject, key: &str) -> Result<i64, Error> {
    // The enclosing JSON decoder has already checked token syntax. Parse the
    // actual integer token, including -0, without Value's object coercion.
    raw_field(value, key)?
        .get()
        .trim()
        .parse()
        .map_err(|_| format!("guest {key} must be an int64 integer").into())
}

fn annotation_map(raw: &RawValue) -> Result<AnnotationMap, Error> {
    struct Annotations;
    impl<'de> Visitor<'de> for Annotations {
        type Value = AnnotationMap;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("guest annotations with unique string keys and string values")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<AnnotationMap, A::Error> {
            let mut annotations = AnnotationMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if annotations.contains_key(&key) {
                    return Err(de::Error::custom("duplicate guest annotation key"));
                }
                annotations.insert(key, map.next_value::<String>()?);
            }
            Ok(annotations)
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(raw.get());
    let annotations = serde::Deserializer::deserialize_map(&mut decoder, Annotations)?;
    decoder.end()?;
    Ok(annotations)
}

fn annotation<'a>(annotations: &'a AnnotationMap, key: &str) -> Result<&'a str, Error> {
    annotations
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing guest annotation {key}").into())
}

fn document(bytes: &[u8], media_type: &str) -> Result<(JsonObject, AnnotationMap), Error> {
    let value: JsonObject = serde_json::from_slice(bytes)?;
    if integer_field(&value, "schemaVersion")? != 2
        || read_field::<String>(&value, "mediaType")? != media_type
    {
        return Err(
            "guest OCI document must have schemaVersion 2 and the required mediaType".into(),
        );
    }
    if read_field::<String>(&value, "artifactType")? != ARTIFACT_TYPE {
        return Err("wrong guest artifactType".into());
    }
    let annotations = annotation_map(raw_field(&value, "annotations")?)?;
    Ok((value, annotations))
}

/// Independent guest release identity shared by the index and children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestAnnotations {
    pub version: String,
    pub revision: String,
    pub compatibility: String,
}

impl GuestAnnotations {
    fn parse(value: &AnnotationMap) -> Result<Self, Error> {
        let version = annotation(value, VERSION)?;
        let (date, number) = version
            .strip_prefix("guest-")
            .and_then(|v| v.split_once('.'))
            .ok_or("guest version must use guest-YYYY-MM-DD.N")?;
        if date.len() != 10
            || date.as_bytes()[4] != b'-'
            || date.as_bytes()[7] != b'-'
            || !date
                .bytes()
                .enumerate()
                .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
            || number.is_empty()
            || !number.bytes().all(|b| b.is_ascii_digit())
            || version.len() > 128
        {
            return Err("guest version must use guest-YYYY-MM-DD.N".into());
        }
        time::Date::from_calendar_date(
            date[..4].parse()?,
            time::Month::try_from(date[5..7].parse::<u8>()?)?,
            date[8..].parse()?,
        )?;
        if annotation(value, SOURCE_ANNOTATION)? != SOURCE {
            return Err("wrong guest source repository".into());
        }
        let revision = annotation(value, REVISION)?;
        if !matches!(revision.len(), 40 | 64) || !lower_hex(revision) {
            return Err("guest revision must be a full lowercase Git object ID".into());
        }
        let compatibility = annotation(value, COMPATIBILITY)?;
        // compat- plus this identifier must be a standard OCI distribution tag.
        if compatibility.is_empty()
            || compatibility.len() > 121
            || !compatibility
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            return Err(
                "guest compatibility must be a nonempty OCI tag suffix of at most 121 characters"
                    .into(),
            );
        }
        Ok(Self {
            version: version.into(),
            revision: revision.into(),
            compatibility: compatibility.into(),
        })
    }
}

/// A verified, complete index. All later content follows its digest descriptors.
#[derive(Debug)]
pub struct GuestIndex {
    pub identity: Descriptor,
    pub annotations: GuestAnnotations,
    children: [Descriptor; 3],
}

impl GuestIndex {
    /// `digest` is the identity resolved once from discovery, or an explicit release.
    /// The root index has no parent descriptor; its size records the observed bytes.
    pub fn parse(bytes: &[u8], digest: &str, host_compatibility: &str) -> Result<Self, Error> {
        let identity = Descriptor {
            digest: digest.into(),
            size: bytes.len() as u64,
        };
        identity.verify(bytes)?;
        let (value, annotation_values) = document(bytes, INDEX_MEDIA_TYPE)?;
        let annotations = GuestAnnotations::parse(&annotation_values)?;
        if annotations.compatibility != host_compatibility {
            return Err("guest compatibility does not match the host".into());
        }
        let manifests: Vec<JsonObject> = read_field(&value, "manifests")?;
        let mut children = [None, None, None];
        for manifest in manifests {
            let consumer: JsonObject = read_field(&manifest, "platform")?;
            let platform = ConsumerPlatform::from_oci(
                &read_field::<String>(&consumer, "os")?,
                &read_field::<String>(&consumer, "architecture")?,
            )?;
            let slot = &mut children[platform.position()];
            if slot.is_some() {
                return Err("duplicate guest consumer platform".into());
            }
            *slot = Some(Descriptor::parse(&manifest, MANIFEST_MEDIA_TYPE)?);
        }
        let children = [
            children[0].take().ok_or("missing darwin/arm64 guest")?,
            children[1].take().ok_or("missing linux/amd64 guest")?,
            children[2].take().ok_or("missing linux/arm64 guest")?,
        ];
        Ok(Self {
            identity,
            annotations,
            children,
        })
    }

    pub fn manifest(&self, platform: ConsumerPlatform) -> &Descriptor {
        &self.children[platform.position()]
    }

    /// Validate the selected child's raw bytes before following its config/archive.
    pub fn validate_child(
        &self,
        platform: ConsumerPlatform,
        bytes: &[u8],
    ) -> Result<GuestChild, Error> {
        self.manifest(platform).verify(bytes)?;
        let (value, annotations) = document(bytes, MANIFEST_MEDIA_TYPE)?;
        if GuestAnnotations::parse(&annotations)? != self.annotations {
            return Err("guest child annotations do not agree with the index".into());
        }
        let build_base = annotation(&annotations, BUILD_BASE)?;
        let (name, digest) = build_base
            .split_once('@')
            .ok_or("guest build-base must be pinned by SHA-256")?;
        sha256_hex(digest)?;
        let (registry, repository) = name
            .split_once('/')
            .ok_or("guest build-base must be fully qualified")?;
        let reference_syntax = regex::Regex::new(concat!(
            r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?",
            r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*|\[[0-9A-Fa-f:]+\])",
            r"(?::[0-9]+)?/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*",
            r"(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*",
            r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$"
        ))?;
        if registry.is_empty()
            || !(registry.contains('.') || registry.contains(':') || registry == "localhost")
            || repository.is_empty()
            || !reference_syntax.is_match(name)
        {
            return Err("guest build-base must name a fully qualified pinned build input".into());
        }
        let layers: Vec<JsonObject> = read_field(&value, "layers")?;
        if layers.len() != 1 {
            return Err("guest child must have exactly one opaque archive layer".into());
        }
        Ok(GuestChild {
            platform,
            config: Descriptor::parse(&read_field(&value, "config")?, CONFIG_MEDIA_TYPE)?,
            archive: Descriptor::parse(&layers[0], ARCHIVE_MEDIA_TYPE)?,
            build_base: build_base.into(),
        })
    }

    /// Publisher check of all children in `ConsumerPlatform::ALL` order.
    /// A consumer can validate just its selected chain with `validate_child`.
    pub fn validate_children(&self, bytes: [&[u8]; 3]) -> Result<[GuestChild; 3], Error> {
        let children = [
            self.validate_child(ConsumerPlatform::DarwinArm64, bytes[0])?,
            self.validate_child(ConsumerPlatform::LinuxAmd64, bytes[1])?,
            self.validate_child(ConsumerPlatform::LinuxArm64, bytes[2])?,
        ];
        if children[0].archive.digest == children[2].archive.digest {
            return Err("darwin/arm64 and linux/arm64 must have distinct guest archives".into());
        }
        Ok(children)
    }
}

#[derive(Debug)]
pub struct GuestChild {
    pub platform: ConsumerPlatform,
    pub config: Descriptor,
    pub archive: Descriptor,
    pub build_base: String,
}

impl GuestChild {
    pub fn validate_config(&self, bytes: &[u8]) -> Result<(), Error> {
        self.config.verify(bytes)?;
        let value: JsonObject = serde_json::from_slice(bytes)?;
        if value.len() != 2
            || ConsumerPlatform::from_oci(
                &read_field::<String>(&value, "os")?,
                &read_field::<String>(&value, "architecture")?,
            )? != self.platform
        {
            return Err(
                "guest config must contain only the selected consumer os and architecture".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "guest_oci/tests.rs"]
mod tests;
