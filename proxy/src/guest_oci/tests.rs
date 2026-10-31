use super::*;
use serde_json::{Value, json};

fn encode(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn digest(bytes: &[u8]) -> String {
    sha256_string(ring::digest::digest(&SHA256, bytes).as_ref())
}
fn descriptor(media_type: &str, bytes: &[u8]) -> Value {
    json!({"mediaType": media_type, "digest": digest(bytes), "size": bytes.len()})
}
fn annotations() -> Value {
    json!({VERSION: "guest-2026-10-12.1", SOURCE_ANNOTATION: SOURCE,
        REVISION: "6e268b5ad5801fc5f86c6751acfeedf7efa4e8bf", COMPATIBILITY: "v1",
        "example.org/extra": "unknown annotations are allowed"})
}

struct Release {
    index: Value,
    children: [Value; 3],
    configs: [Vec<u8>; 3],
    archives: [Vec<u8>; 3],
}

impl Release {
    fn new() -> Self {
        let configs = ConsumerPlatform::ALL.map(|platform| {
            let (os, architecture) = platform.os_architecture();
            encode(&json!({"os": os, "architecture": architecture}))
        });
        // The contract treats archive bytes as opaque; extraction is a later boundary.
        let archives = [
            b"Mac prepared archive".to_vec(),
            b"Linux amd64 archive".to_vec(),
            b"Linux arm64 archive".to_vec(),
        ];
        let children = std::array::from_fn(|i| {
            let mut ann = annotations();
            ann[BUILD_BASE] = json!(format!(
                "docker.io/library/debian:trixie@{}",
                digest(format!("base-{i}").as_bytes())
            ));
            json!({"schemaVersion": 2, "mediaType": MANIFEST_MEDIA_TYPE, "artifactType": ARTIFACT_TYPE,
                "annotations": ann, "config": descriptor(CONFIG_MEDIA_TYPE, &configs[i]),
                "layers": [descriptor(ARCHIVE_MEDIA_TYPE, &archives[i])]})
        });
        let mut result = Self {
            index: json!({"schemaVersion": 2, "mediaType": INDEX_MEDIA_TYPE,
            "artifactType": ARTIFACT_TYPE, "annotations": annotations(), "manifests": []}),
            children,
            configs,
            archives,
        };
        result.refresh_children();
        result
    }

    fn refresh_children(&mut self) {
        self.index["manifests"] = ConsumerPlatform::ALL
            .iter()
            .enumerate()
            .map(|(i, platform)| {
                let mut child = descriptor(MANIFEST_MEDIA_TYPE, &encode(&self.children[i]));
                let (os, architecture) = platform.os_architecture();
                child["platform"] = json!({"os": os, "architecture": architecture});
                child
            })
            .collect();
    }

    fn parse(&self) -> Result<GuestIndex, Error> {
        let bytes = encode(&self.index);
        GuestIndex::parse(&bytes, &digest(&bytes), "v1")
    }

    fn selected_child(&self) -> Result<GuestChild, Error> {
        self.parse()?
            .validate_child(ConsumerPlatform::DarwinArm64, &encode(&self.children[0]))
    }

    fn raw_child(&self, bytes: &[u8]) -> Result<GuestChild, Error> {
        let mut index = self.index.clone();
        index["manifests"][0]["digest"] = json!(digest(bytes));
        index["manifests"][0]["size"] = json!(bytes.len());
        raw_index(&encode(&index))?.validate_child(ConsumerPlatform::DarwinArm64, bytes)
    }
}

fn raw_index(bytes: &[u8]) -> Result<GuestIndex, Error> {
    GuestIndex::parse(bytes, &digest(bytes), "v1")
}

// Splice the field into raw JSON after serialization so duplicate entries and
// library-private object shapes reach the real parser unchanged.
fn wire_field(value: &Value, pointer: &str, raw: &str) -> Vec<u8> {
    let mut value = value.clone();
    let (parent, name) = pointer.rsplit_once('/').unwrap();
    let name = name.replace("~1", "/").replace("~0", "~");
    let marker = "guest OCI regression raw field";
    value
        .pointer_mut(parent)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(name, json!(marker));
    String::from_utf8(encode(&value))
        .unwrap()
        .replacen(&serde_json::to_string(marker).unwrap(), raw, 1)
        .into_bytes()
}

#[test]
fn rejects_duplicate_raw_annotations_at_every_consumed_location() {
    let release = Release::new();
    for (is_index, pointer) in [
        (true, "/annotations"),
        (true, "/manifests/0/annotations"),
        (false, "/annotations"),
        (false, "/config/annotations"),
        (false, "/layers/0/annotations"),
    ] {
        for first in [r#""discarded""#, "123", r#""last""#] {
            let original = if is_index {
                &release.index
            } else {
                &release.children[0]
            };
            let mut annotations = original
                .pointer(pointer)
                .cloned()
                .unwrap_or_else(|| json!({}));
            annotations["example.org/duplicate"] = json!("last");
            let encoded = serde_json::to_string(&annotations).unwrap();
            let raw = encoded.replacen(
                r#""example.org/duplicate":"last""#,
                &format!(r#""example.org/duplicate":{first},"example.org/duplicate":"last""#),
                1,
            );
            let bytes = wire_field(original, pointer, &raw);
            let error = if is_index {
                raw_index(&bytes).map(|_| ())
            } else {
                release.raw_child(&bytes).map(|_| ())
            }
            .expect_err(&format!("accepted duplicate at {pointer}"));
            let diagnosis = if first == "123" {
                "string"
            } else {
                "duplicate"
            };
            assert!(error.to_string().contains(diagnosis), "{pointer}: {error}");
        }
    }
    let raw = String::from_utf8(encode(&release.index)).unwrap().replacen(
        r#""dev.safeyolo.guest.compatibility":"v1""#,
        r#""dev.safeyolo.guest.compatibility":"v2","dev.safeyolo.guest.compatibility":"v1""#,
        1,
    );
    assert!(raw_index(raw.as_bytes()).is_err());
    let escaped = wire_field(
        &release.index,
        "/manifests/0/annotations",
        r#"{"example.org/a":"first","example.org/\u0061":"last"}"#,
    );
    assert!(
        raw_index(&escaped)
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );
}

#[test]
fn rejects_private_token_objects_in_raw_required_scalar_fields() {
    let release = Release::new();
    let index_fields = [
        "/schemaVersion",
        "/mediaType",
        "/artifactType",
        "/annotations/org.opencontainers.image.version",
        "/annotations/org.opencontainers.image.source",
        "/annotations/org.opencontainers.image.revision",
        "/annotations/dev.safeyolo.guest.compatibility",
        "/annotations/example.org~1extra",
        "/manifests/0/mediaType",
        "/manifests/0/digest",
        "/manifests/0/size",
        "/manifests/0/platform/os",
        "/manifests/0/platform/architecture",
    ];
    let child_fields = [
        "/schemaVersion",
        "/mediaType",
        "/artifactType",
        "/annotations/org.opencontainers.image.version",
        "/annotations/org.opencontainers.image.source",
        "/annotations/org.opencontainers.image.revision",
        "/annotations/dev.safeyolo.guest.compatibility",
        "/annotations/dev.safeyolo.guest.build-base",
        "/annotations/example.org~1extra",
        "/config/mediaType",
        "/config/digest",
        "/config/size",
        "/layers/0/mediaType",
        "/layers/0/digest",
        "/layers/0/size",
    ];
    for token in [
        "$serde_json::private::Number",
        "$serde_json::private::RawValue",
    ] {
        for (is_index, fields) in [
            (true, index_fields.as_slice()),
            (false, child_fields.as_slice()),
        ] {
            let original = if is_index {
                &release.index
            } else {
                &release.children[0]
            };
            for pointer in fields {
                let scalar = original.pointer(pointer).unwrap();
                let payload = if token.ends_with("Number") {
                    scalar
                        .as_str()
                        .map_or_else(|| serde_json::to_string(scalar).unwrap(), str::to_owned)
                } else {
                    serde_json::to_string(scalar).unwrap()
                };
                let raw = format!(
                    "{{{}:{}}}",
                    serde_json::to_string(token).unwrap(),
                    serde_json::to_string(&payload).unwrap()
                );
                let bytes = wire_field(original, pointer, &raw);
                let result = if is_index {
                    raw_index(&bytes).map(|_| ())
                } else {
                    release.raw_child(&bytes).map(|_| ())
                };
                assert!(result.is_err(), "accepted {token} object at {pointer}");
            }
        }
        for pointer in ["/os", "/architecture"] {
            let mut release = Release::new();
            let config: Value = serde_json::from_slice(&release.configs[0]).unwrap();
            let scalar = config.pointer(pointer).unwrap();
            let payload = if token.ends_with("Number") {
                scalar.as_str().unwrap().to_owned()
            } else {
                serde_json::to_string(scalar).unwrap()
            };
            let raw = format!(
                "{{{}:{}}}",
                serde_json::to_string(token).unwrap(),
                serde_json::to_string(&payload).unwrap()
            );
            let config_bytes = wire_field(&config, pointer, &raw);
            release.children[0]["config"] = descriptor(CONFIG_MEDIA_TYPE, &config_bytes);
            release.refresh_children();
            assert!(
                release
                    .selected_child()
                    .unwrap()
                    .validate_config(&config_bytes)
                    .is_err(),
                "accepted {token} object at config {pointer}"
            );
        }
        for (is_index, pointer) in [
            (true, "/manifests/0/annotations"),
            (false, "/config/annotations"),
            (false, "/layers/0/annotations"),
        ] {
            let original = if is_index {
                &release.index
            } else {
                &release.children[0]
            };
            let payload = if token.ends_with("Number") {
                "2"
            } else {
                r#""value""#
            };
            let raw = format!(
                r#"{{"example.org/value":{{{}:{}}}}}"#,
                serde_json::to_string(token).unwrap(),
                serde_json::to_string(payload).unwrap()
            );
            let bytes = wire_field(original, pointer, &raw);
            let result = if is_index {
                raw_index(&bytes).map(|_| ())
            } else {
                release.raw_child(&bytes).map(|_| ())
            };
            assert!(
                result.is_err(),
                "accepted {token} annotation object at {pointer}"
            );
        }
    }
}

#[test]
fn keeps_unknown_string_annotations_and_unconsumed_object_fields() {
    let mut release = Release::new();
    for object in [&mut release.index, &mut release.children[0]] {
        object["annotations"]["$serde_json::private::Number"] = json!("123");
        object["annotations"]["$serde_json::private::RawValue"] = json!(r#""v1""#);
        object["annotations"]["例/キー"] = json!("été 💫");
        object["annotations"]["example.org/empty"] = json!("");
        object["example.org/extension"] = json!({"$serde_json::private::Number": "2"});
    }
    release.refresh_children();
    let index = release.parse().unwrap();
    let child = index
        .validate_child(ConsumerPlatform::DarwinArm64, &encode(&release.children[0]))
        .unwrap();
    child.validate_config(&release.configs[0]).unwrap();
    for key in [
        "$serde_json::private::Number",
        "$serde_json::private::RawValue",
    ] {
        for (is_index, pointer) in [
            (true, "/manifests/0/annotations"),
            (false, "/config/annotations"),
            (false, "/layers/0/annotations"),
        ] {
            let original = if is_index {
                &release.index
            } else {
                &release.children[0]
            };
            let raw = serde_json::to_string(&json!({key: "123"})).unwrap();
            let bytes = wire_field(original, pointer, &raw);
            if is_index {
                raw_index(&bytes).unwrap();
            } else {
                release.raw_child(&bytes).unwrap();
            }
        }
    }
}

#[test]
fn complete_release_explicitly_selects_all_platforms_and_verifies_content() {
    let release = Release::new();
    let index = release.parse().unwrap();
    assert_eq!(index.annotations.version, "guest-2026-10-12.1");
    let bytes = release.children.each_ref().map(encode);
    let children = index
        .validate_children(bytes.each_ref().map(Vec::as_slice))
        .unwrap();
    for (i, child) in children.iter().enumerate() {
        assert_eq!(child.platform, ConsumerPlatform::ALL[i]);
        child.validate_config(&release.configs[i]).unwrap();
        child
            .archive
            .verify(release.archives[i].as_slice())
            .unwrap();
        assert_eq!(
            index.manifest(child.platform).unwrap().digest,
            digest(&bytes[i])
        );
    }
    assert_ne!(children[0].archive.digest, children[2].archive.digest);
}

#[test]
fn custom_profile_validates_only_its_declared_consumers() {
    let mut release = Release::new();
    release.index["annotations"][PROFILE] = json!("kali-pentest");
    for child in &mut release.children {
        child["annotations"][PROFILE] = json!("kali-pentest");
        child["annotations"][BUILD_INPUTS] = json!(digest(b"declared build inputs"));
    }
    release.refresh_children();
    release.index["manifests"] = json!([release.index["manifests"][1]]);
    let index = release.parse().unwrap();
    assert_eq!(
        index.platforms().collect::<Vec<_>>(),
        vec![ConsumerPlatform::LinuxAmd64]
    );
    assert!(index.manifest(ConsumerPlatform::DarwinArm64).is_err());
    let child_bytes = encode(&release.children[1]);
    let children = index.validate_children([child_bytes.as_slice()]).unwrap();
    assert_eq!(
        children[0].build_inputs.as_deref(),
        Some(digest(b"declared build inputs").as_str())
    );
    children[0]
        .archive
        .verify(release.archives[1].as_slice())
        .unwrap();

    release.index["annotations"]
        .as_object_mut()
        .unwrap()
        .remove(PROFILE);
    assert!(
        release.parse().is_err(),
        "default releases still need every consumer"
    );
}

#[test]
fn custom_profile_requires_matching_identity_and_declared_input_digest() {
    let mut release = Release::new();
    release.index["annotations"][PROFILE] = json!("kali-pentest");
    assert!(release.selected_child().is_err());
    release.children[0]["annotations"][PROFILE] = json!("kali-pentest");
    release.refresh_children();
    assert!(release.selected_child().is_err());
    release.children[0]["annotations"][BUILD_INPUTS] = json!("unverified");
    release.refresh_children();
    assert!(release.selected_child().is_err());
    release.children[0]["annotations"][BUILD_INPUTS] = json!(digest(b"inputs"));
    release.refresh_children();
    release.selected_child().unwrap();
    release.index["manifests"] = json!([]);
    assert!(release.parse().is_err());
}

#[test]
fn validates_actual_oras_1_3_4_layout_with_inferred_consumer_platforms() {
    // ORAS 1.3.4 push --image-spec v1.1 --config ... and manifest index create
    // produced this tiny synthetic layout. It is wire data, not installed proof.
    let layout = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/guest-oci");
    let read = |digest: &str| {
        std::fs::read(
            layout
                .join("blobs/sha256")
                .join(sha256_hex(digest).unwrap()),
        )
        .unwrap()
    };
    let catalogue: Value =
        serde_json::from_slice(&std::fs::read(layout.join("index.json")).unwrap()).unwrap();
    let release = catalogue["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| {
            entry["annotations"]["org.opencontainers.image.ref.name"] == "guest-2026-10-12.1"
        })
        .unwrap();
    let descriptor = Descriptor::parse(
        &serde_json::from_slice(&encode(release)).unwrap(),
        INDEX_MEDIA_TYPE,
    )
    .unwrap();
    let bytes = read(&descriptor.digest);
    descriptor.verify(bytes.as_slice()).unwrap();
    let index = GuestIndex::parse(&bytes, &descriptor.digest, "v1").unwrap();
    let manifests =
        ConsumerPlatform::ALL.map(|platform| read(&index.manifest(platform).unwrap().digest));
    let children = index
        .validate_children(manifests.each_ref().map(Vec::as_slice))
        .unwrap();
    for child in children {
        child.validate_config(&read(&child.config.digest)).unwrap();
        let archive = std::fs::File::open(
            layout
                .join("blobs/sha256")
                .join(sha256_hex(&child.archive.digest).unwrap()),
        )
        .unwrap();
        child.archive.verify(archive).unwrap();
    }
}

#[test]
fn rejects_missing_duplicate_and_unsupported_consumer_platforms() {
    for i in 0..3 {
        let mut release = Release::new();
        release.index["manifests"].as_array_mut().unwrap().remove(i);
        assert!(release.parse().unwrap_err().to_string().contains("missing"));
    }
    let mut release = Release::new();
    let duplicate = release.index["manifests"][0].clone();
    release.index["manifests"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(
        release
            .parse()
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );
    for platform in [
        Value::Null,
        json!([]),
        json!({"os":"linux"}),
        json!({"os":3,"architecture":"arm64"}),
        json!({"os":"windows","architecture":"arm64"}),
        json!({"os":"linux","architecture":"aarch64"}),
    ] {
        let mut release = Release::new();
        release.index["manifests"][0]["platform"] = platform;
        assert!(release.parse().is_err());
    }
}

#[test]
fn rejects_malformed_documents_descriptors_and_required_annotations() {
    for root in [
        Value::Null,
        json!(false),
        json!(12),
        json!("index"),
        json!([]),
    ] {
        let bytes = encode(&root);
        assert!(GuestIndex::parse(&bytes, &digest(&bytes), "v1").is_err());
    }
    let mutations = [
        ("/schemaVersion", json!(1)),
        ("/schemaVersion", json!(2.0)),
        ("/mediaType", json!(MANIFEST_MEDIA_TYPE)),
        ("/artifactType", Value::Null),
        ("/manifests", json!({})),
        ("/annotations", json!([])),
        (
            "/annotations/org.opencontainers.image.version",
            json!("guest-2026-02-30.1"),
        ),
        (
            "/annotations/org.opencontainers.image.version",
            json!("2026-10-12"),
        ),
        (
            "/annotations/org.opencontainers.image.source",
            json!("https://example.org"),
        ),
        (
            "/annotations/org.opencontainers.image.revision",
            json!("6e268b5"),
        ),
        ("/annotations/dev.safeyolo.guest.compatibility", json!("")),
        (
            "/annotations/dev.safeyolo.guest.compatibility",
            json!("bad tag"),
        ),
        ("/annotations/example.org~1extra", json!(123)),
        ("/manifests/0/mediaType", json!(INDEX_MEDIA_TYPE)),
        ("/manifests/0/digest", json!("sha256:abc")),
        (
            "/manifests/0/digest",
            json!(format!("sha256:{}", "A".repeat(64))),
        ),
        (
            "/manifests/0/digest",
            json!(format!("sha512:{}", "a".repeat(128))),
        ),
        ("/manifests/0/size", json!(-1)),
        ("/manifests/0/size", json!(1.5)),
        ("/manifests/0/size", json!(u64::MAX)),
        ("/manifests/0/size", json!("200")),
    ];
    for (pointer, value) in mutations {
        let mut release = Release::new();
        *release.index.pointer_mut(pointer).unwrap() = value;
        assert!(release.parse().is_err(), "accepted mutation of {pointer}");
    }
    for key in [VERSION, SOURCE_ANNOTATION, REVISION, COMPATIBILITY] {
        for value in [Value::Null, json!({}), json!(12)] {
            let mut release = Release::new();
            release.index["annotations"][key] = value;
            assert!(release.parse().is_err(), "accepted {key}");
        }
        let mut release = Release::new();
        release.index["annotations"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(release.parse().is_err());
    }
}

#[test]
fn compatibility_is_checked_against_host_and_raw_index_identity_is_checked() {
    let release = Release::new();
    let bytes = encode(&release.index);
    assert!(
        GuestIndex::parse(&bytes, &digest(&bytes), "v2")
            .unwrap_err()
            .to_string()
            .contains("compatibility")
    );
    assert!(GuestIndex::parse(&bytes, &digest(b"other index"), "v1").is_err());
    assert!(GuestIndex::parse(b"{broken", &digest(b"{broken"), "v1").is_err());
}

#[test]
fn rejects_child_mismatch_and_wrong_layer_config_or_build_input() {
    let mutations = [
        ("/schemaVersion", json!(3)),
        ("/mediaType", json!(INDEX_MEDIA_TYPE)),
        ("/artifactType", json!("application/vnd.other")),
        (
            "/annotations/org.opencontainers.image.version",
            json!("guest-2026-10-13.2"),
        ),
        (
            "/annotations/org.opencontainers.image.revision",
            json!("a".repeat(40)),
        ),
        ("/annotations/dev.safeyolo.guest.compatibility", json!("v2")),
        (
            "/annotations/dev.safeyolo.guest.build-base",
            json!("debian:trixie"),
        ),
        (
            "/annotations/dev.safeyolo.guest.build-base",
            json!(format!("debian@{}", digest(b"base"))),
        ),
        (
            "/annotations/dev.safeyolo.guest.build-base",
            json!("docker.io/library/debian@sha256:bad"),
        ),
        ("/layers", json!([])),
        ("/layers", json!([{}, {}])),
        ("/layers", json!({})),
        (
            "/layers/0/mediaType",
            json!("application/vnd.oci.image.layer.v1.tar+gzip"),
        ),
        ("/layers/0/digest", json!(false)),
        ("/layers/0/size", Value::Null),
        (
            "/config/mediaType",
            json!("application/vnd.oci.image.config.v1+json"),
        ),
        ("/config/size", json!(-1)),
        ("/config/digest", json!("")),
    ];
    for (pointer, value) in mutations {
        let mut release = Release::new();
        *release.children[0].pointer_mut(pointer).unwrap() = value;
        release.refresh_children();
        assert!(
            release.selected_child().is_err(),
            "accepted mutation of {pointer}"
        );
    }
    for value in [Value::Null, json!(1), json!([]), json!({})] {
        let mut release = Release::new();
        release.children[0] = value;
        release.refresh_children();
        assert!(release.selected_child().is_err());
    }
    for name in [
        "docker.io//debian",
        "docker.io/../debian",
        "docker.io/UPPER",
        "docker.io/debian:",
        "bad host/debian",
        "docker.io/debian\0",
    ] {
        let mut release = Release::new();
        release.children[0]["annotations"][BUILD_BASE] =
            json!(format!("{name}@{}", digest(b"base")));
        release.refresh_children();
        assert!(
            release.selected_child().is_err(),
            "accepted build input {name}"
        );
    }
}

#[test]
fn child_and_config_checks_bind_raw_hash_size_and_consumer_platform() {
    let mut release = Release::new();
    release.index["manifests"][0]["size"] = json!(encode(&release.children[0]).len() + 1);
    assert!(
        release
            .selected_child()
            .unwrap_err()
            .to_string()
            .contains("size mismatch")
    );
    let release = Release::new();
    let index = release.parse().unwrap();
    let mut altered = encode(&release.children[0]);
    let last = altered.len() - 1;
    altered[last] = b' ';
    assert!(
        index
            .validate_child(ConsumerPlatform::DarwinArm64, &altered)
            .unwrap_err()
            .to_string()
            .contains("SHA-256")
    );
    for config in [
        Value::Null,
        json!([]),
        json!({"os":"linux","architecture":"arm64"}),
        json!({"os":"darwin","architecture":"arm64","extra":true}),
        json!({"os":"darwin","architecture":3}),
    ] {
        let mut release = Release::new();
        release.configs[0] = encode(&config);
        release.children[0]["config"] = descriptor(CONFIG_MEDIA_TYPE, &release.configs[0]);
        release.refresh_children();
        assert!(
            release
                .selected_child()
                .unwrap()
                .validate_config(&release.configs[0])
                .is_err()
        );
    }
    let child = release.selected_child().unwrap();
    assert!(child.validate_config(&release.configs[2]).is_err());
}

#[test]
fn publisher_rejects_identical_mac_and_linux_arm_archives() {
    let mut release = Release::new();
    release.children[2]["layers"] = release.children[0]["layers"].clone();
    release.refresh_children();
    let index = release.parse().unwrap();
    let bytes = release.children.each_ref().map(encode);
    assert!(
        index
            .validate_children(bytes.each_ref().map(Vec::as_slice))
            .unwrap_err()
            .to_string()
            .contains("distinct")
    );
}

#[test]
fn streaming_verification_rejects_partial_long_corrupt_and_failed_reads() {
    let bytes = b"verified opaque content";
    let desc = Descriptor {
        digest: digest(bytes),
        size: bytes.len() as u64,
    };
    desc.verify(bytes.as_slice()).unwrap();
    for content in [
        bytes[..3].to_vec(),
        [bytes.as_slice(), b"extra"].concat(),
        vec![b'x'; bytes.len()],
    ] {
        assert!(desc.verify(content.as_slice()).is_err());
    }
    struct Failed;
    impl Read for Failed {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("staged read failed"))
        }
    }
    assert!(
        desc.verify(Failed)
            .unwrap_err()
            .to_string()
            .contains("staged read failed")
    );
    struct SmallReads<'a>(&'a [u8]);
    impl Read for SmallReads<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = self.0.len().min(3).min(buffer.len());
            buffer[..count].copy_from_slice(&self.0[..count]);
            self.0 = &self.0[count..];
            Ok(count)
        }
    }
    desc.verify(SmallReads(bytes)).unwrap();
    struct InterruptedOnce<'a> {
        interrupted: bool,
        content: &'a [u8],
    }
    impl Read for InterruptedOnce<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.content.read(buffer)
        }
    }
    desc.verify(InterruptedOnce {
        interrupted: false,
        content: bytes,
    })
    .unwrap();
}
