use super::*;
use serde_json::json;

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
        assert_eq!(index.manifest(child.platform).digest, digest(&bytes[i]));
    }
    assert_ne!(children[0].archive.digest, children[2].archive.digest);
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
    let descriptor = Descriptor::parse(release, INDEX_MEDIA_TYPE).unwrap();
    let bytes = read(&descriptor.digest);
    descriptor.verify(bytes.as_slice()).unwrap();
    let index = GuestIndex::parse(&bytes, &descriptor.digest, "v1").unwrap();
    let manifests = ConsumerPlatform::ALL.map(|platform| read(&index.manifest(platform).digest));
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
