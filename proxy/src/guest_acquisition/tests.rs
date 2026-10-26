use super::*;

#[tokio::test]
async fn download_decoder_preserves_concatenated_frames_and_checks_the_last_frame() {
    use std::io::{Read, Write};

    let plain = vec![b'x'; 3 * 1024 * 1024 + 7];
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).unwrap();
    encoder.include_checksum(true).unwrap();
    encoder.write_all(&plain).unwrap();
    let frame = encoder.finish().unwrap();
    for fault in ["none", "truncated", "checksum"] {
        let mut compressed = [frame.as_slice(), frame.as_slice()].concat();
        if fault == "truncated" {
            compressed.pop();
        } else if fault == "checksum" {
            *compressed.last_mut().unwrap() ^= 1;
        }
        let mut decoder = archive::DownloadDecoder::new(tempfile::tempfile().unwrap()).unwrap();
        let mut written = Ok(());
        for chunk in compressed.chunks(7) {
            written = decoder.write(bytes::Bytes::copy_from_slice(chunk)).await;
            if written.is_err() {
                break;
            }
        }
        let result = match written {
            Ok(()) => decoder.finish().await,
            Err(error) => Err(error),
        };
        if fault == "none" {
            let mut actual = Vec::new();
            result.unwrap().read_to_end(&mut actual).unwrap();
            assert_eq!(actual, [plain.as_slice(), plain.as_slice()].concat());
        } else {
            assert!(result.is_err(), "accepted {fault} frame");
        }
    }
}

#[tokio::test]
async fn download_decoder_reports_buffered_and_full_write_failures() {
    // A read-only output accepts buffered bytes but must fail before returning
    // a decoded file, including when the final buffer is the only output.
    for size in [7, 2 * 1024 * 1024 + 7] {
        let plain = vec![b'x'; size];
        let compressed = zstd::stream::encode_all(plain.as_slice(), 1).unwrap();
        let output = tempfile::NamedTempFile::new().unwrap();
        let mut decoder =
            archive::DownloadDecoder::new(fs::File::open(output.path()).unwrap()).unwrap();
        let result = match decoder.write(compressed.into()).await {
            Ok(()) => decoder.finish().await,
            Err(error) => Err(error),
        };
        assert!(result.is_err(), "lost output failure for {size} bytes");
    }
}

#[tokio::test]
async fn download_decoder_overlaps_output_with_bounded_input_and_cancels_pending_finish() {
    use std::{io::Read, os::fd::FromRawFd};

    // A real pipe holds output back independently of decoding or network speed.
    // Its capacity is smaller than one decoded output batch.
    let mut descriptors = [-1; 2];
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    let mut reader = unsafe { fs::File::from_raw_fd(descriptors[0]) };
    let output = unsafe { fs::File::from_raw_fd(descriptors[1]) };
    let plain = vec![b'x'; 3 * 1024 * 1024];
    let chunk = bytes::Bytes::from(zstd::stream::encode_all(plain.as_slice(), 1).unwrap());
    let mut decoder = archive::DownloadDecoder::new(output).unwrap();
    tokio::time::timeout(Duration::from_secs(5), decoder.write(chunk.clone()))
        .await
        .expect("input waited for blocked output")
        .unwrap();
    // Wait for the worker to reach the blocked file write.
    let mut reader = tokio::task::spawn_blocking(move || {
        reader.read_exact(&mut [0]).unwrap();
        reader
    })
    .await
    .unwrap();
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(5), decoder.write(chunk.clone()))
            .await
            .expect("queued input waited for blocked output")
            .unwrap();
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), decoder.write(chunk))
            .await
            .is_err(),
        "blocked decoder accepted unbounded queued input"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), decoder.finish())
            .await
            .is_err(),
        "decoder finished while output was blocked"
    );
    // Closing the download discards queued work. Once the current write can
    // finish, the worker must close its file without another input or EOF marker.
    let drained = tokio::task::spawn_blocking(move || reader.read_to_end(&mut Vec::new()).unwrap());
    let remaining = tokio::time::timeout(Duration::from_secs(5), drained)
        .await
        .expect("decoder retained its output after cancellation")
        .unwrap();
    assert!(
        remaining + 1 < plain.len(),
        "decoder kept decoding after cancellation"
    );
}

#[test]
fn package_guest_uses_the_existing_strict_fields() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("package-info");
    let (os, architecture) = consumer_platform().unwrap().os_architecture();
    let original = format!(
        "source_commit={}\nprofile=debug\nplatform={os}-{architecture}\nminimum_runtime=2.34\nguest_compatibility=v1\nguest_repository={}\nguest_discovery_tag=compat-v1\n",
        "a".repeat(40),
        guest_oci::REPOSITORY
    );
    fs::write(&path, &original).unwrap();
    assert!(PackageGuest::read(&path).is_ok());
    for libc in ["glibc", "musl"] {
        fs::write(&path, format!("{original}libc={libc}\n")).unwrap();
        let expected = libc != "musl" || os == "linux";
        assert_eq!(PackageGuest::read(&path).is_ok(), expected);
    }
    for bad in [
        original.replace("compat-v1", "compat-v2"),
        original.replace(guest_oci::REPOSITORY, "example.test/guest"),
        original.replace("guest_compatibility=v1", "guest_compatibility=../v1"),
        format!("{original}guest_compatibility=v1\n"),
        format!("{original}unknown=field\n"),
        original.replace("guest_discovery_tag=compat-v1\n", ""),
        format!("{original}libc=unknown\n"),
        format!("{original}libc=musl\nlibc=glibc\n"),
    ] {
        fs::write(&path, bad).unwrap();
        assert!(PackageGuest::read(&path).is_err());
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use serde_json::{Value, json};
    use std::{
        io::{Read, Seek, Write},
        net::{TcpListener, TcpStream},
        os::unix::fs::{MetadataExt, symlink},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread,
    };

    fn digest(bytes: &[u8]) -> String {
        format!(
            "sha256:{}",
            ring::digest::digest(&ring::digest::SHA256, bytes)
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }

    fn descriptor(bytes: &[u8], media_type: &str) -> Value {
        json!({"mediaType": media_type, "digest": digest(bytes), "size": bytes.len()})
    }

    fn annotations() -> Value {
        json!({
            guest_oci::VERSION: "guest-2026-10-12.1",
            guest_oci::SOURCE_ANNOTATION: guest_oci::SOURCE,
            guest_oci::REVISION: "a".repeat(40),
            guest_oci::COMPATIBILITY: "v1",
        })
    }

    struct Release {
        index: Vec<u8>,
        contents: BTreeMap<String, Vec<u8>>,
        archive: Descriptor,
    }

    fn release(archive: Vec<u8>) -> Release {
        let mut contents = BTreeMap::new();
        contents.insert(format!("blobs/{}", digest(&archive)), archive.clone());
        let mut manifests = Vec::new();
        for platform in ConsumerPlatform::ALL {
            let (os, architecture) = platform.os_architecture();
            let config =
                serde_json::to_vec(&json!({"os": os, "architecture": architecture})).unwrap();
            contents.insert(format!("blobs/{}", digest(&config)), config.clone());
            let mut annotations = annotations();
            annotations[guest_oci::BUILD_BASE] = json!(format!(
                "docker.io/library/debian@sha256:{}",
                "b".repeat(64)
            ));
            let child = serde_json::to_vec(
                &json!({"schemaVersion": 2, "mediaType": guest_oci::MANIFEST_MEDIA_TYPE,
            "artifactType": guest_oci::ARTIFACT_TYPE, "annotations": annotations,
            "config": descriptor(&config, guest_oci::CONFIG_MEDIA_TYPE),
            "layers": [descriptor(&archive, guest_oci::ARCHIVE_MEDIA_TYPE)]}),
            )
            .unwrap();
            contents.insert(format!("manifests/{}", digest(&child)), child.clone());
            let mut entry = descriptor(&child, guest_oci::MANIFEST_MEDIA_TYPE);
            entry["platform"] = json!({"os": os, "architecture": architecture});
            manifests.push(entry);
        }
        let index = serde_json::to_vec(&json!({"schemaVersion": 2, "mediaType": guest_oci::INDEX_MEDIA_TYPE,
        "artifactType": guest_oci::ARTIFACT_TYPE, "annotations": annotations(), "manifests": manifests})).unwrap();
        Release {
            index,
            contents,
            archive: Descriptor {
                digest: digest(&archive),
                size: archive.len() as u64,
            },
        }
    }

    struct Registry {
        address: String,
        contents: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        requests: Arc<Mutex<Vec<String>>>,
        truncated: Arc<Mutex<Option<String>>>,
        stopped: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl Registry {
        fn new(release: &Release) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let mut data = release.contents.clone();
            data.insert("manifests/compat-v1".into(), release.index.clone());
            let contents = Arc::new(Mutex::new(data));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let truncated: Arc<Mutex<Option<String>>> = Arc::default();
            let stopped = Arc::new(AtomicBool::new(false));
            let (data, seen, partial, stop) = (
                contents.clone(),
                requests.clone(),
                truncated.clone(),
                stopped.clone(),
            );
            let worker = thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut stream = stream.unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        if stream.read(&mut byte).unwrap() == 0 {
                            break;
                        }
                        header.push(byte[0]);
                        assert!(header.len() < 16384);
                    }
                    let header = String::from_utf8(header).unwrap();
                    // Anonymous acquisition never reads user registry credentials.
                    assert!(!header.to_ascii_lowercase().contains("authorization: basic"));
                    let path = header.split_whitespace().nth(1).unwrap_or_default();
                    seen.lock().unwrap().push(path.into());
                    let key = path.strip_prefix("/v2/guest/").unwrap_or(path);
                    let body = data.lock().unwrap().get(key).cloned();
                    let body = if path == "/v2/" {
                        Some(Vec::new())
                    } else {
                        body
                    };
                    if let Some(body) = body {
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nDocker-Content-Digest: {}\r\nConnection: close\r\n\r\n",
                            body.len(),
                            digest(&body)
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let body = if partial.lock().unwrap().as_deref() == Some(key) {
                            &body[..body.len() / 2]
                        } else {
                            &body
                        };
                        let _ = stream.write_all(body);
                    } else {
                        let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    }
                }
            });
            Self {
                address,
                contents,
                requests,
                truncated,
                stopped,
                worker: Some(worker),
            }
        }

        fn package(&self) -> PackageGuest {
            PackageGuest {
                compatibility: "v1".into(),
                discovery_tag: "compat-v1".into(),
                repository: format!("{}/guest", self.address),
                platform: consumer_platform().unwrap(),
                runsc_version: None,
            }
        }

        fn client(&self) -> Client {
            let _ = rustls::crypto::ring::default_provider().install_default();
            Client::try_from(ClientConfig {
                protocol: oci_client::client::ClientProtocol::Http,
                http_proxy: None,
                platform_resolver: None,
                ..Default::default()
            })
            .unwrap()
        }
    }

    impl Drop for Registry {
        fn drop(&mut self) {
            self.stopped.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(&self.address);
            self.worker.take().unwrap().join().unwrap();
        }
    }

    fn linux_archive(directory: &Path) -> Vec<u8> {
        let source = directory.join("source");
        fs::create_dir_all(source.join("rootfs-tree/usr/bin")).unwrap();
        fs::write(source.join("rootfs-tree/usr/bin/fixture"), "guest bytes").unwrap();
        fs::write(source.join("rootfs-tree/usr/bin/guest-user"), "user bytes").unwrap();
        fs::hard_link(
            source.join("rootfs-tree/usr/bin/fixture"),
            source.join("rootfs-tree/usr/bin/hardlink"),
        )
        .unwrap();
        symlink("usr/bin", source.join("rootfs-tree/bin")).unwrap();
        fs::write(source.join("cache-paths.txt"), "/var/cache/apt\n").unwrap();
        assert!(
            std::process::Command::new("sudo")
                .args(["-n", "chown", "-R", "100000:100000"])
                .arg(source.join("rootfs-tree"))
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("sudo")
                .args(["-n", "chown", "101000:101000"])
                .arg(source.join("rootfs-tree/usr/bin/guest-user"))
                .status()
                .unwrap()
                .success()
        );
        let tar = std::process::Command::new("sudo")
            .args(["-n", "tar", "--format=pax", "--numeric-owner", "-C"])
            .arg(&source)
            .args(["-cf", "-", "rootfs-tree", "cache-paths.txt"])
            .output()
            .unwrap();
        assert!(tar.status.success());
        assert!(
            std::process::Command::new("sudo")
                .args(["-n", "rm", "-rf", "--"])
                .arg(source)
                .status()
                .unwrap()
                .success()
        );
        zstd::stream::encode_all(tar.stdout.as_slice(), 1).unwrap()
    }

    #[tokio::test]
    async fn acquisition_installs_backend_inputs_and_reuses_selected_digests() {
        assert_ne!(
            unsafe { libc::getuid() },
            0,
            "run acquisition as the ordinary host account"
        );
        for (uid_base, gid_base) in [(100000, 100000), (231072, 400000)] {
            let temp = tempfile::tempdir().unwrap();
            let release = release(linux_archive(temp.path()));
            let registry = Registry::new(&release);
            let package = registry.package();
            let store = temp.path().join("store");
            let selection = acquire(
                &registry.client(),
                &package,
                &store,
                None,
                None,
                crate::linux_host::Mapping::for_bases(uid_base, gid_base),
            )
            .await
            .unwrap();
            assert_eq!(selection.archive, release.archive);
            let tree = selection.assets.join("rootfs-tree");
            assert_eq!(tree.metadata().unwrap().uid(), uid_base);
            assert_eq!(tree.metadata().unwrap().gid(), gid_base);
            let guest_user = tree.join("usr/bin/guest-user").metadata().unwrap();
            assert_eq!(guest_user.uid(), unsafe { libc::getuid() });
            assert_eq!(guest_user.gid(), unsafe { libc::getgid() });
            assert_eq!(
                tree.join("usr/bin/fixture").metadata().unwrap().ino(),
                tree.join("usr/bin/hardlink").metadata().unwrap().ino()
            );
            assert_eq!(
                fs::read_link(tree.join("bin")).unwrap(),
                Path::new("usr/bin")
            );
            assert_eq!(
                fs::read_to_string(selection.assets.join("cache-paths.txt")).unwrap(),
                "/var/cache/apt\n"
            );
            let tree_identity = selection.assets.metadata().unwrap().ino();
            let requests = registry.requests.lock().unwrap().len();
            let again = acquire(
                &registry.client(),
                &package,
                &store,
                None,
                None,
                crate::linux_host::Mapping::for_bases(uid_base, gid_base),
            )
            .await
            .unwrap();
            assert_eq!(again.assets.metadata().unwrap().ino(), tree_identity);
            let seen = registry.requests.lock().unwrap();
            assert!(
                seen[requests..]
                    .iter()
                    .all(|path| !path.contains("/blobs/"))
            );
            assert_eq!(
                seen.iter()
                    .filter(|path| *path == "/v2/guest/manifests/compat-v1")
                    .count(),
                2
            );
            drop(seen);
            archive::remove_stage(&store, package.platform).unwrap();
        }
    }

    #[tokio::test]
    async fn partial_and_corrupt_pulls_do_not_publish_blobs_or_trees() {
        let temp = tempfile::tempdir().unwrap();
        let release = release(linux_archive(temp.path()));
        let registry = Registry::new(&release);
        let key = format!("blobs/{}", release.archive.digest);
        *registry.truncated.lock().unwrap() = Some(key.clone());
        let store = temp.path().join("store");
        assert!(
            acquire(
                &registry.client(),
                &registry.package(),
                &store,
                None,
                None,
                crate::linux_host::Mapping::for_bases(100000, 100000)
            )
            .await
            .is_err()
        );
        let blobs = store.join("blobs/sha256");
        assert!(
            !blobs
                .join(guest_oci::sha256_hex(&release.archive.digest).unwrap())
                .exists()
        );
        assert!(
            fs::read_dir(&blobs).unwrap().all(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .len()
                == 64)
        );
        assert_eq!(fs::read_dir(store.join("trees/sha256")).unwrap().count(), 0);
        *registry.truncated.lock().unwrap() = None;
        registry.contents.lock().unwrap().get_mut(&key).unwrap()[0] ^= 1;
        assert!(
            acquire(
                &registry.client(),
                &registry.package(),
                &store,
                None,
                None,
                crate::linux_host::Mapping::for_bases(100000, 100000)
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read_dir(store.join("trees/sha256")).unwrap().count(), 0);
    }

    #[test]
    fn darwin_layout_decodes_images_and_rejects_links_and_truncated_frames() {
        // Linux GNU tar exercises the archive/layout branch; this is not an APFS witness.
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("Image"), "kernel fixture").unwrap();
        let initramfs: Vec<u8> = (0..384 * 1024 + 7).map(|n| (n % 251) as u8).collect();
        fs::write(source.join("initramfs.cpio.gz"), &initramfs).unwrap();
        let mut image = fs::File::create(source.join("rootfs-base.ext4")).unwrap();
        image.seek(std::io::SeekFrom::Start(1024 * 1024)).unwrap();
        image.write_all(b"end").unwrap();
        for fault in ["none", "truncated", "link"] {
            if fault == "link" {
                fs::remove_file(source.join("Image")).unwrap();
                symlink("rootfs-base.ext4", source.join("Image")).unwrap();
            }
            let tar = std::process::Command::new("tar")
                .args(["--format=pax", "--sparse", "-C"])
                .arg(&source)
                .args(["-cf", "-", "Image", "initramfs.cpio.gz", "rootfs-base.ext4"])
                .output()
                .unwrap();
            assert!(tar.status.success());
            let input = temp.path().join("archive.zst");
            let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).unwrap();
            encoder.include_checksum(true).unwrap();
            encoder.write_all(&tar.stdout).unwrap();
            let mut encoded = encoder.finish().unwrap();
            if fault == "truncated" {
                // Tar has all its bytes; the decoder must still check the frame end.
                encoded.pop();
            }
            fs::write(&input, encoded).unwrap();
            let destination = temp.path().join(format!("prepared-{fault}"));
            let result = archive::prepare(
                &input,
                None,
                &destination,
                ConsumerPlatform::DarwinArm64,
                crate::linux_host::Mapping::for_bases(100000, 100000),
                None,
            );
            if fault != "none" {
                assert!(result.is_err());
                assert!(!destination.exists());
            } else {
                result.unwrap();
                assert_eq!(
                    fs::read_to_string(destination.join("Image")).unwrap(),
                    "kernel fixture"
                );
                assert_eq!(
                    fs::read(destination.join("initramfs.cpio.gz")).unwrap(),
                    initramfs
                );
                assert_eq!(
                    destination
                        .join("rootfs-base.ext4")
                        .metadata()
                        .unwrap()
                        .len(),
                    1024 * 1024 + 3
                );
            }
            assert!(fs::read_dir(temp.path()).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b"extract-")
            }));
        }
    }
}
