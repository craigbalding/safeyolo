//! Ephemeral instance isolation and owned cleanup through the installed CLI.

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use serde_json::Value;
use tempfile::TempDir;

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .env(safeyolo_proxy::host_root::ENVIRONMENT, "1")
        .arg("--instance-dir")
        .arg(root)
        .arg("--json")
        .args(args)
        .output()
        .unwrap()
}

fn success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

struct Fixture {
    directory: TempDir,
    peer: Child,
    runtime: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("instance-proof-")
            .tempdir_in(
                std::env::var_os("SAFEYOLO_TEST_TMPDIR").unwrap_or_else(|| "/var/tmp".into()),
            )
            .unwrap();
        let root = directory.path();
        success(cli(root, &["init"]));
        let config = root.join("config.toml");
        fs::write(
            &config,
            fs::read_to_string(&config)
                .unwrap()
                .replace("admin_port = 9090", "admin_port = 0"),
        )
        .unwrap();
        let runtime = root.join("runtime");
        fs::create_dir_all(runtime.join("bin")).unwrap();
        for (name, source) in [
            ("safeyolo", env!("CARGO_BIN_EXE_safeyolo")),
            ("safeyolo-proxy", env!("CARGO_BIN_EXE_safeyolo-proxy")),
            ("safeyolo-coord", env!("CARGO_BIN_EXE_safeyolo-coord")),
        ] {
            symlink(source, runtime.join("bin").join(name)).unwrap();
        }
        symlink(runtime.join("bin"), root.join("bin")).unwrap();
        let peer = Command::new(env!("CARGO_BIN_EXE_safeyolo-proxy"))
            .env(safeyolo_proxy::host_root::ENVIRONMENT, "1")
            .arg("--config")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut fixture = Self {
            directory,
            peer,
            runtime,
        };
        fixture.wait("data/ready.json");
        fixture.wait("data/proxy-process.json");
        fixture
    }

    fn root(&self) -> &Path {
        self.directory.path()
    }
    fn wait(&mut self, path: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !self.root().join(path).is_file() {
            assert!(
                self.peer.try_wait().unwrap().is_none(),
                "unrelated proxy exited"
            );
            assert!(Instant::now() < deadline, "timed out waiting for {path}");
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    fn run(&self, script: &str, reuse: bool) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_safeyolo"));
        command
            .arg(safeyolo_proxy::host_root::FLAG)
            .arg("--instance-dir")
            .arg(self.root())
            .args(["instance", "run", "--ephemeral", "--runtime"])
            .arg(&self.runtime);
        if reuse {
            command.arg("--reuse-guest-assets-from").arg(self.root());
        }
        command
            .args(["--", "/bin/sh", "-c", script, "instance-proof"])
            .arg(self.root());
        // Hostile inherited overrides must all be replaced for this command.
        command
            .env_remove(safeyolo_proxy::host_root::ENVIRONMENT)
            .env("SAFEYOLO_CONFIG_DIR", self.root())
            .env(
                "SAFEYOLO_NATIVE_CONFIG_PATH",
                self.root().join("config.toml"),
            )
            .env("SAFEYOLO_COORD_DATA_DIR", self.root().join("data/coord"))
            .env("SAFEYOLO_RUNSC_ROOT", self.root().join("run"))
            .env("SAFEYOLO_LOGS_DIR", self.root().join("logs"));
        command
    }
    fn ephemeral_root(&self) -> PathBuf {
        PathBuf::from(
            fs::read_to_string(self.root().join("selected-root"))
                .unwrap()
                .trim(),
        )
    }
    fn assert_peer_live(&mut self) {
        assert!(
            self.peer.try_wait().unwrap().is_none(),
            "unrelated instance was stopped"
        );
        let status: Value =
            serde_json::from_slice(&success(cli(self.root(), &["status"])).stdout).unwrap();
        assert_eq!(status["proxy_state"], "running");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.peer.kill();
        let _ = self.peer.wait();
    }
}

#[test]
fn cleanup_stops_only_the_instances_private_tmux_server() {
    for packaged in [false, true] {
        check_private_tmux_cleanup(packaged);
    }
}

fn check_private_tmux_cleanup(packaged: bool) {
    let mut fixture = Fixture::new();
    let tmux = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|path| path.join("tmux"))
        .find(|path| path.is_file())
        .expect("install the existing tmux test prerequisite");
    let entrypoint = fixture.runtime.join("bin/tmux");
    if packaged {
        fs::create_dir(fixture.runtime.join("libexec")).unwrap();
        symlink(&tmux, fixture.runtime.join("libexec/tmux")).unwrap();
        fs::write(&entrypoint, include_bytes!("../../scripts/tmux_runtime.sh")).unwrap();
        fs::set_permissions(&entrypoint, fs::Permissions::from_mode(0o755)).unwrap();
    } else {
        symlink(&tmux, &entrypoint).unwrap();
    }
    let peer_socket = fixture.root().join("data/peer-tmux.sock");
    struct OwnedTmux(PathBuf, PathBuf);
    impl Drop for OwnedTmux {
        fn drop(&mut self) {
            let _ = Command::new(&self.0)
                .arg("-S")
                .arg(&self.1)
                .arg("kill-server")
                .output();
        }
    }
    let _peer = OwnedTmux(tmux.clone(), peer_socket.clone());
    success(
        Command::new(&tmux)
            .arg("-S")
            .arg(&peer_socket)
            .args(["new-session", "-d", "-s", "peer", "sleep 60"])
            .output()
            .unwrap(),
    );
    success(
        fixture
            .run(
                r#"set -eu
printf '%s\n' "$SAFEYOLO_CONFIG_DIR" > "$1/selected-root"
tmux -S "$SAFEYOLO_CONFIG_DIR/data/tmux.sock" new-session -d -s temporary 'sleep 60'
"#,
                false,
            )
            .output()
            .unwrap(),
    );
    assert!(!fixture.ephemeral_root().exists());
    success(
        Command::new(tmux)
            .arg("-S")
            .arg(peer_socket)
            .args(["has-session", "-t", "peer"])
            .output()
            .unwrap(),
    );
    fixture.assert_peer_live();
}

const START: &str = r#"
set -eu
printf '%s\n' "$SAFEYOLO_CONFIG_DIR" > "$1/selected-root"
test "$SAFEYOLO_CONFIG_DIR" != "$1"
test "$SAFEYOLO_COORD_DATA_DIR" = "$SAFEYOLO_CONFIG_DIR/data/coord"
test "$SAFEYOLO_RUNSC_ROOT" = "$SAFEYOLO_CONFIG_DIR/run"
safeyolo-proxy --config "$SAFEYOLO_NATIVE_CONFIG_PATH" > "$SAFEYOLO_CONFIG_DIR/logs/proxy.log" 2>&1 &
while [ ! -f "$SAFEYOLO_CONFIG_DIR/data/ready.json" ] || [ ! -f "$SAFEYOLO_CONFIG_DIR/data/proxy-process.json" ]; do sleep 0.02; done
safeyolo status
"#;

#[test]
fn successful_and_failed_commands_remove_only_the_ephemeral_instance() {
    let mut fixture = Fixture::new();
    let identity = fs::read(fixture.root().join("data/instance_id")).unwrap();
    let record = fs::read(fixture.root().join("data/proxy-process.json")).unwrap();
    for code in [0, 37] {
        let output = fixture
            .run(&format!("{START}\nexit {code}"), false)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!fixture.ephemeral_root().exists());
        fixture.assert_peer_live();
        assert_eq!(
            fs::read(fixture.root().join("data/instance_id")).unwrap(),
            identity
        );
        assert_eq!(
            fs::read(fixture.root().join("data/proxy-process.json")).unwrap(),
            record
        );
    }
}

#[test]
fn interruption_stops_the_command_group_and_preserves_the_other_instance() {
    let mut fixture = Fixture::new();
    let mut runner = fixture.run(&format!("{START}\nprintf ready > \"$1/command-ready\"\ntrap '' TERM\nwhile :; do sleep 1; done"), false).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    fixture.wait("command-ready");
    // A live Child is the authority for this signal, never a saved PID file.
    assert_eq!(unsafe { libc::kill(runner.id() as i32, libc::SIGINT) }, 0);
    assert_eq!(runner.wait().unwrap().code(), Some(130));
    assert!(!fixture.ephemeral_root().exists());
    fixture.assert_peer_live();
}

#[test]
fn mismatched_process_ownership_retains_the_root_without_signalling_the_peer() {
    let mut fixture = Fixture::new();
    let peer: Value =
        serde_json::from_slice(&fs::read(fixture.root().join("data/proxy-process.json")).unwrap())
            .unwrap();
    for token in [peer["token"].as_str().unwrap(), "stale-process-birth"] {
        let mut record = peer.clone();
        record["token"] = token.into();
        fs::write(
            fixture.root().join("copied-process.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let output = fixture
            .run(
                r#"set -eu
printf '%s\n' "$SAFEYOLO_CONFIG_DIR" > "$1/selected-root"
cp "$1/copied-process.json" "$SAFEYOLO_CONFIG_DIR/data/proxy-process.json"
"#,
                false,
            )
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("proxy ownership is unverified"));
        let root = fixture.ephemeral_root();
        assert!(root.is_dir());
        fixture.assert_peer_live();
        fs::remove_file(root.join("data/proxy-process.json")).unwrap();
        success(cli(&root, &["instance", "cleanup"]));
        assert!(!root.exists());
    }
}

#[test]
fn reuse_is_explicit_pinned_and_read_only_to_guests() {
    let mut fixture = Fixture::new();
    let source = fixture.root().join("share");
    fs::create_dir_all(source.join("rootfs-tree")).unwrap();
    fs::write(source.join("rootfs-tree/marker"), "original").unwrap();
    fs::write(source.join("cache-paths.txt"), "").unwrap();
    #[cfg(target_os = "macos")]
    for name in ["Image", "initramfs.cpio.gz", "rootfs-base.ext4"] {
        fs::write(source.join(name), "fixture").unwrap();
    }
    fs::create_dir(fixture.root().join("workspace")).unwrap();
    success(fixture.run(r#"set -eu
printf '%s\n' "$SAFEYOLO_CONFIG_DIR" > "$1/selected-root"
test -f "$SAFEYOLO_CONFIG_DIR/data/ephemeral-instance.json"
test -d "$SAFEYOLO_CONFIG_DIR/share/rootfs-tree" || test -f "$SAFEYOLO_CONFIG_DIR/share/rootfs-base.ext4"
"#, true).output().unwrap());
    assert!(!fixture.ephemeral_root().exists());
    assert_eq!(
        fs::read(source.join("rootfs-tree/marker")).unwrap(),
        b"original"
    );
    let script = r#"set -eu
printf '%s\n' "$SAFEYOLO_CONFIG_DIR" > "$1/selected-root"
! safeyolo agent create bad --workspace "$1/share"
safeyolo agent create test --workspace "$1/workspace" --mount "$1/share:/source:ro"
! safeyolo agent configure test --mount "$1/share:/source"
cp "$SAFEYOLO_CONFIG_DIR/data/ephemeral-instance.json" "$1/manifest-copy"
printf changed > "$1/share/rootfs-tree/marker"
printf changed > "$1/share/rootfs-base.ext4"
if safeyolo agent start test --sandbox-only > "$1/start-out" 2> "$1/start-error"; then exit 90; fi
grep 'reused guest asset changed' "$1/start-error"
"#;
    success(fixture.run(script, true).output().unwrap());
    assert!(!fixture.ephemeral_root().exists());
    let manifest: Value =
        serde_json::from_slice(&fs::read(fixture.root().join("manifest-copy")).unwrap()).unwrap();
    assert!(!manifest["assets"].as_array().unwrap().is_empty());
    assert!(
        manifest["assets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|asset| asset["sha256"].as_str().unwrap().len() == 64)
    );
    // Only the explicit test mutation touched the source; cleanup did not remove it.
    assert_eq!(
        fs::read(source.join("rootfs-tree/marker")).unwrap(),
        b"changed"
    );
    fixture.assert_peer_live();
}

#[test]
fn instance_paths_cannot_be_redirected_to_another_instances_data() {
    let mut fixture = Fixture::new();
    let output = fixture
        .run(
            r#"set -eu
printf '%s\n' "$SAFEYOLO_CONFIG_DIR" > "$1/selected-root"
cp "$SAFEYOLO_NATIVE_CONFIG_PATH" "$SAFEYOLO_CONFIG_DIR/original.toml"
printf '\ndata_dir = "%s/data"\n' "$1" >> "$SAFEYOLO_NATIVE_CONFIG_PATH"
if safeyolo coord stop > "$1/redirect-out" 2> "$1/redirect-error"; then exit 91; fi
grep 'ephemeral instance path escapes' "$1/redirect-error"
cp "$SAFEYOLO_CONFIG_DIR/original.toml" "$SAFEYOLO_NATIVE_CONFIG_PATH"
rm "$SAFEYOLO_NATIVE_CONFIG_PATH"
ln -s "$1/config.toml" "$SAFEYOLO_NATIVE_CONFIG_PATH"
if safeyolo coord stop > "$1/symlink-out" 2> "$1/symlink-error"; then exit 92; fi
grep 'ephemeral config path escapes' "$1/symlink-error"
rm "$SAFEYOLO_NATIVE_CONFIG_PATH"
cp "$SAFEYOLO_CONFIG_DIR/original.toml" "$SAFEYOLO_NATIVE_CONFIG_PATH"
"#,
            false,
        )
        .output()
        .unwrap();
    success(output);
    assert!(!fixture.ephemeral_root().exists());
    fixture.assert_peer_live();
}
