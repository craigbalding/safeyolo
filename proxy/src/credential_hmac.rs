//! Source-compatible HMAC key loading from explicit, caller-owned inputs.
//!
//! No environment lookup, logging, key formatting, or fingerprint calculation
//! occurs here. The caller decides when an empty key should be loaded again.

use std::{
    ffi::OsStr,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::IntoRawFd,
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::Path,
};

use ring::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, Zeroizing};

/// Intentionally has no Debug, Display, Serialize, or implicit byte conversion.
pub(crate) struct HmacSecret(Zeroizing<Vec<u8>>);

impl HmacSecret {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Only operation/category survives an I/O error: its path and message do not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    EnvironmentEncoding,
    Stat(io::ErrorKind),
    Read(io::ErrorKind),
    Random,
    Parent(io::ErrorKind),
    Create(io::ErrorKind),
    Write(io::ErrorKind),
    Close(io::ErrorKind),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (operation, kind) = match self {
            Self::EnvironmentEncoding => {
                return formatter.write_str("HMAC environment value is not UTF-8");
            }
            Self::Random => return formatter.write_str("HMAC key generation failed"),
            Self::Stat(kind) => ("stat", kind),
            Self::Read(kind) => ("read", kind),
            Self::Parent(kind) => ("parent creation", kind),
            Self::Create(kind) => ("exclusive creation", kind),
            Self::Write(kind) => ("write", kind),
            Self::Close(kind) => ("close", kind),
        };
        write!(formatter, "HMAC key {operation} failed ({kind:?})")
    }
}

impl std::error::Error for Error {}

fn exists(path: &Path) -> Result<bool, Error> {
    // Python Path.exists catches the ValueError from an embedded NUL. The
    // later exclusive open still fails, after the source parent-creation step.
    if path.as_os_str().as_bytes().contains(&0) {
        return Ok(false);
    }
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) || matches!(error.raw_os_error(), Some(libc::EBADF | libc::ELOOP)) =>
        {
            Ok(false)
        }
        Err(error) => Err(Error::Stat(error.kind())),
    }
}

fn byte_whitespace(byte: u8) -> bool {
    // Python bytes.strip includes vertical tab; Rust is_ascii_whitespace does not.
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn read(path: &Path) -> Result<HmacSecret, Error> {
    let mut bytes = Zeroizing::new(fs::read(path).map_err(|error| Error::Read(error.kind()))?);
    let start = bytes
        .iter()
        .position(|byte| !byte_whitespace(*byte))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte_whitespace(*byte))
        .map_or(start, |index| index + 1);
    let length = end - start;
    bytes.copy_within(start..end, 0);
    // Wipe the removed/duplicated tail before reducing the visible length.
    bytes[length..].zeroize();
    bytes.truncate(length);
    Ok(HmacSecret(bytes))
}

fn persist(writer: &mut impl Write, secret: &HmacSecret) -> Result<(), Error> {
    // Bounded source repair: Python ignores a short os.write result, causing
    // current and restarted processes to use different keys. Complete the write
    // or return an error, without deleting/replacing a partially written file.
    writer
        .write_all(secret.as_bytes())
        .map_err(|error| Error::Write(error.kind()))
}

fn create(path: &Path, secret: &HmacSecret) -> Result<(), Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| Error::Create(error.kind()))?;
    let written = persist(&mut file, secret);
    // Python closes in a finally block. A close error takes precedence over a
    // write error, and the descriptor must not be closed a second time.
    close(file).and(written)
}

fn close(file: File) -> Result<(), Error> {
    let descriptor = file.into_raw_fd();
    // SAFETY: into_raw_fd transferred the only File owner. Close exactly once;
    // do not retry EINTR because the OS may already have released the descriptor.
    if unsafe { libc::close(descriptor) } == 0 {
        Ok(())
    } else {
        Err(Error::Close(io::Error::last_os_error().kind()))
    }
}

pub(crate) fn load(path: &Path, environment: Option<&OsStr>) -> Result<HmacSecret, Error> {
    if let Some(value) = environment.filter(|value| !value.is_empty()) {
        let value = value.to_str().ok_or(Error::EnvironmentEncoding)?;
        return Ok(HmacSecret(Zeroizing::new(value.as_bytes().to_vec())));
    }
    if exists(path)? {
        return read(path);
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(entropy.as_mut())
        .map_err(|_| Error::Random)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(64));
    for byte in entropy.iter() {
        bytes.push(b"0123456789abcdef"[(byte >> 4) as usize]);
        bytes.push(b"0123456789abcdef"[(byte & 15) as usize]);
    }
    let secret = HmacSecret(bytes);
    fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(|error| Error::Parent(error.kind()))?;
    create(path, &secret)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{digest, hmac};
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{PermissionsExt, symlink},
    };
    use std::{
        path::PathBuf,
        process::{Command, Stdio},
    };
    use tempfile::TempDir;

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/credential_hmac_source.json")).unwrap()
    }

    #[test]
    fn environment_is_first_truthy_untrimmed_utf8_input() {
        let directory = TempDir::new().unwrap();
        for value in [" \tsynthetic-env\r\n", "synthetic-é🙂", " \t\u{b}\r\n"] {
            let secret = load(directory.path(), Some(OsStr::new(value))).unwrap();
            assert!(secret.as_bytes() == value.as_bytes());
        }
        assert!(matches!(
            load(directory.path(), Some(OsStr::from_bytes(b"\xff"))),
            Err(Error::EnvironmentEncoding)
        ));
        assert!(matches!(
            load(directory.path(), Some(OsStr::new(""))),
            Err(Error::Read(io::ErrorKind::IsADirectory))
        ));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        let rows = fixture();
        assert_eq!(rows["rows"][0]["calls"], serde_json::json!([]));
        assert_eq!(rows["rows"][3]["outcome"], "UnicodeEncodeError");
    }

    #[test]
    fn existing_arbitrary_bytes_trim_six_whitespace_bytes_and_keep_mode() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("key");
        for (input, expected) in [
            (b"".as_slice(), b"".as_slice()),
            (b" \t\n\r\x0b\x0c", b""),
            (
                b" \t\n\r\x0b\x0c\0\x1c\x85\xa0\xff\x0b\x0c\r\n\t ",
                b"\0\x1c\x85\xa0\xff",
            ),
            (b"x", b"x"),
        ] {
            fs::write(&path, input).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            for environment in [None, Some(OsStr::new(""))] {
                let secret = load(&path, environment).unwrap();
                assert!(secret.as_bytes() == expected);
                assert_eq!(secret.is_empty(), expected.is_empty());
            }
            assert!(fs::read(&path).unwrap() == input);
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
        let long = vec![b'k'; 4097];
        fs::write(&path, &long).unwrap();
        assert!(load(&path, None).unwrap().as_bytes() == long);
        // Empty-file loads are real reads; they neither regenerate nor cache.
        fs::write(&path, b" ").unwrap();
        assert!(load(&path, None).unwrap().is_empty());
        fs::write(&path, b"replacement").unwrap();
        assert!(load(&path, None).unwrap().as_bytes() == b"replacement");
    }

    #[test]
    fn existing_symlink_is_followed_but_missing_and_looping_links_are_not_replaced() {
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("target");
        let path = directory.path().join("key");
        fs::write(&target, b" \tsynthetic-link\r\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&target, &path).unwrap();
        assert!(load(&path, None).unwrap().as_bytes() == b"synthetic-link");
        assert!(path.is_symlink());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );
        fs::remove_file(&target).unwrap();
        assert!(matches!(
            load(&path, None),
            Err(Error::Create(io::ErrorKind::AlreadyExists))
        ));
        assert!(path.is_symlink() && !target.exists());
        fs::remove_file(&path).unwrap();
        symlink(&path, &path).unwrap();
        assert!(matches!(
            load(&path, None),
            Err(Error::Create(io::ErrorKind::AlreadyExists))
        ));
        assert!(path.is_symlink());
    }

    #[test]
    fn new_key_is_64_lower_hex_persisted_at_creation_mode_and_reused() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("new/nested/key");
        let secret = load(&path, None).unwrap();
        assert_eq!(secret.as_bytes().len(), 64);
        assert!(
            secret
                .as_bytes()
                .iter()
                .all(|byte| b"0123456789abcdef".contains(byte))
        );
        assert!(fs::read(&path).unwrap() == secret.as_bytes());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(load(&path, None).unwrap().as_bytes() == secret.as_bytes());
        assert!(load(&path, Some(OsStr::new(""))).unwrap().as_bytes() == secret.as_bytes());
    }

    #[test]
    fn exclusive_creation_does_not_retry_or_replace_a_competing_file() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("key");
        fs::write(&path, b"synthetic-competitor").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let secret = HmacSecret(Zeroizing::new(vec![b'k'; 64]));
        assert_eq!(
            create(&path, &secret),
            Err(Error::Create(io::ErrorKind::AlreadyExists))
        );
        assert!(fs::read(&path).unwrap() == b"synthetic-competitor");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(matches!(
            load(&path.join("child"), None),
            Err(Error::Parent(io::ErrorKind::AlreadyExists))
        ));
        let invalid = directory.path().join("new-parent/bad\0key");
        assert!(matches!(
            load(&invalid, None),
            Err(Error::Create(io::ErrorKind::InvalidInput))
        ));
        assert!(invalid.parent().unwrap().is_dir());
    }

    struct ShortWriter<W> {
        writer: W,
        left: usize,
    }
    impl<W: Write> Write for ShortWriter<W> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.left == 0 {
                return Err(io::Error::other("synthetic-private-error"));
            }
            let length = bytes.len().min(7).min(self.left);
            let written = self.writer.write(&bytes[..length])?;
            self.left -= written;
            Ok(written)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.writer.flush()
        }
    }

    #[test]
    fn completes_short_writes_and_leaves_failed_partial_file_without_exposing_errors() {
        let secret = HmacSecret(Zeroizing::new(vec![b'k'; 64]));
        let mut complete = ShortWriter {
            writer: Vec::new(),
            left: 64,
        };
        persist(&mut complete, &secret).unwrap();
        assert!(complete.writer == secret.as_bytes());
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("key");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let mut partial = ShortWriter {
            writer: file,
            left: 7,
        };
        let error = persist(&mut partial, &secret).unwrap_err();
        assert_eq!(error, Error::Write(io::ErrorKind::Other));
        assert!(!error.to_string().contains("synthetic-private-error"));
        assert!(!format!("{error:?}").contains("synthetic-private-error"));
        drop(partial);
        assert!(path.exists());
        assert!(fs::read(&path).unwrap() == secret.as_bytes()[..7]);
        let witness = fixture();
        let row = witness["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "source_short_write_defect")
            .unwrap();
        assert_eq!(row["outcome"], "ok");
        assert_eq!(row["length"], 64);
        assert_eq!(row["file_length"], 7);
        assert_eq!(row["file_equals_generated"], false);
        assert_eq!(row["file_is_generated_prefix"], true);
    }

    const COMPARATOR_COMMIT: &str = "7e934a5470f1aa9b74052fea08c6bae9b5f32e8a";

    fn sha256(bytes: &[u8]) -> String {
        digest::digest(&digest::SHA256, bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn file_mode(path: &std::path::Path) -> String {
        format!(
            "{:04o}",
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        )
    }

    fn native_fingerprint(secret: &[u8]) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        hmac::sign(&key, b"synthetic-credential").as_ref()[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn native_stage(path: &std::path::Path, operation: &str) -> serde_json::Value {
        let secret = load(path, None).unwrap();
        let bytes = secret.as_bytes();
        assert_eq!(bytes.len(), 64, "native key must remain a 64-byte hex key");
        assert!(bytes.iter().all(u8::is_ascii_hexdigit));
        serde_json::json!({
            "backend": "rust-native",
            "operation": operation,
            "key_sha256": sha256(bytes),
            "key_mode": file_mode(path),
            "key_length": bytes.len(),
            "fingerprint": native_fingerprint(bytes),
        })
    }

    fn git_output(repository: &std::path::Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(repository)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn python_stage(
        root: &std::path::Path,
        source: &std::path::Path,
        executable: &std::path::Path,
        operation: &str,
    ) -> serde_json::Value {
        let script = r#"
import hashlib
import hmac
import importlib.metadata
import json
import pathlib
import stat
import sys

from safeyolo.core.utils import hmac_fingerprint, load_hmac_secret

root = pathlib.Path(sys.argv[1])
operation = sys.argv[2]
expected_executable = pathlib.Path(sys.argv[3])
source = pathlib.Path(sys.argv[4])
assert pathlib.Path(sys.executable).resolve() == expected_executable.resolve()
path = root / 'data' / 'hmac_secret'
secret = load_hmac_secret(path)
assert secret == path.read_bytes()
print(json.dumps({
    'backend': 'python-comparator',
    'operation': operation,
    'runtime': {
        'source': str(source),
        'commit': '7e934a5470f1aa9b74052fea08c6bae9b5f32e8a',
        'program': sys.executable,
        'python_version': '.'.join(map(str, sys.version_info[:3])),
        'safeyolo': importlib.metadata.version('safeyolo'),
        'mitmproxy': importlib.metadata.version('mitmproxy'),
    },
    'key_sha256': hashlib.sha256(secret).hexdigest(),
    'key_mode': format(stat.S_IMODE(path.stat().st_mode), '04o'),
    'key_length': len(secret),
    'fingerprint': hmac_fingerprint('synthetic-credential', secret),
}))
"#;
        let output = Command::new(executable)
            .args(["-c", script, &root.to_string_lossy(), operation])
            .arg(executable)
            .arg(source)
            .env_remove("CREDGUARD_HMAC_SECRET")
            .env(
                "PYTHONPATH",
                format!("{}:{}", source.join("cli/src").display(), source.display()),
            )
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Python HMAC stage {operation} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "Python HMAC stage {operation} returned invalid JSON: {error}; stdout={}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
    }

    #[test]
    #[ignore = "requires the pinned Python comparator and retained evidence directory"]
    fn selected_python_native_python_native_hmac_key_transition() {
        let source = PathBuf::from(
            std::env::var_os("SAFEYOLO_STATE_PYTHON_SOURCE")
                .expect("SAFEYOLO_STATE_PYTHON_SOURCE must name the comparator checkout"),
        );
        let executable = PathBuf::from(
            std::env::var_os("SAFEYOLO_POLICY_PYTHON")
                .expect("SAFEYOLO_POLICY_PYTHON must name the comparator interpreter"),
        );
        let evidence = PathBuf::from(
            std::env::var_os("SAFEYOLO_STATE_EVIDENCE_DIR")
                .expect("SAFEYOLO_STATE_EVIDENCE_DIR must name retained evidence"),
        );
        assert_eq!(
            git_output(&source, &["rev-parse", "HEAD"]),
            COMPARATOR_COMMIT
        );
        assert!(git_output(&source, &["status", "--porcelain"]).is_empty());
        assert!(executable.is_file());
        fs::create_dir_all(&evidence).unwrap();

        let python_first = TempDir::new().unwrap();
        let python_write = python_stage(python_first.path(), &source, &executable, "write");
        let native_read = native_stage(
            &python_first.path().join("data/hmac_secret"),
            "read-python-key",
        );
        let python_reload = python_stage(python_first.path(), &source, &executable, "read");
        let native_reload = native_stage(
            &python_first.path().join("data/hmac_secret"),
            "reload-python-key",
        );
        for stage in [&native_read, &python_reload, &native_reload] {
            assert_eq!(stage["key_sha256"], python_write["key_sha256"]);
            assert_eq!(stage["key_mode"], "0600");
            assert_eq!(stage["fingerprint"], python_write["fingerprint"]);
        }

        let native_first = TempDir::new().unwrap();
        let native_write = native_stage(&native_first.path().join("data/hmac_secret"), "write");
        let python_read_native = python_stage(native_first.path(), &source, &executable, "read");
        let native_reopen = native_stage(&native_first.path().join("data/hmac_secret"), "reload");
        for stage in [&python_read_native, &native_reopen] {
            assert_eq!(stage["key_sha256"], native_write["key_sha256"]);
            assert_eq!(stage["key_mode"], "0600");
            assert_eq!(stage["fingerprint"], native_write["fingerprint"]);
        }

        let manifest = serde_json::json!({
            "test": "selected_python_native_python_native_hmac_key_transition",
            "comparator": {
                "source": source,
                "commit": COMPARATOR_COMMIT,
                "program": executable,
            },
            "secret_policy": "key bytes are represented only by SHA-256 and a synthetic-value HMAC fingerprint",
            "python_rust_python_rust": {
                "python_write": python_write,
                "native_read": native_read,
                "python_reload": python_reload,
                "native_reload": native_reload,
            },
            "rust_python_rust": {
                "native_write": native_write,
                "python_read": python_read_native,
                "native_reload": native_reopen,
            },
        });
        fs::write(
            evidence.join("hmac-python-rust-python-rust.json"),
            serde_json::to_vec_pretty(&manifest["python_rust_python_rust"]).unwrap(),
        )
        .unwrap();
        fs::write(
            evidence.join("hmac-rust-python-rust.json"),
            serde_json::to_vec_pretty(&manifest["rust_python_rust"]).unwrap(),
        )
        .unwrap();
        fs::write(
            evidence.join("hmac-transition-manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }
}
