use ring::digest::{SHA256, digest};
use safeyolo_proxy::{
    credentials::{Secret, Vault},
    oauth::{OAuthRefresh, RefreshOutcome, RefreshResponse, RefreshStart},
};
use serde_json::{Value, json};
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use time::OffsetDateTime;

const PASS: &str = "synthetic-vault-passphrase";
const NAME: &str = "oauth-synthetic";
const COMPARATOR_COMMIT: &str = "7e934a5470f1aa9b74052fea08c6bae9b5f32e8a";

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_704_067_200).unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn state_sha256(path: &Path) -> String {
    sha256(&std::fs::read(path).unwrap())
}

fn file_mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn git_output(directory: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn comparator_python_stage(script: &str, input: &Value) -> Value {
    let source = Path::new(
        &std::env::var("SAFEYOLO_STATE_PYTHON_SOURCE")
            .expect("set SAFEYOLO_STATE_PYTHON_SOURCE to the selected comparator checkout"),
    )
    .canonicalize()
    .unwrap();
    assert_eq!(
        git_output(&source, &["rev-parse", "HEAD"]),
        COMPARATOR_COMMIT
    );
    assert!(git_output(&source, &["status", "--porcelain"]).is_empty());
    let executable_path = std::env::var("SAFEYOLO_POLICY_PYTHON")
        .expect("set SAFEYOLO_POLICY_PYTHON to the selected comparator interpreter");
    let executable = Path::new(&executable_path);
    assert_eq!(
        executable.canonicalize().unwrap(),
        source.join(".venv/bin/python").canonicalize().unwrap()
    );
    let mut child = Command::new(executable)
        .args(["-c", script])
        .env(
            "PYTHONPATH",
            format!("{}:{}", source.join("cli/src").display(), source.display()),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "comparator stage failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn fingerprint(value: &str) -> String {
    sha256(value.as_bytes())
}

/// Prove the supported OAuth state transition with the retained Python vault
/// consumer: Python writes, Rust refreshes, Python reads and refreshes again,
/// and Rust explicitly reloads that Python-authored state. The HTTP responses
/// are synthetic and never leave the process; encrypted file hashes and
/// secret fingerprints are the only retained state evidence.
#[test]
#[ignore = "selected Python→Rust OAuth vault transition"]
fn selected_python_native_python_native_oauth_vault_transition() {
    let comparator = PathBuf::from(
        std::env::var("SAFEYOLO_STATE_PYTHON_SOURCE")
            .expect("set SAFEYOLO_STATE_PYTHON_SOURCE to the selected comparator checkout"),
    )
    .canonicalize()
    .unwrap();
    let comparator_python = comparator.join(".venv/bin/python");
    let root = tempfile::tempdir().unwrap();
    let vault_path = root.path().join("vault.yaml.enc");
    let input = json!({"path": vault_path, "password": PASS, "name": NAME});

    let initial = comparator_python_stage(
        r#"
import hashlib, importlib.metadata, json, sys
from pathlib import Path
from safeyolo.core.vault import Vault, VaultCredential
x=json.load(sys.stdin); p=Path(x['path']); v=Vault(p); v.unlock(x['password'])
v.store(VaultCredential(
    x['name'], 'oauth2', 'synthetic-python-old-access',
    refresh_token='synthetic-python-old-refresh',
    token_url='https://oauth.synthetic.invalid/token',
    client_id='synthetic-client', client_secret='synthetic-client-secret',
    expires_at='2020-01-01T00:00:00+00:00'))
c=v.get(x['name'])
assert c is not None and c.type == 'oauth2' and c.is_expired()
raw=p.read_bytes()
print(json.dumps({'program':sys.executable,'python_version':sys.version.split()[0],
 'safeyolo':importlib.metadata.version('safeyolo'),
 'source':str(Path(__import__('safeyolo').__file__).resolve()),
 'name':c.name,'type':c.type,'expires_at':c.expires_at,
 'names':v.list_names(),'mode':p.stat().st_mode&0o777,
 'sha256':hashlib.sha256(raw).hexdigest()}))
"#,
        &input,
    );
    assert_eq!(
        initial["program"],
        comparator_python.to_string_lossy().as_ref()
    );
    assert_eq!(initial["names"], json!([NAME]));
    assert_eq!(initial["type"], "oauth2");
    assert_eq!(initial["mode"], 0o600);
    assert_eq!(initial["sha256"], state_sha256(&vault_path));

    let mut stages = vec![json!({
        "backend": "python-comparator",
        "operation": "write-expired-oauth-v1",
        "sha256": initial["sha256"],
        "mode": initial["mode"],
        "names": initial["names"],
        "credential": {"name": NAME, "type": "oauth2", "expired": true},
    })];

    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    let initial_credential = vault.get(NAME).unwrap().unwrap();
    assert_eq!(initial_credential.name, NAME);
    assert_eq!(initial_credential.credential_type, "oauth2");
    assert_eq!(
        initial_credential.value.expose_secret(),
        "synthetic-python-old-access"
    );
    assert_eq!(
        initial_credential
            .refresh_token
            .as_ref()
            .unwrap()
            .expose_secret(),
        "synthetic-python-old-refresh"
    );
    assert!(initial_credential.needs_oauth_refresh(now()).unwrap());

    let oauth = OAuthRefresh::new(vault.clone());
    let RefreshStart::Leader(failed_attempt) = oauth.begin(NAME, now()).unwrap() else {
        panic!("expected failed refresh leader")
    };
    let failed = failed_attempt.complete(
        Ok(RefreshResponse::new(
            503,
            b"synthetic-provider-failure".to_vec(),
        )),
        now(),
    );
    assert_eq!(
        failed,
        RefreshOutcome::Retained(safeyolo_proxy::oauth::RefreshError::HttpStatus(503))
    );
    assert_eq!(state_sha256(&vault_path), initial["sha256"]);
    assert_eq!(
        vault.get(NAME).unwrap().unwrap().value.expose_secret(),
        "synthetic-python-old-access"
    );
    stages.push(json!({
        "backend": "rust-native-oauth",
        "operation": "retain-on-provider-http-failure",
        "sha256": state_sha256(&vault_path),
        "mode": file_mode(&vault_path),
        "effective": {"outcome": "retained", "http_status": 503, "bytes_unchanged": true},
    }));

    let RefreshStart::Leader(success_attempt) = oauth.begin(NAME, now()).unwrap() else {
        panic!("expected successful refresh leader")
    };
    let refreshed = success_attempt.complete(
        Ok(RefreshResponse::new(
            200,
            br#"{"access_token":"synthetic-rust-access-v2","refresh_token":"synthetic-rust-refresh-v2","expires_in":3600}"#.to_vec(),
        )),
        now(),
    );
    assert_eq!(refreshed, RefreshOutcome::Refreshed);
    vault.reload().unwrap();
    let rust_credential = vault.get(NAME).unwrap().unwrap();
    assert_eq!(
        rust_credential.value.expose_secret(),
        "synthetic-rust-access-v2"
    );
    assert_eq!(
        rust_credential
            .refresh_token
            .as_ref()
            .unwrap()
            .expose_secret(),
        "synthetic-rust-refresh-v2"
    );
    assert_eq!(rust_credential.credential_type, "oauth2");
    stages.push(json!({
        "backend": "rust-native-oauth",
        "operation": "read-and-publish-refresh-v2",
        "sha256": state_sha256(&vault_path),
        "mode": file_mode(&vault_path),
        "effective": {
            "name": NAME,
            "type": "oauth2",
            "access_fingerprint": fingerprint(rust_credential.value.expose_secret()),
            "refresh_fingerprint": fingerprint(rust_credential.refresh_token.as_ref().unwrap().expose_secret()),
            "expires_at_present": rust_credential.expires_at.is_some(),
        },
    }));

    let python_after = comparator_python_stage(
        r#"
import hashlib, json, sys
from pathlib import Path
import httpx
from safeyolo.core.vault import Vault
x=json.load(sys.stdin); p=Path(x['path']); v=Vault(p); v.unlock(x['password'])
c=v.get(x['name'])
assert c is not None and c.type == 'oauth2'
assert c.value == 'synthetic-rust-access-v2'
assert c.refresh_token == 'synthetic-rust-refresh-v2'
class Response:
    def raise_for_status(self): pass
    def json(self): return {'access_token':'synthetic-python-access-v3',
                            'refresh_token':'synthetic-python-refresh-v3',
                            'expires_in':3600}
httpx.post=lambda *args, **kwargs: Response()
assert v.refresh_oauth2(x['name'])
c=v.get(x['name'])
assert c is not None and c.value == 'synthetic-python-access-v3'
assert c.refresh_token == 'synthetic-python-refresh-v3'
raw=p.read_bytes()
print(json.dumps({'name':c.name,'type':c.type,'expires_at_present':bool(c.expires_at),
 'names':v.list_names(),'mode':p.stat().st_mode&0o777,
 'sha256':hashlib.sha256(raw).hexdigest()}))
"#,
        &input,
    );
    assert_eq!(python_after["names"], json!([NAME]));
    assert_eq!(python_after["type"], "oauth2");
    assert_eq!(python_after["mode"], 0o600);
    assert_eq!(python_after["sha256"], state_sha256(&vault_path));
    stages.push(json!({
        "backend": "python-comparator",
        "operation": "read-rust-refresh-and-use-python-refresh-v3",
        "sha256": python_after["sha256"],
        "mode": python_after["mode"],
        "effective": {
            "name": NAME,
            "type": "oauth2",
            "access_fingerprint": sha256(b"synthetic-python-access-v3"),
            "refresh_fingerprint": sha256(b"synthetic-python-refresh-v3"),
            "writer": "Vault.refresh_oauth2",
        },
    }));

    assert!(vault.has_changes().unwrap());
    vault.reload().unwrap();
    let final_credential = vault.get(NAME).unwrap().unwrap();
    assert_eq!(final_credential.name, NAME);
    assert_eq!(final_credential.credential_type, "oauth2");
    assert_eq!(
        final_credential.value.expose_secret(),
        "synthetic-python-access-v3"
    );
    assert_eq!(
        final_credential
            .refresh_token
            .as_ref()
            .unwrap()
            .expose_secret(),
        "synthetic-python-refresh-v3"
    );
    stages.push(json!({
        "backend": "rust-native-oauth",
        "operation": "reload-python-refresh-v3",
        "sha256": state_sha256(&vault_path),
        "mode": file_mode(&vault_path),
        "effective": {
            "name": NAME,
            "type": "oauth2",
            "access_fingerprint": fingerprint(final_credential.value.expose_secret()),
            "refresh_fingerprint": fingerprint(final_credential.refresh_token.as_ref().unwrap().expose_secret()),
            "exact_name_and_type": true,
        },
    }));

    let native_source = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = json!({
        "schema": 1,
        "family": "oauth-vault-cross-version",
        "comparator": {
            "source": comparator,
            "commit": COMPARATOR_COMMIT,
            "launcher": comparator_python,
            "program": initial["program"],
            "python_version": initial["python_version"],
            "safeyolo": initial["safeyolo"],
        },
        "native": {
            "source": git_output(native_source, &["rev-parse", "HEAD"]),
            "package": "safeyolo-proxy",
            "version": env!("CARGO_PKG_VERSION"),
            "lock_sha256":
                sha256(&std::fs::read(native_source.join("proxy/Cargo.lock")).unwrap()),
        },
        "files": {
            "vault": vault_path,
            "mode": format!("{:04o}", file_mode(&vault_path)),
            "final_sha256": state_sha256(&vault_path),
        },
        "stages": stages,
    });
    let manifest_text = serde_json::to_string_pretty(&manifest).unwrap();
    for secret in [
        PASS,
        "synthetic-python-old-access",
        "synthetic-python-old-refresh",
        "synthetic-rust-access-v2",
        "synthetic-rust-refresh-v2",
        "synthetic-python-access-v3",
        "synthetic-python-refresh-v3",
        "synthetic-client-secret",
    ] {
        assert!(!manifest_text.contains(secret));
    }
    println!("OAuth cross-version manifest: {manifest_text}");
    if let Some(directory) = std::env::var_os("SAFEYOLO_STATE_EVIDENCE_DIR") {
        let directory = Path::new(&directory);
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            directory.join("oauth-vault-python-rust-python-rust.json"),
            format!("{manifest_text}\n"),
        )
        .unwrap();
    }
}
