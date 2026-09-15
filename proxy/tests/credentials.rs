use safeyolo_proxy::credentials::{Credential, ErrorKind, Secret, Vault};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Barrier},
};
use time::OffsetDateTime;

fn password() -> Secret {
    Secret::new("synthetic vault passphrase — not an operator key")
}
fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1704067200).unwrap()
}
fn credential(name: &str) -> Credential {
    Credential::new(
        name,
        "bearer",
        Secret::new(format!("synthetic-private-value-for-{name}")),
    )
}
fn setup() -> (tempfile::TempDir, PathBuf, Vault) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.yaml.enc");
    let vault = Vault::unlock(&path, &password()).unwrap();
    (directory, path, vault)
}

#[test]
fn store_restart_remove_and_metadata_keep_secret_access_explicit() {
    let (_directory, path, vault) = setup();
    assert!(vault.list_names().unwrap().is_empty());
    let mut oauth = credential("mail");
    oauth.credential_type = "oauth2".into();
    oauth.refresh_token = Some(Secret::new("synthetic-refresh"));
    oauth.token_url = Some("https://example.invalid/token".into());
    oauth.client_id = Some("synthetic-client".into());
    oauth.client_secret = Some(Secret::new("synthetic-client-secret"));
    oauth.expires_at = Some("2099-01-01T00:00:00+00:00".into());
    vault.store(oauth).unwrap();
    vault.store(credential("second")).unwrap();
    let metadata = serde_json::to_string(&vault.metadata().unwrap()).unwrap();
    assert!(metadata.contains("mail"));
    for private in [
        "synthetic-private-value",
        "synthetic-refresh",
        "synthetic-client-secret",
        "example.invalid",
    ] {
        assert!(!metadata.contains(private));
    }
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        !fs::read(&path)
            .unwrap()
            .windows(b"synthetic-private-value".len())
            .any(|value| value == b"synthetic-private-value")
    );
    let restarted = Vault::unlock(&path, &password()).unwrap();
    assert_eq!(restarted.list_names().unwrap(), ["mail", "second"]);
    let loaded = restarted.get("mail").unwrap().unwrap();
    assert_eq!(
        loaded.value.expose_secret(),
        "synthetic-private-value-for-mail"
    );
    assert_eq!(
        loaded.refresh_token.as_ref().unwrap().expose_secret(),
        "synthetic-refresh"
    );
    assert_eq!(
        loaded.client_secret.as_ref().unwrap().expose_secret(),
        "synthetic-client-secret"
    );
    assert_eq!(loaded.client_id.as_deref(), Some("synthetic-client"));
    assert_eq!(
        loaded.token_url.as_deref(),
        Some("https://example.invalid/token")
    );
    assert_eq!(
        loaded.expires_at.as_deref(),
        Some("2099-01-01T00:00:00+00:00")
    );
    assert!(!loaded.is_expired(now()).unwrap());
    assert!(restarted.remove("mail").unwrap());
    assert!(!restarted.remove("missing").unwrap());
    assert!(vault.has_changes().unwrap());
    assert!(vault.reload_if_changed().unwrap());
    assert!(!vault.reload_if_changed().unwrap());
    assert!(vault.get("mail").unwrap().is_none());
    assert_eq!(vault.list_names().unwrap(), ["second"]);
}

#[test]
fn wrong_password_corruption_and_truncation_never_replace_active_credentials() {
    use base64::{Engine, engine::general_purpose::URL_SAFE};
    let (_directory, path, vault) = setup();
    vault.store(credential("kept")).unwrap();
    let original = fs::read(&path).unwrap();
    assert_eq!(
        Vault::unlock(&path, &Secret::new("wrong synthetic password"))
            .err()
            .unwrap()
            .kind,
        ErrorKind::Authentication
    );
    let decoded = URL_SAFE.decode(&original[16..]).unwrap();
    for position in [0, 1, 9, 25, decoded.len() - 1] {
        let mut tampered = decoded.clone();
        tampered[position] ^= 1;
        let mut bytes = original[..16].to_vec();
        bytes.extend_from_slice(URL_SAFE.encode(tampered).as_bytes());
        fs::write(&path, bytes).unwrap();
        let failure = vault.reload().unwrap_err();
        assert_eq!(failure.kind, ErrorKind::Authentication);
        assert_eq!(failure.to_string(), "wrong passphrase or corrupted vault");
        assert_eq!(
            vault.get("kept").unwrap().unwrap().value.expose_secret(),
            "synthetic-private-value-for-kept"
        );
    }
    for length in [0, 1, 15, 16, 17, original.len() - 3] {
        fs::write(&path, &original[..length]).unwrap();
        assert_eq!(
            Vault::unlock(&path, &password()).err().unwrap().kind,
            ErrorKind::Authentication
        );
    }
    let mut changed_salt = original.clone();
    changed_salt[0] ^= 1;
    fs::write(&path, changed_salt).unwrap();
    assert_eq!(vault.reload().unwrap_err().kind, ErrorKind::KeyChanged);
    assert_eq!(
        Vault::unlock(&path, &password()).err().unwrap().kind,
        ErrorKind::Authentication
    );
    fs::write(&path, &original).unwrap();
    vault.reload().unwrap();
    assert_eq!(vault.list_names().unwrap(), ["kept"]);
}

#[test]
fn write_activation_rollback_restores_exact_encrypted_file_and_snapshot() {
    let (directory, path, vault) = setup();
    vault.store(credential("kept")).unwrap();
    let original = fs::read(&path).unwrap();
    let mut calls = Vec::new();
    let failure = vault
        .store_with_activation(credential("rejected"), |metadata| {
            calls.push(
                metadata
                    .iter()
                    .map(|value| value.name.clone())
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            if calls.len() == 1 { Err(()) } else { Ok(()) }
        })
        .unwrap_err();
    assert_eq!(failure.kind, ErrorKind::Activation);
    assert_eq!(
        calls,
        [
            vec!["kept".to_owned(), "rejected".to_owned()],
            vec!["kept".to_owned()]
        ]
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(vault.get("rejected").unwrap().is_none());
    assert_eq!(
        Vault::unlock(&path, &password())
            .unwrap()
            .list_names()
            .unwrap(),
        ["kept"]
    );
    assert_eq!(
        vault
            .remove_with_activation("kept", |_| Err(()))
            .unwrap_err()
            .kind,
        ErrorKind::Rollback
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(vault.get("kept").unwrap().is_some());
    assert_eq!(
        fs::read_dir(directory.path()).unwrap().count(),
        1,
        "private temporary files are cleaned after success and rollback"
    );
}

#[test]
fn reload_activation_is_atomic_and_missing_file_retains_previous_snapshot() {
    let (_directory, path, vault) = setup();
    vault.store(credential("kept")).unwrap();
    let external = Vault::unlock(&path, &password()).unwrap();
    external.store(credential("external")).unwrap();
    let changed = fs::read(&path).unwrap();
    let mut calls = 0;
    assert_eq!(
        vault
            .reload_with_activation(|_| {
                calls += 1;
                if calls == 1 { Err(()) } else { Ok(()) }
            })
            .unwrap_err()
            .kind,
        ErrorKind::Activation
    );
    assert_eq!(calls, 2);
    assert!(vault.get("external").unwrap().is_none());
    assert_eq!(fs::read(&path).unwrap(), changed);
    assert!(vault.reload_if_changed().unwrap());
    assert!(vault.get("external").unwrap().is_some());
    fs::remove_file(&path).unwrap();
    assert!(!vault.has_changes().unwrap());
    assert_eq!(vault.reload().unwrap_err().kind, ErrorKind::Io);
    assert_eq!(vault.list_names().unwrap(), ["kept", "external"]);
    assert_eq!(
        vault.store(credential("failed")).unwrap_err().kind,
        ErrorKind::Io
    );
    assert!(vault.get("failed").unwrap().is_none());
}

#[test]
fn shared_writers_publish_complete_credentials_without_lost_local_updates() {
    let (_directory, path, vault) = setup();
    let barrier = Arc::new(Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|worker| {
            let vault = vault.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                for item in 0..4 {
                    let name = format!("worker-{worker}-{item}");
                    vault.store(credential(&name)).unwrap();
                    assert!(vault.get(&name).unwrap().is_some());
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(vault.list_names().unwrap().len(), 32);
    assert_eq!(
        Vault::unlock(&path, &password())
            .unwrap()
            .list_names()
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn empty_values_unknown_types_and_optional_empty_fields_keep_existing_vault_semantics() {
    let (_directory, path, vault) = setup();
    let mut value = Credential::new("", "operator-custom-type", Secret::new(""));
    value.refresh_token = Some(Secret::new(""));
    value.token_url = Some("".into());
    value.client_id = Some("".into());
    value.client_secret = Some(Secret::new(""));
    value.expires_at = Some("".into());
    vault.store(value).unwrap();
    let loaded = Vault::unlock(path, &password())
        .unwrap()
        .get("")
        .unwrap()
        .unwrap();
    assert_eq!(loaded.credential_type, "operator-custom-type");
    assert!(loaded.value.expose_secret().is_empty());
    assert!(loaded.refresh_token.is_none());
    assert!(loaded.token_url.is_none());
    assert!(loaded.client_id.is_none());
    assert!(loaded.client_secret.is_none());
    assert!(loaded.expires_at.is_none());
}

#[test]
fn expiry_and_refresh_eligibility_keep_naive_timestamp_errors_explicit() {
    let cases = [
        (None, Ok(false)),
        (Some(""), Ok(false)),
        (Some("malformed"), Ok(true)),
        (Some("2024-01-01T00:00:00Z"), Ok(true)),
        (Some("2024-01-01T00:00:01Z"), Ok(false)),
        (Some("2024-01-01T01:00:00+01:00"), Ok(true)),
        (Some("2024-01-01T00:00:00"), Err(ErrorKind::InvalidExpiry)),
        (Some("2024-01-01"), Err(ErrorKind::InvalidExpiry)),
    ];
    for (expiry, expected) in cases {
        let mut value = credential("synthetic");
        value.expires_at = expiry.map(str::to_owned);
        assert_eq!(
            value.is_expired(now()).map_err(|failure| failure.kind),
            expected
        );
        assert!(!value.needs_oauth_refresh(now()).unwrap());
        value.credential_type = "oauth2".into();
        value.refresh_token = Some(Secret::new("synthetic-refresh"));
        value.token_url = Some("https://example.invalid/token".into());
        assert_eq!(
            value
                .needs_oauth_refresh(now())
                .map_err(|failure| failure.kind),
            expected
        );
    }
}

fn python_command(script: &str) -> std::process::Command {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut command = std::process::Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    );
    command.args(["-c", script]).env(
        "PYTHONPATH",
        format!("{}:{}", root.join("cli/src").display(), root.display()),
    );
    command
}
fn python(script: &str, input: &serde_json::Value) -> serde_json::Value {
    use std::{io::Write, process::Stdio};
    let mut child = python_command(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(input).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    // Fixture outputs are synthetic. Production errors never include plaintext.
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
#[ignore = "Python Fernet/YAML interoperability; set SAFEYOLO_POLICY_PYTHON"]
fn python_rust_roundtrip_future_timestamps_unknown_fields_and_atomic_rollback() {
    use serde_json::json;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.yaml.enc");
    let input = json!({"path":path,"password":password().expose_secret()});
    let created = python(
        r#"
import json,sys
from pathlib import Path
from safeyolo.core.vault import Vault,VaultCredential
x=json.load(sys.stdin);v=Vault(Path(x['path']));v.unlock(x['password'])
v.store(VaultCredential('python-mail','oauth2','synthetic-python-access',refresh_token='synthetic-python-refresh',token_url='https://example.invalid/token',client_id='synthetic-client-id',client_secret='synthetic-client-secret',expires_at='2099-01-01T00:00:00+00:00'))
v.store(VaultCredential('unicode-雪','operator-custom','line1\nline2 "quoted" 雪\0'))
print(json.dumps({'names':v.list_names(),'mode':Path(x['path']).stat().st_mode&0o777}))
"#,
        &input,
    );
    assert_eq!(created["mode"], json!(384));
    let vault = Vault::unlock(&path, &password()).unwrap();
    assert_eq!(
        serde_json::to_value(vault.list_names().unwrap()).unwrap(),
        created["names"]
    );
    let loaded = vault.get("python-mail").unwrap().unwrap();
    assert_eq!(loaded.value.expose_secret(), "synthetic-python-access");
    assert_eq!(
        loaded.refresh_token.as_ref().unwrap().expose_secret(),
        "synthetic-python-refresh"
    );
    assert_eq!(
        loaded.client_secret.as_ref().unwrap().expose_secret(),
        "synthetic-client-secret"
    );
    assert_eq!(
        vault
            .get("unicode-雪")
            .unwrap()
            .unwrap()
            .value
            .expose_secret(),
        "line1\nline2 \"quoted\" 雪\0"
    );
    let mut native = Credential::new("rust-mail", "oauth2", Secret::new("synthetic-rust-access"));
    native.refresh_token = Some(Secret::new("synthetic-rust-refresh"));
    native.token_url = Some("https://example.invalid/native-token".into());
    native.client_id = Some("synthetic-native-client".into());
    native.client_secret = Some(Secret::new("synthetic-native-secret"));
    native.expires_at = Some("2035-01-01T00:00:00Z".into());
    vault.store(native).unwrap();
    let original = fs::read(&path).unwrap();
    let mut calls = 0;
    assert_eq!(
        vault
            .remove_with_activation("python-mail", |_| {
                calls += 1;
                if calls == 1 { Err(()) } else { Ok(()) }
            })
            .unwrap_err()
            .kind,
        ErrorKind::Activation
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    let inspected = python(
        r#"
import json,sys,yaml
from pathlib import Path
from safeyolo.core.vault import Vault
x=json.load(sys.stdin);v=Vault(Path(x['path']));v.unlock(x['password'])
assert v.get('python-mail').value=='synthetic-python-access'
assert v.get('unicode-雪').value=='line1\nline2 "quoted" 雪\0'
c=v.get('rust-mail')
assert c.to_dict()=={'name':'rust-mail','type':'oauth2','value':'synthetic-rust-access','refresh_token':'synthetic-rust-refresh','token_url':'https://example.invalid/native-token','client_id':'synthetic-native-client','client_secret':'synthetic-native-secret','expires_at':'2035-01-01T00:00:00Z'}
raw=Path(x['path']).read_bytes();assert yaml.safe_load(v._fernet.decrypt(raw[16:]).decode())['credentials']
print(json.dumps({'names':v.list_names(),'mode':Path(x['path']).stat().st_mode&0o777}))
"#,
        &input,
    );
    assert_eq!(
        inspected["names"],
        json!(["python-mail", "unicode-雪", "rust-mail"])
    );
    assert_eq!(inspected["mode"], json!(384));
    assert_eq!(
        Vault::unlock(&path, &password())
            .unwrap()
            .list_names()
            .unwrap(),
        ["python-mail", "unicode-雪", "rust-mail"]
    );

    let special = python(
        r#"
import json,sys,yaml
from pathlib import Path
from safeyolo.core.vault import Vault
x=json.load(sys.stdin);path=Path(x['path']);v=Vault(path);v.unlock(x['password'])
document={'extra_root':'dropped','credentials':[{'name':'duplicate','type':'bearer','value':'first','extra_field':'dropped'},{'name':'duplicate','type':'api_key','value':'last','refresh_token':''}]}
out=[]
for timestamp in [0,4102444800,2**64-1]:
 target=path.with_name(f'timestamp-{timestamp}.enc');target.write_bytes(v._salt+v._fernet.encrypt_at_time(yaml.safe_dump(document).encode(),timestamp))
 old=Vault(target);old.unlock(x['password']);assert old.get('duplicate').value=='last';out.append(str(target))
print(json.dumps(out))
"#,
        &input,
    );
    for value in special.as_array().unwrap() {
        let target = PathBuf::from(value.as_str().unwrap());
        let special = Vault::unlock(&target, &password()).unwrap();
        assert_eq!(special.list_names().unwrap(), ["duplicate"]);
        assert_eq!(
            special
                .get("duplicate")
                .unwrap()
                .unwrap()
                .value
                .expose_secret(),
            "last"
        );
        special.save().unwrap();
        let output = python(
            r#"
import json,sys,yaml
from pathlib import Path
from safeyolo.core.vault import Vault
x=json.load(sys.stdin);p=Path(x['path']);v=Vault(p);v.unlock(x['password']);doc=yaml.safe_load(v._fernet.decrypt(p.read_bytes()[16:]).decode())
assert doc=={'credentials':[{'name':'duplicate','type':'api_key','value':'last'}]}
print('true')
"#,
            &json!({"path":target,"password":password().expose_secret()}),
        );
        assert_eq!(output, json!(true));
    }
    println!(
        "Python→Rust and Rust→Python full-field restart/rollback round trips pass; old, year-2100 and u64::MAX Fernet timestamps match Python's no-TTL behavior; duplicate names and unknown-field dropping agree."
    );
}

#[test]
#[ignore = "Controlled historical vault defects and expiry oracle; set SAFEYOLO_POLICY_PYTHON"]
fn historical_failed_save_partial_reload_salt_tamper_and_expiry_oracle() {
    use serde_json::json;
    let (_directory, path, vault) = setup();
    vault.store(credential("kept")).unwrap();
    let input = json!({"path":path,"password":password().expose_secret(),"expiries":[null,"","malformed","2024-01-01T00:00:00Z","2024-01-01T00:00:01Z","2024-01-01T01:00:00+01:00","2024-01-01T00:00:00","2024-01-01","2024-W01-1T00:00:01Z"]});
    let output = python(
        r#"
import json,sys,yaml
from pathlib import Path
from datetime import datetime,UTC
from unittest.mock import patch
import safeyolo.core.vault as module
x=json.load(sys.stdin);path=Path(x['path']);v=module.Vault(path);v.unlock(x['password']);original=path.read_bytes()
with patch.object(v,'save',side_effect=OSError('synthetic failure')):
 try:v.store(module.VaultCredential('failed','bearer','synthetic-failed'))
 except OSError:pass
out={'old_failed_save_published':v.get('failed') is not None,'old_disk_unchanged':path.read_bytes()==original}
v=module.Vault(path);v.unlock(x['password']);changed=bytearray(original);changed[0]^=1;path.write_bytes(changed);v._reload()
out['old_changed_salt_reload_accepted']=not v._has_changes() and v.get('kept') is not None
path.write_bytes(original);v=module.Vault(path);v.unlock(x['password'])
bad={'credentials':[{'name':'partial','type':'bearer','value':'synthetic-partial'},{'name':'broken','type':'bearer'}]}
path.write_bytes(v._salt+v._fernet.encrypt(yaml.safe_dump(bad).encode()));v._reload()
out['old_partial_reload_published']=v.get('partial') is not None and v.get('kept') is None
class Frozen(datetime):
 @classmethod
 def now(cls,tz=None):return cls(2024,1,1,tzinfo=UTC)
module.datetime=Frozen
out['expiry']=[]
for expiry in x['expiries']:
 credential=module.VaultCredential('synthetic','oauth2','synthetic-value',expires_at=expiry)
 try:out['expiry'].append(credential.is_expired())
 except TypeError:out['expiry'].append('naive_timestamp_error')
print(json.dumps(out))
"#,
        &input,
    );
    assert_eq!(output["old_failed_save_published"], json!(true));
    assert_eq!(output["old_disk_unchanged"], json!(true));
    assert_eq!(output["old_changed_salt_reload_accepted"], json!(true));
    assert_eq!(output["old_partial_reload_published"], json!(true));
    let error = vault.reload().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Format);
    assert_eq!(error.to_string(), "invalid decrypted vault document");
    assert_eq!(vault.list_names().unwrap(), ["kept"]);
    let actual: Vec<_> = input["expiries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|expiry| {
            let mut credential = credential("synthetic");
            credential.expires_at = expiry.as_str().map(str::to_owned);
            match credential.is_expired(now()) {
                Ok(value) => json!(value),
                Err(failure) if failure.kind == ErrorKind::InvalidExpiry => {
                    json!("naive_timestamp_error")
                }
                Err(_) => panic!("unexpected expiry error"),
            }
        })
        .collect();
    assert_eq!(json!(actual), output["expiry"]);
    println!(
        "Python oracle confirms 9 expiry cases and three native lifecycle corrections: failed-save publication, partial malformed reload, changed-salt reload acceptance."
    );
}

#[test]
#[ignore = "Python authenticated padding and token encoding oracle; set SAFEYOLO_POLICY_PYTHON"]
fn authenticated_bad_padding_and_python_base64_encodings_keep_the_same_acceptance() {
    use serde_json::json;
    let (_directory, path, vault) = setup();
    vault.store(credential("kept")).unwrap();
    let original = fs::read(&path).unwrap();
    let fixtures = python(
        r#"
import base64,json,sys,hmac,hashlib
from pathlib import Path
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from safeyolo.core.vault import Vault
x=json.load(sys.stdin);path=Path(x['path']);v=Vault(path);v.unlock(x['password'])
raw=path.read_bytes();token=raw[16:]
plaintext=v._fernet.decrypt(token)
for spaces in range(33):
 token=v._fernet.encrypt(plaintext+b' '*spaces)
 if token.endswith(b'='):break
assert token.endswith(b'=')
variants={'canonical':token,'standard_alphabet':token.replace(b'-',b'+').replace(b'_',b'/'),'ignored_bytes':b' \xff\n'+token[:20]+b'\x00\t!'+token[20:],'extra_padding':token+b'====','missing_padding':token.rstrip(b'='),'incomplete':token[:-1],'leading_padding':b'===='+token,'padding_after_one':token[:1]+b'='+token[1:],'padding_after_two':token[:2]+b'='+token[2:],'alphabet_suffix':token+b'AAAA','garbage_suffix':token+b'!\xff\n'}
for position in [0,1,2,3,4,5,6,7,8,len(token)-3]:
 for padding in [b'=',b'==']:
  variants[f'pad_{position}_{len(padding)}']=token[:position]+padding+token[position:]
if token.endswith(b'='):
 alphabet=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
 index=len(token.rstrip(b'='))-1;value=alphabet.index(token[index]);variants['nonzero_pad_bits']=token[:index]+bytes([alphabet[value|1]])+token[index+1:]
# Build valid-HMAC encrypted blocks with a deliberately invalid PKCS7 pad byte.
# The maintained Python primitives supply AES-CBC/HMAC; the fixture tests the
# Rust Fernet verifier, not new production cryptography.
iv=b'\0'*16;encryptor=Cipher(algorithms.AES(v._fernet._encryption_key),modes.CBC(iv)).encryptor()
encrypted=encryptor.update(b'\0'*16)+encryptor.finalize()
for version,label in [(128,'valid_hmac_bad_padding'),(129,'valid_hmac_bad_version')]:
 message=bytes([version])+(0).to_bytes(8,'big')+iv+encrypted
 variants[label]=base64.urlsafe_b64encode(message+hmac.digest(v._fernet._signing_key,message,hashlib.sha256))
out=[]
for label,value in variants.items():
 target=path.with_name(label+'.enc');target.write_bytes(raw[:16]+value)
 try:v._fernet.decrypt(value);accepted=True
 except InvalidToken:accepted=False
 out.append({'path':str(target),'label':label,'accepted':accepted})
assert not next(item['accepted'] for item in out if item['label']=='valid_hmac_bad_padding')
print(json.dumps(out))
"#,
        &json!({"path":path,"password":password().expose_secret()}),
    );
    for fixture in fixtures.as_array().unwrap() {
        fs::write(&path, fs::read(fixture["path"].as_str().unwrap()).unwrap()).unwrap();
        let result = vault.reload();
        assert_eq!(
            result.is_ok(),
            fixture["accepted"].as_bool().unwrap(),
            "{}",
            fixture["label"]
        );
        if let Err(failure) = result {
            assert_eq!(failure.kind, ErrorKind::Authentication);
        }
        assert_eq!(vault.list_names().unwrap(), ["kept"]);
    }
    fs::write(path, original).unwrap();
    println!(
        "Python token-format and authenticated invalid-padding/version differential: {} cases passed.",
        fixtures.as_array().unwrap().len()
    );
}

#[test]
#[ignore = "Python typed YAML expiry oracle; set SAFEYOLO_POLICY_PYTHON"]
fn unquoted_yaml_datetime_is_not_silently_coerced_to_a_valid_expiry_string() {
    use serde_json::json;
    let (_directory, path, vault) = setup();
    vault.store(credential("kept")).unwrap();
    let fixtures = python(
        r#"
import json,sys
from pathlib import Path
from safeyolo.core.vault import Vault
x=json.load(sys.stdin);path=Path(x['path']);v=Vault(path);v.unlock(x['password']);out=[]
for label,scalar in [('quoted',"'2099-01-01T00:00:00Z'"),('datetime','2099-01-01T00:00:00Z'),('explicit_datetime',"!!timestamp '2099-01-01T00:00:00Z'"),('ignored_timestamp',"'2099-01-01T00:00:00Z'"),('timestamp_alias','*expiry')]:
 document="credentials:\n- name: candidate\n  type: oauth2\n  value: synthetic-value\n  expires_at: "+scalar+'\n'
 if label=='ignored_timestamp':document="ignored_root: 2099-01-01T00:00:00Z\n"+document+"  ignored_field: !!timestamp '2099-01-01T00:00:00Z'\n"
 if label=='timestamp_alias':document="ignored_root: &expiry 2099-01-01T00:00:00Z\n"+document
 target=path.with_name(label+'.enc');target.write_bytes(v._salt+v._fernet.encrypt(document.encode()))
 old=Vault(target);old.unlock(x['password'])
 try:old.get('candidate').is_expired();outcome='valid_string'
 except TypeError:outcome='typed_timestamp_error'
 out.append({'path':str(target),'label':label,'old_outcome':outcome})
print(json.dumps(out))
"#,
        &json!({"path":path,"password":password().expose_secret()}),
    );
    let original = fs::read(&path).unwrap();
    for fixture in fixtures.as_array().unwrap() {
        fs::write(&path, fs::read(fixture["path"].as_str().unwrap()).unwrap()).unwrap();
        if fixture["old_outcome"] == "valid_string" {
            assert_eq!(fixture["old_outcome"], json!("valid_string"));
            vault.reload().unwrap();
            assert!(
                !vault
                    .get("candidate")
                    .unwrap()
                    .unwrap()
                    .is_expired(now())
                    .unwrap()
            );
        } else {
            assert_eq!(fixture["old_outcome"], json!("typed_timestamp_error"));
            assert_eq!(vault.reload().unwrap_err().kind, ErrorKind::Format);
            assert_eq!(vault.list_names().unwrap(), ["kept"]);
        }
        fs::write(&path, &original).unwrap();
        vault.reload().unwrap();
    }
}
