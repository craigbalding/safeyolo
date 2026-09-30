use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use ring::digest::{SHA256, digest};
use safeyolo_proxy::{
    approvals::{self, ErrorKind, NetworkScope},
    policy::{Format, NetworkRequest, Policy},
};
use serde_json::{Value, json};

const COMPARATOR_COMMIT: &str = "7e934a5470f1aa9b74052fea08c6bae9b5f32e8a";
const FIXTURE_SOURCE_PATH: &str = "proxy/tests/state_policy_transition.rs";
const FIXTURE_SOURCE_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/state_policy_transition.rs"
));
const INITIAL_POLICY: &str = r#"# state transition fixture
budget = 1200
[hosts]
"*" = { egress = "prompt" }
"legacy.example" = { egress = "deny" }
[agents.alice.hosts]
"legacy-agent.example:443" = { egress = "deny", expires = 2099-01-01T00:00:00Z }
"#;

fn digest_bytes(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn digest_file(path: &Path) -> String {
    digest_bytes(&fs::read(path).unwrap())
}

fn mode(path: &Path) -> String {
    format!(
        "{:04o}",
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    )
}

fn git_output(repository: &Path, args: &[&str]) -> String {
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

fn fixture_identity(repository: &Path) -> Value {
    let source_path = repository.join(FIXTURE_SOURCE_PATH);
    assert!(source_path.is_file(), "fixture source is missing");
    let candidate_commit = git_output(repository, &["rev-parse", "HEAD"]);
    let object_ref = format!("HEAD:{FIXTURE_SOURCE_PATH}");
    let git_blob_sha1 = git_output(repository, &["rev-parse", &object_ref]);
    assert_eq!(
        git_output(repository, &["hash-object", FIXTURE_SOURCE_PATH]),
        git_blob_sha1,
        "working-tree fixture must be the candidate's committed source"
    );
    let committed = Command::new("git")
        .args(["cat-file", "blob", &git_blob_sha1])
        .current_dir(repository)
        .output()
        .unwrap();
    assert!(
        committed.status.success(),
        "git cat-file failed for fixture blob {git_blob_sha1}"
    );
    assert_eq!(
        committed.stdout, FIXTURE_SOURCE_BYTES,
        "compiled fixture, worktree source and committed blob must agree"
    );
    let working_tree_sha256 = digest_file(&source_path);
    let compiled_sha256 = digest_bytes(FIXTURE_SOURCE_BYTES);
    assert_eq!(working_tree_sha256, compiled_sha256);
    json!({
        "repository": repository,
        "relative_path": FIXTURE_SOURCE_PATH,
        "absolute_path": source_path,
        "candidate_commit": candidate_commit,
        "git_blob_sha1": git_blob_sha1,
        "working_tree_sha256": working_tree_sha256,
        "compiled_fixture_sha256": compiled_sha256,
        "verification": {
            "blob": format!("git -C {} rev-parse {}:{}", repository.display(), candidate_commit, FIXTURE_SOURCE_PATH),
            "content": format!("git -C {} cat-file blob {} | sha256sum", repository.display(), git_blob_sha1),
        },
    })
}

fn request<'a>(host: &'a str, agent: Option<&'a str>, port: u16) -> NetworkRequest<'a> {
    NetworkRequest {
        host,
        agent,
        port: Some(port),
        method: "GET",
        path: "/state-transition",
    }
}

fn evaluate(policy: &Policy, host: &str, agent: Option<&str>, port: u16) -> String {
    format!(
        "{:?}",
        policy
            .evaluate(request(host, agent, port), 1_800_000_000_000., false)
            .unwrap()
            .effect
    )
    .to_ascii_lowercase()
}

fn native_snapshot(policy: &Policy, path: &Path, operation: &str) -> Value {
    json!({
        "backend": "rust-native",
        "operation": operation,
        "policy": {
            "sha256": digest_file(path),
            "mode": mode(path),
            "contains_fixture_comment": fs::read_to_string(path).unwrap().contains("# state transition fixture"),
        },
        "effective": {
            "python_host_allow": evaluate(policy, "python.example", Some("alice"), 443),
            "python_host_deny": evaluate(policy, "python-denied.example", Some("alice"), 8443),
            "native_host_allow": evaluate(policy, "native.example", Some("alice"), 8443),
            "native_host_deny": evaluate(policy, "native-denied.example", None, 443),
            "rejected_host": evaluate(policy, "rejected.example", Some("alice"), 9443),
            "python_after_host_allow": evaluate(policy, "python-after.example", Some("alice"), 9443),
            "legacy_global_deny": evaluate(policy, "legacy.example", None, 443),
            "legacy_agent_deny": evaluate(policy, "legacy-agent.example", Some("alice"), 443),
        },
    })
}

fn comparator_stage(root: &Path, operation: &str) -> Value {
    let source = PathBuf::from(
        std::env::var_os("SAFEYOLO_STATE_PYTHON_SOURCE")
            .expect("SAFEYOLO_STATE_PYTHON_SOURCE must name the comparator checkout"),
    );
    let executable = PathBuf::from(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON")
            .expect("SAFEYOLO_POLICY_PYTHON must name the comparator interpreter"),
    );
    assert_eq!(
        git_output(&source, &["rev-parse", "HEAD"]),
        COMPARATOR_COMMIT
    );
    assert!(
        git_output(&source, &["status", "--porcelain"]).is_empty(),
        "selected Python comparator must be clean"
    );
    assert!(
        executable.is_file(),
        "selected Python comparator is missing"
    );
    let script = r#"
import hashlib
import importlib.metadata
import json
import pathlib
import stat
import sys

from safeyolo.policy.engine import PolicyEngine

root = pathlib.Path(sys.argv[1])
operation = sys.argv[2]
expected_executable = pathlib.Path(sys.argv[3])
source = pathlib.Path(sys.argv[4])
assert pathlib.Path(sys.executable).resolve() == expected_executable.resolve()
policy = root / 'policy.toml'

def snapshot(engine):
    def effect(host, agent, port):
        return engine.evaluate_request(
            host,
            path='/state-transition',
            method='GET',
            agent=agent,
            port=port,
            consume_budget=False,
        ).effect
    return {
        'policy': {
            'sha256': hashlib.sha256(policy.read_bytes()).hexdigest(),
            'mode': format(stat.S_IMODE(policy.stat().st_mode), '04o'),
            'contains_fixture_comment': '# state transition fixture' in policy.read_text(),
        },
        'effective': {
            'python_host_allow': effect('python.example', 'alice', 443),
            'python_host_deny': effect('python-denied.example', 'alice', 8443),
            'native_host_allow': effect('native.example', 'alice', 8443),
            'native_host_deny': effect('native-denied.example', None, 443),
            'rejected_host': effect('rejected.example', 'alice', 9443),
            'python_after_host_allow': effect('python-after.example', 'alice', 9443),
            'legacy_global_deny': effect('legacy.example', None, 443),
            'legacy_agent_deny': effect('legacy-agent.example', 'alice', 443),
        },
    }

if operation == 'write':
    policy.write_text(__INITIAL_POLICY__)
    policy.chmod(0o600)
    engine = PolicyEngine(baseline_path=policy)
    engine._loader.stop_watcher()
    engine.add_host_allowance('python.example', rate=400, agent='alice', port=443)
    engine.add_host_denial(
        'python-denied.example',
        expires='2099-01-01T00:00:00+00:00',
        agent='alice',
        port=8443,
    )
    result = snapshot(engine)
    engine.done()
elif operation == 'read-and-write':
    engine = PolicyEngine(baseline_path=policy)
    engine._loader.stop_watcher()
    before = snapshot(engine)
    assert before['effective']['native_host_allow'] == 'allow'
    assert before['effective']['native_host_deny'] == 'deny'
    assert before['effective']['rejected_host'] == 'prompt'
    engine.add_host_allowance('python-after.example', rate=700, agent='alice', port=9443)
    engine.add_host_denial(
        'native.example',
        expires='2099-01-01T00:00:00+00:00',
        agent='alice',
        port=8443,
    )
    result = snapshot(engine)
    engine.done()
else:
    raise AssertionError(operation)

print(json.dumps({
    'backend': 'python-comparator',
    'operation': operation,
    'runtime': {
        'source': str(source),
        'commit': '7e934a5470f1aa9b74052fea08c6bae9b5f32e8a',
        'launcher': str(expected_executable),
        'program': sys.executable,
        'python_version': '.'.join(map(str, sys.version_info[:3])),
        'safeyolo': importlib.metadata.version('safeyolo'),
        'mitmproxy': importlib.metadata.version('mitmproxy'),
        'tomlkit': importlib.metadata.version('tomlkit'),
        'safeyolo_file': str(pathlib.Path(__import__('safeyolo').__file__).resolve()),
        'policy_engine_file': str(pathlib.Path(__import__('safeyolo.policy.engine', fromlist=['__file__']).__file__).resolve()),
    },
    'state': result,
}))
"#;
    let script = script.replace("__INITIAL_POLICY__", &format!("{INITIAL_POLICY:?}"));
    let output = Command::new(&executable)
        .arg("-c")
        .arg(script)
        .arg(root)
        .arg(operation)
        .arg(&executable)
        .arg(&source)
        .env(
            "PYTHONPATH",
            format!("{}:{}", source.join("cli/src").display(), source.display()),
        )
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Python policy stage {operation} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "Python policy stage {operation} returned invalid JSON: {error}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn retain_raw(evidence: &Path, name: &str, policy: &Path) -> Value {
    let destination = evidence.join(name);
    fs::copy(policy, &destination).unwrap();
    json!({
        "path": destination,
        "sha256": digest_file(&destination),
        "mode": mode(&destination),
    })
}

#[test]
#[ignore = "selected Python→Rust→Python→Rust host-policy approval transition"]
fn selected_python_native_python_native_host_policy_transition() {
    let evidence = PathBuf::from(
        std::env::var_os("SAFEYOLO_STATE_EVIDENCE_DIR")
            .expect("SAFEYOLO_STATE_EVIDENCE_DIR must retain evidence"),
    );
    fs::create_dir_all(&evidence).unwrap();
    let root = tempfile::tempdir().unwrap();
    let policy = root.path().join("policy.toml");

    let initial = comparator_stage(root.path(), "write");
    let initial_policy = retain_raw(&evidence, "01-python-initial-policy.toml", &policy);
    assert_eq!(
        initial["state"]["policy"]["sha256"],
        initial_policy["sha256"]
    );
    assert_eq!(initial["state"]["policy"]["mode"], "0600");

    let mut active = Policy::from_path(&policy).unwrap();
    let first_native = native_snapshot(&active, &policy, "read-before-native-write");
    assert_eq!(
        initial["state"]["effective"], first_native["effective"],
        "native reader must use the old comparator's host decisions"
    );
    assert_eq!(initial["state"]["policy"]["contains_fixture_comment"], true);
    assert_eq!(first_native["policy"]["mode"], "0600");

    let native_scope = NetworkScope::new("native.example", Some("alice"), Some(8443)).unwrap();
    approvals::allow_host(&policy, &native_scope, Some(600), |source| {
        active = Policy::parse(source, Format::Toml).map_err(|error| error.to_string())?;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        evaluate(&active, "native.example", Some("alice"), 8443),
        "allow"
    );

    let rejected_before = fs::read(&policy).unwrap();
    let mut activation_calls = 0;
    let rejected_scope = NetworkScope::new("rejected.example", Some("alice"), Some(9443)).unwrap();
    let rejected = approvals::allow_host(&policy, &rejected_scope, Some(500), |source| {
        activation_calls += 1;
        if activation_calls == 1 {
            Err("synthetic activation rejection".to_owned())
        } else {
            active = Policy::parse(source, Format::Toml).map_err(|error| error.to_string())?;
            Ok(())
        }
    })
    .unwrap_err();
    assert_eq!(rejected.kind, ErrorKind::Activation);
    assert_eq!(
        activation_calls, 2,
        "rollback must reactivate the original policy"
    );
    assert_eq!(fs::read(&policy).unwrap(), rejected_before);
    assert_eq!(
        evaluate(&active, "rejected.example", Some("alice"), 9443),
        "prompt",
        "rejected policy must not become active"
    );
    let native_failure = json!({
        "backend": "rust-native",
        "operation": "rejected-write-rollback",
        "policy": {
            "sha256": digest_file(&policy),
            "mode": mode(&policy),
            "bytes_unchanged": fs::read(&policy).unwrap() == rejected_before,
        },
        "effective": {
            "rejected_host": evaluate(&active, "rejected.example", Some("alice"), 9443),
        },
    });
    let failed_policy = retain_raw(
        &evidence,
        "03-native-rejected-rollback-policy.toml",
        &policy,
    );
    assert_eq!(failed_policy["sha256"], native_failure["policy"]["sha256"]);

    let denied_scope = NetworkScope::new("native-denied.example", None, Some(443)).unwrap();
    approvals::deny_host(&policy, &denied_scope, None, |source| {
        active = Policy::parse(source, Format::Toml).map_err(|error| error.to_string())?;
        Ok(())
    })
    .unwrap();
    let after_native_policy = retain_raw(&evidence, "02-native-written-policy.toml", &policy);
    let after_native = native_snapshot(&active, &policy, "native-write-and-rollback-complete");
    assert_eq!(after_native["effective"]["native_host_allow"], "allow");
    assert_eq!(after_native["effective"]["native_host_deny"], "deny");
    assert_eq!(after_native["effective"]["rejected_host"], "prompt");
    assert_eq!(
        after_native_policy["sha256"],
        after_native["policy"]["sha256"]
    );

    let python_after = comparator_stage(root.path(), "read-and-write");
    let python_after_policy = retain_raw(
        &evidence,
        "04-python-read-native-write-policy.toml",
        &policy,
    );
    assert_eq!(
        python_after["state"]["effective"]["native_host_allow"], "deny",
        "old Python reader must observe its own post-native denial"
    );
    assert_eq!(
        python_after["state"]["effective"]["python_after_host_allow"],
        "allow"
    );
    assert_eq!(
        python_after_policy["sha256"],
        python_after["state"]["policy"]["sha256"]
    );

    active = Policy::from_path(&policy).unwrap();
    let final_native = native_snapshot(&active, &policy, "restart-after-python-write");
    assert_eq!(
        final_native["effective"], python_after["state"]["effective"],
        "fresh native reader must use the prior release's durable write"
    );
    let final_policy = retain_raw(&evidence, "05-native-final-policy.toml", &policy);
    assert_eq!(final_policy["sha256"], final_native["policy"]["sha256"]);

    let native_source = git_output(
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap(),
        &["rev-parse", "HEAD"],
    );
    let native_repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let fixture = fixture_identity(native_repository);
    let executable = PathBuf::from(std::env::var_os("SAFEYOLO_POLICY_PYTHON").unwrap());
    let source = PathBuf::from(std::env::var_os("SAFEYOLO_STATE_PYTHON_SOURCE").unwrap());
    let manifest = json!({
        "schema": 1,
        "family": "host-policy-and-network-approvals",
        "comparator": initial["runtime"],
        "native": {
            "source": native_source.clone(),
            "package": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "test": "selected_python_native_python_native_host_policy_transition",
            "fixture": fixture,
        },
        "commands": {
            "python": format!("{} -c <embedded-policy-fixture> ROOT OP", executable.display()),
            "native": "cargo test --test state_policy_transition selected_python_native_python_native_host_policy_transition -- --ignored --exact --nocapture",
        },
        "source_identity": {
            "comparator_checkout": source,
            "comparator_commit": COMPARATOR_COMMIT,
            "native_commit": native_source,
        },
        "raw_state": [
            initial_policy,
            after_native_policy,
            failed_policy,
            python_after_policy,
            final_policy,
        ],
        "rollback": native_failure,
        "stages": [initial, first_native, after_native, python_after, final_native],
        "secret_free": true,
    });
    let manifest_path = evidence.join("policy-python-rust-python-rust.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    println!(
        "host policy transition manifest: {}",
        serde_json::to_string_pretty(&manifest).unwrap()
    );
}
