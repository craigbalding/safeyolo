//! Full authored-policy disclosure through real local HTTP and installed tools.
//! Controlled ingress proves authority checks, not an installed guest journey.
#![cfg(target_os = "linux")]

use safeyolo_proxy::{coord_tools::Client, policy::Policy};
use serde_json::{Value, json};
use std::{fs, path::Path};
use tokio::io::AsyncWriteExt;

#[path = "support/controlled_runs.rs"]
mod controlled_runs;
#[path = "support/operator_pty.rs"]
mod operator_pty;
#[allow(dead_code)]
#[path = "support/shared_approvals.rs"]
mod shared_approval_fixture;
mod test_owned_endpoint;
use shared_approval_fixture::{Fixture, HELPER_ID, WORKER_ID};

const RUN: &str = "1234567890abcdef1234567890abcdef";
const SECRET: &str = "fixture-literal-password-do-not-disclose";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_watch_shows_snapshot_identity_and_decides_the_canonical_request() {
    let f = Fixture::new().await;
    let _worker = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    fs::write(f.root.path().join("config.toml"),format!(
        "admin_port={}\nadmin_api_token_file='admin_token'\npolicy_file='policy.toml'\naudit_log_path='audit.jsonl'\n", f.admin)).unwrap();
    let source = f.source();
    let (id, pending) = request(&f).await;
    let mut terminal = operator_pty::Terminal::start(f.root.path(), &["watch", "--no-color"]);
    terminal
        .until(0, "PENDING APPROVALS: 1 (current state refreshed)")
        .await;
    terminal.until(0, "agent=worker ").await;
    terminal.send("1\n");
    terminal
        .until(0, "Request #1: approve snapshot / reject")
        .await;
    terminal.until(0, "Full authored policy snapshot:").await;
    terminal.until(0, "saved source revision:").await;
    terminal.until(0, "saved matches active: true").await;
    terminal
        .until(0, pending["snapshot"]["instance_id"].as_str().unwrap())
        .await;
    let decision = terminal.mark();
    terminal.send("approve snapshot\n");
    terminal
        .until(decision, "CANONICAL OUTCOME Request #1: approved")
        .await;
    terminal.finish().await;
    assert_eq!(read(&f, &id).await["snapshot"]["source"], source);
    assert_eq!(f.source(), source);
    f.stop().await;
}

fn client(f: &Fixture, name: &str) -> Client {
    Client {
        socket: Some(f.root.path().join(format!("{name}.sock"))),
        token_file: f.root.path().join("data/agent_token"),
        home: None,
    }
}

fn operation() -> String {
    format!("req-{}", uuid::Uuid::new_v4().simple())
}

async fn installed_tool(f: &Fixture, name: &str, input: Value) -> Value {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo-coord"))
        .args(["call", name])
        .env("SAFEYOLO_COORD_SOCKET", f.root.path().join("worker.sock"))
        .env(
            "SAFEYOLO_COORD_TOKEN_PATH",
            f.root.path().join("data/agent_token"),
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .await
        .unwrap();
    let output = child.wait_with_output().await.unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

async fn request(f: &Fixture) -> (String, Value) {
    let id = operation();
    let result = installed_tool(f, "request_policy_snapshot", json!({"operation_id":id})).await;
    assert_eq!(result["status"], "pending", "{result}");
    assert_eq!(
        result["approval"]["target"],
        result["snapshot"]["instance_id"]
    );
    assert!(result["snapshot"]["source"].is_null());
    (id, result)
}

async fn decide(f: &Fixture, id: &str, decision: &str) -> Value {
    let result = f
        .admin(
            "POST",
            &format!("/admin/approvals/{id}"),
            Some(json!({"decision":decision,"option":"snapshot"})),
        )
        .await;
    assert_eq!(result.status, 200, "{}", result.json());
    result.json()
}

async fn read(f: &Fixture, id: &str) -> Value {
    client(f, "worker")
        .call("read_policy_snapshot", &json!({"request_id":id}))
        .await
        .unwrap()
}

async fn definitions(f: &Fixture) {
    let delegation = json!({"delegation":{
        "reviewers":[{"name":"helper","agent_id":HELPER_ID}],
        "beneficiaries":[{"name":"worker","agent_id":WORKER_ID}],
        "scopes":[{"type":"network_egress","host":f.address.ip().to_string(),"ports":[f.address.port()],"all_ports":false,"actions":["request"]}],
        "expires_at":null,"grant_seconds":null,"gateway_once":true,"acknowledgment":null}});
    let preview = f
        .admin(
            "POST",
            "/admin/approval-delegations/local/preview",
            Some(delegation),
        )
        .await;
    assert_eq!(preview.status, 200, "{}", preview.json());
    let mut input =
        json!({"delegation":preview.json()["after"],"authority":preview.json()["authority"]});
    input["delegation"]["acknowledgment"] = preview.json()["revision"].clone();
    let applied = f
        .admin(
            "POST",
            "/admin/approval-delegations/local/apply",
            Some(input),
        )
        .await;
    assert_eq!(applied.status, 200, "{}", applied.json());

    let grant = json!({"grant":{"instance_id":"sy-11111111111111111111111111111111",
        "support":{"name":"helper","agent_id":HELPER_ID},"targets":[{"name":"worker","agent_id":WORKER_ID}],
        "guest_admin":false,"guest_logs":[],"lifecycle":[],"expires_at":null,"acknowledgment":null}});
    let preview = f
        .admin(
            "POST",
            "/admin/support-grants/incident/preview",
            Some(grant),
        )
        .await;
    assert_eq!(preview.status, 200, "{}", preview.json());
    let mut input =
        json!({"grant":preview.json()["after"],"authority":preview.json()["authority"]});
    input["grant"]["acknowledgment"] = preview.json()["revision"].clone();
    let applied = f
        .admin("POST", "/admin/support-grants/incident/apply", Some(input))
        .await;
    assert_eq!(applied.status, 200, "{}", applied.json());
}

#[tokio::test]
async fn approved_installed_tools_return_full_authored_source_and_same_snapshot_on_retry() {
    let f = Fixture::new().await;
    let _worker = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let _helper = controlled_runs::agent_run(f.root.path(), "helper", HELPER_ID, RUN);
    definitions(&f).await;
    let source = format!(
        "{}\n# preserve this authored comment\n[private]\npassword='{SECRET}'\n[agents.worker.services.demo]\ncapability='reader'\ntoken='provider-reference'\n",
        f.source()
    );
    f.apply(&source).await;
    let original = f.source();
    let baseline = f.agent("worker", "GET", "/policy", None).await.json();
    let (id, pending) = request(&f).await;
    let (_, equivalent) = request(&f).await;
    assert_eq!(equivalent["approval_id"], pending["approval_id"]);
    assert_eq!(read(&f, &id).await["status"], "pending");
    let approval_id = pending["approval_id"].as_str().unwrap();
    let listed = f.admin("GET", "/admin/approvals", None).await.json();
    assert!(listed.to_string().contains(approval_id));
    let explained = f
        .admin(
            "POST",
            &format!("/admin/approvals/{approval_id}/explain"),
            Some(json!({"option":"snapshot"})),
        )
        .await;
    assert_eq!(explained.status, 200, "{}", explained.json());
    assert!(
        explained
            .json()
            .to_string()
            .contains("saved_source_revision")
    );
    assert_eq!(
        decide(&f, approval_id, "approve").await["status"],
        "approved"
    );
    let disclosed = installed_tool(&f, "read_policy_snapshot", json!({"request_id":id})).await;
    let snapshot = &disclosed["snapshot"];
    let text = snapshot["source"].as_str().unwrap();
    let authored = text.parse::<toml_edit::DocumentMut>().unwrap();
    let support: Value =
        serde_json::from_str(authored["support_grants"]["incident"].as_str().unwrap()).unwrap();
    assert_eq!(support["targets"][0]["agent_id"], WORKER_ID);
    let delegation: Value =
        serde_json::from_str(authored["approval_delegations"]["local"].as_str().unwrap()).unwrap();
    assert_eq!(delegation["reviewers"][0]["agent_id"], HELPER_ID);
    assert_eq!(
        authored["controls"]["credentials"]["enabled"].as_bool(),
        Some(false)
    );
    assert!(text.contains("preserve this authored comment"));
    assert!(text.contains("provider-reference"));
    assert!(!disclosed.to_string().contains(SECRET));
    assert!(!text.contains("synthetic-operator-token"));
    assert!(
        snapshot["effective"]["controls"]["network"]["enabled"]
            .as_bool()
            .unwrap()
    );
    assert!(snapshot["saved_matches_active"].as_bool().unwrap());
    assert_eq!(snapshot["redactions"].as_array().unwrap().len(), 1);
    assert_eq!(f.source(), original);
    assert_eq!(
        f.agent("worker", "GET", "/policy", None).await.json(),
        baseline
    );
    assert_eq!(read(&f, approval_id).await["snapshot"], *snapshot);
    let retried = client(&f, "worker")
        .call("request_policy_snapshot", &json!({"operation_id":id}))
        .await
        .unwrap();
    assert_eq!(retried["approval_id"], pending["approval_id"]);
    assert_eq!(
        decide(&f, approval_id, "approve").await["status"],
        "approved"
    );
    f.apply(&format!(
        "{original}\n# later revision not covered by this approval\n"
    ))
    .await;
    assert_eq!(read(&f, &id).await["snapshot"], *snapshot);
    let wrong = f
        .agent("helper", "GET", &format!("/policy/snapshots/{id}"), None)
        .await;
    assert_eq!(wrong.status, 404);
    assert!(!String::from_utf8_lossy(&wrong.body).contains("provider-reference"));
    let f = f.restart().await;
    assert_eq!(read(&f, &id).await["snapshot"], *snapshot);
    let before_stop = f.source();
    f.proxy.shutdown().await;
    let audit = fs::read_to_string(f.root.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains(SECRET));
    assert!(!audit.contains("preserve this authored comment"));
    assert!(audit.contains("agent.policy_snapshot_requested"));
    assert!(audit.contains("admin.policy_snapshot_decided"));
    assert!(!audit.contains("Audit event validation failed"));
    assert_eq!(
        fs::read_to_string(f.root.path().join("policy.toml")).unwrap(),
        before_stop
    );
}

#[tokio::test]
async fn decline_stale_bases_and_replaced_requesters_never_disclose_source() {
    let f = Fixture::new().await;
    let _worker = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let _helper = controlled_runs::agent_run(f.root.path(), "helper", HELPER_ID, RUN);
    let (declined, _) = request(&f).await;
    assert_eq!(decide(&f, &declined, "reject").await["status"], "rejected");
    assert!(read(&f, &declined).await["snapshot"]["source"].is_null());
    let (stale, _) = request(&f).await;
    fs::write(
        f.root.path().join("policy.toml"),
        format!("{}\n# saved edit\n", f.source()),
    )
    .unwrap();
    assert_eq!(decide(&f, &stale, "approve").await["status"], "superseded");
    assert!(read(&f, &stale).await["snapshot"]["source"].is_null());
    let (mismatch, _) = request(&f).await;
    assert_eq!(decide(&f, &mismatch, "approve").await["status"], "approved");
    let snapshot = read(&f, &mismatch).await;
    assert_eq!(snapshot["snapshot"]["saved_matches_active"], false);
    assert_ne!(
        snapshot["snapshot"]["saved_source_revision"],
        snapshot["snapshot"]["active_source_revision"]
    );
    assert!(
        snapshot["snapshot"]["source"]
            .as_str()
            .unwrap()
            .contains("# saved edit")
    );
    let _new_worker = controlled_runs::agent_run(
        f.root.path(),
        "worker",
        WORKER_ID,
        "2234567890abcdef1234567890abcdef",
    );
    let refused = f
        .agent(
            "worker",
            "GET",
            &format!("/policy/snapshots/{mismatch}"),
            None,
        )
        .await;
    assert_eq!(refused.status, 404);
    let (new_id, _) = request(&f).await;
    assert_eq!(decide(&f, &new_id, "approve").await["status"], "approved");
    f.apply(
        &f.source()
            .replace(WORKER_ID, "ag-44444444444444444444444444444444"),
    )
    .await;
    let replaced = f
        .agent(
            "worker",
            "GET",
            &format!("/policy/snapshots/{new_id}"),
            None,
        )
        .await;
    assert_ne!(replaced.status, 200);
    assert!(!String::from_utf8_lossy(&replaced.body).contains("source_kind"));
    f.stop().await;
}

#[tokio::test]
async fn missing_private_snapshot_reports_unavailable_without_reading_new_source() {
    let f = Fixture::new().await;
    let _worker = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let (id, pending) = request(&f).await;
    decide(&f, &id, "approve").await;
    let saved = f.source();
    let db = rusqlite::Connection::open(f.root.path().join("data/approvals.sqlite3")).unwrap();
    assert_eq!(
        db.execute(
            "DELETE FROM policy_snapshots WHERE approval_id=?1",
            [pending["approval_id"].as_str().unwrap()]
        )
        .unwrap(),
        1
    );
    let failed = f
        .agent("worker", "GET", &format!("/policy/snapshots/{id}"), None)
        .await;
    assert_eq!(failed.status, 503);
    assert!(failed.json()["snapshot"]["source"].is_null());
    assert_eq!(f.source(), saved);
    f.stop().await;
}

#[tokio::test]
async fn an_authored_policy_receipt_cannot_supply_the_disclosure_decision() {
    let f = Fixture::new().await;
    let _worker = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let (id, pending) = request(&f).await;
    let mut source = f.source().parse::<toml_edit::DocumentMut>().unwrap();
    source["approval_results"][pending["approval_id"].as_str().unwrap()] = toml_edit::value(
        json!({
            "authority_digest":pending["authority_digest"],"option":"snapshot",
            "result":{"status":"approved","snapshot_id":pending["snapshot"]["snapshot_id"]}
        })
        .to_string(),
    );
    f.apply(&source.to_string()).await;
    let result = read(&f, &id).await;
    assert_eq!(result["status"], "superseded");
    assert!(result["snapshot"]["source"].is_null());
    assert_eq!(decide(&f, &id, "approve").await["status"], "superseded");
    f.stop().await;
}

#[tokio::test]
async fn paths_identity_overrides_remote_homes_and_delegated_decisions_are_refused() {
    let f = Fixture::new().await;
    let _worker = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let _helper = controlled_runs::agent_run(f.root.path(), "helper", HELPER_ID, RUN);
    definitions(&f).await;
    for field in ["path", "agent", "instance_id", "source", "home"] {
        let mut body = json!({"operation_id":operation()});
        body[field] = json!("/etc/passwd");
        let refused = f
            .agent("worker", "POST", "/policy/snapshots", Some(body))
            .await;
        assert_eq!(refused.status, 400, "{}", refused.json());
    }
    let refused = f
        .agent(
            "worker",
            "POST",
            "/policy/snapshots?home=elsewhere",
            Some(json!({"operation_id":operation()})),
        )
        .await;
    assert_eq!(refused.status, 400);
    assert!(
        client(&f, "worker")
            .call(
                "request_policy_snapshot",
                &json!({"operation_id":operation(),"home":"elsewhere"})
            )
            .await
            .is_err()
    );
    let (id, _) = request(&f).await;
    let refused = f
        .agent(
            "helper",
            "POST",
            &format!("/approvals/{id}/resolve"),
            Some(json!({"decision":"approve","delegation":"local","option":"snapshot"})),
        )
        .await;
    assert_ne!(refused.status, 200);
    let refused = f
        .agent(
            "worker",
            "POST",
            &format!("/approvals/{id}/resolve"),
            Some(json!({"decision":"approve","delegation":"local","option":"snapshot"})),
        )
        .await;
    assert_ne!(refused.status, 200);
    assert_eq!(read(&f, &id).await["status"], "pending");
    assert!(read(&f, &id).await["snapshot"]["source"].is_null());
    assert_eq!(
        f.agent("worker", "GET", "/policy/snapshots/../../admin_token", None)
            .await
            .status,
        404
    );
    f.stop().await;
}

#[test]
fn array_encoded_credentials_are_redacted_and_restored_at_their_original_fields() {
    let record = json!({"password":"array-private-password", "api_key":"array-private-key",
        "token":"provider-reference", "note":"keep-note"})
    .to_string();
    for (authored, path, json_prefix) in [
        (
            format!("records=['{record}']"),
            json!(["private", "records", 0]),
            vec![],
        ),
        (
            format!("records=[['{record}']]"),
            json!(["private", "records", 0, 0]),
            vec![],
        ),
        (
            format!("records=[{{record='{record}'}}]"),
            json!(["private", "records", 0, "record"]),
            vec![],
        ),
        (
            format!("records=['[{record}]']"),
            json!(["private", "records", 0]),
            vec![json!(0)],
        ),
        (
            format!("[[private.records]]\nrecord='{record}'"),
            json!(["private", "records", 0, "record"]),
            vec![],
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let policy_path = root.path().join("policy.toml");
        let source = format!("# exact authored bytes\nbudget=17\n[hosts]\n[private]\n{authored}\n");
        fs::write(&policy_path, &source).unwrap();
        let policy = Policy::from_native_path(&policy_path).unwrap();
        let run =
            serde_json::from_value(json!({"agent":"worker","agent_id":WORKER_ID,"run_id":RUN}))
                .unwrap();
        let snapshot = policy
            .full_snapshot(&source, &policy_path, "fixture-instance", &run)
            .unwrap();
        let disclosed = snapshot.disclosed();
        let candidate = disclosed["source"].as_str().unwrap();
        assert!(!candidate.contains("array-private-password"), "{authored}");
        assert!(!candidate.contains("array-private-key"), "{authored}");
        assert!(candidate.contains("provider-reference"));
        assert_ne!(
            disclosed["source_revision"],
            disclosed["disclosed_source_revision"]
        );
        assert_eq!(snapshot.materialize(candidate).unwrap().as_str(), source);

        let fields = disclosed["redactions"].as_array().unwrap();
        assert_eq!(fields.len(), 2);
        for name in ["password", "api_key"] {
            let mut json_path = json_prefix.clone();
            json_path.push(json!(name));
            let field = fields
                .iter()
                .find(|field| field["json_path"] == json!(json_path))
                .unwrap();
            assert_eq!(field["path"], path);
            let marker = field["marker"].as_str().unwrap();
            assert!(candidate.contains(marker));
            assert!(
                snapshot
                    .materialize(&candidate.replace(marker, "literal-placeholder"))
                    .is_err()
            );
            assert!(
                snapshot
                    .materialize(&candidate.replace(marker, "__SAFEYOLO_PRESERVE_forged__"))
                    .is_err()
            );
            assert!(
                snapshot
                    .materialize(&format!("{candidate}\ncopied_marker='{marker}'\n"))
                    .is_err()
            );
        }

        let changed = candidate
            .replace("budget=17", "budget=23")
            .replace("keep-note", "edited-note");
        let restored = snapshot.materialize(&changed).unwrap();
        let expected = source
            .replace("budget=17", "budget=23")
            .replace("keep-note", "edited-note");
        assert_eq!(
            restored.parse::<toml::Value>().unwrap(),
            expected.parse::<toml::Value>().unwrap()
        );

        let mut removed = changed.parse::<toml_edit::DocumentMut>().unwrap();
        removed["private"].as_table_mut().unwrap().remove("records");
        assert!(snapshot.materialize(&removed.to_string()).is_err());
        assert_eq!(fs::read_to_string(policy_path).unwrap(), source);
    }
}

#[test]
fn materialization_restores_hidden_values_and_preserves_unrelated_source() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("policy.toml");
    let source = format!(
        "# exact authored bytes\nbudget=17\ndescription='__SAFEYOLO_PRESERVE_authored_example__'\n[hosts]\n[private]\npassword='{SECRET}'\nitems=[{{api_key='another-private-fixture', note='keep'}}]\n[agents.worker]\nagent_id='{WORKER_ID}'\n[agents.worker.services.demo]\ncapability='reader'\ntoken='provider-reference'\n"
    );
    let mut document = source.parse::<toml_edit::DocumentMut>().unwrap();
    document["approval_results"]["prior"] = toml_edit::value(
        json!({"result":{"bound_values":{
            "api_key":"encoded-private-fixture","repository":"keep-repository"
        }}})
        .to_string(),
    );
    let source = document.to_string();
    fs::write(&path, &source).unwrap();
    let policy = Policy::from_native_path(Path::new(&path)).unwrap();
    let run = serde_json::from_value(json!({"agent":"worker","agent_id":WORKER_ID,"run_id":RUN}))
        .unwrap();
    let snapshot = policy
        .full_snapshot(&source, &path, "fixture-instance", &run)
        .unwrap();
    let disclosed = snapshot.disclosed();
    let candidate = disclosed["source"].as_str().unwrap();
    assert!(!candidate.contains(SECRET));
    assert!(!candidate.contains("another-private-fixture"));
    assert!(!candidate.contains("encoded-private-fixture"));
    assert!(candidate.contains("provider-reference"));
    assert_eq!(snapshot.materialize(candidate).unwrap().as_str(), source);
    let changed = candidate.replace("budget=17", "budget=23");
    let restored = snapshot.materialize(&changed).unwrap();
    assert!(restored.contains("budget=23"));
    assert!(restored.contains(SECRET));
    assert!(restored.contains("another-private-fixture"));
    assert!(restored.contains("note='keep'"));
    let restored_document = restored.parse::<toml_edit::DocumentMut>().unwrap();
    let restored_record: Value = serde_json::from_str(
        restored_document["approval_results"]["prior"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        restored_record["result"]["bound_values"]["api_key"],
        "encoded-private-fixture"
    );
    assert_eq!(
        restored_record["result"]["bound_values"]["repository"],
        "keep-repository"
    );
    let encoded_marker = disclosed["redactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| !field["json_path"].is_null())
        .unwrap()["marker"]
        .as_str()
        .unwrap();
    assert!(
        snapshot
            .materialize(&changed.replace(encoded_marker, "literal-encoded-placeholder"))
            .is_err()
    );
    let marker = disclosed["redactions"][0]["marker"].as_str().unwrap();
    assert!(
        snapshot
            .materialize(&changed.replace(marker, "literal-placeholder"))
            .is_err()
    );
    let mut removed = changed.parse::<toml_edit::DocumentMut>().unwrap();
    removed["private"]
        .as_table_mut()
        .unwrap()
        .remove("password");
    assert!(snapshot.materialize(&removed.to_string()).is_err());
    assert!(
        snapshot
            .materialize(&format!("{changed}\ncopied_marker=\"{marker}\"\n"))
            .is_err()
    );
    assert!(
        snapshot
            .materialize(&changed.replace(marker, "__SAFEYOLO_PRESERVE_forged__"))
            .is_err()
    );
    assert_eq!(fs::read_to_string(path).unwrap(), source);
}
