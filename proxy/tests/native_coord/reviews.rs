//! The same public check/challenge operations over code and report artifacts.
use super::*;
use rusqlite::Connection;

const ALICE: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn principal(id: &str) -> Value {
    json!({"kind":"agent","id":id})
}
pub(super) fn subject(work: &Value) -> Value {
    json!({"kind":"output","work_id":work["work_id"],"target_generation":work["target_generation"]})
}
fn hash(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub(super) async fn claim(client: &Client, work: &Value, op: &str) -> Value {
    client.call("claim_work",&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],"operation_id":op})).await.unwrap()["work"].clone()
}
pub(super) async fn read(client: &Client, work: &Value) -> Value {
    client
        .call(
            "read_work",
            &json!({"room_name":"shared","work_id":work["work_id"]}),
        )
        .await
        .unwrap()
}
pub(super) async fn publish(client: &Client, work: &Value, path: &Path, op: &str) -> Value {
    let digest = hash(&fs::read(path).unwrap());
    client.call("publish_work_output",&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],
        "expected_target_generation":work["target_generation"],"target_ref":format!("file://{}#sha256={digest}",path.display()),"execution_outcome":"succeeded","summary":"Retained exact artifact","operation_id":op})).await.unwrap()["work"].clone()
}
async fn request(client: &Client, work: &Value, op: &str) -> Value {
    client.call("request_check",&json!({"room_name":"shared","subject":subject(work),"criterion":"Verify the retained artifact includes the required result",
        "reviewer":principal(BOB),"independent":true,"operation_id":op})).await.unwrap()["work"].clone()
}
pub(super) fn answer(work: &Value, verdict: &str, op: &str) -> Value {
    json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],"verdict":verdict,"summary":"Inspected retained artifact bytes","operation_id":op})
}
pub(super) fn requirements(
    work: &Value,
    checks: &[Value],
    challenges: &[Value],
    op: &str,
) -> Value {
    json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],
        "expected_generation":work["claim_generation"],"expected_requirements_version":work["acceptance_requirements"]["version"].as_i64().unwrap_or(0),
        "authorities":[principal(BOB)],"deciders":[principal(BOB),{"kind":"operator","id":"operator"}],"independent":true,
        "checks":checks.iter().map(|w|json!({"work_id":w["work_id"],"version":w["version"]})).collect::<Vec<_>>(),
        "challenges":challenges.iter().map(|w|json!({"work_id":w["work_id"],"version":w["version"]})).collect::<Vec<_>>(),
        "reason":"Select the independent review obligations for this retained output","operation_id":op})
}
fn selection(work: &Value, review: &Value, kind: &str, replace: Option<&Value>, op: &str) -> Value {
    let mut input = json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],
        "expected_generation":work["claim_generation"],"expected_requirements_version":work["acceptance_requirements"]["version"],
        "review_kind":kind,"review":{"work_id":review["work_id"],"version":review["version"]},
        "reason":"Amend one required review while retaining the remaining policy","operation_id":op});
    if let Some(replace) = replace {
        input["replace_work_id"] = replace["work_id"].clone();
    }
    input
}

async fn commit_without_reply(root: &Path, input: &Value, action: &str) {
    let mut body = input.clone();
    body.as_object_mut().unwrap().remove("room_name");
    body["action"] = json!(action);
    let body = body.to_string();
    let mut socket = tokio::net::UnixStream::connect(root.join("bob.sock"))
        .await
        .unwrap();
    let token = fs::read_to_string(root.join("data/agent_token")).unwrap();
    socket.write_all(format!("POST /api/coord/rooms/shared/work HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",token.trim(),body.len()).as_bytes()).await.unwrap();
    stage0::until(|| {
        Connection::open(root.join("data/coord/v0.db"))
            .unwrap()
            .query_row(
                "SELECT count(*) FROM coord_operations WHERE operation_id=?1",
                [input["operation_id"].as_str().unwrap()],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
            == 1
    })
    .await;
    // Deliberately lose the committed HTTP response. Recovery must use the
    // original operation ID and inputs after the caller restarts the proxy.
    drop(socket);
}
pub(super) fn acceptance(work: &Value, verdict: &str, op: &str) -> Value {
    json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],
        "expected_generation":work["claim_generation"],"expected_requirements_version":work["acceptance_requirements"]["version"],
        "expected_target_generation":work["target_generation"],"verdict":verdict,
        "summary":"Inspected the exact retained output and selected review outcomes","operation_id":op})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; real assigned checks, challenges and attributed dispositions"]
async fn code_and_report_checks_challenges_corrections_and_independent_dispositions() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let retained = tempfile::Builder::new()
        .prefix("coord-reviews-")
        .tempdir()
        .unwrap()
        .keep();
    let root = retained.join("instance");
    fs::create_dir(&root).unwrap();
    println!("review fixture: {}", retained.display());
    assert!(host_cli(&root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n").unwrap();
    fs::write(root.join("policy.toml"),format!("[controls.network]\nenabled=false\n[hosts]\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='{BOB}'\n")).unwrap();
    coord_json(&root, &["start", "--binary", &nats]).await;
    let cleanup = NatsCleanup(root.clone());
    coord_json(&root, &["room", "create", "shared"]).await;
    for name in ["alice", "bob"] {
        coord_json(&root, &["grant", "shared", name]).await;
    }
    let mut proxy = stage0::start_proxy(&root).await;
    let client = |name: &str| Client {
        socket: Some(root.join(format!("{name}.sock"))),
        token_file: root.join("data/agent_token"),
        home: None,
    };
    let alice = client("alice");
    let bob = client("bob");
    let artifacts = retained.join("artifacts");
    fs::create_dir(&artifacts).unwrap();
    for (kind, extension, original, correction) in [
        (
            "code",
            "rs",
            "fn main() { println!(\"omitted\"); }\n",
            "fn main() { println!(\"required result\"); }\n",
        ),
        (
            "report",
            "md",
            "# Report revision 1\nThe requested observation is missing.\n",
            "# Report revision 2\nThe required result is recorded here.\n",
        ),
    ] {
        let first = artifacts.join(format!("{kind}-v1.{extension}"));
        let corrected = artifacts.join(format!("{kind}-v2.{extension}"));
        fs::write(&first, original).unwrap();
        fs::write(&corrected, correction).unwrap();
        let first_hash = hash(&fs::read(&first).unwrap());
        let created=alice.call("create_work",&json!({"room_name":"shared","title":kind,"external_ref":format!("opaque:run-{kind}"),"operation_id":format!("create-{kind}")})).await.unwrap()["work"].clone();
        let created = alice
            .call(
                "set_work_requirements",
                &requirements(&created, &[], &[], &format!("select-{kind}")),
            )
            .await
            .unwrap()["work"]
            .clone();
        let owned = claim(&alice, &created, &format!("claim-{kind}")).await;
        let mut output = publish(&alice, &owned, &first, &format!("publish-{kind}")).await;
        let requested = request(&alice, &output, &format!("request-{kind}")).await;
        output = bob
            .call(
                "select_work_review",
                &selection(
                    &output,
                    &requested,
                    "check",
                    None,
                    &format!("require-check-{kind}"),
                ),
            )
            .await
            .unwrap()["work"]
            .clone();
        assert!(
            alice
                .call(
                    "select_work_review",
                    &selection(
                        &output,
                        &requested,
                        "check",
                        Some(&requested),
                        &format!("worker-relax-{kind}")
                    )
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("403")
        );
        assert!(
            bob.call(
                "decide_work_acceptance",
                &acceptance(&output, "approve", &format!("early-accept-{kind}"))
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("409")
        );
        assert!(alice.call("claim_work",&json!({"room_name":"shared","work_id":requested["work_id"],"expected_version":1,"expected_generation":0,"operation_id":format!("wrong-reviewer-{kind}")})).await.unwrap_err().to_string().contains("403"));
        let checking = claim(&bob, &requested, &format!("review-claim-{kind}")).await;
        assert!(
            !fs::read_to_string(&first)
                .unwrap()
                .contains("required result")
        );
        let reject = answer(&checking, "reject", &format!("reject-{kind}"));
        if kind == "code" {
            let lock = Connection::open(root.join("data/coord/v0.db")).unwrap();
            lock.execute_batch("BEGIN IMMEDIATE").unwrap();
            let pending = {
                let bob = bob.clone();
                let input = reject.clone();
                tokio::spawn(async move {
                    bob.call("answer_check", &input)
                        .await
                        .map_err(|e| e.to_string())
                })
            };
            tokio::time::sleep(Duration::from_millis(150)).await;
            stage0::crash(proxy).await;
            lock.execute_batch("ROLLBACK").unwrap();
            assert!(pending.await.unwrap().is_err());
            proxy = stage0::start_proxy(&root).await;
            assert_eq!(read(&bob, &checking).await["state"], "claimed");
        }
        let rejected = bob.call("answer_check", &reject).await.unwrap();
        assert_eq!(rejected["work"]["state"], "done");
        assert_eq!(rejected["work"]["check"]["answer"]["verdict"], "reject");
        output=alice.call("complete_work",&json!({"room_name":"shared","work_id":output["work_id"],"expected_version":output["version"],"expected_generation":1,"operation_id":format!("finish-execution-{kind}")})).await.unwrap()["work"].clone();
        assert_eq!(
            read(&bob, &output).await["acceptance_status"]["obligations"][0]["status"],
            "rejected_check"
        );
        let raised=bob.call("raise_challenge",&json!({"room_name":"shared","subject":subject(&output),"assertion":"Required result omitted","grounds":"Read retained artifact bytes",
            "evidence_refs":[format!("sha256:{first_hash}")],"responder":principal(ALICE),"deciders":[principal(BOB)],"independent":true,"operation_id":format!("raise-{kind}")})).await.unwrap()["work"].clone();
        output = bob
            .call(
                "select_work_review",
                &selection(
                    &output,
                    &raised,
                    "challenge",
                    None,
                    &format!("require-challenge-{kind}"),
                ),
            )
            .await
            .unwrap()["work"]
            .clone();
        let responding = claim(&alice, &raised, &format!("respond-claim-{kind}")).await;
        let mut replacement =
            publish(&alice, &output, &corrected, &format!("correct-{kind}")).await;
        let pending = read(&bob, &replacement).await;
        assert_eq!(
            pending["acceptance_status"]["obligations"][0]["status"],
            "stale_subject"
        );
        assert_eq!(
            pending["acceptance_status"]["obligations"][1]["status"],
            "unresolved_challenge"
        );
        assert_eq!(
            read(&bob, &rejected["work"]).await["review_status"]["subject_current"],
            false
        );
        assert_eq!(
            read(&alice, &responding).await["review_status"]["state"],
            "unresolved"
        );
        let responded=alice.call("respond_challenge",&json!({"room_name":"shared","work_id":responding["work_id"],"expected_version":responding["version"],"expected_generation":1,
            "summary":"Retained correction includes the required result","correction":subject(&replacement),"operation_id":format!("respond-{kind}")})).await.unwrap()["work"].clone();
        assert_eq!(responded["state"], "done");
        assert_eq!(
            read(&alice, &responded).await["review_status"]["state"],
            "unresolved"
        );
        let decision = json!({"room_name":"shared","work_id":responded["work_id"],"expected_version":responded["version"],"expected_generation":1,"expected_response_version":responded["challenge"]["response"]["work_version"],
            "decision":"dismissed","reason":"Independently inspected the exact corrected artifact","operation_id":format!("dispose-{kind}")});
        assert!(
            alice
                .call("resolve_challenge", &decision)
                .await
                .unwrap_err()
                .to_string()
                .contains("403")
        );
        assert!(
            fs::read_to_string(&corrected)
                .unwrap()
                .contains("required result")
        );
        let disposed = bob.call("resolve_challenge", &decision).await.unwrap();
        assert_eq!(
            disposed["work"]["challenge"]["disposition"]["author"],
            principal(BOB)
        );
        assert_eq!(
            read(&bob, &disposed["work"]).await["review_status"]["state"],
            "resolved"
        );
        assert_eq!(bob.call("answer_check", &reject).await.unwrap(), rejected);
        let next_check = request(&alice, &replacement, &format!("next-check-{kind}")).await;
        let retained_policy = replacement["acceptance_requirements"].clone();
        let select = selection(
            &replacement,
            &next_check,
            "check",
            Some(&requested),
            &format!("require-corrected-check-{kind}"),
        );
        if kind == "code" {
            let lock = Connection::open(root.join("data/coord/v0.db")).unwrap();
            lock.execute_batch("BEGIN IMMEDIATE").unwrap();
            let pending = {
                let bob = bob.clone();
                let input = select.clone();
                tokio::spawn(async move {
                    bob.call("select_work_review", &input)
                        .await
                        .map_err(|e| e.to_string())
                })
            };
            tokio::time::sleep(Duration::from_millis(150)).await;
            stage0::crash(proxy).await;
            lock.execute_batch("ROLLBACK").unwrap();
            assert!(pending.await.unwrap().is_err());
            proxy = stage0::start_proxy(&root).await;
            assert_eq!(
                read(&bob, &replacement).await["acceptance_requirements"],
                retained_policy
            );
            commit_without_reply(&root, &select, "select_review").await;
            stage0::crash(proxy).await;
            proxy = stage0::start_proxy(&root).await;
        }
        replacement = bob.call("select_work_review", &select).await.unwrap()["work"].clone();
        assert_eq!(
            bob.call("select_work_review", &select).await.unwrap()["work"],
            replacement
        );
        for field in ["challenges", "authorities", "deciders", "independent"] {
            assert_eq!(
                replacement["acceptance_requirements"][field],
                retained_policy[field]
            );
        }
        let next_claim = claim(&bob, &next_check, &format!("next-claim-{kind}")).await;
        let approved = bob
            .call(
                "answer_check",
                &answer(&next_claim, "approve", &format!("approve-{kind}")),
            )
            .await
            .unwrap();
        assert_eq!(approved["work"]["check"]["answer"]["verdict"], "approve");
        assert_eq!(
            read(&bob, &replacement).await["acceptance_status"]["state"],
            "pending"
        );
        let accept = acceptance(&replacement, "approve", &format!("accept-{kind}"));
        if kind == "code" {
            commit_without_reply(&root, &accept, "decide_acceptance").await;
            stage0::crash(proxy).await;
            proxy = stage0::start_proxy(&root).await;
        }
        let accepted = bob.call("decide_work_acceptance", &accept).await.unwrap();
        assert_eq!(
            bob.call("decide_work_acceptance", &accept).await.unwrap(),
            accepted
        );
        assert_eq!(
            read(&bob, &replacement).await["acceptance_status"]["state"],
            "accepted"
        );
        assert_eq!(accepted["work"]["state"], "done");
        let reviews = bob
            .call(
                "list_work_reviews",
                &json!({"room_name":"shared","work_id":output["work_id"]}),
            )
            .await
            .unwrap();
        assert_eq!(reviews["items"].as_array().unwrap().len(), 3);
        let history=bob.call("read_work",&json!({"room_name":"shared","work_id":responded["work_id"],"version":responded["version"]})).await.unwrap();
        assert!(history["challenge"]["disposition"].is_null());
        assert_eq!(
            history["challenge"]["subject"]["reference"],
            subject(&output)
        );
        assert_eq!(hash(&fs::read(&first).unwrap()), first_hash);
        if kind == "report" {
            let id = accepted["work"]["work_id"].as_str().unwrap();
            let version = accepted["work"]["version"].to_string();
            let requirements_version =
                accepted["work"]["acceptance_requirements"]["version"].to_string();
            let rejected = coord_json(
                &root,
                &[
                    "work",
                    "decide-acceptance",
                    "shared",
                    id,
                    "--expected-version",
                    &version,
                    "--expected-generation",
                    "1",
                    "--expected-requirements-version",
                    &requirements_version,
                    "--expected-target-generation",
                    "2",
                    "--verdict",
                    "reject",
                    "--summary",
                    "Operator has a conflicting observation",
                    "--operation-id",
                    "operator-acceptance-reject",
                ],
            )
            .await;
            assert_eq!(
                read(&bob, &replacement).await["acceptance_status"]["state"],
                "conflicting"
            );
            let version = rejected["work"]["version"].to_string();
            coord_json(
                &root,
                &[
                    "work",
                    "decide-acceptance",
                    "shared",
                    id,
                    "--expected-version",
                    &version,
                    "--expected-generation",
                    "1",
                    "--expected-requirements-version",
                    &requirements_version,
                    "--expected-target-generation",
                    "2",
                    "--verdict",
                    "approve",
                    "--summary",
                    "Operator explicitly corrected the observation",
                    "--operation-id",
                    "operator-acceptance-correct",
                ],
            )
            .await;
            assert_eq!(
                read(&bob, &replacement).await["acceptance_status"]["state"],
                "accepted"
            );
            assert_eq!(
                bob.call("decide_work_acceptance", &accept).await.unwrap(),
                accepted
            );
            let report_subject = subject(&replacement).to_string();
            let human = coord_json(
                &root,
                &[
                    "work",
                    "request-check",
                    "shared",
                    "--subject",
                    &report_subject,
                    "--criterion",
                    "Inspect the versioned report",
                    "--reviewer",
                    "{\"kind\":\"operator\",\"id\":\"operator\"}",
                    "--independent",
                    "true",
                    "--operation-id",
                    "operator-check",
                ],
            )
            .await;
            let id = human["work"]["work_id"].as_str().unwrap();
            let answered = coord_json(
                &root,
                &[
                    "work",
                    "answer-check",
                    "shared",
                    id,
                    "--expected-version",
                    "1",
                    "--expected-generation",
                    "0",
                    "--verdict",
                    "reject",
                    "--summary",
                    "Human identified a concern",
                    "--operation-id",
                    "operator-answer",
                ],
            )
            .await;
            let fixed = coord_json(
                &root,
                &[
                    "work",
                    "answer-check",
                    "shared",
                    id,
                    "--expected-version",
                    "2",
                    "--expected-generation",
                    "0",
                    "--verdict",
                    "approve",
                    "--summary",
                    "Human corrected the conclusion",
                    "--operation-id",
                    "operator-correction",
                ],
            )
            .await;
            assert_eq!(answered["work"]["state"], "done");
            assert_eq!(
                fixed["work"]["check"]["answer"]["author"]["kind"],
                "operator"
            );
            let history =
                coord_json(&root, &["work", "show", "shared", id, "--version", "2"]).await;
            assert_eq!(history["check"]["answer"]["verdict"], "reject");
            let page = coord_json(
                &root,
                &[
                    "work",
                    "reviews",
                    "shared",
                    output["work_id"].as_str().unwrap(),
                ],
            )
            .await;
            assert_eq!(page["items"].as_array().unwrap().len(), 4);
            let next_challenge = bob.call("raise_challenge", &json!({"room_name":"shared","subject":subject(&replacement),
                "assertion":"Corrected report coverage needs review","grounds":"Inspect the current report scope",
                "responder":principal(ALICE),"deciders":[principal(BOB)],"independent":true,
                "operation_id":"replacement-report-challenge"})).await.unwrap()["work"].clone();
            let current = read(&bob, &replacement).await;
            let reference =
                json!({"work_id":next_challenge["work_id"],"version":next_challenge["version"]})
                    .to_string();
            let amended = coord_json(
                &root,
                &[
                    "work",
                    "select-review",
                    "shared",
                    current["work_id"].as_str().unwrap(),
                    "--expected-version",
                    &current["version"].to_string(),
                    "--expected-generation",
                    &current["claim_generation"].to_string(),
                    "--expected-requirements-version",
                    &current["acceptance_requirements"]["version"].to_string(),
                    "--review-kind",
                    "challenge",
                    "--review",
                    &reference,
                    "--replace-work-id",
                    raised["work_id"].as_str().unwrap(),
                    "--reason",
                    "Select the current report coverage challenge",
                    "--operation-id",
                    "operator-replace-challenge",
                ],
            )
            .await;
            assert_eq!(
                amended["work"]["acceptance_requirements"]["checks"],
                current["acceptance_requirements"]["checks"]
            );
            assert_eq!(
                amended["work"]["acceptance_requirements"]["challenges"][0]["work_id"],
                next_challenge["work_id"]
            );
            let status = read(&bob, &replacement).await["acceptance_status"].clone();
            assert_eq!(status["state"], "pending");
            assert_eq!(status["obligations"][1]["status"], "unresolved_challenge");
        }
        println!(
            "{kind}: selected requirements -> exact-subject rejection -> challenge -> retained correction -> independent disposition -> current check approval -> output acceptance; original evidence unchanged"
        );
    }
    stage0::crash(proxy).await;
    drop(cleanup);
    fs::remove_dir_all(retained).unwrap();
}
