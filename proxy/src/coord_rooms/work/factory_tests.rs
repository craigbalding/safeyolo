use super::*;

pub(super) async fn approved() -> (tempfile::TempDir, Connection, Value) {
    let root = fixture();
    fs::write(
        root.path().join("policy.toml"),
        "[agents.alice]\nagent_id='alice'\n[agents.bob]\nagent_id='bob'\n",
    )
    .unwrap();
    fs::write(
        root.path().join("role.md"),
        "Use native assigned work and independently inspect its exact output.\n",
    )
    .unwrap();
    let source = root.path().join("factory.toml");
    fs::write(
        &source,
        r#"schema="safeyolo.factory/v1"
name="native"
room="owned"
[roles.producer]
agent="alice"
contract="role.md"
[roles.reviewer]
agent="bob"
contract="role.md"
[operator_input]
to="reviewer"
types=["DIRECTION"]
[work]
creators=["producer"]
authorities=["reviewer"]
deciders=["reviewer"]
independent=true
[[work.checks]]
reviewer="reviewer"
criterion="Independently inspect the exact retained output"
independent=true
"#,
    )
    .unwrap();
    crate::factory::run(
        &root.path().join("config.toml"),
        &[
            "approve".into(),
            source.to_str().unwrap().into(),
            "--yes".into(),
        ],
    )
    .await
    .unwrap();
    let id = fs::read_to_string(root.path().join("factories/native/approved")).unwrap();
    let reference = json!({"name":"native","snapshot_id":id.trim()});
    let conn = db(&root);
    (root, conn, reference)
}

fn submit(
    root: &std::path::Path,
    conn: &mut Connection,
    actor: Actor<'_>,
    value: Value,
    op: &str,
) -> Result<Value, WorkError> {
    mutate(
        Some((root, &root.join("policy.toml"))),
        conn,
        "owned",
        actor,
        serde_json::from_value(value).unwrap(),
        Some(op),
    )
}
fn input(work: &Value, action: &str) -> Value {
    json!({"action":action,"work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"]})
}
fn publication(work: &Value) -> Value {
    let mut v = input(work, "publish_output");
    v["expected_target_generation"] = work["target_generation"].clone();
    v["target_ref"] = json!("urn:sha256:retained");
    v["execution_outcome"] = json!("succeeded");
    v["summary"] = json!("Retained artifact before publishing");
    v
}
fn required_check(conn: &mut Connection, work: &Value) -> Value {
    read(
        conn,
        "owned",
        Actor::Operator,
        work["factory"]["current_checks"][0].as_str().unwrap(),
    )
    .unwrap()
}
fn requirements(work: &Value) -> Value {
    let r = &work["acceptance_requirements"];
    let mut v = input(work, "set_requirements");
    v["expected_requirements_version"] = r["version"].clone();
    v["authorities"] = r["authorities"].clone();
    v["deciders"] = r["deciders"].clone();
    v["independent"] = r["independent"].clone();
    v["checks"] = json!([]);
    v["challenges"] = json!([]);
    v["reason"] = json!("Explicit authorized policy amendment");
    v
}

#[tokio::test]
async fn selected_identities_use_the_callers_configured_policy_not_a_default_file() {
    let (root, mut conn, reference) = approved().await;
    let configured = root.path().join("review-identities.toml");
    fs::rename(root.path().join("policy.toml"), &configured).unwrap();
    fs::write(
        root.path().join("policy.toml"),
        "[agents.bob]\nagent_id='wrong-default-id'\n",
    )
    .unwrap();
    fs::rename(
        root.path().join("config.toml"),
        root.path().join("custom-config.toml"),
    )
    .unwrap();
    let receipt = mutate(
        Some((root.path(), &configured)),
        &mut conn,
        "owned",
        Actor::Operator,
        serde_json::from_value(
            json!({"action":"create","title":"Configured identity authority","factory":reference}),
        )
        .unwrap(),
        Some("configured-policy"),
    )
    .unwrap();
    assert_eq!(
        receipt["work"]["acceptance_requirements"]["deciders"][0]["id"],
        "bob"
    );
    assert_eq!(
        receipt["work"]["factory"]["checks"][0]["reviewer"]["id"],
        "bob"
    );
}

#[tokio::test]
async fn approved_factory_policy_is_native_and_publication_replay_creates_one_required_check() {
    let (root, mut conn, reference) = approved().await;
    let create = json!({"action":"create","title":"Factory output","factory":reference,"assignee":{"kind":"agent","id":"alice"}});
    assert_eq!(
        submit(
            root.path(),
            &mut conn,
            Actor::Agent("bob"),
            create.clone(),
            "wrong-creator"
        )
        .unwrap_err()
        .0,
        403
    );
    let work = submit(
        root.path(),
        &mut conn,
        Actor::Agent("alice"),
        create.clone(),
        "create",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(work["factory"]["reference"], reference);
    assert_eq!(
        work["acceptance_requirements"]["authorities"],
        json!([{"kind":"agent","id":"bob"}])
    );
    assert_eq!(
        submit(
            root.path(),
            &mut conn,
            Actor::Agent("alice"),
            requirements(&work),
            "relax"
        )
        .unwrap_err()
        .0,
        403
    );
    let work =
        change(&mut conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone();
    let publish = publication(&work);
    let receipt = submit(
        root.path(),
        &mut conn,
        Actor::Agent("alice"),
        publish.clone(),
        "publish",
    )
    .unwrap();
    let before = counts(&conn);
    assert_eq!(
        submit(
            root.path(),
            &mut conn,
            Actor::Agent("alice"),
            publish,
            "publish"
        )
        .unwrap(),
        receipt
    );
    assert_eq!(counts(&conn), before);
    let work = &receipt["work"];
    let check = required_check(&mut conn, work);
    assert_eq!(check["check"]["subject"]["producer"]["id"], "alice");
    assert_eq!(check["check"]["subject"]["work_version"], work["version"]);
    assert_eq!(
        check["check"]["subject"]["reference"]["target_generation"],
        1
    );
    assert_eq!(
        work["acceptance_requirements"]["checks"][0]["work_id"],
        check["work_id"]
    );
    let mut approve = input(work, "decide_acceptance");
    approve["expected_requirements_version"] = work["acceptance_requirements"]["version"].clone();
    approve["expected_target_generation"] = json!(1);
    approve["verdict"] = json!("approve");
    approve["summary"] = json!("Attempted before the check");
    assert_eq!(
        submit(
            root.path(),
            &mut conn,
            Actor::Agent("bob"),
            approve,
            "early"
        )
        .unwrap_err()
        .0,
        409
    );
    let correction = submit(
        root.path(),
        &mut conn,
        Actor::Agent("alice"),
        publication(work),
        "correction",
    )
    .unwrap()["work"]
        .clone();
    let new_check = required_check(&mut conn, &correction);
    assert_ne!(new_check["work_id"], check["work_id"]);
    assert_eq!(
        correction["acceptance_requirements"]["checks"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        new_check["check"]["subject"]["reference"]["target_generation"],
        2
    );
    let mut delegation = requirements(&correction);
    delegation["authorities"] = json!([{"kind":"agent","id":"alice"}]);
    let delegated = submit(
        root.path(),
        &mut conn,
        Actor::Agent("bob"),
        delegation,
        "delegate",
    )
    .unwrap()["work"]
        .clone();
    assert!(
        submit(
            root.path(),
            &mut conn,
            Actor::Agent("alice"),
            requirements(&delegated),
            "authorized-worker-amendment"
        )
        .is_ok()
    );
    assert_eq!(
        read(
            &mut conn,
            "owned",
            Actor::Operator,
            check["work_id"].as_str().unwrap()
        )
        .unwrap()["check"]["subject"]["reference"]["target_generation"],
        1
    );
    // Old accepted create receipts remain recoverable after approval changes.
    fs::write(
        root.path().join("factories/native/approved"),
        format!("{}\n", "0".repeat(64)),
    )
    .unwrap();
    assert_eq!(
        submit(
            root.path(),
            &mut conn,
            Actor::Agent("alice"),
            create.clone(),
            "create"
        )
        .unwrap()["work"]["work_id"],
        work["work_id"]
    );
    assert!(
        submit(
            root.path(),
            &mut conn,
            Actor::Agent("alice"),
            create,
            "new-after-change"
        )
        .is_err()
    );
}

#[tokio::test]
async fn replacement_preserves_explicit_required_checks_and_open_challenges() {
    let (root, mut conn, reference) = approved().await;
    let work = submit(
        root.path(),
        &mut conn,
        Actor::Operator,
        json!({"action":"create","title":"Preserve selected obligations","factory":reference}),
        "create",
    )
    .unwrap()["work"]
        .clone();
    let work =
        change(&mut conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone();
    let work = submit(
        root.path(),
        &mut conn,
        Actor::Agent("alice"),
        publication(&work),
        "publish",
    )
    .unwrap()["work"]
        .clone();
    let generated = required_check(&mut conn, &work);
    let subject = json!({"kind":"output","work_id":work["work_id"],"target_generation":1});
    let additional = submit(root.path(), &mut conn, Actor::Agent("bob"),
        json!({"action":"request_check","subject":subject,"criterion":"An explicitly selected additional check",
            "reviewer":{"kind":"agent","id":"bob"},"independent":true}), "additional")
        .unwrap()["work"].clone();
    let challenge = submit(
        root.path(),
        &mut conn,
        Actor::Agent("bob"),
        json!({"action":"raise_challenge","subject":subject,"assertion":"An unresolved omission",
            "grounds":"Retained evidence","responder":{"kind":"agent","id":"alice"},
            "deciders":[{"kind":"agent","id":"bob"}],"independent":true}),
        "objection",
    )
    .unwrap()["work"]
        .clone();
    let mut selected = requirements(&work);
    selected["checks"] = json!([
        {"work_id":generated["work_id"],"version":generated["version"]},
        {"work_id":additional["work_id"],"version":additional["version"]}]);
    selected["challenges"] =
        json!([{ "work_id":challenge["work_id"],"version":challenge["version"]}]);
    let work = submit(
        root.path(),
        &mut conn,
        Actor::Agent("bob"),
        selected,
        "select",
    )
    .unwrap()["work"]
        .clone();
    let corrected = submit(
        root.path(),
        &mut conn,
        Actor::Agent("alice"),
        publication(&work),
        "correct",
    )
    .unwrap()["work"]
        .clone();
    let checks = corrected["acceptance_requirements"]["checks"]
        .as_array()
        .unwrap();
    assert_eq!(checks.len(), 2);
    assert!(checks.iter().any(|c| c["work_id"] == additional["work_id"]));
    assert!(!checks.iter().any(|c| c["work_id"] == generated["work_id"]));
    assert_eq!(
        corrected["acceptance_requirements"]["challenges"][0]["work_id"],
        challenge["work_id"]
    );
    let challenge = read(
        &mut conn,
        "owned",
        Actor::Operator,
        challenge["work_id"].as_str().unwrap(),
    )
    .unwrap();
    assert!(challenge["challenge"]["disposition"].is_null());
    assert_eq!(
        challenge["challenge"]["subject"]["reference"]["target_generation"],
        1
    );
    assert_eq!(
        required_check(&mut conn, &corrected)["check"]["subject"]["reference"]["target_generation"],
        2
    );
}

#[tokio::test]
async fn factory_publication_rolls_back_child_checks_and_concurrent_replay_is_one_operation() {
    let (root, mut conn, reference) = approved().await;
    let work = submit(
        root.path(),
        &mut conn,
        Actor::Operator,
        json!({"action":"create","title":"Atomic policy","factory":reference}),
        "create",
    )
    .unwrap()["work"]
        .clone();
    let work =
        change(&mut conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone();
    let before = counts(&conn);
    // Fail after a required child and its attention were staged, before root commit.
    conn.execute_batch("CREATE TRIGGER fail_root BEFORE INSERT ON coord_work_revisions WHEN json_extract(NEW.document_json,'$.output') IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected root failure'); END;").unwrap();
    assert!(
        submit(
            root.path(),
            &mut conn,
            Actor::Agent("alice"),
            publication(&work),
            "publish"
        )
        .is_err()
    );
    assert_eq!(counts(&conn), before);
    conn.execute_batch("DROP TRIGGER fail_root").unwrap();
    let gate = Arc::new(Barrier::new(2));
    let outcomes = std::thread::scope(|scope| {
        (0..2)
            .map(|_| {
                let gate = gate.clone();
                let root = &root;
                let work = &work;
                scope.spawn(move || {
                    let mut conn = db(root);
                    gate.wait();
                    submit(
                        root.path(),
                        &mut conn,
                        Actor::Agent("alice"),
                        publication(work),
                        "publish",
                    )
                    .unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(outcomes[0], outcomes[1]);
    assert_eq!(
        counts(&conn)[0] - before[0],
        1,
        "one required child; no duplicate task"
    );
}

#[tokio::test]
async fn unavailable_or_ineligible_selected_reviewer_does_not_block_retaining_a_correction() {
    let (root, mut conn, reference) = approved().await;
    let work = submit(
        root.path(),
        &mut conn,
        Actor::Operator,
        json!({"action":"create","title":"Retain despite reviewer recovery","factory":reference}),
        "create",
    )
    .unwrap()["work"]
        .clone();
    let work =
        change(&mut conn, Actor::Agent("bob"), "claim", &work, "claim").unwrap()["work"].clone();
    let work = submit(
        root.path(),
        &mut conn,
        Actor::Agent("bob"),
        publication(&work),
        "publish",
    )
    .unwrap()["work"]
        .clone();
    let check = required_check(&mut conn, &work);
    assert_eq!(
        change(
            &mut conn,
            Actor::Agent("bob"),
            "claim",
            &check,
            "self-review"
        )
        .unwrap_err()
        .0,
        403
    );
    assert!(
        actions::read(
            &mut conn,
            "owned",
            Actor::Agent("bob"),
            check["work_id"].as_str().unwrap(),
            false
        )
        .unwrap()["actions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["kind"] != "answer_check")
    );
    assert_eq!(
        read(
            &mut conn,
            "owned",
            Actor::Operator,
            work["work_id"].as_str().unwrap()
        )
        .unwrap()["acceptance_status"]["obligations"][0]["status"],
        "ineligible_reviewer"
    );
    let work=submit(root.path(),&mut conn,Actor::Operator,json!({"action":"reassign","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],"agent_id":"alice"}),"recover-producer").unwrap()["work"].clone();
    conn.execute("DELETE FROM memberships WHERE principal_id='bob'", [])
        .unwrap();
    let work = submit(
        root.path(),
        &mut conn,
        Actor::Agent("alice"),
        publication(&work),
        "retained-correction",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(work["target_generation"], 2);
    assert_eq!(
        required_check(&mut conn, &work)["check"]["reviewer"]["id"],
        "bob"
    );
    assert_eq!(work["output"]["producer"]["id"], "alice");
}
