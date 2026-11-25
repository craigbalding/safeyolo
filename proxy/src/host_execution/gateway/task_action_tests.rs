//! Controlled job outputs exercise configured admission, not VM isolation or
//! model accuracy. The installed checker/model measurements cover those owners.
use super::*;
use crate::policy::checks::{challenges, content_digest, task_action};

async fn configured_fixture() -> Fixture {
    let mut f = Fixture::new("").await;
    let config = f.root.path().join("config.toml");
    std::fs::write(&config, "").unwrap();
    Arc::make_mut(&mut f.proxy.runtime.write().unwrap())
        .config
        .native_config_path = Some(config);
    // Reuse the job supervisor's pinned-helper protocol fixture. Only its
    // output is controlled; named-check execution and host admission are real.
    let checker = include_bytes!("../../../tests/fixtures/task_action_helper.py");
    let python = std::process::Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .unwrap();
    assert!(python.status.success());
    let python = String::from_utf8(python.stdout).unwrap();
    // The supervisor clears PATH. Resolve the test interpreter before launch,
    // and keep its host path out of the job input and assessed agent's control.
    let helper = format!(
        "#!/bin/sh\nexec '{}' \"${{1%/*}}/code/checker\" \"$@\"\n",
        python.trim().replace('\'', "'\\''")
    );
    for (name, bytes) in [
        ("helper", helper.as_bytes()),
        ("rootfs", b"controlled supervisor fixture, no VM".as_slice()),
        ("checker", checker.as_slice()),
    ] {
        std::fs::write(f.root.path().join(name), bytes).unwrap();
    }
    std::fs::set_permissions(
        f.root.path().join("helper"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let manifest = json!({"protocol":4,"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,
        "hyperlight":"0.19.0","unikraft":"0.21.0","kernel_contract":"controlled fixture",
        "helper":{"file":"helper","sha256":content_digest(helper.as_bytes())},
        "rootfs":{"file":"rootfs","sha256":content_digest(b"controlled supervisor fixture, no VM")},
        "rootfs_source":"controlled fixture"});
    let manifest = serde_json::to_vec(&manifest).unwrap();
    std::fs::write(f.root.path().join("runtime.json"), &manifest).unwrap();
    let spec = json!({"engine":{"kind":"hyperlight-unikraft",
        "runtime":{"path":"runtime.json","sha256":content_digest(&manifest)},
        "checker":{"path":"checker","sha256":content_digest(checker)}},
        "gate_id":"task-action-fixture","argv":[f.root.path().join("mode"),f.root.path().join("calls.jsonl")],
        "timeout_seconds":3,"max_input_bytes":32768,"max_input_entries":4,"retain_bytes":16384,
        "memory_mb":16,"network":false});
    let spec = serde_json::to_vec(&spec).unwrap();
    let path = f.root.path().join("check.json");
    std::fs::write(&path, &spec).unwrap();
    std::fs::write(f.root.path().join("mode"), "adaptive").unwrap();
    let policy = task_action_policy()
        .replace("/absent-task-action-spec.json", path.to_str().unwrap())
        .replace(&"a".repeat(64), &content_digest(&spec))
        .replace("timeout_ms=100", "timeout_ms=5000");
    f.install(f.source.clone() + &policy);
    f
}

fn mode(f: &Fixture, value: &str) {
    std::fs::write(f.root.path().join("mode"), value).unwrap();
}

fn calls(f: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(f.root.path().join("calls.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn record(f: &Fixture, request: &str) -> pending::Record {
    f.proxy
        .runtime
        .read()
        .unwrap()
        .audit
        .approvals()
        .list()
        .unwrap()
        .into_iter()
        .find(|r| r.authority.action["request"]["request_id"] == request)
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn task_action_history_filters_before_selecting_the_bounded_tail() {
    let f = Fixture::new("").await;
    let runtime = f.proxy.runtime.read().unwrap().clone();
    for index in 0..128 {
        let mut event = crate::audit::Event::new(
            "gateway.host_result",
            crate::audit::Kind::Gateway,
            crate::audit::Severity::Low,
            "Prior host operation completed",
        );
        event.agent = Some(f.run.agent.clone());
        event.request_id = Some(format!("prior-{index}"));
        event.details = json!({"run":f.run,"result":{"receipt":{"state":"completed"}}}).into();
        runtime.audit.emit_confirmed(event).await.unwrap();
    }
    let before = task_action::history(&runtime, &f.run, "current").unwrap();
    assert_eq!(before["operations"]["rows"].as_array().unwrap().len(), 128);
    for index in 0..130 {
        let mut event = crate::audit::Event::new(
            if index == 0 {
                "gateway.host_admission"
            } else {
                "ops.policy_check_executed"
            },
            if index == 0 {
                crate::audit::Kind::Gateway
            } else {
                crate::audit::Kind::Ops
            },
            crate::audit::Severity::Low,
            "Current action checker activity",
        );
        event.agent = Some(f.run.agent.clone());
        event.request_id = Some("current".into());
        event.details = json!({"run":f.run}).into();
        runtime.audit.emit_confirmed(event).await.unwrap();
    }
    assert_eq!(
        task_action::history(&runtime, &f.run, "current").unwrap(),
        before
    );
    let mut event = crate::audit::Event::new(
        "gateway.host_refused",
        crate::audit::Kind::Gateway,
        crate::audit::Severity::Low,
        "Different host operation refused",
    );
    event.agent = Some(f.run.agent.clone());
    event.request_id = Some("concurrent-action".into());
    event.details = json!({"run":f.run,"refusal":{"code":"policy"}}).into();
    runtime.audit.emit_confirmed(event).await.unwrap();
    let after = task_action::history(&runtime, &f.run, "current").unwrap();
    assert_ne!(
        after, before,
        "A different action must invalidate the history"
    );
    assert_eq!(after["operations"]["rows"].as_array().unwrap().len(), 128);
    // A malformed unselected record still fails the whole audit view closed.
    use std::io::Write;
    let (path, _) = runtime.audit.log_source();
    writeln!(
        std::fs::OpenOptions::new().append(true).open(path).unwrap(),
        "invalid"
    )
    .unwrap();
    assert_eq!(
        task_action::history(&runtime, &f.run, "current").unwrap()["operations"]["status"],
        "unavailable"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_task_action_history_respects_the_adopted_input_limit() {
    let mut f = configured_fixture().await;
    let base = f
        .source
        .split("\n[checks.independent]")
        .next()
        .unwrap()
        .to_owned();
    let path = f.root.path().join("check.json");
    let mut spec: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let action = json!({"task_action":{
        "task":{"objective":"Diagnose the selected service"},"requester":{},
        "action":{"invocation":{"arguments":{"wait":5}}},"prepared":{},"constraints":{},
        "history":{"refusals":[{"reason":"x".repeat(32768)}]}}});
    for limit in [131072, 32768] {
        spec["max_input_bytes"] = json!(limit);
        let bytes = serde_json::to_vec(&spec).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let policy = task_action_policy()
            .replace("/absent-task-action-spec.json", path.to_str().unwrap())
            .replace(&"a".repeat(64), &content_digest(&bytes))
            .replace("timeout_ms=100", "timeout_ms=5000")
            .replace("max_input_bytes=32768", &format!("max_input_bytes={limit}"));
        f.install(base.clone() + &policy);
        let runtime = f.proxy.runtime.read().unwrap().clone();
        let checks = runtime.policy.as_ref().unwrap().named_checks();
        let subject = task_action::subject(
            &action,
            "authority",
            &checks.checks["independent"],
            "host",
            "revision",
            &BTreeMap::new(),
            false,
        )
        .unwrap();
        let subject =
            task_action::reconsideration(subject, &json!({"attempt":1,"prior_findings":[]}))
                .unwrap();
        let result = checks
            .invoke_challenge("independent", subject, &runtime, &f.proxy.runtime)
            .await;
        if limit == 131072 {
            assert!(result.unwrap().unavailable.is_none());
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                "check input limit exceeded"
            );
        }
        let observed = calls(&f);
        assert_eq!(
            observed.len(),
            1,
            "An over-budget input must start no checker"
        );
        assert_eq!(
            observed[0]["subject"]["trusted"]["history"]["refusals"],
            action["task_action"]["history"]["refusals"]
        );
        let input_bytes = serde_json::to_vec(&observed[0]["request"]).unwrap().len();
        assert!(
            input_bytes > 32768 && input_bytes <= 131072,
            "{input_bytes}"
        );
        assert_eq!(f.mutations.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_task_action_dispatches_adaptive_operations_and_retains_refusals() {
    let mut f = configured_fixture().await;
    // More successful operations than max_attempts must each run the check.
    for index in 0..3 {
        let id = format!("benign-{index}");
        let reply = f.call(f.prepared(&id, Some(5)).await).await;
        assert_eq!(reply.status, 200, "{}", reply.value);
        assert_eq!(record(&f, &id).status, "completed");
        assert_eq!(f.mutations.load(Ordering::SeqCst), index + 1);
        assert_eq!(calls(&f).len(), index + 1);
    }
    let concern = f.prepared("concern", Some(6)).await;
    let reply = f.call(concern.clone()).await;
    assert_eq!(reply.status, 428, "{}", reply.value);
    assert_eq!(
        reply.value["assessment"]["steps"][0]["finding"]["assessment"]["relevance"],
        "irrelevant"
    );
    assert_eq!(reply.value["assessment"]["steps"][1]["field"], "narrower");
    let id = reply.value["challenge_id"].as_str().unwrap();
    let escalation = format!("/gateway/challenges/{id}/escalate");
    let context = json!({"source":"direct_operator_request","context":{"task":"approved-task",
        "reason":"Exercise this synthetic operation","fallback":"Inspect the narrower status"}});
    assert_eq!(f.api(&escalation, "POST", context).await.status, 422);
    assert_eq!(f.mutations.load(Ordering::SeqCst), 3);
    assert_eq!(calls(&f).len(), 5);
    // Escalation reassessed the concern before refusing the missing answer;
    // both attempts are now retained in the same bounded episode.
    // A new request ID does not erase the continuing concern's attempt limit.
    for index in 0..2 {
        let reply = f
            .call(f.prepared(&format!("concern-{index}"), Some(6)).await)
            .await;
        assert_eq!(reply.status, 428, "{}", reply.value);
        assert!(
            reply.value["assessment"]["steps"][0]["unavailable"]
                .as_str()
                .is_some_and(|s| s.contains("attempt limit")),
            "{}",
            reply.value
        );
    }
    assert_eq!(f.mutations.load(Ordering::SeqCst), 3);
    assert_eq!(calls(&f).len(), 5);
    f.install(f.source.replace(
        "on_concern={kind='question',field='narrower',question='Explain the need or choose a narrower action'}",
        "on_concern={kind='deny'}").replace("revision='synthetic-1'", "revision='refusal-1'"));
    let denied = f.call(f.prepared("refused", Some(6)).await).await;
    assert_eq!(denied.status, 403, "{}", denied.value);
    let refused = record(&f, "refused");
    assert_eq!(refused.status, "rejected");
    assert_eq!(
        refused.result["refusal_source"],
        "adopted_task_action_check"
    );
    assert_eq!(f.mutations.load(Ordering::SeqCst), 3);
    // The agent can adapt to a narrower allowed action; its canonical input
    // retains the real refusal rather than a seeded completion record.
    let reply = f.call(f.prepared("adapted", Some(5)).await).await;
    assert_eq!(reply.status, 200, "{}", reply.value);
    assert_eq!(f.mutations.load(Ordering::SeqCst), 4);
    let calls = calls(&f);
    assert_eq!(calls.len(), 7);
    let history = &calls.last().unwrap()["subject"]["trusted"]["history"]["approvals"];
    assert!(
        history
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["approval_id"] == refused.approval_id && r["status"] == "rejected")
    );
    assert_eq!(record(&f, "refused").result, refused.result);
    println!(
        "configured admission: 7 real check jobs; 4 benign dispatches; concern/challenge/budget/refusal caused 0 extra target effects"
    );
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_task_action_rejects_prior_findings_and_required_check_bypass() {
    let mut f = configured_fixture().await;
    mode(&f, "concern");
    let mut input = f.prepared("prior-favorable", Some(5)).await;
    let challenge = f.call(input.clone()).await;
    assert_eq!(challenge.status, 428, "{}", challenge.value);
    let id = challenge.value["challenge_id"].as_str().unwrap().to_owned();
    mode(&f, "favorable");
    let context = json!({"source":"direct_operator_request","context":{"task":"approved-task",
        "reason":"Run the synthetic task operation","fallback":"Use a narrower status"},
        "answers":{"narrower":"The operator's selected service is the sole target"}});
    let escalation = f
        .api(
            &format!("/gateway/challenges/{id}/escalate"),
            "POST",
            context,
        )
        .await;
    assert_eq!(escalation.status, 202, "{}", escalation.value);
    let runtime = f.proxy.runtime.read().unwrap().clone();
    let (state, audit, approval_id) = (f.proxy.runtime.clone(), runtime.audit.clone(), id.clone());
    tokio::task::spawn_blocking(move || {
        pending::resolve(
            &state,
            &audit,
            &approval_id,
            crate::approvals::network_action::Decision::Approve,
            Some("exact"),
        )
    })
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let prior = record(&f, "prior-favorable");
    assert_eq!(prior.status, "approved");
    assert_eq!(
        prior.result["evidence"]["independent"]["result"]["finding"]["assessment"]["relevance"],
        "relevant"
    );
    assert!(challenges::evidence_current(
        runtime.policy.as_ref().unwrap(),
        &prior
    ));
    assert!(
        admission(
            &f.proxy.runtime,
            &runtime,
            prior.authority.action.clone(),
            Some(&id)
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(calls(&f).len(), 2);
    assert_eq!(f.mutations.load(Ordering::SeqCst), 0);

    // Keep the real prior evidence and request ID. Alter one canonical binding
    // at a time, then enter the actual selected-approval admission consumer.
    for (pointer, value) in [
        ("/task_action/task/revision", json!("task-2")),
        (
            "/task_action/task/objective",
            json!("Inspect another service"),
        ),
        ("/task_action/action/invocation/arguments/wait", json!(6)),
        ("/task_action/action/package_revision", json!("package-2")),
        ("/task_action/requester/run/run_id", json!("1".repeat(32))),
        (
            "/task_action/history/approvals",
            json!([{"status":"rejected","request_id":"previous"}]),
        ),
        (
            "/task_action/constraints/policy_revision",
            json!("policy-2"),
        ),
    ] {
        let mut changed = prior.clone();
        *changed.authority.action.pointer_mut(pointer).unwrap() = value;
        assert!(
            !challenges::evidence_current(runtime.policy.as_ref().unwrap(), &changed),
            "{pointer}"
        );
        assert!(
            admission(
                &f.proxy.runtime,
                &runtime,
                changed.authority.action,
                Some(&id)
            )
            .await
            .is_err(),
            "{pointer}"
        );
    }
    // Replay the genuine approved finding with absent or expired retained
    // evidence. Neither status nor an old favorable result can skip the check.
    mode(&f, "concern");
    for missing in [false, true] {
        runtime
            .audit
            .approvals()
            .decide(&prior.approval_id, |record| {
                record.status = "approved".into();
                record.result = prior.result.clone();
                if missing {
                    record.result["evidence"] = json!({});
                } else {
                    record.result["evidence"]["independent"]["result"]["valid_until_ms"] = json!(1);
                }
                Ok(())
            })
            .unwrap();
        let retained = record(&f, "prior-favorable");
        assert!(!challenges::evidence_current(
            runtime.policy.as_ref().unwrap(),
            &retained
        ));
        assert!(!matches!(
            admission(
                &f.proxy.runtime,
                &runtime,
                prior.authority.action.clone(),
                Some(&id)
            )
            .await,
            Ok(None)
        ));
        assert_eq!(f.mutations.load(Ordering::SeqCst), 0);
    }
    let source = f.source.clone();
    for (before, after) in [
        (
            "implementation_version='adapter-1'",
            "implementation_version='adapter-2'",
        ),
        (
            "configuration_version='synthetic-1'",
            "configuration_version='synthetic-2'",
        ),
        ("model_revision='model-1'", "model_revision='model-2'"),
        ("input_revision='input-1'", "input_revision='input-2'"),
        (
            "prompt_revision='task-action-1'",
            "prompt_revision='task-action-2'",
        ),
        ("revision='synthetic-1'", "revision='synthetic-2'"),
    ] {
        let changed = source.replace(before, after);
        assert_ne!(changed, source);
        f.install(changed);
        let current = f.proxy.runtime.read().unwrap().clone();
        assert!(
            !challenges::current(current.policy.as_ref().unwrap(), &prior.authority.action),
            "{before}"
        );
        assert!(
            !challenges::evidence_current(current.policy.as_ref().unwrap(), &prior),
            "{before}"
        );
        assert!(
            admission(
                &f.proxy.runtime,
                &current,
                prior.authority.action.clone(),
                Some(&id)
            )
            .await
            .is_err(),
            "{before}"
        );
    }
    f.install(source.clone());
    // An actual API retry cannot select the old approval after policy reload,
    // and omitting the old challenge must still run the required current job.
    input.challenge_id = Some(id);
    assert_ne!(f.call(input).await.status, 200);
    // Each adopted definition starts an independent fixture episode. Reusing
    // the exhausted favorable episode would test its budget, not these faults.
    f.install(source.replace(
        "configuration_version='synthetic-1'",
        "configuration_version='expired-fixture'",
    ));
    mode(&f, "expired");
    let expired = f.call(f.prepared("expired", Some(5)).await).await;
    assert_eq!(expired.status, 428, "{}", expired.value);
    assert!(
        expired.value["assessment"]["steps"][0]["unavailable"]
            .as_str()
            .is_some_and(|s| s == "stale evidence"),
        "{}",
        expired.value
    );
    f.install(source.replace(
        "configuration_version='synthetic-1'",
        "configuration_version='malformed-fixture'",
    ));
    mode(&f, "malformed");
    let malformed = f.call(f.prepared("malformed", Some(6)).await).await;
    assert_eq!(malformed.status, 428, "{}", malformed.value);
    assert!(
        malformed.value["assessment"]["steps"][0]["unavailable"]
            .as_str()
            .is_some_and(|s| s == "malformed typed check result"),
        "{}",
        malformed.value
    );
    f.install(source.replace(
        "configuration_version='synthetic-1'",
        "configuration_version='substituted-fixture'",
    ));
    std::fs::write(f.root.path().join("check.json"), b"{}").unwrap();
    let substituted = f.call(f.prepared("substituted-spec", Some(5)).await).await;
    assert_eq!(substituted.status, 428, "{}", substituted.value);
    assert!(
        substituted.value["assessment"]["steps"][0]["unavailable"]
            .as_str()
            .unwrap()
            .contains("adopted SHA-256"),
        "{}",
        substituted.value
    );
    assert_eq!(f.mutations.load(Ordering::SeqCst), 0);
    assert_eq!(calls(&f).len(), 4);
    println!(
        "configured admission: genuine approved favorable baseline; 7 task/action/history bindings + 6 adopted revisions rejected; missing/expired prior evidence and expired/malformed/substituted required jobs dispatched 0 target effects"
    );
    f.stop().await;
}
