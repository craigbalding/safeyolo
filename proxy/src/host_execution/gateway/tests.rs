//! Real issuer/vault/policy, signed socket protocol and durable target ledger.
//! Native containment is covered by the executor's separate platform tests.
use super::*;
use crate::{Config, Proxy};
use std::{
    os::unix::{fs::PermissionsExt, process::CommandExt},
    sync::{
        Mutex, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

struct Fixture {
    root: tempfile::TempDir,
    proxy: Proxy,
    binding: Binding,
    run: AgentRun,
    target: Arc<RwLock<Target>>,
    ledger: Arc<Mutex<Ledger>>,
    key: Ed25519KeyPair,
    mutations: Arc<AtomicUsize>,
    lose_reply: Arc<AtomicBool>,
    server: tokio::task::JoinHandle<()>,
    backend: tokio::process::Child,
    source: String,
}

impl Fixture {
    async fn new(extra: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let run = AgentRun {
            agent: "alice".into(),
            agent_id: format!("ag-{}", "a".repeat(32)),
            run_id: "0123456789abcdef0123456789abcdef".into(),
        };
        let mut command = tokio::process::Command::new("/bin/bash");
        command.as_std_mut().arg0("runsc");
        let backend = command
            .args(["-c", "read -r marker", "boot", "--root"])
            .arg(root.path().join("run"))
            .arg(format!("safeyolo-{}", run.run_id))
            .stdin(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = backend.id().unwrap();
        let share = root.path().join("agents/alice/config-share");
        std::fs::create_dir_all(&share).unwrap();
        std::fs::write(
            share.join("host-launch-context.json"),
            json!({"agent_id":run.agent_id,"generation":run.run_id}).to_string(),
        )
        .unwrap();
        std::fs::write(root.path().join("agents/alice/runtime.json"),json!({"name":"alice","agent_id":run.agent_id,"run_id":run.run_id,"state":"running","backend_pid":pid,
            "backend_token":crate::host_lifecycle::process_token(i64::from(pid)).unwrap()}).to_string()).unwrap();
        let share = root.path().join("agents/bob/config-share");
        std::fs::create_dir_all(&share).unwrap();
        let bob_id = format!("ag-{}", "b".repeat(32));
        std::fs::write(
            share.join("host-launch-context.json"),
            json!({"agent_id":bob_id,"generation":run.run_id}).to_string(),
        )
        .unwrap();
        std::fs::write(root.path().join("agents/bob/runtime.json"),json!({"name":"bob","agent_id":bob_id,"run_id":run.run_id,"state":"running","backend_pid":pid,
            "backend_token":crate::host_lifecycle::process_token(i64::from(pid)).unwrap()}).to_string()).unwrap();
        let key_bytes = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(key_bytes.as_ref()).unwrap();
        let data = root.path().join("data");
        let vault = crate::credentials::open(&data).unwrap();
        std::fs::write(data.join("instance_id"), "issuer").unwrap();
        std::fs::write(data.join("agent_token"), "host-fixture").unwrap();
        vault
            .store(crate::credentials::Credential::new(
                "host-key",
                "ed25519",
                crate::credentials::Secret::new(STANDARD.encode(key_bytes.as_ref())),
            ))
            .unwrap();
        let mut package: Package = serde_json::from_str(include_str!(
            "../../../tests/fixtures/host_execution/package.json"
        ))
        .unwrap();
        package
            .operations
            .insert("hidden".into(), package.operations["restart"].clone());
        let scope = OperationScope {
            implementation_sha256: package.operations["restart"].implementation_sha256(),
            resources: ["service:demo".into()].into(),
            arguments: BTreeMap::from([
                ("wait".into(), vec![json!(5), json!(6)]),
                ("mode".into(), vec![json!("normal"), json!("quiet")]),
            ]),
            budgets: Budgets {
                calls: 100,
                concurrent: 10,
                timeout_seconds: 20,
                output_bytes: 1024,
            },
            updates: None,
            checks: Default::default(),
        };
        let verbs = [
            Verb::Discover,
            Verb::Propose,
            Verb::Invoke,
            Verb::Job,
            Verb::Output,
            Verb::Cancel,
        ]
        .into();
        let grant = Grant {
            principal: Principal {
                run: run.clone(),
                task_id: Some("approved-task".into()),
            },
            not_before: now() - 1,
            expires_at: now() + 600,
            verbs,
            operations: BTreeMap::from([("restart".into(), scope.clone())]),
            families: Vec::new(),
        };
        let mut target = Target {
            target_id: "local-test".into(),
            ceiling_revision: "1".into(),
            allowed_verbs: grant.verbs.clone(),
            max_authority_age_seconds: 600,
            issuers: BTreeMap::from([(
                "issuer".into(),
                IssuerTrust {
                    revision: "1".into(),
                    public_keys: BTreeMap::from([(
                        "key".into(),
                        STANDARD.encode(key.public_key().as_ref()),
                    )]),
                    authority: IssuerAuthority {
                        revision: "1".into(),
                        assessment_revision: "1".into(),
                        observed_at: now() - 1,
                        valid_until: now() + 600,
                        grants: BTreeMap::from([("approved".into(), grant)]),
                    },
                },
            )]),
            ceiling: BTreeMap::from([("restart".into(), scope)]),
            package,
            families: Vec::new(),
            catalogue: None,
        };
        let mut foreign = target.issuers["issuer"].authority.grants["approved"].clone();
        foreign.principal.run.agent = "bob".into();
        foreign.principal.run.agent_id = format!("ag-{}", "b".repeat(32));
        foreign.operations = BTreeMap::from([("hidden".into(), target.ceiling["restart"].clone())]);
        target
            .issuers
            .get_mut("issuer")
            .unwrap()
            .authority
            .grants
            .insert("foreign".into(), foreign);
        target
            .ceiling
            .insert("hidden".into(), target.ceiling["restart"].clone());
        let task = json!({"permissions":[]});
        let socket = root.path().join("executor.sock");
        let binding = Binding {
            target: target.clone(),
            issuer_id: "issuer".into(),
            grant_id: "approved".into(),
            key_id: "key".into(),
            credential: "host-key".into(),
            service: "local-host".into(),
            socket: socket.clone(),
            executor_uid: unsafe { libc::geteuid() },
            task_revision: revision(&task),
            timeout_ms: 1000,
            request_bytes: 131072,
            response_bytes: 1048576,
        };
        let source = format!(
            "budget=10000\n[agents.alice]\nagent_id={:?}\n[agents.bob]\nagent_id={:?}\n[[permissions]]\naction='gateway:request'\nresource='local-host:/v1/host-execution/*'\neffect='allow'\n[host_bindings]\nlocal={}\n{}",
            run.agent_id,
            format!("ag-{}", "b".repeat(32)),
            serde_json::to_string(&serde_json::to_string(&binding).unwrap()).unwrap(),
            extra
        );
        std::fs::write(root.path().join("policy.toml"), &source).unwrap();
        let mut config:Config=serde_json::from_value(json!({"native_product":true,"policy_file":root.path().join("policy.toml"),"data_dir":data,
            "listeners":[{"agent_id":"alice","socket_path":root.path().join("alice.sock")},{"agent_id":"bob","socket_path":root.path().join("bob.sock")}],"admin_port":0,"readiness_file":root.path().join("ready"),
            "audit_log_path":root.path().join("audit.jsonl"),"flow_store_enabled":false,"circuit_breaker_enabled":false})).unwrap();
        config.native_config_dir = Some(root.path().into());
        let proxy = Proxy::start(config).await.unwrap();
        proxy
            .runtime
            .read()
            .unwrap()
            .tasks
            .upsert("approved-task", task)
            .unwrap();
        assert!(crate::activate_registered_task(&proxy.runtime, "approved-task").is_ok());
        assert!(run.current(proxy.runtime.read().unwrap().policy.as_ref().unwrap()));
        let ledger_dir = root.path().join("target-ledger");
        std::fs::create_dir(&ledger_dir).unwrap();
        std::fs::set_permissions(&ledger_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = Arc::new(Mutex::new(
            Ledger::open(
                &ledger_dir,
                &target.target_id,
                LedgerLimits {
                    jobs: 100,
                    mutation_records: 200,
                    output_bytes: 1048576,
                    database_bytes: 16 * 1048576,
                    request_bytes: 131072,
                },
            )
            .unwrap(),
        ));
        let target = Arc::new(RwLock::new(target));
        let mutations = Arc::new(AtomicUsize::new(0));
        let lose_reply = Arc::new(AtomicBool::new(false));
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = {
            let ledger = ledger.clone();
            let target = target.clone();
            let mutations = mutations.clone();
            let lose_reply = lose_reply.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    reader.read_line(&mut line).await.unwrap();
                    let path = line.split_whitespace().nth(1).unwrap().to_string();
                    let mut size = 0;
                    loop {
                        line.clear();
                        reader.read_line(&mut line).await.unwrap();
                        if line == "\r\n" {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("content-length")
                        {
                            size = value.trim().parse().unwrap();
                        }
                    }
                    let mut bytes = vec![0; size];
                    reader.read_exact(&mut bytes).await.unwrap();
                    let result = ledger.lock().unwrap().handle(
                        &target.read().unwrap(),
                        &path,
                        &bytes,
                        now(),
                    );
                    let response = match result {
                        Ok(admitted) => {
                            if admitted.dispatch {
                                mutations.fetch_add(1, Ordering::SeqCst);
                            }
                            admitted.response
                        }
                        Err(refusal) => Response::Refused { refusal },
                    };
                    if lose_reply.swap(false, Ordering::SeqCst) {
                        continue;
                    }
                    let bytes = serde_json::to_vec(&response).unwrap();
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        bytes.len()
                    );
                    let stream = reader.get_mut();
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(&bytes).await;
                }
            })
        };
        Self {
            root,
            proxy,
            binding,
            run,
            target,
            ledger,
            key,
            mutations,
            lose_reply,
            server,
            backend,
            source,
        }
    }

    async fn call(&self, input: Input) -> Reply {
        self.api("/gateway/host/local", "POST", json!(input)).await
    }
    fn input(&self, id: &str, action: Action) -> Input {
        Input {
            request_id: id.into(),
            expected: Some(
                self.binding
                    .target
                    .request_revisions(&self.binding.issuer_id, &self.binding.grant_id, &action)
                    .unwrap(),
            ),
            action,
            untrusted_rationale: String::new(),
            challenge_id: None,
        }
    }
    fn invocation(&self, wait: Option<i64>) -> Invocation {
        Invocation {
            operation_id: "restart".into(),
            resource_id: "service:demo".into(),
            operation_sha256: self
                .binding
                .target
                .package
                .operation_sha256("restart")
                .unwrap(),
            implementation_sha256: self.binding.target.package.operations["restart"]
                .implementation_sha256(),
            arguments: wait.map_or(BTreeMap::new(), |wait| {
                BTreeMap::from([("wait".into(), json!(wait))])
            }),
            expected_assessment_sha256: None,
        }
    }
    async fn prepared(&self, id: &str, wait: Option<i64>) -> Input {
        let reply = self
            .call(self.input(
                &format!("propose-{id}"),
                Action::Propose {
                    invocation: self.invocation(wait),
                },
            ))
            .await;
        assert_eq!(reply.status, 200, "{}", reply.value);
        let Response::Proposal { prepared } = serde_json::from_value(reply.value).unwrap() else {
            panic!()
        };
        self.input(
            id,
            Action::Invoke {
                invocation: prepared.invocation,
            },
        )
    }
    async fn stop(mut self) {
        self.server.abort();
        let _ = self.backend.kill().await;
        self.proxy.shutdown().await;
    }

    async fn api(&self, path: &str, method: &str, value: Value) -> Reply {
        self.api_for("alice", path, method, value).await
    }

    async fn api_for(&self, agent: &str, path: &str, method: &str, value: Value) -> Reply {
        use http_body_util::{BodyExt, Full};
        use hyper_util::rt::TokioIo;
        let stream =
            tokio::net::UnixStream::connect(self.root.path().join(format!("{agent}.sock")))
                .await
                .unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let connection = tokio::spawn(connection);
        let request = hyper::Request::builder()
            .method(method)
            .uri(format!("http://_safeyolo.proxy.internal{path}"))
            .header("host", "_safeyolo.proxy.internal")
            .header("authorization", "Bearer host-fixture")
            .header("content-type", "application/json")
            .body(Full::new(bytes::Bytes::from(if method == "GET" {
                Vec::new()
            } else {
                serde_json::to_vec(&value).unwrap()
            })))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        connection.abort();
        Reply {
            status,
            value: serde_json::from_slice(&bytes).unwrap(),
        }
    }

    fn install(&mut self, source: String) {
        crate::apply_native_policy(&self.proxy.runtime, &source).unwrap();
        self.source = source;
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adaptive_operations_and_lost_reply_use_real_target_receipts_without_duplicate_dispatch() {
    let f = Fixture::new("").await;
    let discovery = f.call(f.input("discover", Action::Discover)).await;
    assert_eq!(discovery.status, 200, "{}", discovery.value);
    assert_eq!(
        discovery.value["discovery"]["operations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        discovery.value["discovery"]["operations"][0]["operation_id"],
        "restart"
    );
    let first = f.prepared("first", None).await;
    f.lose_reply.store(true, Ordering::SeqCst);
    let lost = f.call(first.clone()).await;
    assert_eq!(lost.value["execution_outcome"], "uncertain");
    let job = lost.value["possible_job_id"].as_str().unwrap().to_string();
    let inspected = f
        .call(f.input(
            "inspect-first",
            Action::Job {
                job_id: job.clone(),
            },
        ))
        .await;
    assert_eq!(inspected.value["receipt"]["request_id"], "first");
    let replay = f.call(first).await;
    assert_eq!(replay.status, 200);
    assert_eq!(f.mutations.load(Ordering::SeqCst), 1);
    let second = f.prepared("second", Some(6)).await;
    assert_eq!(f.call(second).await.status, 200);
    assert_eq!(f.mutations.load(Ordering::SeqCst), 2);
    assert!(
        f.proxy
            .runtime
            .read()
            .unwrap()
            .audit
            .approvals()
            .list()
            .unwrap()
            .is_empty()
    );
    let output = f
        .call(f.input(
            "output",
            Action::Output {
                job_id: job.clone(),
                offset: 0,
                max_bytes: 100,
            },
        ))
        .await;
    assert_eq!(output.status, 200);
    let cancelled = f
        .call(f.input(
            "cancel",
            Action::Cancel {
                job_id: job,
                expected_revision: 1,
            },
        ))
        .await;
    assert_eq!(cancelled.value["receipt"]["cancellation_requested"], true);
    f.stop().await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_scopes_defaults_current_policy_and_cross_agent_objects_are_enforced() {
    let mut f = Fixture::new("").await;
    assert_eq!(
        f.api_for(
            "bob",
            "/gateway/host/local",
            "POST",
            json!({"request_id":"unbound-ingress","expected":null,"action":{"kind":"discover"}})
        )
        .await
        .status,
        403
    );
    assert_eq!(
        f.api_for("bob", "/gateway/host", "GET", Value::Null)
            .await
            .value["host_bindings"],
        json!([])
    );
    let mut outsider = f.run.clone();
    outsider.agent = "bob".into();
    outsider.agent_id = format!("ag-{}", "b".repeat(32));
    let error = execute(
        &f.proxy.runtime,
        &outsider,
        "local",
        f.input("unbound", Action::Discover),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(
        error.downcast_ref::<Refusal>().unwrap().code,
        RefusalCode::Principal
    );
    assert_eq!(
        f.api(
            "/gateway/host/local",
            "POST",
            json!({"request_id":"substitute","action":{"kind":"discover"},"target_id":"attacker"})
        )
        .await
        .status,
        400
    );
    let visible = f.api("/gateway/host", "GET", Value::Null).await;
    assert_eq!(
        visible.value["host_bindings"][0]["principal"]["task_id"],
        "approved-task"
    );
    for variant in ["argument", "unknown", "selector", "default"] {
        let mut invocation = f.invocation(None);
        match variant {
            "argument" => {
                invocation.arguments.insert("wait".into(), json!(7));
            }
            "unknown" => {
                invocation
                    .arguments
                    .insert("principal".into(), json!("root"));
            }
            "selector" => invocation.resource_id = "service:*".into(),
            "default" => {
                invocation.arguments.insert("mode".into(), Value::Null);
            }
            _ => unreachable!(),
        }
        assert!(
            execute(
                &f.proxy.runtime,
                &f.run,
                "local",
                f.input(variant, Action::Propose { invocation })
            )
            .await
            .is_err(),
            "{variant}"
        );
    }
    // A target-owned foreign job exists in the same ledger and is addressable
    // by its real ID. The caller's project/name claims cannot change its owner.
    let mut foreign = f.binding.clone();
    foreign.grant_id = "foreign".into();
    let mut invocation = f.invocation(None);
    invocation.operation_id = "hidden".into();
    invocation.operation_sha256 = foreign.target.package.operation_sha256("hidden").unwrap();
    let mut input = f.input("foreign-proposal", Action::Propose { invocation });
    let principal = foreign.grant().unwrap().principal.clone();
    let request = foreign.request(principal.clone(), &input).unwrap();
    input.expected = Some(
        foreign
            .target
            .request_revisions("issuer", "foreign", &input.action)
            .unwrap(),
    );
    let request = Request {
        expected: input.expected.clone(),
        ..request
    };
    let signed = SignedRequest::sign(request, "key".into(), &f.key);
    let prepared = f
        .ledger
        .lock()
        .unwrap()
        .handle(
            &foreign.target,
            Verb::Propose.path(),
            &serde_json::to_vec(&signed).unwrap(),
            now(),
        )
        .unwrap();
    let Response::Proposal { prepared } = prepared.response else {
        panic!()
    };
    input.request_id = "foreign-invoke".into();
    input.action = Action::Invoke {
        invocation: prepared.invocation,
    };
    let signed = SignedRequest::sign(
        foreign.request(principal, &input).unwrap(),
        "key".into(),
        &f.key,
    );
    let receipt = f
        .ledger
        .lock()
        .unwrap()
        .handle(
            &foreign.target,
            Verb::Invoke.path(),
            &serde_json::to_vec(&signed).unwrap(),
            now(),
        )
        .unwrap();
    let Response::Job { receipt } = receipt.response else {
        panic!()
    };
    for action in [
        Action::Job {
            job_id: receipt.job_id.clone(),
        },
        Action::Output {
            job_id: receipt.job_id.clone(),
            offset: 0,
            max_bytes: 1,
        },
        Action::Cancel {
            job_id: receipt.job_id.clone(),
            expected_revision: 1,
        },
    ] {
        let reply = f.call(f.input("foreign-read", action)).await;
        assert_eq!(reply.status, 403, "{}", reply.value);
    }
    let ready = f.prepared("blocked-by-policy", None).await;
    let denied = f.source.clone()
        + "\n[[permissions]]\naction='gateway:request'\nresource='local-host:/v1/host-execution/invoke'\neffect='deny'\n";
    f.install(denied);
    assert!(
        execute(&f.proxy.runtime, &f.run, "local", ready)
            .await
            .is_err()
    );
    assert_eq!(f.mutations.load(Ordering::SeqCst), 0);
    f.stop().await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_reconsideration_and_explicit_exact_escalation_reuse_the_approval_owner() {
    let requirements = "[route_challenges.host]\nagents=['alice']\nservice='local-host'\ncapability='restart'\nmethods=['POST']\npath='/v1/host-execution/invoke'\nrevision='1'\nsteps=[{kind='question',field='origin',question='Identify the instruction origin'}]\n";
    let mut f = Fixture::new(requirements).await;
    let mut input = f.prepared("needs-check", None).await;
    let challenge = f.call(input.clone()).await;
    assert_eq!(challenge.status, 428);
    let id = challenge.value["challenge_id"].as_str().unwrap().to_owned();
    assert_eq!(f.mutations.load(Ordering::SeqCst), 0);
    assert!(
        f.proxy
            .runtime
            .read()
            .unwrap()
            .audit
            .approvals()
            .list()
            .unwrap()
            .iter()
            .all(|record| record.status == "challenged")
    );
    let escalation = format!("/gateway/challenges/{id}/escalate");
    let context = json!({"source":"direct_operator_request","context":{"task":"approved-task","reason":"Exercise this operation","fallback":"Status cannot perform the requested change"}});
    assert_eq!(
        f.api(&escalation, "POST", context.clone()).await.status,
        422
    );
    let mut answers = context.clone();
    answers["answers"] = json!({"origin":"Operator request in the approved task"});
    let pending = f.api(&escalation, "POST", answers).await;
    assert_eq!(pending.status, 202, "{}", pending.value);
    let runtime = f.proxy.runtime.read().unwrap().clone();
    let state = f.proxy.runtime.clone();
    let audit = runtime.audit.clone();
    let approval_id = id.clone();
    let approved = tokio::task::spawn_blocking(move || {
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
    assert_eq!(approved.1["status"], "approved", "{}", approved.1);
    input.challenge_id = Some(id.clone());
    assert_eq!(f.call(input.clone()).await.status, 200);
    assert_eq!(f.call(input.clone()).await.status, 200);
    assert_eq!(f.mutations.load(Ordering::SeqCst), 1);
    // An approved sample does not permit a new operation ID or payload.
    input.request_id = "different".into();
    assert!(
        execute(&f.proxy.runtime, &f.run, "local", input)
            .await
            .is_err()
    );
    let next = f.prepared("changed-check", Some(6)).await;
    let old = f.call(next.clone()).await;
    let old_id = old.value["challenge_id"].as_str().unwrap();
    let source = f.source.replace("revision='1'", "revision='2'");
    f.install(source);
    let record = pending::lookup(&runtime.audit, old_id).unwrap().unwrap();
    assert_eq!(
        record
            .current_status(f.proxy.runtime.read().unwrap().policy.as_ref().unwrap())
            .unwrap(),
        "superseded"
    );
    assert_eq!(f.mutations.load(Ordering::SeqCst), 1);
    let next = f.prepared("changed-credential", None).await;
    let challenge = f.call(next.clone()).await;
    let id = challenge.value["challenge_id"].as_str().unwrap();
    let record = pending::lookup(&runtime.audit, id).unwrap().unwrap();
    let vault = crate::credentials::open(&f.root.path().join("data")).unwrap();
    assert!(vault.remove("host-key").unwrap());
    let current = f.proxy.runtime.read().unwrap().clone();
    let view = pending::current_view(
        &runtime.audit,
        current.policy.as_ref().unwrap(),
        &record,
        Some(&f.proxy.runtime),
    )
    .unwrap();
    assert_eq!(view["status"], "superseded");
    assert_eq!(view["admission_active"], false);
    assert_eq!(f.call(next).await.status, 503);
    assert_eq!(f.mutations.load(Ordering::SeqCst), 1);
    f.stop().await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_task_switch_and_target_revision_changes_preserve_retained_jobs() {
    let f = Fixture::new("").await;
    let first = f.prepared("retained", None).await;
    let admitted = f.call(first).await;
    let job = admitted.value["receipt"]["job_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let stale = f.prepared("changed-catalogue", Some(6)).await;
    f.target
        .write()
        .unwrap()
        .package
        .operations
        .get_mut("restart")
        .unwrap()
        .arguments
        .get_mut("mode")
        .unwrap()
        .default = Some(json!("quiet"));
    assert_eq!(f.call(stale).await.status, 409);
    assert_eq!(f.mutations.load(Ordering::SeqCst), 1);
    *f.target.write().unwrap() = f.binding.target.clone();
    let future = f.prepared("after-revoke", Some(6)).await;
    f.target
        .write()
        .unwrap()
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .remove("approved");
    assert_eq!(f.call(future).await.status, 403);
    assert_eq!(
        f.ledger.lock().unwrap().observe(&job).unwrap().request_id,
        "retained"
    );
    assert_eq!(f.mutations.load(Ordering::SeqCst), 1);
    // Replacing an activated task with byte-identical policy still changes its
    // trusted identity. It cannot borrow the original task's host binding.
    f.proxy
        .runtime
        .read()
        .unwrap()
        .tasks
        .upsert("other-task", json!({"permissions":[]}))
        .unwrap();
    assert!(crate::activate_registered_task(&f.proxy.runtime, "other-task").is_ok());
    assert!(
        execute(
            &f.proxy.runtime,
            &f.run,
            "local",
            f.input("new-task", Action::Discover)
        )
        .await
        .is_err()
    );
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_allowed_host_route_still_requires_its_adopted_check_evidence() {
    let f = Fixture::new(
        r#"
[checks.native]
source_id='task-assessor'
meaning='A positive finding identifies an unsafe task action'
subject='value'
result_type='finding'
influences=['advisory']
implementation_version='1'
configuration_version='1'
max_age_seconds=60
source={kind='service',operation={gate_id='native',service='assessor',capability='read',endpoint='http://127.0.0.1:9',method='POST',path='/assess',effects='active',mapping='typed'},limits={timeout_ms=100,max_input_bytes=65536,max_output_bytes=1024,max_concurrent=1,max_pending=1,max_cached=1}}
[route_challenges.host]
agents=['alice']
service='local-host'
capability='restart'
methods=['POST']
path='/v1/host-execution/invoke'
revision='1'
steps=[{kind='check',check='native',on_positive={kind='deny'}}]
"#,
    )
    .await;
    // The assessor has no adopted dependency/grant. Missing evidence must
    // stop the actual gateway consumer before any target invocation.
    let input = f.prepared("required-check", None).await;
    let reply = f.call(input).await;
    assert_eq!(reply.status, 428, "{}", reply.value);
    assert_eq!(reply.value["assessment"]["ready_for_escalation"], false);
    assert_eq!(reply.value["assessment"]["steps"][0]["check"], "native");
    assert!(
        reply.value["assessment"]["steps"][0]["unavailable"].is_string(),
        "{}",
        reply.value
    );
    assert_eq!(f.mutations.load(Ordering::SeqCst), 0);
    assert!(
        f.proxy
            .runtime
            .read()
            .unwrap()
            .audit
            .approvals()
            .list()
            .unwrap()
            .iter()
            .all(|record| record.status == "challenged")
    );
    f.stop().await;
}

#[test]
fn agent_input_cannot_substitute_authority_or_enrol_issuers_and_definitions() {
    let base = json!({"request_id":"one","expected":null,"action":{"kind":"discover"}});
    for field in [
        "target_id",
        "issuer_id",
        "grant_id",
        "principal",
        "expires_at",
        "credential",
        "socket",
        "key_id",
        "signature",
        "definitions",
        "project",
    ] {
        let mut value = base.clone();
        value[field] = json!("attacker");
        assert!(serde_json::from_value::<Input>(value).is_err(), "{field}");
    }
    for kind in ["define", "enrol", "delete_definition", "replace_catalogue"] {
        let mut value = base.clone();
        value["action"]["kind"] = json!(kind);
        assert!(serde_json::from_value::<Input>(value).is_err());
    }
}
