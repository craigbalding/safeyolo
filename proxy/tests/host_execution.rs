//! Authenticated HTTP contract witness; it executes no host operation.
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full};
use hyper::{Request as HttpRequest, Response as HttpResponse, body::Bytes, service::service_fn};
use hyper_util::rt::TokioIo;
use ring::signature::{Ed25519KeyPair, KeyPair};
use safeyolo_proxy::{host_execution::*, services::ServiceDefinition};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

const NOW: u64 = 100;

fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[47; 32]).unwrap()
}

fn principal() -> Principal {
    serde_json::from_value(json!({"run":{"agent":"alice","agent_id":"ag-alice","run_id":"11111111111111111111111111111111"},"task_id":"task-demo"})).unwrap()
}

fn fixture_target() -> Target {
    let package: Package =
        serde_json::from_str(include_str!("fixtures/host_execution/package.json")).unwrap();
    let scope:OperationScope=serde_json::from_value(json!({"implementation_sha256":package.operations["restart"].implementation_sha256(),"resources":["service:demo"],"arguments":{"wait":[5],"mode":["normal","quiet"]},"budgets":{"calls":2,"concurrent":1,"timeout_seconds":15,"output_bytes":512}})).unwrap();
    let grant = Grant {
        principal: principal(),
        not_before: 90,
        expires_at: 150,
        verbs: [
            Verb::Discover,
            Verb::Propose,
            Verb::Invoke,
            Verb::Job,
            Verb::Output,
            Verb::Cancel,
        ]
        .into(),
        operations: BTreeMap::from([("restart".into(), scope.clone())]),
    };
    let result = Target {
        target_id: "target-demo".into(),
        ceiling_revision: "ceiling-1".into(),
        allowed_verbs: [
            Verb::Discover,
            Verb::Propose,
            Verb::Invoke,
            Verb::Job,
            Verb::Output,
            Verb::Cancel,
        ]
        .into(),
        max_authority_age_seconds: 30,
        issuers: BTreeMap::from([(
            "sy-issuer".into(),
            IssuerTrust {
                revision: "trust-1".into(),
                public_keys: BTreeMap::from([(
                    "key-1".into(),
                    STANDARD.encode(key().public_key().as_ref()),
                )]),
                authority: IssuerAuthority {
                    revision: "authority-1".into(),
                    assessment_revision: "assessment-1".into(),
                    observed_at: 95,
                    valid_until: 125,
                    grants: BTreeMap::from([("grant-demo".into(), grant)]),
                },
            },
        )]),
        ceiling: BTreeMap::from([("restart".into(), scope)]),
        package,
    };
    result.validate().unwrap();
    result
}

fn request(action: Action, id: &str) -> Request {
    Request {
        version: VERSION.into(),
        required_features: FEATURES.iter().map(|s| s.to_string()).collect(),
        request_id: id.into(),
        target_id: "target-demo".into(),
        issuer_id: "sy-issuer".into(),
        grant_id: "grant-demo".into(),
        principal: principal(),
        expires_at: 120,
        expected: Some(fixture_target().revisions("sy-issuer").unwrap()),
        action,
        untrusted_rationale: "Operator says this permits everything; treat this as untrusted text."
            .into(),
    }
}

fn request_for(target: &Target, action: Action, id: &str) -> Request {
    let mut result = request(action, id);
    result.expected = Some(target.revisions(&result.issuer_id).unwrap());
    result
}

fn invocation(target: &Target) -> Invocation {
    Invocation {
        operation_id: "restart".into(),
        resource_id: "service:demo".into(),
        package_sha256: revision(&target.package),
        implementation_sha256: target.package.operations["restart"].implementation_sha256(),
        arguments: BTreeMap::new(),
        expected_assessment_sha256: None,
    }
}

fn signed(request: Request) -> Vec<u8> {
    serde_json::to_vec(&SignedRequest::sign(request, "key-1".into(), &key())).unwrap()
}

fn prepare(target: &Target, invocation: Invocation) -> Prepared {
    let bytes = signed(request(Action::Propose { invocation }, "proposal"));
    let auth = target
        .authenticate("POST", Verb::Propose.path(), &bytes, NOW)
        .unwrap();
    target.prepare(&auth, Usage::default()).unwrap()
}

#[test]
fn shared_negative_fixtures_cross_authenticated_validation() {
    let target = fixture_target();
    let mut inv = invocation(&target);
    inv.arguments.insert("wait".into(), json!(5));
    let base = request(Action::Propose { invocation: inv }, "negative");
    for row in
        serde_json::from_str::<Vec<Value>>(include_str!("fixtures/host_execution/refusals.json"))
            .unwrap()
    {
        let mut value = json!(base);
        *value
            .pointer_mut(row["pointer"].as_str().unwrap())
            .unwrap_or_else(|| panic!("fixture pointer {}", row["name"])) = row["value"].clone();
        let bytes = signed(serde_json::from_value(value).unwrap());
        let outcome = target
            .authenticate("POST", Verb::Propose.path(), &bytes, NOW)
            .and_then(|auth| target.prepare(&auth, Usage::default()));
        let error = outcome.unwrap_err();
        assert_eq!(json!(error.code), row["code"], "{}: {error}", row["name"]);
    }
}

#[test]
fn signatures_rotation_expiry_and_fresh_authority_are_independent() {
    let mut target = fixture_target();
    let req = request(Action::Discover, "discovery");
    let bytes = signed(req.clone());
    let mut tampered: SignedRequest = serde_json::from_slice(&bytes).unwrap();
    tampered.request.untrusted_rationale.push('!');
    assert_eq!(
        target
            .authenticate(
                "POST",
                Verb::Discover.path(),
                &serde_json::to_vec(&tampered).unwrap(),
                NOW
            )
            .err()
            .unwrap()
            .code,
        RefusalCode::Signature
    );
    assert_eq!(
        target
            .authenticate("GET", Verb::Discover.path(), &bytes, NOW)
            .err()
            .unwrap()
            .code,
        RefusalCode::Protocol
    );
    assert_eq!(
        target
            .authenticate("POST", Verb::Invoke.path(), &bytes, NOW)
            .err()
            .unwrap()
            .code,
        RefusalCode::Protocol
    );
    assert_eq!(
        target
            .authenticate("POST", Verb::Discover.path(), &bytes, 125)
            .err()
            .unwrap()
            .code,
        RefusalCode::Stale
    );
    target
        .issuers
        .get_mut("sy-issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant-demo")
        .unwrap()
        .expires_at = NOW;
    assert_eq!(
        target
            .authenticate("POST", Verb::Discover.path(), &bytes, NOW)
            .err()
            .unwrap()
            .code,
        RefusalCode::Expired
    );
    target
        .issuers
        .get_mut("sy-issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant-demo")
        .unwrap()
        .expires_at = 150;
    target
        .issuers
        .get_mut("sy-issuer")
        .unwrap()
        .public_keys
        .remove("key-1");
    target
        .issuers
        .get_mut("sy-issuer")
        .unwrap()
        .public_keys
        .insert("key-2".into(), STANDARD.encode(key().public_key().as_ref()));
    assert_eq!(
        target
            .authenticate("POST", Verb::Discover.path(), &bytes, NOW)
            .err()
            .unwrap()
            .code,
        RefusalCode::Issuer
    );
    let rotated = serde_json::to_vec(&SignedRequest::sign(req, "key-2".into(), &key())).unwrap();
    assert!(
        target
            .authenticate("POST", Verb::Discover.path(), &rotated, NOW)
            .is_ok()
    );
    target
        .issuers
        .get_mut("sy-issuer")
        .unwrap()
        .authority
        .grants
        .clear();
    assert_eq!(
        target
            .authenticate("POST", Verb::Discover.path(), &rotated, NOW)
            .err()
            .unwrap()
            .code,
        RefusalCode::Authority
    );
}

#[test]
fn membership_scope_defaults_and_proposal_inputs_do_not_confer_authority() {
    let mut target = fixture_target();
    let prepared = prepare(&target, invocation(&target));
    assert_eq!(prepared.invocation.arguments["wait"], 5);
    assert_eq!(prepared.limits.timeout_seconds, 15);
    assert_eq!(prepared.limits.output_bytes, 512);
    let bytes = signed(request(
        Action::Invoke {
            invocation: prepared.invocation.clone(),
        },
        "admit",
    ));
    let auth = target
        .authenticate("POST", Verb::Invoke.path(), &bytes, NOW)
        .unwrap();
    assert!(
        target
            .admit(
                &auth,
                Usage {
                    admitted: 1,
                    active: 0
                },
                NOW
            )
            .is_ok()
    );
    assert_eq!(
        target
            .admit(
                &auth,
                Usage {
                    admitted: 2,
                    active: 0
                },
                NOW
            )
            .unwrap_err()
            .code,
        RefusalCode::Budget
    );
    assert_eq!(
        target
            .admit(
                &auth,
                Usage {
                    admitted: 0,
                    active: 1
                },
                NOW
            )
            .unwrap_err()
            .code,
        RefusalCode::Budget
    );
    assert_eq!(
        target.admit(&auth, Usage::default(), 120).unwrap_err().code,
        RefusalCode::Expired
    );
    let mut changed = prepared.invocation;
    changed.arguments.insert("mode".into(), json!("quiet")); // Also allowed, but not the assessed invocation.
    let bytes = signed(request(
        Action::Invoke {
            invocation: changed,
        },
        "changed",
    ));
    let auth = target
        .authenticate("POST", Verb::Invoke.path(), &bytes, NOW)
        .unwrap();
    assert_eq!(
        target.prepare(&auth, Usage::default()).unwrap_err().code,
        RefusalCode::Stale
    );
    target
        .issuers
        .get_mut("sy-issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant-demo")
        .unwrap()
        .operations
        .clear();
    let bytes = signed(request(Action::Discover, "membership"));
    let auth = target
        .authenticate("POST", Verb::Discover.path(), &bytes, NOW)
        .unwrap();
    let discovery = target.discover(&auth).unwrap();
    assert_eq!(discovery.operations.len(), 1);
    assert!(!discovery.operations[0].has_invocation_scope);
    let bytes = signed(request_for(
        &target,
        Action::Propose {
            invocation: invocation(&target),
        },
        "not-authorized",
    ));
    let auth = target
        .authenticate("POST", Verb::Propose.path(), &bytes, NOW)
        .unwrap();
    assert_eq!(
        target.prepare(&auth, Usage::default()).unwrap_err().code,
        RefusalCode::Authority
    );
    let mut target = fixture_target();
    target
        .ceiling
        .get_mut("restart")
        .unwrap()
        .arguments
        .insert("wait".into(), vec![json!(6)]);
    let bytes = signed(request_for(
        &target,
        Action::Propose {
            invocation: invocation(&target),
        },
        "default-outside-ceiling",
    ));
    let auth = target
        .authenticate("POST", Verb::Propose.path(), &bytes, NOW)
        .unwrap();
    assert_eq!(
        target.prepare(&auth, Usage::default()).unwrap_err().code,
        RefusalCode::Authority
    );
}

#[test]
fn one_package_binds_native_gateway_material_and_target_scope() {
    let target = fixture_target();
    let projections = target.package.projections().unwrap();
    target.package.verify_projections(&projections).unwrap();
    let service = ServiceDefinition::from_value(projections.gateway["restart"].clone()).unwrap();
    assert_eq!(
        service.capabilities["invoke"].routes[0].path,
        Verb::Invoke.path()
    );
    assert!(service.effect_model.unwrap().enforcement.is_empty()); // No unsupported nested-identity claim.
    let mut changed = projections.clone();
    changed
        .target
        .get_mut("restart")
        .unwrap()
        .execution
        .environment
        .clear();
    assert!(target.package.verify_projections(&changed).is_err());
    let mut changed = projections;
    changed.gateway.get_mut("restart").unwrap()["host_execution_source"]["package_version"] =
        json!(2);
    assert!(target.package.verify_projections(&changed).is_err());
    let discovery = safeyolo_proxy::policy::capabilities::discover();
    assert!(
        discovery["definitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["definition"] == "host_execution_package")
    );
    let schemas = schemas();
    assert!(schemas["request"]["$defs"]["Action"].is_object());
    let mut invalid = json!(target.package);
    invalid["operations"]["restart"]["arguments"]["wait"]["default"] = json!("5");
    assert!(
        serde_json::from_value::<Package>(invalid)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn generated_gateway_contract_requires_bound_resource_and_exact_operation_payload() {
    use safeyolo_proxy::contracts::{ContractBinding, ContractRequest, enforce_request};
    let target = fixture_target();
    let projections = target.package.projections().unwrap();
    let service = ServiceDefinition::from_value(projections.gateway["restart"].clone()).unwrap();
    let contract = service.capabilities["invoke"].contract.as_ref().unwrap();
    let binding:ContractBinding=serde_json::from_value(json!({"agent":"alice","service":service.name,"capability":"invoke","template":contract.template,"bound_values":{"resource_id":"service:demo","argument:wait":5,"argument:mode":"normal"},"grantable_operations":["invoke"]})).unwrap();
    let prepared = prepare(&target, invocation(&target));
    let good: Value = serde_json::from_slice(&signed(request(
        Action::Invoke {
            invocation: prepared.invocation,
        },
        "gateway",
    )))
    .unwrap();
    let headers = vec![("content-type".into(), "application/json".into())];
    let check = |value: &Value, bound: bool| {
        let body = serde_json::to_vec(value).unwrap();
        enforce_request(
            contract,
            bound.then_some(&binding),
            "authorization",
            ContractRequest {
                method: "POST",
                target: Verb::Invoke.path(),
                headers: &headers,
                body: &body,
            },
        )
        .is_ok()
    };
    assert!(check(&good, true));
    assert!(!check(&good, false));
    for (pointer, value) in [
        ("/request/action/invocation/operation_id", json!("replace")),
        (
            "/request/action/invocation/resource_id",
            json!("service:other"),
        ),
        ("/request/action/invocation/arguments/wait", json!(6)),
    ] {
        let mut changed = good.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(!check(&changed, true), "{pointer}");
    }
    let mut replacement = good;
    replacement["request"]["action"]["invocation"]["executable"] = json!("/bin/sh");
    assert!(!check(&replacement, true));
}

#[test]
fn invocation_cannot_replace_definitions_or_add_an_executable() {
    let target = fixture_target();
    let bytes = signed(request(
        Action::Propose {
            invocation: invocation(&target),
        },
        "replace",
    ));
    for pointer in [
        "/request/action/invocation/executable",
        "/request/action/invocation/environment",
        "/request/action/invocation/unit",
    ] {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        let parent = pointer.rsplit_once('/').unwrap();
        value
            .pointer_mut(parent.0)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(parent.1.into(), json!("replacement"));
        assert_eq!(
            target
                .authenticate(
                    "POST",
                    Verb::Propose.path(),
                    &serde_json::to_vec(&value).unwrap(),
                    NOW
                )
                .err()
                .unwrap()
                .code,
            RefusalCode::Malformed
        );
    }
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["request"]["action"]["kind"] = json!("deploy");
    assert_eq!(
        target
            .authenticate(
                "POST",
                Verb::Propose.path(),
                &serde_json::to_vec(&value).unwrap(),
                NOW
            )
            .err()
            .unwrap()
            .code,
        RefusalCode::Malformed
    );
    let mut inv = invocation(&target);
    inv.arguments.insert("executable".into(), json!("/bin/sh"));
    let bytes = signed(request(Action::Propose { invocation: inv }, "extra-arg"));
    let auth = target
        .authenticate("POST", Verb::Propose.path(), &bytes, NOW)
        .unwrap();
    assert_eq!(
        target.prepare(&auth, Usage::default()).unwrap_err().code,
        RefusalCode::Arguments
    );
}

/// Reference lifecycle only. Native persistence, process containment and issuer
/// synchronization are deliberately absent from this HTTP contract fixture.
struct Witness {
    target: Target,
    jobs: BTreeMap<String, Receipt>,
    outputs: BTreeMap<String, Vec<u8>>,
    replay: BTreeMap<(String, String), (String, Response)>,
    usage: BTreeMap<(String, String, String, String), u64>,
    dispatches: u64,
}

impl Witness {
    fn new() -> Self {
        Self {
            target: fixture_target(),
            jobs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            replay: BTreeMap::new(),
            usage: BTreeMap::new(),
            dispatches: 0,
        }
    }
    fn handle(&mut self, path: &str, bytes: &[u8]) -> Response {
        match self.dispatch(path, bytes) {
            Ok(value) => value,
            Err(refusal) => Response::Refused { refusal },
        }
    }
    fn dispatch(&mut self, path: &str, bytes: &[u8]) -> Result<Response, Refusal> {
        let auth = self.target.authenticate("POST", path, bytes, NOW)?;
        let req = auth.request();
        let replay_key = (req.issuer_id.clone(), req.request_id.clone());
        if let Some((digest, response)) = self.replay.get(&replay_key) {
            if digest != &revision(req) {
                return Err(Refusal {
                    code: RefusalCode::Conflict,
                    message: "request ID already identifies different content".into(),
                });
            }
            return Ok(response.clone());
        }
        let response = match &req.action {
            Action::Discover => Response::Discovery {
                discovery: self.target.discover(&auth)?,
            },
            Action::Propose { .. } => Response::Proposal {
                prepared: self.target.prepare(&auth, Usage::default())?,
            },
            Action::Invoke { invocation } => {
                let key = (
                    req.issuer_id.clone(),
                    req.grant_id.clone(),
                    auth.grant_revision(),
                    invocation.operation_id.clone(),
                );
                let usage = Usage {
                    admitted: *self.usage.get(&key).unwrap_or(&0),
                    active: self
                        .jobs
                        .values()
                        .filter(|j| {
                            !j.state.terminal()
                                && j.issuer_id == req.issuer_id
                                && j.grant_id == req.grant_id
                                && j.prepared.invocation.operation_id == invocation.operation_id
                        })
                        .count() as u64,
                };
                let receipt = self.target.admit(&auth, usage, NOW)?;
                self.usage.entry(key).and_modify(|n| *n += 1).or_insert(1);
                self.jobs.insert(receipt.job_id.clone(), receipt.clone());
                self.dispatches += 1;
                Response::Job {
                    receipt: Box::new(receipt),
                }
            }
            Action::Job { job_id }
            | Action::Output { job_id, .. }
            | Action::Cancel { job_id, .. } => {
                let receipt = self.jobs.get_mut(job_id).ok_or_else(|| Refusal {
                    code: RefusalCode::Selector,
                    message: "unknown job".into(),
                })?;
                self.target.authorize_job(&auth, receipt)?;
                match req.action {
                    Action::Cancel {
                        expected_revision, ..
                    } => {
                        receipt.request_cancellation(expected_revision, NOW)?;
                        Response::Job {
                            receipt: Box::new(receipt.clone()),
                        }
                    }
                    Action::Output {
                        offset, max_bytes, ..
                    } => {
                        let data = self.outputs.get(job_id).map_or(&[][..], Vec::as_slice);
                        if offset > data.len() as u64
                            || max_bytes == 0
                            || max_bytes > receipt.prepared.limits.output_bytes
                        {
                            return Err(Refusal {
                                code: RefusalCode::Arguments,
                                message: "output range exceeds retained output or effective limit"
                                    .into(),
                            });
                        }
                        let end = (offset.saturating_add(max_bytes) as usize).min(data.len());
                        Response::Output {
                            job_id: job_id.clone(),
                            revision: receipt.revision,
                            offset,
                            data_base64: STANDARD.encode(&data[offset as usize..end]),
                            eof: end == data.len(),
                            retained_bytes: data.len() as u64,
                            sha256: receipt.output_sha256.clone(),
                        }
                    }
                    _ => Response::Job {
                        receipt: Box::new(receipt.clone()),
                    },
                }
            }
        };
        // Inspection is current. Mutating replay responses are retained before
        // the response, allowing the lost-response demonstration below.
        if matches!(req.action, Action::Invoke { .. } | Action::Cancel { .. }) {
            self.replay
                .insert(replay_key, (revision(req), response.clone()));
        }
        Ok(response)
    }
}

async fn serve(
    witness: Arc<Mutex<Witness>>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let witness = witness.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: HttpRequest<hyper::body::Incoming>| {
                    let witness = witness.clone();
                    async move {
                        assert_eq!(request.method(), "POST");
                        let path = request.uri().path().to_owned();
                        let body = http_body_util::Limited::new(request.into_body(), 65536)
                            .collect()
                            .await
                            .unwrap()
                            .to_bytes();
                        let response = witness.lock().unwrap().handle(&path, &body);
                        Ok::<_, Infallible>(
                            HttpResponse::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(
                                    serde_json::to_vec(&response).unwrap(),
                                )))
                                .unwrap(),
                        )
                    }
                });
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });
    (addr, server)
}

async fn call(addr: std::net::SocketAddr, request: &Request) -> Response {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let http = HttpRequest::builder()
        .method("POST")
        .uri(request.action.verb().path())
        .header("host", addr.to_string())
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(signed(request.clone()))))
        .unwrap();
    let response = sender
        .send_request(http)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    serde_json::from_slice(&response).unwrap()
}

#[tokio::test]
async fn same_authenticated_http_protocol_on_standalone_and_safeyolo_targets() {
    for with_safeyolo in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let proxy = if with_safeyolo {
            std::fs::create_dir(root.path().join("data")).unwrap();
            std::fs::write(root.path().join("policy.toml"),"[agents.alice]\nagent_id='ag-alice'\n[hosts.'*']\negress='deny'\n[controls.credentials]\nenabled=false\n").unwrap();
            let config=serde_json::from_value(json!({"native_product":true,"policy_file":root.path().join("policy.toml"),"data_dir":root.path().join("data"),"listeners":[],"admin_port":0,"readiness_file":root.path().join("ready.json"),"audit_log_path":root.path().join("audit.jsonl"),"flow_store_enabled":false,"circuit_breaker_enabled":false})).unwrap();
            let proxy = safeyolo_proxy::Proxy::start(config).await.unwrap();
            assert!(root.path().join("ready.json").exists());
            Some(proxy)
        } else {
            None
        };
        let witness = Arc::new(Mutex::new(Witness::new()));
        let (addr, server) = serve(witness.clone()).await;
        let mut discover = request(Action::Discover, "discover");
        discover.expected = None;
        let Response::Discovery { discovery } = call(addr, &discover).await else {
            panic!("discovery failed")
        };
        assert_eq!(discovery.target_id, discover.target_id);
        assert_eq!(discovery.routes[&Verb::Invoke], Verb::Invoke.path());
        let mut inv = invocation(&witness.lock().unwrap().target);
        inv.package_sha256 = discovery.package_sha256;
        inv.implementation_sha256 = discovery.operations[0].implementation_sha256.clone();
        let Response::Proposal { prepared } = call(
            addr,
            &request(Action::Propose { invocation: inv }, "propose"),
        )
        .await
        else {
            panic!("proposal failed")
        };
        let invoke = request(
            Action::Invoke {
                invocation: prepared.invocation,
            },
            "invoke",
        );
        let Response::Job { receipt } = call(addr, &invoke).await else {
            panic!("admission failed")
        };
        assert_eq!(receipt.state, JobState::Admitted);
        // Treat the first reply as lost. Exact replay returns the retained job;
        // it must not consume another budget or dispatch another effect.
        let Response::Job { receipt: replayed } = call(addr, &invoke).await else {
            panic!("recovery failed")
        };
        assert_eq!(receipt.job_id, replayed.job_id);
        assert_eq!(witness.lock().unwrap().dispatches, 1);
        let mut conflict = invoke.clone();
        conflict.untrusted_rationale.push('!');
        let Response::Refused { refusal } = call(addr, &conflict).await else {
            panic!("ID conflict accepted")
        };
        assert_eq!(refusal.code, RefusalCode::Conflict);
        {
            let mut state = witness.lock().unwrap();
            let job = state.jobs.get_mut(&receipt.job_id).unwrap();
            job.transition(
                job.revision,
                JobState::Running,
                NOW,
                "reference dispatch started".into(),
            )
            .unwrap();
            job.record_output(job.revision, b"fixed witness output", NOW)
                .unwrap();
            state
                .outputs
                .insert(receipt.job_id.clone(), b"fixed witness output".to_vec());
        }
        let Response::Output {
            data_base64, eof, ..
        } = call(
            addr,
            &request(
                Action::Output {
                    job_id: receipt.job_id.clone(),
                    offset: 0,
                    max_bytes: 100,
                },
                "output",
            ),
        )
        .await
        else {
            panic!("output failed")
        };
        assert!(eof);
        assert_eq!(
            STANDARD.decode(data_base64).unwrap(),
            b"fixed witness output"
        );
        let Response::Job { receipt: running } = call(
            addr,
            &request(
                Action::Job {
                    job_id: receipt.job_id.clone(),
                },
                "read",
            ),
        )
        .await
        else {
            panic!("job read failed")
        };
        let Response::Job { receipt: cancel } = call(
            addr,
            &request(
                Action::Cancel {
                    job_id: receipt.job_id.clone(),
                    expected_revision: running.revision,
                },
                "cancel",
            ),
        )
        .await
        else {
            panic!("cancel request failed")
        };
        assert!(cancel.cancellation_requested);
        assert_eq!(cancel.state, JobState::Running);
        {
            let mut state = witness.lock().unwrap();
            let job = state.jobs.get_mut(&receipt.job_id).unwrap();
            job.transition(
                job.revision,
                JobState::Cancelled,
                NOW,
                "reference executor confirmed stop".into(),
            )
            .unwrap();
        }
        let Response::Job { receipt: cancelled } = call(
            addr,
            &request(
                Action::Job {
                    job_id: receipt.job_id.clone(),
                },
                "read-cancelled",
            ),
        )
        .await
        else {
            panic!("cancelled job missing")
        };
        assert_eq!(cancelled.state, JobState::Cancelled);
        let mut base = request(
            Action::Propose {
                invocation: invocation(&witness.lock().unwrap().target),
            },
            "negative",
        );
        if let Action::Propose { invocation } = &mut base.action {
            invocation.arguments.insert("wait".into(), json!(5));
        }
        for row in serde_json::from_str::<Vec<Value>>(include_str!(
            "fixtures/host_execution/refusals.json"
        ))
        .unwrap()
        {
            let mut value = json!(base);
            *value.pointer_mut(row["pointer"].as_str().unwrap()).unwrap() = row["value"].clone();
            let negative: Request = serde_json::from_value(value).unwrap();
            let Response::Refused { refusal } = call(addr, &negative).await else {
                panic!("HTTP fixture {} was accepted", row["name"])
            };
            assert_eq!(
                json!(refusal.code),
                row["code"],
                "HTTP fixture {}",
                row["name"]
            );
        }
        eprintln!(
            "host-execution witness: target={}, safeyolo_running={with_safeyolo}, discovery/proposal/admission/replay/output/cancel passed",
            cancelled.target_id
        );
        server.abort();
        if let Some(proxy) = proxy {
            proxy.shutdown().await;
        }
    }
}

#[test]
fn issuer_namespaces_job_disclosure_and_terminal_states_are_explicit() {
    let mut witness = Witness::new();
    let prepared = prepare(&witness.target, invocation(&witness.target));
    let req = request(
        Action::Invoke {
            invocation: prepared.invocation,
        },
        "same-id",
    );
    let Response::Job { receipt } = witness.handle(Verb::Invoke.path(), &signed(req.clone()))
    else {
        panic!("admit")
    };
    let mut not_cancelled = receipt.clone();
    assert_eq!(
        not_cancelled
            .transition(1, JobState::Cancelled, NOW, "unconfirmed".into())
            .unwrap_err()
            .code,
        RefusalCode::Conflict
    );
    assert_eq!(
        not_cancelled
            .record_output(1, &vec![0; 513], NOW)
            .unwrap_err()
            .code,
        RefusalCode::Budget
    );
    for terminal in [JobState::Completed, JobState::Failed, JobState::Uncertain] {
        let mut job = receipt.clone();
        job.transition(1, JobState::Running, NOW, "started".into())
            .unwrap();
        job.transition(2, terminal, NOW, "observed result".into())
            .unwrap();
        assert!(job.state.terminal());
        assert!(
            job.transition(3, JobState::Running, NOW, "replay".into())
                .is_err()
        );
        let restored: Receipt = serde_json::from_value(json!(job)).unwrap();
        assert_eq!(restored.state, terminal);
    }
    let mut trust = witness.target.issuers["sy-issuer"].clone();
    trust.public_keys.insert(
        "key-1".into(),
        STANDARD.encode(
            Ed25519KeyPair::from_seed_unchecked(&[48; 32])
                .unwrap()
                .public_key()
                .as_ref(),
        ),
    );
    witness.target.issuers.insert("sy-other".into(), trust);
    let mut other = req.clone();
    other.issuer_id = "sy-other".into();
    let response = witness.handle(Verb::Invoke.path(), &signed(other.clone()));
    assert!(matches!(
        response,
        Response::Refused {
            refusal: Refusal {
                code: RefusalCode::Signature,
                ..
            }
        }
    ));
    witness
        .target
        .issuers
        .get_mut("sy-other")
        .unwrap()
        .public_keys
        .insert("key-1".into(), STANDARD.encode(key().public_key().as_ref()));
    other.expected = Some(witness.target.revisions("sy-other").unwrap());
    let mut proposed = other.clone();
    proposed.request_id = "other-proposal".into();
    let mut inv = invocation(&witness.target);
    inv.expected_assessment_sha256 = None;
    proposed.action = Action::Propose { invocation: inv };
    let Response::Proposal { prepared } = witness.handle(Verb::Propose.path(), &signed(proposed))
    else {
        panic!("other proposal")
    };
    other.action = Action::Invoke {
        invocation: prepared.invocation,
    };
    let Response::Job { receipt: other_job } = witness.handle(Verb::Invoke.path(), &signed(other))
    else {
        panic!("second issuer admit")
    };
    assert_ne!(receipt.job_id, other_job.job_id);
    let mut read = request(
        Action::Job {
            job_id: receipt.job_id,
        },
        "read-other",
    );
    read.issuer_id = "sy-other".into();
    read.expected = Some(witness.target.revisions("sy-other").unwrap());
    assert!(matches!(
        witness.handle(Verb::Job.path(), &signed(read)),
        Response::Refused {
            refusal: Refusal {
                code: RefusalCode::Authority,
                ..
            }
        }
    ));
}

#[test]
fn command_words_preserve_fixed_implementation_and_never_evaluate_shell_text() {
    let target = fixture_target();
    let mut op = target.package.operations["restart"].clone();
    let command = op.command(&BTreeMap::new()).unwrap();
    assert_eq!(command.executable, "/usr/bin/fixed-demo-restart");
    assert_eq!(command.argv, ["demo.service", "5"]);
    assert_eq!(
        command.environment,
        BTreeMap::from([("LANG".into(), "C".into())])
    );
    op.arguments.insert(
        "words".into(),
        Argument {
            kind: ArgumentType::StringList,
            required: true,
            default: None,
            options: vec![],
        },
    );
    op.execution.argv.push(Word::Argument {
        name: "words".into(),
    });
    let supplied = BTreeMap::from([(
        "words".into(),
        json!(["$(touch /forbidden)", "a b", ";echo injected"]),
    )]);
    let command = op.command(&supplied).unwrap();
    assert_eq!(
        &command.argv[2..],
        ["$(touch /forbidden)", "a b", ";echo injected"]
    );
    op.execution.environment.insert(
        "WORDS".into(),
        Word::Argument {
            name: "words".into(),
        },
    );
    assert_eq!(
        op.command(&supplied).unwrap_err().code,
        RefusalCode::Arguments
    );
}

#[test]
fn local_action_ceiling_and_content_revisions_cannot_be_bypassed_by_labels() {
    let mut target = fixture_target();
    let before = target.revisions("sy-issuer").unwrap();
    target.allowed_verbs.remove(&Verb::Discover);
    let bytes = signed(request(Action::Discover, "local-denial"));
    assert_eq!(
        target
            .authenticate("POST", Verb::Discover.path(), &bytes, NOW)
            .err()
            .unwrap()
            .code,
        RefusalCode::Authority
    );
    assert_ne!(
        target.revisions("sy-issuer").unwrap().ceiling,
        before.ceiling
    );
    target.allowed_verbs.insert(Verb::Discover);
    target
        .issuers
        .get_mut("sy-issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant-demo")
        .unwrap()
        .operations
        .get_mut("restart")
        .unwrap()
        .budgets
        .calls = 9;
    assert_ne!(
        target.revisions("sy-issuer").unwrap().authority,
        before.authority
    );
    let bytes = signed(request(
        Action::Propose {
            invocation: invocation(&target),
        },
        "stale-content",
    ));
    assert_eq!(
        target
            .authenticate("POST", Verb::Propose.path(), &bytes, NOW)
            .err()
            .unwrap()
            .code,
        RefusalCode::Stale
    );
}
