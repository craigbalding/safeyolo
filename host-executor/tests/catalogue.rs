//! Real signed adoption and ledger consumers; no native program is launched.
#![cfg(unix)]
mod common;
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use safeyolo_host_executor::*;
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};

fn fixture() -> (Target, Ed25519KeyPair, CatalogueAdoption) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[59; 32]).unwrap();
    let mut package: Package = serde_json::from_str(include_str!(
        "../../proxy/tests/fixtures/host_execution/package.json"
    ))
    .unwrap();
    let op = package.operations.get_mut("restart").unwrap();
    op.arguments.clear();
    op.execution.argv.truncate(1);
    op.enforcement.unresolved.clear();
    op.enforcement
        .enforced
        .push("second represented boundary".into());
    let mut target = common::target("catalogue-fixture".into(), package.operations, &key);
    target.package.name = "catalogue-fixture".into();
    let rule = UpdateRule {
        ceiling: target.package.operations["restart"].clone(),
        allow_narrower: true,
        allow_implementation_updates: true,
    };
    target.ceiling.get_mut("restart").unwrap().updates = Some(rule.clone());
    target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant")
        .unwrap()
        .operations
        .get_mut("restart")
        .unwrap()
        .updates = Some(rule.clone());
    let active = signed_catalogue(&target.package, &key, false, None);
    let adoption = CatalogueAdoption {
        policy: CataloguePolicy {
            publisher: "publisher".into(),
            public_key: STANDARD.encode(key.public_key().as_ref()),
            package_name: target.package.name.clone(),
            operations: BTreeMap::from([("restart".into(), rule)]),
            families: Vec::new(),
            on_withdraw: Withdrawal::Retain,
        },
        active: active.clone(),
        previous: None,
        observed: active,
        pin: None,
        observed_file: None,
    };
    (target, key, adoption)
}
fn signed_catalogue(
    package: &Package,
    key: &Ed25519KeyPair,
    withdrawn: bool,
    previous: Option<String>,
) -> SignedCatalogue {
    SignedCatalogue::sign(
        CatalogueRevision {
            publisher: "publisher".into(),
            announcement_revision: package.version * 2 + u64::from(withdrawn),
            package: package.clone(),
            observed_at: now() - 1,
            expires_at: now() + 600,
            withdrawn,
            previous,
        },
        key,
    )
}
fn activate(target: &Target, adoption: &CatalogueAdoption) -> Target {
    let plan = adoption.plan(now()).unwrap();
    let mut target = target.clone();
    target.package = plan.package;
    target.catalogue = Some(plan.status);
    target
}
fn invocation(target: &Target, id: &str) -> Invocation {
    Invocation {
        operation_id: id.into(),
        resource_id: "service:demo".into(),
        operation_sha256: target.package.operation_sha256(id).unwrap(),
        implementation_sha256: target.package.operations[id].implementation_sha256(),
        arguments: BTreeMap::new(),
        expected_assessment_sha256: None,
    }
}
fn request(target: &Target, action: Action, id: &str) -> Request {
    Request {
        version: VERSION.into(),
        required_features: Vec::new(),
        request_id: id.into(),
        target_id: target.target_id.clone(),
        issuer_id: "issuer".into(),
        grant_id: "grant".into(),
        principal: target.issuers["issuer"].authority.grants["grant"]
            .principal
            .clone(),
        expires_at: now() + 300,
        expected: Some(
            target
                .request_revisions("issuer", "grant", &action)
                .unwrap(),
        ),
        action,
        untrusted_rationale: String::new(),
    }
}
fn bytes(target: &Target, action: Action, id: &str, key: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&SignedRequest::sign(
        request(target, action, id),
        "key".into(),
        key,
    ))
    .unwrap()
}
struct Store {
    root: PathBuf,
    ledger: Option<Ledger>,
}
impl Store {
    fn new(target: &Target) -> Self {
        let root = std::env::temp_dir().join(format!(
            "catalogue-ledger-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = Ledger::open(
            &root,
            &target.target_id,
            LedgerLimits {
                jobs: 10,
                mutation_records: 20,
                output_bytes: 40960,
                database_bytes: 1024 * 1024,
                request_bytes: 131072,
            },
        )
        .unwrap();
        Self {
            root,
            ledger: Some(ledger),
        }
    }
    fn call(
        &mut self,
        target: &Target,
        action: Action,
        id: &str,
        key: &Ed25519KeyPair,
    ) -> Response {
        let body = bytes(target, action.clone(), id, key);
        self.ledger
            .as_mut()
            .unwrap()
            .handle(target, action.verb().path(), &body, now())
            .unwrap()
            .response
    }
    fn prepared(&mut self, target: &Target, id: &str, key: &Ed25519KeyPair) -> Prepared {
        let Response::Proposal { prepared } = self.call(
            target,
            Action::Propose {
                invocation: invocation(target, "restart"),
            },
            id,
            key,
        ) else {
            panic!("proposal");
        };
        *prepared
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        self.ledger.take();
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn cosmetic_narrower_and_trusted_code_changes_are_quiet_and_separate_identities() {
    let (target, key, mut adoption) = fixture();
    let mut candidate = target.package.clone();
    candidate.version += 1;
    candidate.source.version = "publisher metadata update".into();
    candidate
        .operations
        .get_mut("restart")
        .unwrap()
        .enforcement
        .enforced
        .reverse();
    let old = candidate.operations["restart"].clone();
    candidate
        .operations
        .get_mut("restart")
        .unwrap()
        .execution
        .identity
        .groups
        .reverse();
    adoption.observed = signed_catalogue(&candidate, &key, false, None);
    let plan = adoption.plan(now()).unwrap();
    assert_eq!(plan.status.state, "active");
    assert_eq!(
        plan.status.changes["restart"].comparison,
        Comparison::Equivalent
    );
    assert_eq!(
        candidate.operation_sha256("restart").unwrap(),
        target.package.operation_sha256("restart").unwrap()
    );
    let op = candidate.operations.get_mut("restart").unwrap();
    op.execution.resources.timeout_seconds /= 2;
    assert_eq!(
        compare_operations(&old, op).comparison,
        Comparison::Narrower
    );
    adoption.observed = signed_catalogue(&candidate, &key, false, None);
    assert_eq!(adoption.plan(now()).unwrap().status.state, "active");
    let op = candidate.operations.get_mut("restart").unwrap();
    let authority = op.authority_sha256();
    let assessment = op.assessment_sha256();
    let implementation = op.implementation_sha256();
    op.execution.executable_sha256 = "b".repeat(64);
    assert_eq!(authority, op.authority_sha256());
    assert_eq!(assessment, op.assessment_sha256());
    assert_ne!(implementation, op.implementation_sha256());
    assert_eq!(compare_operations(&old, op).comparison, Comparison::Unknown);
    adoption.observed = signed_catalogue(&candidate, &key, false, None);
    let current = activate(&target, &adoption);
    assert_eq!(current.catalogue.as_ref().unwrap().state, "active");
    let mut store = Store::new(&current);
    let prepared = store.prepared(&current, "code-update", &key);
    assert_eq!(
        prepared.invocation.implementation_sha256,
        current.package.operations["restart"].implementation_sha256()
    );
}

#[test]
fn expansions_defaults_identity_effects_and_missing_enforcement_cannot_inherit_adoption() {
    let (target, key, adoption) = fixture();
    let base = serde_json::to_value(&target.package.operations["restart"]).unwrap();
    for (path, replacement) in [
        (
            "/resources",
            serde_json::json!(["service:demo", "service:other"]),
        ),
        ("/execution/identity/principal", serde_json::json!("root")),
        (
            "/execution/environment/LANG",
            serde_json::json!({"kind":"literal","value":"other"}),
        ),
        ("/execution/broader", serde_json::json!(["filesystem"])),
        (
            "/effects/restart/persists_after_access",
            serde_json::json!(false),
        ),
        (
            "/effects/restart/description",
            serde_json::json!("untrusted replacement explanation"),
        ),
        ("/enforcement/enforced", serde_json::json!([])),
        ("/enforcement/enforced", {
            let mut claims = base["enforcement"]["enforced"].clone();
            claims
                .as_array_mut()
                .unwrap()
                .push("unproved new guarantee".into());
            claims
        }),
        (
            "/enforcement/unresolved",
            serde_json::json!(["cannot enforce filesystem"]),
        ),
    ] {
        let mut value = base.clone();
        *value.pointer_mut(path).unwrap() = replacement;
        let mut candidate = target.package.clone();
        candidate.version += 1;
        candidate
            .operations
            .insert("restart".into(), serde_json::from_value(value).unwrap());
        let mut attempt = adoption.clone();
        attempt.observed = signed_catalogue(&candidate, &key, false, None);
        let plan = attempt.plan(now()).unwrap();
        assert_eq!(plan.status.state, "awaiting_review", "{path}");
        assert_eq!(revision(&plan.package), revision(&target.package));
    }
    let mut candidate = target.package.clone();
    candidate
        .operations
        .get_mut("restart")
        .unwrap()
        .arguments
        .insert(
            "new-default".into(),
            Argument {
                kind: ArgumentType::Integer,
                required: false,
                default: Some(1.into()),
                options: Vec::new(),
            },
        );
    let mut attempt = adoption;
    attempt.observed = signed_catalogue(&candidate, &key, false, None);
    assert_eq!(attempt.plan(now()).unwrap().status.state, "awaiting_review");
}

#[test]
fn signature_metadata_and_effect_labels_do_not_authorise_same_name_replacement() {
    let (target, key, mut adoption) = fixture();
    adoption
        .policy
        .operations
        .get_mut("restart")
        .unwrap()
        .allow_implementation_updates = false;
    let mut changed = target.package.clone();
    changed
        .operations
        .get_mut("restart")
        .unwrap()
        .execution
        .executable_sha256 = "c".repeat(64);
    adoption.observed = signed_catalogue(&changed, &key, false, None);
    assert_eq!(
        adoption.plan(now()).unwrap().status.state,
        "awaiting_review"
    );
    adoption.observed.signature = STANDARD.encode([0; 64]);
    assert_eq!(adoption.plan(now()).unwrap().status.state, "refused");
}

#[test]
fn unrelated_operation_edits_preserve_prepared_authority_but_changed_operation_refuses() {
    let (mut target, key, mut adoption) = fixture();
    let op = target.package.operations["restart"].clone();
    target.package.operations.insert("other".into(), op.clone());
    adoption.active = signed_catalogue(&target.package, &key, false, None);
    adoption.observed = adoption.active.clone();
    adoption.policy.operations.insert(
        "other".into(),
        adoption.policy.operations["restart"].clone(),
    );
    let mut store = Store::new(&target);
    let prepared = store.prepared(&target, "prepare-original", &key);
    let original = bytes(
        &target,
        Action::Invoke {
            invocation: prepared.invocation.clone(),
        },
        "invoke-original",
        &key,
    );
    let mut changed = target.package.clone();
    changed.version += 1;
    changed
        .operations
        .get_mut("other")
        .unwrap()
        .execution
        .executable_sha256 = "d".repeat(64);
    adoption.observed = signed_catalogue(&changed, &key, false, None);
    let current = activate(&target, &adoption);
    let admission = store
        .ledger
        .as_mut()
        .unwrap()
        .handle(&current, Verb::Invoke.path(), &original, now())
        .unwrap();
    assert!(admission.dispatch);
    let Response::Job { receipt } = admission.response else {
        panic!("admission")
    };
    assert!(
        store
            .ledger
            .as_mut()
            .unwrap()
            .begin(&current, &receipt.job_id, now())
            .is_ok()
    );
    // A different package revision does not hide the exact selected operation.
    changed
        .operations
        .get_mut("restart")
        .unwrap()
        .execution
        .executable_sha256 = "e".repeat(64);
    adoption.observed = signed_catalogue(&changed, &key, false, None);
    let next = activate(&target, &adoption);
    let replay = store
        .ledger
        .as_mut()
        .unwrap()
        .handle(&next, Verb::Invoke.path(), &original, now())
        .unwrap();
    assert!(!replay.dispatch);
    let mut retained: SignedRequest = serde_json::from_slice(&original).unwrap();
    retained.request.request_id = "not-yet-admitted".into();
    let pending =
        serde_json::to_vec(&SignedRequest::sign(retained.request, "key".into(), &key)).unwrap();
    let stale = store
        .ledger
        .as_mut()
        .unwrap()
        .handle(&next, Verb::Invoke.path(), &pending, now())
        .err()
        .unwrap();
    assert_eq!(stale.code, RefusalCode::Stale);
    assert_eq!(
        store
            .ledger
            .as_ref()
            .unwrap()
            .observe(&receipt.job_id)
            .unwrap()
            .state,
        JobState::Running
    );
}

#[test]
fn pending_launch_revalidates_and_rollback_cannot_resurrect_revoked_grants() {
    let (target, key, mut adoption) = fixture();
    let mut store = Store::new(&target);
    let prepared = store.prepared(&target, "before-update", &key);
    let Response::Job { receipt } = store.call(
        &target,
        Action::Invoke {
            invocation: prepared.invocation,
        },
        "admit-before-update",
        &key,
    ) else {
        panic!("admission");
    };
    let mut candidate = target.package.clone();
    candidate.version += 1;
    candidate
        .operations
        .get_mut("restart")
        .unwrap()
        .execution
        .executable_sha256 = "f".repeat(64);
    adoption.observed = signed_catalogue(&candidate, &key, false, None);
    let mut current = activate(&target, &adoption);
    assert_eq!(
        store
            .ledger
            .as_mut()
            .unwrap()
            .begin(&current, &receipt.job_id, now())
            .err()
            .unwrap()
            .code,
        RefusalCode::Stale
    );
    assert_eq!(
        store
            .ledger
            .as_ref()
            .unwrap()
            .observe(&receipt.job_id)
            .unwrap()
            .state,
        JobState::Admitted
    );
    adoption.previous = Some(adoption.active.clone());
    adoption.active = adoption.observed.clone();
    adoption.observed = signed_catalogue(&candidate, &key, true, Some(revision(&target.package)));
    adoption.policy.on_withdraw = Withdrawal::Previous;
    current
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .clear();
    let rolled_back = activate(&current, &adoption);
    assert_eq!(rolled_back.catalogue.as_ref().unwrap().state, "rolled_back");
    assert_eq!(revision(&rolled_back.package), revision(&target.package));
    let body = bytes(
        &target,
        Action::Propose {
            invocation: invocation(&target, "restart"),
        },
        "after-revocation",
        &key,
    );
    assert_eq!(
        store
            .ledger
            .as_mut()
            .unwrap()
            .handle(&rolled_back, Verb::Propose.path(), &body, now())
            .err()
            .unwrap()
            .code,
        RefusalCode::Authority
    );
    assert_eq!(
        store
            .ledger
            .as_ref()
            .unwrap()
            .observe(&receipt.job_id)
            .unwrap()
            .state,
        JobState::Admitted
    );
    // Duplicate/reconnect planning is deterministic and retains source identity.
    assert_eq!(
        revision(&adoption.plan(now()).unwrap().status),
        revision(&adoption.plan(now()).unwrap().status)
    );
}

#[test]
fn new_operations_need_explicit_family_membership_at_both_authority_owners() {
    let (target, key, mut adoption) = fixture();
    let op = target.package.operations["restart"].clone();
    let family = OperationFamily {
        prefix: "diagnose:".into(),
        excluded: Default::default(),
        rule: adoption.policy.operations["restart"].clone(),
        scope: target.ceiling["restart"].clone(),
    };
    let mut candidate = target.package.clone();
    candidate.version += 1;
    candidate.operations.insert("diagnose:new".into(), op);
    adoption.observed = signed_catalogue(&candidate, &key, false, None);
    let plan = adoption.plan(now()).unwrap();
    assert!(plan.status.discovered.contains_key("diagnose:new"));
    assert!(!plan.package.operations.contains_key("diagnose:new"));
    adoption.policy.families.push(family.clone());
    let mut current = activate(&target, &adoption);
    let mut store = Store::new(&current);
    let propose = |current: &Target, id: &str| {
        bytes(
            current,
            Action::Propose {
                invocation: invocation(current, "diagnose:new"),
            },
            id,
            &key,
        )
    };
    assert_eq!(
        store
            .ledger
            .as_mut()
            .unwrap()
            .handle(
                &current,
                Verb::Propose.path(),
                &propose(&current, "no-family-grant"),
                now()
            )
            .err()
            .unwrap()
            .code,
        RefusalCode::Authority
    );
    current.families.push(family.clone());
    current
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant")
        .unwrap()
        .families
        .push(family);
    assert!(
        store
            .ledger
            .as_mut()
            .unwrap()
            .handle(
                &current,
                Verb::Propose.path(),
                &propose(&current, "approved-family"),
                now()
            )
            .is_ok()
    );
    current.families[0].excluded.insert("diagnose:new".into());
    assert_eq!(
        store
            .ledger
            .as_mut()
            .unwrap()
            .handle(
                &current,
                Verb::Propose.path(),
                &propose(&current, "revoked-member"),
                now()
            )
            .err()
            .unwrap()
            .code,
        RefusalCode::Authority
    );
}

#[test]
fn standing_ceiling_covers_non_adjacent_expansion_but_invocation_permission_stays_separate() {
    let (target, key, mut adoption) = fixture();
    adoption
        .policy
        .operations
        .get_mut("restart")
        .unwrap()
        .ceiling
        .resources
        .insert("service:future".into());
    let mut candidate = target.package.clone();
    candidate.version += 1;
    candidate
        .operations
        .get_mut("restart")
        .unwrap()
        .resources
        .insert("service:future".into());
    adoption.observed = signed_catalogue(&candidate, &key, false, None);
    let plan = adoption.plan(now()).unwrap();
    assert_eq!(
        plan.status.changes["restart"].comparison,
        Comparison::Broader
    );
    assert_eq!(plan.status.state, "active");
    let current = activate(&target, &adoption);
    let mut store = Store::new(&current);
    let mut invocation = invocation(&current, "restart");
    invocation.resource_id = "service:future".into();
    let request = bytes(
        &current,
        Action::Propose { invocation },
        "unrelated-resource",
        &key,
    );
    assert_eq!(
        store
            .ledger
            .as_mut()
            .unwrap()
            .handle(&current, Verb::Propose.path(), &request, now())
            .err()
            .unwrap()
            .code,
        RefusalCode::Stale
    );
}

#[test]
fn family_call_budget_counts_distinct_operation_selectors_together() {
    let (mut target, key, mut adoption) = fixture();
    let mut family = OperationFamily {
        prefix: "diagnose:".into(),
        excluded: Default::default(),
        rule: adoption.policy.operations["restart"].clone(),
        scope: target.ceiling["restart"].clone(),
    };
    family.scope.budgets.calls = 1;
    family.scope.budgets.concurrent = 1;
    adoption.policy.families.push(family.clone());
    target.families.push(family.clone());
    target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant")
        .unwrap()
        .families
        .push(family);
    let mut package = target.package.clone();
    package.version += 1;
    for id in ["diagnose:first", "diagnose:second"] {
        package
            .operations
            .insert(id.into(), package.operations["restart"].clone());
    }
    adoption.observed = signed_catalogue(&package, &key, false, None);
    let current = activate(&target, &adoption);
    let mut store = Store::new(&current);
    let Response::Proposal { prepared } = store.call(
        &current,
        Action::Propose {
            invocation: invocation(&current, "diagnose:first"),
        },
        "first-proposal",
        &key,
    ) else {
        panic!("family proposal")
    };
    let Response::Job { receipt } = store.call(
        &current,
        Action::Invoke {
            invocation: prepared.invocation,
        },
        "first-call",
        &key,
    ) else {
        panic!("family admission")
    };
    store
        .ledger
        .as_mut()
        .unwrap()
        .finish(
            &receipt.job_id,
            JobState::Failed,
            true,
            now(),
            "no process launched by this ledger control".into(),
        )
        .unwrap();
    let next = bytes(
        &current,
        Action::Propose {
            invocation: invocation(&current, "diagnose:second"),
        },
        "second-proposal",
        &key,
    );
    assert_eq!(
        store
            .ledger
            .as_mut()
            .unwrap()
            .handle(&current, Verb::Propose.path(), &next, now())
            .err()
            .unwrap()
            .code,
        RefusalCode::Budget
    );
}

fn budget_fixture(
    issuer_prefix: Option<&str>,
    target_prefix: Option<&str>,
    issuer_limit: u64,
    target_limit: u64,
    concurrent: bool,
) -> (Target, Ed25519KeyPair) {
    let (mut target, key, mut adoption) = fixture();
    let mut family = OperationFamily {
        prefix: "diagnose:".into(),
        excluded: Default::default(),
        rule: adoption.policy.operations["restart"].clone(),
        scope: target.ceiling["restart"].clone(),
    };
    family.scope.budgets.calls = 32;
    family.scope.budgets.concurrent = 32;
    adoption.policy.families.push(family.clone());
    let grant = target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant")
        .unwrap();
    // Keep the prepared validity bound stable while this table crosses a UTC
    // second. Per-request expiry is later than this fixed grant expiry.
    grant.expires_at = now() + 120;
    for (prefix, limit, exact, families) in [
        (
            issuer_prefix,
            issuer_limit,
            &mut grant.operations,
            &mut grant.families,
        ),
        (
            target_prefix,
            target_limit,
            &mut target.ceiling,
            &mut target.families,
        ),
    ] {
        let mut scope = family.scope.clone();
        if concurrent {
            scope.budgets.concurrent = limit;
        } else {
            scope.budgets.calls = limit;
        }
        if let Some(prefix) = prefix {
            let mut selected = family.clone();
            selected.prefix = prefix.into();
            selected.scope = scope;
            families.push(selected);
        } else {
            for id in ["diagnose:sub:first", "diagnose:sub:second"] {
                exact.insert(id.into(), scope.clone());
            }
        }
    }
    target.package.version += 1;
    for id in ["diagnose:sub:first", "diagnose:sub:second"] {
        target
            .package
            .operations
            .insert(id.into(), target.package.operations["restart"].clone());
    }
    adoption.observed = signed_catalogue(&target.package, &key, false, None);
    let current = activate(&target, &adoption);
    current.validate().unwrap();
    (current, key)
}

fn independent_budget_scopes(concurrent: bool) {
    // The first six cases share an exhausted scope. The final three have
    // independent exact scopes whose smaller limits must not be applied to
    // the other owner's wider family consumption.
    for (issuer, target, issuer_limit, target_limit, second_allowed) in [
        (None, Some("diagnose:"), 32, 1, false),
        (Some("diagnose:"), None, 1, 32, false),
        (Some("diagnose:"), Some("diagnose:sub:"), 32, 1, false),
        (Some("diagnose:sub:"), Some("diagnose:"), 1, 32, false),
        (Some("diagnose:"), Some("diagnose:"), 32, 1, false),
        (Some("diagnose:"), Some("diagnose:"), 1, 32, false),
        (None, Some("diagnose:"), 1, 32, true),
        (Some("diagnose:"), None, 32, 1, true),
        (None, None, 1, 1, true),
    ] {
        let (current, key) = budget_fixture(issuer, target, issuer_limit, target_limit, concurrent);
        let mut store = Store::new(&current);
        let mut prepared = Vec::new();
        for id in ["diagnose:sub:first", "diagnose:sub:second"] {
            let Response::Proposal { prepared: proposal } = store.call(
                &current,
                Action::Propose {
                    invocation: invocation(&current, id),
                },
                id,
                &key,
            ) else {
                panic!("proposal");
            };
            prepared.push(proposal);
        }
        let first = bytes(
            &current,
            Action::Invoke {
                invocation: prepared[0].invocation.clone(),
            },
            "first-call",
            &key,
        );
        let ledger = store.ledger.as_mut().unwrap();
        let admitted = ledger
            .handle(&current, Verb::Invoke.path(), &first, now())
            .unwrap();
        assert!(admitted.dispatch);
        let Response::Job { receipt } = admitted.response else {
            panic!("admission");
        };
        // Revalidation excludes this job's own reservation in both scopes.
        ledger.begin(&current, &receipt.job_id, now()).unwrap();
        assert!(
            !ledger
                .handle(&current, Verb::Invoke.path(), &first, now())
                .unwrap()
                .dispatch
        );
        ledger
            .finish(
                &receipt.job_id,
                if concurrent {
                    JobState::Uncertain
                } else {
                    JobState::Failed
                },
                !concurrent,
                now(),
                "ledger control; no workload was launched".into(),
            )
            .unwrap();
        store.ledger.take();
        store.ledger = Some(
            Ledger::open(
                &store.root,
                &current.target_id,
                LedgerLimits {
                    jobs: 10,
                    mutation_records: 20,
                    output_bytes: 40960,
                    database_bytes: 1024 * 1024,
                    request_bytes: 131072,
                },
            )
            .unwrap(),
        );
        let second = bytes(
            &current,
            Action::Invoke {
                invocation: prepared[1].invocation.clone(),
            },
            "second-call",
            &key,
        );
        let ledger = store.ledger.as_mut().unwrap();
        let result = ledger.handle(&current, Verb::Invoke.path(), &second, now());
        if second_allowed {
            assert!(
                result.unwrap().dispatch,
                "issuer={issuer:?}, target={target:?}"
            );
        } else {
            assert_eq!(
                result.err().unwrap().code,
                RefusalCode::Budget,
                "issuer={issuer:?}, target={target:?}"
            );
            let proposal = bytes(
                &current,
                Action::Propose {
                    invocation: invocation(&current, "diagnose:sub:second"),
                },
                "fresh-second",
                &key,
            );
            assert_eq!(
                ledger
                    .handle(&current, Verb::Propose.path(), &proposal, now())
                    .err()
                    .unwrap()
                    .code,
                RefusalCode::Budget
            );
        }
        let db = rusqlite::Connection::open_with_flags(
            store.root.join("jobs.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM jobs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1 + i64::from(second_allowed)
        );
    }
}

#[test]
fn call_budgets_reserve_issuer_and_target_scopes_independently() {
    independent_budget_scopes(false);
}

#[test]
fn concurrency_budgets_retain_both_scopes_across_replay_and_restart() {
    independent_budget_scopes(true);
}

#[test]
fn target_budget_is_shared_across_issuers_and_grants() {
    for concurrent in [false, true] {
        for separate_issuer in [false, true] {
            let (mut target, key) = budget_fixture(None, Some("diagnose:"), 32, 1, concurrent);
            let original = target.issuers["issuer"].clone();
            if separate_issuer {
                target.issuers.insert("other".into(), original);
            } else {
                target
                    .issuers
                    .get_mut("issuer")
                    .unwrap()
                    .authority
                    .grants
                    .insert("other".into(), original.authority.grants["grant"].clone());
            }
            let mut store = Store::new(&target);
            let Response::Proposal { prepared } = store.call(
                &target,
                Action::Propose {
                    invocation: invocation(&target, "diagnose:sub:first"),
                },
                "first-proposal",
                &key,
            ) else {
                panic!("proposal");
            };
            let Response::Job { receipt } = store.call(
                &target,
                Action::Invoke {
                    invocation: prepared.invocation,
                },
                "first-call",
                &key,
            ) else {
                panic!("admission");
            };
            store
                .ledger
                .as_mut()
                .unwrap()
                .finish(
                    &receipt.job_id,
                    if concurrent {
                        JobState::Uncertain
                    } else {
                        JobState::Failed
                    },
                    !concurrent,
                    now(),
                    "no workload launched".into(),
                )
                .unwrap();
            // An unrelated grant edit changes its call epoch, but cannot reset
            // target calls or release uncertain concurrency reservations.
            for trust in target.issuers.values_mut() {
                for grant in trust.authority.grants.values_mut() {
                    grant.expires_at += 1;
                }
            }
            if concurrent {
                target.families[0].scope.budgets.calls += 1;
            }
            let action = Action::Propose {
                invocation: invocation(&target, "diagnose:sub:second"),
            };
            let mut req = request(&target, action, "other-proposal");
            if separate_issuer {
                req.issuer_id = "other".into();
            } else {
                req.grant_id = "other".into();
            }
            req.expected = Some(
                target
                    .request_revisions(&req.issuer_id, &req.grant_id, &req.action)
                    .unwrap(),
            );
            let body = serde_json::to_vec(&SignedRequest::sign(req, "key".into(), &key)).unwrap();
            assert_eq!(
                store
                    .ledger
                    .as_mut()
                    .unwrap()
                    .handle(&target, Verb::Propose.path(), &body, now())
                    .err()
                    .unwrap()
                    .code,
                RefusalCode::Budget
            );
        }
    }
}

#[test]
fn pending_dispatch_excludes_only_its_own_grant_revision_reservation() {
    let (mut target, key) = budget_fixture(Some("diagnose:"), None, 1, 32, false);
    let mut store = Store::new(&target);
    let mut jobs = Vec::new();
    for (index, id) in ["diagnose:sub:first", "diagnose:sub:second"]
        .into_iter()
        .enumerate()
    {
        if index == 1 {
            // This edit changes the grant's usage revision while preserving the
            // first operation's scoped request/assessment identities.
            target
                .issuers
                .get_mut("issuer")
                .unwrap()
                .authority
                .grants
                .get_mut("grant")
                .unwrap()
                .operations
                .get_mut("restart")
                .unwrap()
                .budgets
                .calls += 1;
        }
        let Response::Proposal { prepared } = store.call(
            &target,
            Action::Propose {
                invocation: invocation(&target, id),
            },
            &format!("proposal-{index}"),
            &key,
        ) else {
            panic!("proposal");
        };
        let Response::Job { receipt } = store.call(
            &target,
            Action::Invoke {
                invocation: prepared.invocation,
            },
            &format!("invoke-{index}"),
            &key,
        ) else {
            panic!("admission");
        };
        jobs.push(receipt.job_id);
    }
    let ledger = store.ledger.as_mut().unwrap();
    assert_eq!(
        ledger.begin(&target, &jobs[0], now()).unwrap_err().code,
        RefusalCode::Budget
    );
    // The new grant revision has its own call allowance. Excluding this job
    // leaves no other call charged to that revision.
    ledger.begin(&target, &jobs[1], now()).unwrap();
}

#[test]
fn dependency_byte_ceilings_compare_as_bounds_without_granting_update_trust() {
    let (target, _, _) = fixture();
    let mut before = target.package.operations["restart"].clone();
    before.execution.dependencies.insert(
        "/etc/adopted-config".into(),
        Dependency {
            sha256: "a".repeat(64),
            bytes: 16,
        },
    );
    let mut after = before.clone();
    after
        .execution
        .dependencies
        .get_mut("/etc/adopted-config")
        .unwrap()
        .bytes = 8;
    assert_eq!(
        compare_operations(&before, &after).comparison,
        Comparison::Narrower
    );
    let rule = UpdateRule {
        ceiling: before.clone(),
        allow_narrower: true,
        allow_implementation_updates: false,
    };
    assert!(rule.allows(&after));
    after
        .execution
        .dependencies
        .get_mut("/etc/adopted-config")
        .unwrap()
        .sha256 = "b".repeat(64);
    assert!(!rule.allows(&after));
    after = before.clone();
    after
        .execution
        .dependencies
        .get_mut("/etc/adopted-config")
        .unwrap()
        .bytes = 32;
    assert_eq!(
        compare_operations(&before, &after).comparison,
        Comparison::Broader
    );
    assert!(!rule.allows(&after));
}

#[test]
fn retained_withdrawal_survives_reconnect_and_replayed_signed_updates() {
    let (target, key, mut adoption) = fixture();
    let store = Store::new(&target);
    let path = store.root.join("observed.json");
    adoption.observed_file = Some(ObservedCatalogueFile {
        path: path.clone(),
        max_bytes: 131072,
    });
    let mut package = target.package.clone();
    package.version += 1;
    package
        .operations
        .get_mut("restart")
        .unwrap()
        .execution
        .executable_sha256 = "b".repeat(64);
    let update = signed_catalogue(&package, &key, false, None);
    fs::write(&path, serde_json::to_vec(&update).unwrap()).unwrap();
    let plan = adoption.plan(now()).unwrap();
    assert!(adoption.advance(&plan));
    assert_eq!(
        revision(&adoption.active.catalogue.package),
        revision(&package)
    );
    adoption.policy.on_withdraw = Withdrawal::Previous;
    let withdrawal = signed_catalogue(&package, &key, true, Some(revision(&target.package)));
    fs::write(&path, serde_json::to_vec(&withdrawal).unwrap()).unwrap();
    let plan = adoption.plan(now()).unwrap();
    assert_eq!(plan.status.state, "rolled_back");
    assert!(adoption.advance(&plan));
    let mut reconnected: CatalogueAdoption =
        serde_json::from_slice(&serde_json::to_vec(&adoption).unwrap()).unwrap();
    fs::write(&path, serde_json::to_vec(&update).unwrap()).unwrap();
    let refused = reconnected.plan(now()).unwrap();
    assert_eq!(refused.status.state, "refused");
    assert_eq!(refused.status.active, revision(&target.package));
    assert!(!reconnected.advance(&refused));
    assert!(reconnected.observed.catalogue.withdrawn);
    let mut conflicting = withdrawal.catalogue.clone();
    conflicting.withdrawn = false;
    fs::write(
        &path,
        serde_json::to_vec(&SignedCatalogue::sign(conflicting, &key)).unwrap(),
    )
    .unwrap();
    assert_eq!(reconnected.plan(now()).unwrap().status.state, "refused");
}

#[test]
fn exact_issuer_scope_does_not_inherit_new_effect_understanding_for_the_same_executable() {
    let (mut target, key, _) = fixture();
    target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("grant")
        .unwrap()
        .operations
        .get_mut("restart")
        .unwrap()
        .updates = None;
    target
        .package
        .operations
        .get_mut("restart")
        .unwrap()
        .effects
        .get_mut("restart")
        .unwrap()
        .description = "corrected understanding of persistent host effects".into();
    let mut store = Store::new(&target);
    let request = bytes(
        &target,
        Action::Propose {
            invocation: invocation(&target, "restart"),
        },
        "changed-effects",
        &key,
    );
    assert_eq!(
        store
            .ledger
            .as_mut()
            .unwrap()
            .handle(&target, Verb::Propose.path(), &request, now())
            .err()
            .unwrap()
            .code,
        RefusalCode::Stale
    );
}
