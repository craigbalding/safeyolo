//! Shared adopted target for native component fixtures; no runtime probing.
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use safeyolo_host_executor::*;
use std::collections::BTreeMap;
pub fn target(
    name: String,
    operations: BTreeMap<String, Operation>,
    key: &Ed25519KeyPair,
) -> Target {
    let package = Package {
        semantics: None,
        format: VERSION.into(),
        name: "native-fixture".into(),
        version: 1,
        source: Source {
            location: "repository native fixture".into(),
            version: "1".into(),
        },
        operations,
    };
    let scopes: BTreeMap<_, _> = package
        .operations
        .iter()
        .map(|(id, op)| {
            (
                id.clone(),
                OperationScope {
                    implementation_sha256: op.implementation_sha256(),
                    resources: op.resources.clone(),
                    arguments: BTreeMap::new(),
                    updates: None,
                    checks: Default::default(),
                    budgets: Budgets {
                        calls: 32,
                        concurrent: 1,
                        timeout_seconds: 5,
                        output_bytes: 4096,
                    },
                },
            )
        })
        .collect();
    let verbs = [
        Verb::Discover,
        Verb::Propose,
        Verb::Invoke,
        Verb::Job,
        Verb::Output,
        Verb::File,
        Verb::Cancel,
    ]
    .into();
    Target {
        families: Vec::new(),
        catalogue: None,
        target_id: name,
        ceiling_revision: "1".into(),
        allowed_verbs: verbs,
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
                    observed_at: now(),
                    valid_until: now() + 600,
                    grants: BTreeMap::from([(
                        "grant".into(),
                        Grant {
                            allow_run_refresh: false,
                            families: Vec::new(),
                            principal: Principal {
                                run: AgentRun {
                                    agent: "fixture".into(),
                                    agent_id: "ag-fixture".into(),
                                    run_id: "11111111111111111111111111111111".into(),
                                },
                                task_id: None,
                            },
                            not_before: now() - 1,
                            expires_at: now() + 600,
                            verbs: [
                                Verb::Discover,
                                Verb::Propose,
                                Verb::Invoke,
                                Verb::Job,
                                Verb::Output,
                                Verb::File,
                                Verb::Cancel,
                            ]
                            .into(),
                            operations: scopes.clone(),
                        },
                    )]),
                },
            },
        )]),
        ceiling: scopes,
        package,
    }
}
