use super::*;

fn principal(owner: &str, agent: &str) -> Principal {
    Principal::new(owner, agent)
}

fn control(source: Principal, target: Principal, name: &str) -> Fact {
    let mut fact = Fact {
        fact_id: String::new(),
        owner_instance_id: target.instance_id.clone(),
        source_type: "support_grant".into(),
        source_id: name.into(),
        revision: format!("{name}-revision"),
        holder: source,
        capability: Capability::GuestAdmin { target },
        current: true,
        validity: "current".into(),
        peer_epoch: Some(1),
        expires_at: None,
        observed_at: 1,
        proposed: false,
    };
    fact.identify();
    fact
}

fn deciding(reviewer: Principal, beneficiary: Principal) -> Fact {
    let mut fact = control(reviewer, beneficiary.clone(), "deciding");
    fact.source_type = "approval_delegation".into();
    fact.capability = Capability::ApprovalDecision {
        beneficiaries: vec![beneficiary],
        scopes: vec![crate::policy::delegation::Scope::NetworkEgress {
            host: "example.com".into(),
            ports: vec![443],
            all_ports: false,
            actions: vec!["request".into()],
        }],
        grant_seconds: Some(60),
        gateway_once: false,
    };
    fact.identify();
    fact
}

#[test]
fn only_guest_administration_extends_control_and_qualified_identities_never_collapse() {
    let a = principal("a", "same-id");
    let b = principal("b", "same-id");
    let c = principal("c", "same-id");
    let mut inspection = control(b.clone(), c.clone(), "inspection");
    inspection.capability = Capability::Inspection { target: c.clone() };
    inspection.identify();
    let facts = vec![
        control(a.clone(), b.clone(), "a-b"),
        inspection,
        deciding(b.clone(), c.clone()),
    ];
    let graph = Graph::new(facts.iter().collect());
    let paths = graph.paths(&a, &mut 0, &mut BTreeSet::new());
    assert!(paths.contains_key(&b));
    assert!(!paths.contains_key(&c));
    let reach = graph.reach(Some(&a), &mut BTreeSet::new());
    assert!(
        reach
            .effects
            .iter()
            .any(|effect| effect.fact_id == facts[2].fact_id)
    );
    assert!(reach.common_control.is_empty());
    assert_eq!(
        json!(&facts[2].capability)["scopes"][0]["ports"],
        json!([443])
    );
}

#[test]
fn cycles_terminate_and_an_alternate_path_survives_removal_expiry_and_rebinding() {
    let (a, b, c) = (
        principal("a", "ops"),
        principal("b", "helper"),
        principal("c", "worker"),
    );
    let mut facts = vec![
        control(a.clone(), b.clone(), "a-b"),
        control(b.clone(), c.clone(), "b-c"),
        control(c.clone(), a.clone(), "c-a"),
        control(a.clone(), c.clone(), "a-c"),
    ];
    assert_eq!(
        Graph::new(facts.iter().collect()).paths(&a, &mut 0, &mut BTreeSet::new())[&c].len(),
        1
    );
    facts.pop();
    assert_eq!(
        Graph::new(facts.iter().collect()).paths(&a, &mut 0, &mut BTreeSet::new())[&c].len(),
        2
    );
    facts[1].current = false;
    assert!(
        !Graph::new(facts.iter().collect())
            .paths(&a, &mut 0, &mut BTreeSet::new())
            .contains_key(&c)
    );
    facts[1].current = true;
    facts[1].holder = principal("b", "recreated-helper");
    assert!(
        !Graph::new(facts.iter().collect())
            .paths(&a, &mut 0, &mut BTreeSet::new())
            .contains_key(&c)
    );
}

#[test]
fn multi_hop_common_controller_names_scope_without_controlling_other_beneficiaries() {
    let (a, b, c, r, w, other) = (
        principal("a", "ops"),
        principal("b", "helper"),
        principal("c", "codey"),
        principal("d", "reviewer"),
        principal("d", "worker"),
        principal("e", "other"),
    );
    let facts = vec![
        control(a.clone(), b.clone(), "a-b"),
        control(b, c.clone(), "b-c"),
        control(c.clone(), r.clone(), "c-r"),
        control(c, w.clone(), "c-w"),
        deciding(r.clone(), w.clone()),
        deciding(r.clone(), other.clone()),
    ];
    let mut frontier = BTreeSet::new();
    let graph = Graph::new(facts.iter().collect());
    let reach = graph.reach(Some(&a), &mut frontier);
    let common = reach
        .common_control
        .iter()
        .find(|common| common.controller == a && common.beneficiary == w)
        .unwrap();
    assert_eq!(common.reviewer, r);
    assert_eq!(common.reviewer_path.len(), 3);
    assert_eq!(common.deciding_fact, facts[4].fact_id);
    assert!(!graph.paths(&a, &mut 0, &mut frontier).contains_key(&other));
}

#[test]
fn work_depth_and_output_budgets_preserve_useful_paths_and_an_unknown_frontier() {
    let facts: Vec<_> = (0..1000)
        .map(|index| {
            control(
                principal("owner", &index.to_string()),
                principal("owner", &(index + 1).to_string()),
                &index.to_string(),
            )
        })
        .collect();
    let root = principal("owner", "0");
    let mut frontier = BTreeSet::new();
    let graph = Graph::new(facts.iter().collect());
    let paths = graph.paths(&root, &mut 0, &mut frontier);
    assert!(paths.contains_key(&principal("owner", "1")));
    assert_eq!(paths.len(), MAX_DEPTH + 1);
    assert!(!frontier.is_empty());
    let reach = graph.reach(Some(&root), &mut frontier);
    assert!(reach.effects.len() <= MAX_EFFECTS);
    assert!(reach.common_control.len() <= MAX_COMMON);
    assert!(frontier.iter().any(|gap| gap.contains("budget")));
    let mut steps = MAX_STEPS;
    let mut exhausted = BTreeSet::new();
    assert_eq!(graph.paths(&root, &mut steps, &mut exhausted).len(), 1);
    assert!(!exhausted.is_empty());
}
