//! Bounded read-only collection. Each page is checked against its owner revision;
//! selected owners are never inferred from an outbound route or discovered edge.

use super::*;
use std::collections::BTreeSet;
use std::time::Duration;

const MAX_REQUESTS: usize = 64;
const PAGE_BYTES: usize = 64 * 1024;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Query {
    #[serde(default)]
    pub after: usize,
    pub revision: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    snapshot: Snapshot,
    after: usize,
    next_after: Option<usize>,
    total_facts: usize,
}

pub(crate) fn metadata(
    state: &RuntimeState,
    policy: &Policy,
    disclosure: Option<&crate::policy::authority::Disclosure>,
    query: Query,
) -> Result<Value, Error> {
    let mut snapshot = snapshot(state, policy, disclosure)?;
    if query
        .revision
        .as_ref()
        .is_some_and(|revision| revision != &snapshot.revision)
        || query.after > snapshot.facts.len()
        || (query.after != 0 && query.revision.is_none())
    {
        return Err(super::super::refuse(
            409,
            "owner authority changed during pagination; refresh the report",
        ));
    }
    let total_facts = snapshot.facts.len();
    snapshot.facts = snapshot
        .facts
        .into_iter()
        .skip(query.after)
        .take(PAGE_FACTS)
        .collect();
    let mut page = Page {
        snapshot,
        after: query.after,
        next_after: None,
        total_facts,
    };
    loop {
        let end = query.after + page.snapshot.facts.len();
        page.next_after = (end < total_facts).then_some(end);
        let value = json!(&page);
        if serde_json::to_vec(&value)?.len() <= PAGE_BYTES {
            return Ok(value);
        }
        if page.snapshot.facts.len() <= 1 {
            return Err(super::super::refuse(
                413,
                "owner authority metadata exceeds the response budget",
            ));
        }
        page.snapshot.facts.pop();
    }
}

/// The source instance comes from the broker-authenticated request subject.
/// A null run is an operator assertion permitted only on this read-only route.
pub(crate) fn remote_metadata(
    state: &RuntimeState,
    source: &str,
    credential_hash: &str,
    run: Option<&crate::host_runs::AgentRun>,
    query: Value,
) -> Result<Value, Error> {
    let policy = read_policy(state)?;
    let root = policy
        .identity_root()
        .ok_or("owner identity store unavailable")?;
    let conn = crate::coord_rooms::open(root)?;
    let epoch: i64 = conn.query_row(
        "SELECT epoch FROM coord_federation_peers WHERE instance_id=?1 AND token_hash=?2 AND enabled=1",
        rusqlite::params![source, credential_hash], |row| row.get(0),
    ).map_err(|_| super::super::refuse(403, "peer metadata disclosure is not authorized"))?;
    if run.is_some_and(|run| {
        !crate::desktop_present::valid_agent_id(&run.agent_id)
            || run.run_id.len() != 32
            || !run.run_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err(super::super::refuse(
            403,
            "invalid qualified metadata reader identity",
        ));
    }
    let disclosure = policy
        .authority_disclosure(source, run.map(|run| run.agent_id.as_str()), Some(epoch))
        .map_err(|_| {
            super::super::refuse(
                403,
                "destination has not authorized this reader's metadata disclosure",
            )
        })?;
    let query = serde_json::from_value(query)
        .map_err(|_| super::super::refuse(400, "invalid authority metadata page selection"))?;
    let result = metadata(state, &policy, Some(&disclosure), query)?;
    let saved = read_policy(state)?;
    let current = saved
        .authority_disclosure(source, run.map(|run| run.agent_id.as_str()), Some(epoch))
        .map_err(|_| super::super::refuse(403, "authority metadata disclosure was revoked"))?;
    let trusted: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM coord_federation_peers WHERE instance_id=?1 AND token_hash=?2 AND enabled=1 AND epoch=?3)",
        rusqlite::params![source, credential_hash, epoch], |row| row.get(0),
    )?;
    if !trusted || json!(disclosure) != json!(current) {
        return Err(super::super::refuse(
            403,
            "authority metadata disclosure changed",
        ));
    }
    if snapshot(state, &saved, Some(&current))?.revision != result["snapshot"]["revision"] {
        return Err(super::super::refuse(
            409,
            "owner authority changed during collection",
        ));
    }
    Ok(result)
}

pub(crate) async fn collect(
    state: &RuntimeState,
    selected: &[Owner],
) -> Result<(Vec<Owner>, Vec<Coverage>, Vec<Snapshot>), Error> {
    let instance = super::super::instance_id()?;
    let inventory = if selected.is_empty() {
        vec![Owner {
            instance_id: instance.clone(),
            home: None,
        }]
    } else {
        selected.to_vec()
    };
    if inventory.len() > MAX_OWNERS
        || inventory.iter().any(|owner| owner.instance_id.is_empty())
        || inventory
            .iter()
            .map(|owner| &owner.instance_id)
            .collect::<BTreeSet<_>>()
            .len()
            != inventory.len()
    {
        return Err("select at most 16 distinct owning instances".into());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut requests = 0;
    let mut total_facts = 0;
    let mut coverage = Vec::new();
    let mut snapshots = Vec::new();
    for owner in &inventory {
        let mut entry = Coverage {
            owner: owner.clone(),
            status: "unknown".into(),
            revision: None,
            observed_at: None,
            all_agents: false,
            facts: 0,
        };
        let mut query = Query::default();
        let mut assembled: Option<Snapshot> = None;
        let mut expected_total = None;
        loop {
            if requests >= MAX_REQUESTS
                || total_facts >= MAX_FACTS
                || tokio::time::Instant::now() >= deadline
            {
                entry.status = "collection_budget_exhausted".into();
                break;
            }
            requests += 1;
            let result = if owner.home.is_none() {
                if owner.instance_id != instance {
                    Err("unselected local identity".into())
                } else {
                    read_policy(state)
                        .and_then(|policy| metadata(state, &policy, None, query.clone()))
                }
            } else {
                let remaining = deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(Duration::from_secs(2));
                match tokio::time::timeout(
                    remaining,
                    crate::agent_api::coord::federation::authority_metadata(
                        state,
                        owner,
                        json!(&query),
                    ),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(super::super::refuse(
                        503,
                        "authority metadata owner is unreachable",
                    )),
                }
            };
            let page: Page =
                match result.and_then(|value| serde_json::from_value(value).map_err(Into::into)) {
                    Ok(page) => page,
                    Err(error) => {
                        entry.status = error
                            .downcast_ref::<crate::peer_support::Refusal>()
                            .map_or("unreachable_or_unavailable", |refusal| {
                                match refusal.status {
                                    403 => "disclosure_refused",
                                    409 => "stale_or_changed",
                                    413 => "response_truncated",
                                    _ => "unreachable_or_unavailable",
                                }
                            })
                            .into();
                        break;
                    }
                };
            let count = page.snapshot.facts.len();
            if page.snapshot.owner_instance_id != owner.instance_id
                || page.after != query.after
                || page.total_facts > MAX_FACTS
                || page.snapshot.bindings.len() > MAX_FACTS
                || page
                    .snapshot
                    .facts
                    .iter()
                    .any(|fact| fact.owner_instance_id != owner.instance_id)
                || query
                    .revision
                    .as_ref()
                    .is_some_and(|revision| revision != &page.snapshot.revision)
                || expected_total.is_some_and(|total| total != page.total_facts)
                || page.next_after.is_some_and(|next| {
                    next != query.after + count || next <= query.after || next >= page.total_facts
                })
                || (page.next_after.is_none() && query.after + count != page.total_facts)
                || total_facts + count > MAX_FACTS
            {
                entry.status = "inconsistent_or_truncated_pages".into();
                break;
            }
            expected_total = Some(page.total_facts);
            query.revision = Some(page.snapshot.revision.clone());
            total_facts += count;
            if let Some(snapshot) = &mut assembled {
                if snapshot.bindings.len() != page.snapshot.bindings.len()
                    || snapshot.bindings.iter().zip(&page.snapshot.bindings).any(
                        |(before, after)| {
                            before.principal != after.principal || before.name != after.name
                        },
                    )
                    || snapshot.all_agents != page.snapshot.all_agents
                    || snapshot.truncated != page.snapshot.truncated
                {
                    entry.status = "inconsistent_pages".into();
                    break;
                }
                snapshot.facts.extend(page.snapshot.facts);
            } else {
                assembled = Some(page.snapshot);
            }
            if let Some(next) = page.next_after {
                query.after = next;
            } else {
                let mut snapshot = assembled.take().expect("first page");
                let expected = snapshot.revision.clone();
                snapshot.identify();
                if snapshot.revision != expected {
                    entry.status = "inconsistent_pages".into();
                    break;
                }
                entry.status = if snapshot.truncated {
                    "truncated"
                } else if snapshot.all_agents {
                    "current"
                } else {
                    "selected_subjects_only"
                }
                .into();
                entry.revision = Some(snapshot.revision.clone());
                entry.observed_at = Some(snapshot.observed_at);
                entry.all_agents = snapshot.all_agents;
                entry.facts = snapshot.facts.len();
                snapshots.push(snapshot);
                break;
            }
        }
        // Inconsistent or interrupted per-owner pages are never promoted to
        // current facts. The explicit coverage entry retains the unknown owner.
        coverage.push(entry);
    }
    Ok((inventory, coverage, snapshots))
}
