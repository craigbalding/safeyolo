use super::*;

fn request(path: &str) -> Request<'_> {
    Request {
        method: "GET",
        path_and_query: path,
        authorization: None,
        identity: crate::network_guard::Identity::Unavailable,
        client_ip: None,
        request_id: "test",
    }
}

#[test]
fn explicit_home_selection_cannot_forward_other_apis_or_relay_recursively() {
    for path in [
        "/admin/coord/rooms/shared/state",
        "/gateway/services",
        "/api/coord/rooms/shared/work?home=again",
        "/api/coord/federation/peer",
        "/api/coord/attention/invalid/object",
    ] {
        assert!(!allowed(request(path)), "{path}");
    }
    assert!(allowed(request("/api/coord/rooms/shared/work?limit=1")));
    assert!(allowed(request(
        "/api/coord/attention/wait?since=0&timeout=0"
    )));
    assert_eq!(
        without_home("/api/coord/rooms/shared/work?limit=2&%68ome=primary&after=x").unwrap(),
        "/api/coord/rooms/shared/work?limit=2&after=x"
    );
    assert!(without_home("/api/coord/rooms/shared/work?home=a&%68ome=b").is_err());
    assert!(without_home("/api/coord/rooms/shared/work").is_err());
}

#[test]
fn a_peer_request_has_no_caller_selected_origin_or_principal() {
    let base = json!({"agent_id":"ag-bob","method":"GET","path":"/api/coord/rooms/shared/state","body":null});
    assert!(serde_json::from_value::<PeerRequest>(base.clone()).is_ok());
    for field in [
        "origin_instance_id",
        "sender_agent_id",
        "principal_id",
        "sender_kind",
    ] {
        let mut forged = base.clone();
        forged[field] = json!("forged");
        assert!(serde_json::from_value::<PeerRequest>(forged).is_err());
    }
}
