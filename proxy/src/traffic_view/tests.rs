use super::*;

fn view(max_flows: usize, max_bytes: usize) -> Arc<TrafficView> {
    Arc::new(TrafficView::new(max_flows, max_bytes))
}

fn begin(view: &Arc<TrafficView>, id: &str, agent: Option<&str>, started: f64) -> Arc<Exchange> {
    view.begin(RequestInfo {
        id: id.into(),
        connection_id: "owned-connection".into(),
        agent: agent.map(str::to_owned),
        method: "POST".into(),
        url: "https://owned.invalid/path?query=value".into(),
        headers: vec![
            ("X-Duplicate".into(), "first".into()),
            ("x-duplicate".into(), "second".into()),
        ],
        started,
    })
}

fn metadata(exchange: &Exchange, value: Value) {
    exchange.metadata(value.as_object().unwrap());
}

fn ids(view: &TrafficView) -> Vec<String> {
    view.flows()["flows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().into())
        .collect()
}

#[test]
fn pending_body_headers_early_response_and_late_request_remain_one_row() {
    let view = view(10, 1024);
    let exchange = begin(&view, "first", Some("alice"), 1.0);
    assert_eq!(view.detail("first").unwrap()["state"], "pending");
    assert_eq!(
        view.body("first", Side::Request).unwrap(),
        json!({"available":false,"size":0,"reason":"pending","data_base64":null})
    );
    assert_eq!(
        view.detail("first").unwrap()["request_headers"],
        json!([["X-Duplicate", "first"], ["x-duplicate", "second"]])
    );
    exchange.response_head(
        413,
        vec![
            ("X-Duplicate".into(), "ÿ".into()),
            ("X-Duplicate".into(), "two".into()),
        ],
    );
    exchange.response_body(None);
    exchange.finish_at(None, 3.0);
    assert_eq!(
        view.body("first", Side::Request).unwrap()["reason"],
        "pending"
    );
    exchange.request_headers(vec![("Content-Length".into(), "3".into())]);
    exchange.request_body(Some(&[0, 255, 10]));
    metadata(
        &exchange,
        json!({"agent":"forged","test_id":"owned-test","test_role":"client"}),
    );
    exchange.finish_at(Some("late failure must not replace terminal"), 5.0);
    let detail = view.detail("first").unwrap();
    assert_eq!(detail["state"], "complete");
    assert_eq!(detail["ended"], 3.0);
    assert_eq!(detail["error"], Value::Null);
    assert_eq!(detail["status"], 413);
    assert_eq!(detail["request_headers"], json!([["Content-Length", "3"]]));
    assert_eq!(
        detail["response_headers"],
        json!([["X-Duplicate", "ÿ"], ["X-Duplicate", "two"]])
    );
    assert_eq!(
        detail["metadata"],
        json!({"agent":"alice","test_id":"owned-test","test_role":"client"})
    );
    assert_eq!(
        view.body("first", Side::Request).unwrap(),
        json!({"available":true,"size":3,"reason":null,"data_base64":"AP8K"})
    );
    assert_eq!(
        view.body("first", Side::Response).unwrap()["reason"],
        "streamed_or_unavailable"
    );
    exchange.request_body(Some(&[]));
    assert_eq!(
        view.body("first", Side::Request).unwrap(),
        json!({"available":true,"size":0,"reason":null,"data_base64":""})
    );
    drop(exchange);
    assert_eq!(ids(&view), vec!["first"]);
    assert_eq!(view.detail("first").unwrap()["state"], "complete");

    let unfinished = begin(&view, "unfinished-request", Some("alice"), 4.);
    unfinished.finish(None);
    assert_eq!(
        view.body("unfinished-request", Side::Request).unwrap()["reason"],
        "pending"
    );
    drop(unfinished);
    assert_eq!(
        view.body("unfinished-request", Side::Request).unwrap()["reason"],
        "streamed_or_unavailable"
    );
}

#[test]
fn last_handle_cancellation_error_and_replaced_id_do_not_resurrect_rows() {
    let view = view(10, 1024);
    let first = begin(&view, "same", Some("alice"), 1.0);
    let first_copy = Arc::clone(&first);
    drop(first);
    assert_eq!(view.detail("same").unwrap()["state"], "pending");
    let replacement = begin(&view, "same", Some("bob"), 2.0);
    first_copy.request_body(Some(b"stale"));
    first_copy.finish_at(Some("stale"), 3.0);
    drop(first_copy);
    assert_eq!(view.detail("same").unwrap()["agent"], "bob");
    assert_eq!(view.detail("same").unwrap()["state"], "pending");
    replacement.response_head(502, Vec::new());
    replacement.finish_at(Some("owned transport failure"), 4.0);
    drop(replacement);
    assert_eq!(view.detail("same").unwrap()["state"], "error");
    assert_eq!(
        view.detail("same").unwrap()["error"],
        "owned transport failure"
    );
    let pending = begin(&view, "cancelled", None, 5.0);
    drop(pending);
    assert_eq!(view.detail("cancelled").unwrap()["state"], "incomplete");
    assert_eq!(view.detail("cancelled").unwrap()["error"], "cancelled");
    assert_eq!(
        view.body("cancelled", Side::Request).unwrap()["reason"],
        "streamed_or_unavailable"
    );
    assert_eq!(
        view.body("cancelled", Side::Response).unwrap()["reason"],
        "streamed_or_unavailable"
    );
    assert!(view.detail("cancelled").unwrap()["ended"].is_number());
    let survivor = begin(&view, "survivor", None, 6.0);
    let weak = Arc::downgrade(&view);
    drop(view);
    assert!(weak.upgrade().is_none());
    survivor.request_body(Some(b"no detached store"));
    drop(survivor);
}

#[test]
fn hidden_terminal_rows_evict_by_completion_then_id_and_active_handles_survive_targets() {
    let view = view(4, 100);
    let late_start = begin(&view, "a", Some("alice"), 30.0);
    let early_start = begin(&view, "b", Some("bob"), 1.0);
    let tied = begin(&view, "c", Some("bob"), 2.0);
    late_start.finish_at(None, 10.0);
    early_start.finish_at(None, 5.0);
    tied.finish_at(None, 5.0);
    drop((late_start, early_start, tied));
    view.set_scope(&json!({"agent":"alice"})).unwrap();
    view.configure(2, 100);
    assert!(view.detail("b").is_none());
    assert!(view.detail("c").is_some());
    assert_eq!(ids(&view), vec!["a"]);
    // Hidden rows are included in both count and byte pressure.
    let active = begin(&view, "active", Some("alice"), 40.0);
    active.request_body(Some(&[7; 200]));
    active.finish_at(None, 41.0);
    view.configure(1, 10);
    assert!(view.detail("a").is_none());
    assert!(view.detail("c").is_none());
    assert_eq!(view.body("active", Side::Request).unwrap()["size"], 200);
    // A live observer can still provide late request facts after response EOM.
    active.request_body(Some(b"late"));
    drop(active);
    assert!(view.detail("active").is_some());
    let too_big = begin(&view, "too-big", None, 50.0);
    too_big.response_body(Some(&[1; 20]));
    too_big.finish_at(None, 51.0);
    drop(too_big);
    assert!(view.detail("active").is_none());
    assert!(view.detail("too-big").is_none());
}

#[test]
fn scope_validation_clearing_truthiness_and_exact_display() {
    let view = view(10, 1024);
    let selected = view
        .set_scope(
            &json!({"agent":"a.b \"q\"","test_id":"x+y","intent":" ","role":"r","expect":"e"}),
        )
        .unwrap();
    assert_eq!(
        selected["effective_filter"],
        "~meta \"^agent:\\ a\\.b\\ \\\"q\\\"$\" & ~meta \"^test_id:\\ x\\+y$\" & ~meta \"^test_intent:\\ \\ $\" & ~meta \"^test_role:\\ r$\" & ~meta \"^test_expect:\\ e$\""
    );
    assert_eq!(selected["user_filter"], "");
    for (input, error) in [
        (json!([]), "request body must be a JSON object"),
        (json!({"z":0,"a":0}), "unknown scope field(s): a, z"),
        (
            json!({"agent":false,"unattributed":[0]}),
            "agent and unattributed are mutually exclusive",
        ),
        (
            json!({"agent":""}),
            "agent must be a non-empty string or null",
        ),
        (
            json!({"test_id":false}),
            "test_id must be a non-empty string or null",
        ),
    ] {
        assert_eq!(view.set_scope(&input).unwrap_err(), error);
        assert_eq!(view.scope(), selected);
    }
    for raw in [json!([0]), json!({"x":false}), json!("yes"), json!(1)] {
        let result = view.set_scope(&json!({"unattributed":raw})).unwrap();
        assert_eq!(result["unattributed"], raw);
        assert_eq!(result["agent"], Value::Null);
        assert_eq!(result["test_id"], Value::Null);
        assert_eq!(result["effective_filter"], "!(~meta ^agent:)");
    }
    for raw in [
        Value::Null,
        json!(false),
        json!(0),
        json!(-0.0),
        json!(""),
        json!([]),
        json!({}),
    ] {
        assert_eq!(
            view.set_scope(&json!({"unattributed":raw})).unwrap()["effective_filter"],
            ""
        );
    }
    assert_eq!(
        view.set_scope(&json!({})).unwrap(),
        json!({"agent":null,"unattributed":false,"test_id":null,"intent":null,"role":null,"expect":null,"user_filter":"","effective_filter":""})
    );
}

#[test]
fn scope_matches_source_default_multiline_metadata_and_facets_use_all_rows() {
    let view = view(10, 1024);
    let alice = begin(&view, "alice", Some("Alice"), 1.0);
    let bob = begin(&view, "bob", Some("Bob"), 2.0);
    let no_agent = begin(&view, "none", None, 3.0);
    metadata(
        &alice,
        json!({"test_id":"one","test_intent":"read","test_role":true,"test_expect":["ok",null]}),
    );
    metadata(
        &bob,
        json!({"test_id":"two","test_intent":"write","test_role":false,"test_expect":{"ok":true}}),
    );
    metadata(
        &no_agent,
        json!({"test_id":"none","test_intent":"line1\nagent: injected\nline3","test_role":null}),
    );
    view.set_scope(&json!({"agent":"alice"})).unwrap();
    assert_eq!(ids(&view), vec!["alice"]);
    // Facet narrowing uses typed equality, unlike case-insensitive view filters.
    assert_eq!(view.facets()["test_id"], json!([]));
    view.set_scope(&json!({"agent":"Alice","test_id":"one","role":"missing"}))
        .unwrap();
    assert!(ids(&view).is_empty());
    let facets = view.facets();
    assert_eq!(
        facets["agent"],
        json!([{"value":"Alice","count":1},{"value":"Bob","count":1}])
    );
    assert_eq!(facets["test_id"], json!([{"value":"one","count":1}]));
    assert_eq!(facets["test_role"], json!([{"value":"True","count":1}]));
    assert_eq!(
        facets["test_expect"],
        json!([{"value":"['ok', None]","count":1}])
    );
    view.set_scope(&json!({"unattributed":true})).unwrap();
    // FMeta sees a new metadata-looking line inside the string value.
    assert!(ids(&view).is_empty());
    assert_eq!(
        view.facets()["test_role"],
        json!([{"value":"False","count":1},{"value":"True","count":1}])
    );
    metadata(&no_agent, json!({"test_intent":"ordinary"}));
    assert_eq!(ids(&view), vec!["none"]);
    view.set_scope(&json!({})).unwrap();
    assert_eq!(ids(&view), vec!["none", "bob", "alice"]);
    assert_eq!(
        view.facets()["test_expect"],
        json!([{"value":"['ok', None]","count":1},{"value":"{'ok': True}","count":1}])
    );
}

#[test]
fn owned_wiping_replaces_sensitive_values_and_handles_deep_metadata_cleanup() {
    let view = view(1, 100);
    let exchange = begin(&view, "owned", Some("alice"), 1.0);
    metadata(&exchange, json!({"nested":{"old":"secret"}}));
    metadata(&exchange, json!({"nested":{"new":"replacement"}}));
    assert_eq!(
        view.detail("owned").unwrap()["metadata"]["nested"],
        json!({"new":"replacement"})
    );
    let mut headers = vec![("Authorization".into(), "owned-secret".into())];
    wipe_headers(&mut headers);
    assert!(headers.is_empty());
    let mut value = json!({"owned-secret-key":"owned-secret-value"});
    for index in 0..8192 {
        value = if index % 2 == 0 {
            Value::Array(vec![value])
        } else {
            let mut map = Map::new();
            map.insert("nested".into(), value);
            Value::Object(map)
        };
    }
    wipe_json(&mut value);
    assert_eq!(value, Value::Null);
    assert_eq!(
        python_text(&json!([true,false,null,1.0,1e-7,"a'b",{"key":"value"}])),
        "[True, False, None, 1.0, 1e-07, \"a'b\", {'key': 'value'}]"
    );
}

// Regenerate the pure source fixture with proxy/tests/traffic_scope_source.py.
// Six of eight rows compare scope fields, display, selected matches and facets.
// The two source lexer differences have a separate explicit native control.
#[test]
fn six_actual_source_scope_and_facet_rows() {
    let rows: Value =
        serde_json::from_str(include_str!("../../tests/traffic_scope_source.json")).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 8);
    let supported = rows.as_array().unwrap().iter().filter(|fixture| {
        !matches!(
            fixture["name"].as_str(),
            Some("literal_scope" | "newline_scope")
        )
    });
    for fixture in supported {
        let view = view(100, 1024);
        let mut handles = Vec::new();
        for (index, metadata) in fixture["metadata"].as_array().unwrap().iter().enumerate() {
            let id = index.to_string();
            handles.push(begin(
                &view,
                &id,
                metadata.get("agent").and_then(Value::as_str),
                index as f64,
            ));
            // Direct fixture state includes source agent:null (not emitted by
            // our trusted Option<String> producer); this exercises only the
            // shared view's source metadata projection, not producer parity.
            view.lock().rows.get_mut(&id).unwrap().metadata = metadata.clone();
        }
        assert_eq!(
            view.set_scope(&fixture["scope"]).unwrap(),
            fixture["stats"],
            "{}",
            fixture["name"]
        );
        let visible = ids(&view);
        let matched: Vec<_> = (0..handles.len())
            .map(|index| visible.contains(&index.to_string()))
            .collect();
        assert_eq!(json!(matched), fixture["matches"], "{}", fixture["name"]);
        assert_eq!(view.facets(), fixture["facets"], "{}", fixture["name"]);
    }
}

#[test]
fn native_literal_selector_behavior_is_explicitly_distinct_from_source_lexer() {
    let view = view(100, 1024);
    let literal = begin(&view, "literal", Some("a.b[0]\" x"), 1.0);
    let regex_like = begin(&view, "regex", Some("aXb0\" x"), 2.0);
    view.set_scope(&json!({"agent":"a.b[0]\" x"})).unwrap();
    assert_eq!(ids(&view), vec!["literal"]); // Source oracle returns only regex.
    metadata(&literal, json!({"test_id":"a\nb"}));
    metadata(&regex_like, json!({"test_id":"a"}));
    view.set_scope(&json!({"test_id":"a\nb"})).unwrap(); // Source OptionsError.
    assert_eq!(ids(&view), vec!["literal"]);
}
