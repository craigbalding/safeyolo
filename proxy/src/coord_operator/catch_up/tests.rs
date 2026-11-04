use super::*;

fn current() -> Value {
    json!({"room_id":"rm-one","origin_instance_id":"sy-home"})
}
fn narrative() -> Value {
    json!({"room_id":"rm-one","origin_instance_id":"sy-home","assertions":[{"text":"A claim","sources":["message:12"]}]})
}

#[test]
fn summaries_require_scoped_inspectable_sources_and_reject_mutation_fields() {
    let mut value = narrative();
    assert!(summary(&serde_json::to_vec(&value).unwrap(), &current()).is_ok());
    for source in [
        "https://unfetched.example",
        "message:0",
        "message:01",
        "message:18446744073709551616",
        "state:made-up",
    ] {
        value["assertions"][0]["sources"] = json!([source]);
        assert!(summary(&serde_json::to_vec(&value).unwrap(), &current()).is_err());
    }
    value = narrative();
    value["assertions"][0]["sources"] = json!([]);
    assert!(summary(&serde_json::to_vec(&value).unwrap(), &current()).is_err());
    value = narrative();
    value["room_id"] = json!("rm-other");
    assert!(summary(&serde_json::to_vec(&value).unwrap(), &current()).is_err());
    value = narrative();
    value["origin_instance_id"] = json!("sy-other");
    assert!(summary(&serde_json::to_vec(&value).unwrap(), &current()).is_err());
    value = narrative();
    value["complete_work"] = json!(true);
    assert!(summary(&serde_json::to_vec(&value).unwrap(), &current()).is_err());
}

#[test]
fn summary_bounds_reject_oversize_text_files_and_source_fanout() {
    let mut value = narrative();
    value["assertions"][0]["text"] = json!("x".repeat(4097));
    assert!(summary(&serde_json::to_vec(&value).unwrap(), &current()).is_err());
    assert!(summary(&vec![b' '; MAX_SUMMARY_BYTES + 1], &current()).is_err());
    value = narrative();
    value["assertions"] = json!(vec![value["assertions"][0].clone(); 33]);
    assert!(summary(&serde_json::to_vec(&value).unwrap(), &current()).is_err());
    value = narrative();
    value["assertions"][0]["sources"] =
        json!((1..=9).map(|i| format!("message:{i}")).collect::<Vec<_>>());
    assert!(summary(&serde_json::to_vec(&value).unwrap(), &current()).is_err());
}

#[test]
fn digest_changes_with_authoritative_state_and_excerpts_preserve_attribution() {
    let original = current();
    let mut changed = original.clone();
    changed["owner"] = json!("bob");
    assert_eq!(state_ref(&original), state_ref(&original.clone()));
    assert_ne!(state_ref(&original), state_ref(&changed));
    let item = excerpt(
        &json!({"sequence":42,"sender_kind":"agent","sender_agent_id":"ag-one","origin_instance_id":"sy-remote","body":"€".repeat(2000)}),
    );
    assert_eq!(item["source"], "message:42");
    assert_eq!(item["message"]["origin_instance_id"], "sy-remote");
    assert_eq!(item["body_utf8_bytes"], 6000);
    assert_eq!(item["body_truncated"], true);
    assert!(item["message"]["body"].as_str().unwrap().len() <= MESSAGE_BYTES);
}

#[test]
fn derived_controls_and_wrapping_cannot_impersonate_canonical_headers() {
    let body = format!("\x1b[2J\u{202e}\nAuthoritative state\t{}", "x".repeat(300));
    let rendered = coord_timeline::text_block(&body);
    assert!(!rendered.contains('\x1b') && !rendered.contains('\u{202e}'));
    assert!(rendered.contains("\\x1b") && rendered.contains("RLO U+202E"));
    assert!(rendered.lines().count() > 4);
    assert!(rendered.lines().all(|line| line.starts_with("│ ")));
}

#[test]
fn prompt_and_summary_modes_are_explicit_and_bounded() {
    let args = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert!(
        parse(&args(&[
            "room",
            "--prompt",
            "--since",
            "0",
            "--max-messages",
            "200"
        ]))
        .is_ok()
    );
    for items in [
        vec!["room", "--max-messages", "200"],
        vec!["room", "--prompt", "--max-messages", "201"],
        vec!["room", "--prompt", "--since", "-1"],
        vec!["room", "--prompt", "--summary", "file"],
        vec!["room", "--evidence"],
        vec!["room", "--prompt", "--prompt"],
    ] {
        assert!(parse(&args(&items)).is_err());
    }
}
