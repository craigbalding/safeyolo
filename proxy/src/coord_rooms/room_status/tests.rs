use super::*;

#[test]
fn excerpts_keep_utf8_boundaries_and_full_record_identity() {
    let source = format!("{}🦀tail", "a".repeat(BRIEF_BYTES - 1));
    let brief =
        brief_excerpt(json!({"markdown":source,"revision":7,"content_hash":"canonical-hash"}));
    assert_eq!(brief["excerpt"].as_str().unwrap().len(), BRIEF_BYTES - 1);
    assert_eq!(brief["utf8_bytes"], source.len());
    assert_eq!(brief["truncated"], true);
    assert_eq!(brief["revision"], 7);
    assert_eq!(brief["content_hash"], "canonical-hash");
    assert!(brief.get("markdown").is_none());
    let work = work_summary(
        json!({"title":"🦀".repeat(200),"short_result":"\u{001b}".repeat(600),"version":4,"work_id":"work-example","external_ref":"large-ref"}),
    );
    assert_eq!(work["title"].as_str().unwrap().len(), WORK_TEXT_BYTES);
    assert_eq!(work["title_bytes"], 800);
    assert_eq!(work["title_truncated"], true);
    assert_eq!(work["short_result_truncated"], true);
    assert_eq!(work["version"], 4);
    let github = work_summary(
        json!({"title":"local","external_ref":"https://github.com/o/r/issues/42#comment"}),
    );
    assert_eq!(
        github["github_reference"],
        json!({"source":"github","url":"https://github.com/o/r/issues/42"})
    );
    assert!(github.get("external_ref").is_none());
}

#[test]
fn section_bounds_count_serialized_bytes_including_escapes() {
    let items = vec![json!("\u{001b}".repeat(100)); 60];
    let page = bounded_items(items, 60, 1500);
    assert_eq!(page["total"], 60);
    assert_eq!(page["shown"], 2);
    assert_eq!(page["truncated"], true);
    assert!(page["items"].to_string().len() <= 1500);
    assert_eq!(
        bounded_items(vec![json!(1); 60], 60, SECTION_BYTES)["shown"],
        MAX_ITEMS
    );
}
