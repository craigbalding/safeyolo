use super::*;
use serde_json::json;
use std::os::unix::fs::{PermissionsExt, symlink};

fn source() -> Value {
    json!({"version":1,"period":{"kind":"daily","start":"2026-08-29","end":"2026-08-29"},
        "sections":[{"kind":"shipped","items":[{"theme":"Evidence boundaries","title":"Structured completion notes",
            "body":"Bounded nominations retain canonical attribution.","attribution":"forge_implementation_discovery",
            "evidence":[{"kind":"issue","label":"Issue #437","url":"https://github.com/craigbalding/safeyolo/issues/437"}]}]}]})
}

fn files(value: &Value) -> Vec<GeneratedFile> {
    generate_files(&parse_manifest(&value.to_string()).unwrap()).unwrap()
}

fn checked_files(value: &Value) -> Vec<GeneratedFile> {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let sources = root.join("_sources/dispatch");
    fs::create_dir_all(&sources).unwrap();
    fs::write(sources.join("source.json"), value.to_string()).unwrap();
    let generated = files(value);
    write_generated_files(root, &generated, false).unwrap();
    site::validate_site(root).unwrap();
    generated
}

#[test]
fn retained_source_generates_exact_committed_bytes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = load_manifest(&root.join("site/_sources/dispatch/2026-08-29.json")).unwrap();
    let first = generate_files(&manifest).unwrap();
    assert_eq!(first, generate_files(&manifest).unwrap());
    assert_eq!(first.len(), 2);
    for file in first {
        assert_eq!(
            file.content,
            fs::read_to_string(root.join("site").join(file.relative_path)).unwrap()
        );
    }
    site::validate_site(&root.join("site")).unwrap();
}

#[test]
fn periods_themes_quiet_output_and_topic_corrections() {
    for date in ["20260829", "2026-W35-6", "2026W356"] {
        assert_eq!(
            manifest_date(date).unwrap(),
            parse_date("2026-08-29").unwrap()
        );
    }
    for invalid in ["2026-W356", "2026W35-6", "2026-W-35", "2026W3-5"] {
        assert!(manifest_date(invalid).is_err());
    }
    let mut value = source();
    for (kind, start, end, path) in [
        (
            "daily",
            "2026-08-29",
            "2026-08-29",
            "dispatch/2026-08-29.md",
        ),
        (
            "weekly",
            "2026-08-24",
            "2026-08-30",
            "snapshots/2026-W35.md",
        ),
        (
            "monthly",
            "2026-08-01",
            "2026-08-31",
            "snapshots/2026-08.md",
        ),
    ] {
        value["period"] = json!({"kind":kind,"start":start,"end":end});
        assert_eq!(files(&value)[0].relative_path, Path::new(path));
    }
    value = source();
    let first = value["sections"][0]["items"][0].clone();
    value["sections"][0]["items"]
        .as_array_mut()
        .unwrap()
        .push(first);
    assert_eq!(
        files(&value)[0]
            .content
            .matches("### Evidence boundaries")
            .count(),
        1
    );
    value["sections"] = json!([]);
    let directory = tempfile::tempdir().unwrap();
    let absent = directory.path().join("absent");
    assert!(files(&value).is_empty());
    assert!(
        write_generated_files(&absent, &[], false)
            .unwrap()
            .is_empty()
    );
    assert!(!absent.exists());
    value["topic_updates"] = json!([{"slug":"coord","title":"Coord collaboration","state_key":"coord-v1","summary":"Current state.",
        "current_state":["Coord remains the attributed message authority."],"evidence":source()["sections"][0]["items"][0]["evidence"]}]);
    let initial = files(&value);
    assert_eq!(initial[0].relative_path, Path::new("topics/coord.md"));
    value["topic_updates"][0]["summary"] = json!("Corrected copy without a state change.");
    assert_ne!(initial, files(&value));
    assert!(
        files(&value)[0]
            .content
            .contains("safeyolo-topic-state: coord-v1")
    );
}

#[test]
fn plain_copy_safe_fences_and_transitive_definitions() {
    let mut value = source();
    value["sections"][0]["items"][0]["body"] =
        json!("Authored [link](relative) and <script> stay inert. The plumb route remains.");
    value["definitions"] = json!({"plumb":"The path associates exchanges with a run_id.","run_id":"Identifier for a sandbox run."});
    let output = &checked_files(&value)[0].content;
    assert!(output.contains(r"\[link\](relative) and \<script\>"));
    assert!(output.contains("`run_id` — Identifier for a sandbox run."));
    value["sections"] = json!([{"kind":"lens_caught","items":[{"title":"Fence safely","body":"The plumb example remains inert.",
        "attribution":"lens_review_finding","snippet":{"language":"text","code":"before\n```\nafter [example](missing)"},
        "lesson":"Use a longer fence.","evidence":source()["sections"][0]["items"][0]["evidence"]}]}]);
    assert!(
        checked_files(&value)[0]
            .content
            .contains("````text\nbefore\n```\nafter [example](missing)\n````")
    );
    value["sections"][0]["items"][0]["attribution"] = json!("forge_implementation_discovery");
    assert!(parse_manifest(&value.to_string()).is_err());
}

#[test]
fn liquid_copy_generates_and_checks_without_restricting_authored_examples() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let value: Value = serde_json::from_str(
        &fs::read_to_string(root.join("tests/proxy_contracts/fixtures/dispatch-inert.json"))
            .unwrap(),
    )
    .unwrap();
    let generated = checked_files(&value);
    assert_eq!(generated.len(), 2);
    for (file, labels) in generated.iter().zip([
        &[
            "Theme",
            "Title",
            "Body liquid",
            "Definition",
            "Evidence",
            "Lesson",
        ][..],
        &[
            "Topic",
            "Summary liquid",
            "Definition",
            "State",
            "Topic evidence",
        ][..],
    ]) {
        for label in labels {
            let expected = format!(
                "{label} {}",
                r"{{ '{{' }} 17 \| plus: 4 }} {{ '{%' }} endraw %}"
            );
            assert!(file.content.contains(&expected));
        }
    }
    assert!(
        generated[0]
            .content
            .contains("{{ '{{' }}- 17 \\| plus: 4 -}}")
    );
    assert!(
        generated[0]
            .content
            .contains("Snippet {{ '{{' }} 17 | plus: 4 }}")
    );
    assert!(generated[0].content.contains("after [example](missing)"));
}

#[test]
fn malformed_shapes_and_hostile_text_fail_without_output() {
    for input in [
        "null",
        "[]",
        "true",
        "1",
        r#"{"version":1,"version":1}"#,
        "{",
        r#"{"version":NaN}"#,
    ] {
        assert!(parse_manifest(input).is_err(), "accepted {input}");
    }
    assert!(parse_manifest(&format!("{}0{}", "[".repeat(10000), "]".repeat(10000))).is_err());
    assert!(parse_manifest(&" ".repeat(MAX_MANIFEST_BYTES + 1)).is_err());
    assert!(parse_manifest(&format!(r#"{{"version":{}}}"#, "9".repeat(100))).is_err());
    for invalid in [json!(true), json!(1.0), json!("1"), json!(null), json!(2)] {
        let mut value = source();
        value["version"] = invalid;
        assert!(parse_manifest(&value.to_string()).is_err());
    }
    for invalid in [json!(null), json!({}), json!("x"), json!([true])] {
        let mut value = source();
        value["sections"] = invalid;
        assert!(parse_manifest(&value.to_string()).is_err());
    }
    for body in [
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "github_pat_abcdefghijklmnop",
        "sgw_abcdefghijklmnopqrstuvwxyz",
        "msg-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "coord sequence #296",
        "private chain-of-thought follows",
        "read /app/agent_token",
        "https://example.com raw link",
        "mail@example.com",
        "www.example.com",
        "bad\u{1b}control",
    ] {
        let mut value = source();
        value["sections"][0]["items"][0]["body"] = json!(body);
        assert!(
            parse_manifest(&value.to_string()).is_err(),
            "accepted hostile public text"
        );
    }
    for (kind, start, end) in [
        ("daily", "2026-08-29", "2026-08-30"),
        ("weekly", "2026-08-25", "2026-08-31"),
        ("monthly", "2026-08-02", "2026-08-31"),
    ] {
        let mut value = source();
        value["period"] = json!({"kind":kind,"start":start,"end":end});
        assert!(parse_manifest(&value.to_string()).is_err());
    }
    let mut value = source();
    value["extra"] = json!("unknown");
    assert!(parse_manifest(&value.to_string()).is_err());
    let mut value = source();
    value["definitions"] = json!({"unused":"Filler."});
    assert!(parse_manifest(&value.to_string()).is_err());
    let mut value = source();
    value["sections"][0]["items"][0]["theme"] = Value::Null;
    assert!(parse_manifest(&value.to_string()).is_err());
}

#[test]
fn public_evidence_and_kind_checks() {
    for url in [
        "https://sqlite.org/lockingv3.html",
        "https://www.sqlite.org/lockingv3.html#locking",
        "https://bücher.example/document",
    ] {
        assert!(validate_public_url(url).is_ok(), "{url}");
    }
    for url in [
        "http://github.com/a/b/issues/1",
        "https://service.internal/report",
        "https://127.0.0.1/report",
        "https://127.1/report",
        "https://0177.0.0.1/report",
        "https://100.64.0.1/report",
        "https://192.0.0.8/report",
        "https://example .com/report",
        "https://example%20.com/report",
        "https://example.com/report) **INJECTED**",
        "https://example.com:443/report",
        "https://user@example.com/report",
        "https://example.com/report?token=secret",
    ] {
        assert!(validate_public_url(url).is_err(), "{url}");
    }
    let mut value = source();
    value["sections"][0]["items"][0]["evidence"][0]["kind"] = json!("pr");
    assert!(parse_manifest(&value.to_string()).is_err());
    let mut value = source();
    let evidence = value["sections"][0]["items"][0]["evidence"][0].clone();
    value["sections"][0]["items"][0]["evidence"]
        .as_array_mut()
        .unwrap()
        .push(evidence);
    assert!(parse_manifest(&value.to_string()).is_err());
}

#[test]
fn writer_is_atomic_idempotent_contained_and_truthful() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("site");
    let generated = files(&source());
    assert!(write_generated_files(&root, &generated, true).is_err());
    assert!(!root.exists());
    assert_eq!(
        write_generated_files(&root, &generated, false).unwrap(),
        vec![PathBuf::from("dispatch/2026-08-29.md")]
    );
    assert!(
        write_generated_files(&root, &generated, false)
            .unwrap()
            .is_empty()
    );
    assert!(
        write_generated_files(&root, &generated, true)
            .unwrap()
            .is_empty()
    );
    let target = root.join(&generated[0].relative_path);
    let original = fs::read(&target).unwrap();
    let changed = vec![GeneratedFile {
        relative_path: generated[0].relative_path.clone(),
        content: "corrected\n".into(),
    }];
    assert!(write_generated_files(&root, &changed, true).is_err());
    assert_eq!(fs::read(&target).unwrap(), original);
    for path in [
        "../outside.md",
        "topics/nested/out.md",
        "dispatch/out.json",
        "/topics/out.md",
    ] {
        assert!(
            write_generated_files(
                &root,
                &[GeneratedFile {
                    relative_path: path.into(),
                    content: "safe\n".into()
                }],
                false
            )
            .is_err()
        );
    }
    let link = directory.path().join("linked-site");
    symlink(&root, &link).unwrap();
    assert!(write_generated_files(&link, &generated, false).is_err());
    let outside = directory.path().join("outside.md");
    fs::write(&outside, b"outside\n").unwrap();
    fs::remove_file(&target).unwrap();
    symlink(&outside, &target).unwrap();
    assert!(write_generated_files(&root, &generated, false).is_err());
    assert_eq!(fs::read(&outside).unwrap(), b"outside\n");
    fs::remove_file(&target).unwrap();
    fs::write(&target, &original).unwrap();
    if unsafe { libc::geteuid() } != 0 {
        let parent = target.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o555)).unwrap();
        let result = write_generated_files(&root, &changed, false);
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_err());
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(fs::read_dir(parent).unwrap().count(), 1);
    }
    let source_file = directory.path().join("manifest.json");
    fs::write(&source_file, source().to_string()).unwrap();
    let link = directory.path().join("source-link.json");
    symlink(&source_file, &link).unwrap();
    assert!(load_manifest(&link).is_err());
}

#[test]
fn site_scope_links_hygiene_and_generated_bytes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("site");
    let directory = tempfile::tempdir().unwrap();
    let copy = directory.path().join("site");
    fs::create_dir(&copy).unwrap();
    let mut paths = Vec::new();
    site::paths(&root, &mut paths).unwrap();
    for source in paths {
        let target = copy.join(source.strip_prefix(&root).unwrap());
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(source, target).unwrap();
    }
    site::validate_site(&copy).unwrap();
    let index = copy.join("index.md");
    let original = fs::read_to_string(&index).unwrap();
    for addition in [
        "\ngithub_pat_abcdefghijklmnop\n",
        "\n[Missing](/not-present/)\n",
        "\n[Private](https://localhost/status)\n",
        "\n\\\\[Missing](/not-present/)\n",
        "\n[Escaped \\] label](/not-present/)\n",
        "\n````text\n```\n[Example](missing)\n````\n[Missing](/not-present/)\n",
        "\n````text\n```\n[Example](missing)\n````\n[Private](https://localhost/status)\n",
    ] {
        fs::write(&index, format!("{original}{addition}")).unwrap();
        assert!(site::validate_site(&copy).is_err());
    }
    for addition in ["\n\\[a\\](a)\n", "\n\\\\\\[a](a)\n", "\n[a\\](a)\n"] {
        fs::write(&index, format!("{original}{addition}")).unwrap();
        site::validate_site(&copy).unwrap();
    }
    fs::write(&index, original).unwrap();
    let page = copy.join("dispatch/2026-08-29.md");
    fs::write(
        &page,
        format!("{}\nstale\n", fs::read_to_string(&page).unwrap()),
    )
    .unwrap();
    assert!(
        site::validate_site(&copy)
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
    site::validate_scope(&[
        "site/dispatch/2026-08-30.md".into(),
        "site/_sources/dispatch/2026-08-30.json".into(),
    ])
    .unwrap();
    assert!(site::validate_scope(&[".github/workflows/pages.yml".into()]).is_err());
}
