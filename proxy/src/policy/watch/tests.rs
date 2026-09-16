//! Owned file controls; execution belongs to the joined Runtime build.
use super::*;
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

fn put(path: &Path, text: &str, nanoseconds: i128) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
    let duration = Duration::from_nanos(nanoseconds.unsigned_abs().try_into().unwrap());
    let modified = if nanoseconds < 0 {
        UNIX_EPOCH - duration
    } else {
        UNIX_EPOCH + duration
    };
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
}
fn accepted(path: &Path, previous: Option<&Policy>) -> Policy {
    let mut policy = Policy::from_path_at(path, 0.0).unwrap();
    policy.observe_baseline_files(previous).unwrap();
    policy
}
fn times(policy: &Policy) -> (f64, f64, f64) {
    let value = policy.file_times.unwrap();
    (value.baseline, value.addons, value.lists)
}

#[test]
fn strict_float_mtimes_preserve_epoch_negative_and_adjacent_nanosecond_behavior() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");
    put(&path, "{}", 0);
    let epoch = accepted(&path, None);
    assert_eq!(times(&epoch), (0.0, 0.0, 0.0));
    assert!(!epoch.baseline_files_changed().unwrap());
    put(&path, "{}", -1_000_000_000);
    let negative = accepted(&path, None);
    assert_eq!(times(&negative).0, -1.0);
    put(&path, "{}", -500_000_000);
    assert!(negative.baseline_files_changed().unwrap());
    let large = 1_700_000_000_000_000_000;
    put(&path, "{}", large);
    let policy = accepted(&path, None);
    assert_eq!(times(&policy).0, 1_700_000_000.0);
    put(&path, "{}", large + 1);
    assert_eq!(modified(&path).unwrap(), times(&policy).0);
    assert!(!policy.baseline_files_changed().unwrap());
    put(&path, "{}", large + 1_000);
    assert!(policy.baseline_files_changed().unwrap());
}

#[test]
fn unchanged_older_deleted_and_unobserved_baselines_do_not_trigger() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");
    put(&path, "{}", 100_000_000_000);
    let pure = Policy::from_path_at(&path, 0.0).unwrap();
    assert!(pure.file_times.is_none());
    let policy = accepted(&path, None);
    put(&path, "{\"permissions\":[]}", 100_000_000_000);
    assert!(!policy.baseline_files_changed().unwrap());
    put(&path, "{}", 90_000_000_000);
    assert!(!policy.baseline_files_changed().unwrap());
    fs::remove_file(&path).unwrap();
    assert!(!policy.baseline_files_changed().unwrap());
    assert!(!pure.baseline_files_changed().unwrap());
    put(&path, "{}", 101_000_000_000);
    assert!(policy.baseline_files_changed().unwrap());
    assert!(!pure.baseline_files_changed().unwrap());
    let mut unconfigured = Policy::unconfigured();
    unconfigured.observe_baseline_files(Some(&policy)).unwrap();
    assert!(unconfigured.file_times.is_none());
    assert!(!unconfigured.baseline_files_changed().unwrap());
}

#[test]
fn absent_addon_keeps_old_watermark_until_seen_or_baseline_path_changes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");
    let addons = directory.path().join("addons.yaml");
    put(&path, "{}", 10_000_000_000);
    put(&addons, "{}", 200_000_000_000);
    let first = accepted(&path, None);
    assert_eq!(times(&first), (10.0, 200.0, 0.0));
    fs::remove_file(&addons).unwrap();
    put(&path, "{}", 11_000_000_000);
    let absent = accepted(&path, Some(&first));
    assert_eq!(times(&absent), (11.0, 200.0, 0.0));
    put(&addons, "{}", 150_000_000_000);
    assert!(!absent.baseline_files_changed().unwrap());
    put(&path, "{}", 12_000_000_000);
    let seen = accepted(&path, Some(&absent));
    assert_eq!(times(&seen), (12.0, 150.0, 0.0));
    put(&addons, "{}", 151_000_000_000);
    assert!(seen.baseline_files_changed().unwrap());
    let other = directory.path().join("other/policy.json");
    put(&other, "{}", 1_000_000_000);
    let changed_path = accepted(&other, Some(&seen));
    assert_eq!(times(&changed_path), (1.0, 0.0, 0.0));
    let self_addon = accepted(&addons, None);
    assert_eq!(times(&self_addon), (151.0, 151.0, 0.0));
    put(&addons, "{}", 152_000_000_000);
    assert!(self_addon.baseline_files_changed().unwrap());
}

#[test]
fn raw_list_max_rereads_all_strings_and_ignores_merged_addon_lists() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");
    let used = directory.path().join("used.list");
    let unused = directory.path().join("unused.list");
    let absolute = directory.path().join("absolute.list");
    let negative = directory.path().join("negative.list");
    put(&used, "owned.invalid", 40_000_000_000);
    put(&unused, "unused.invalid", 90_000_000_000);
    put(&absolute, "absolute.invalid", 50_000_000_000);
    put(&negative, "negative.invalid", -1_000_000_000);
    let raw = json!({"lists":{"used":"used.list","unused":"unused.list","absolute":absolute,
        "missing":"missing.list","negative":"negative.list","number":42,"object":{}},
        "hosts":{"$used":{"egress":"allow"}}});
    put(&path, &raw.to_string(), 20_000_000_000);
    let policy = accepted(&path, None);
    assert_eq!(times(&policy).2, 90.0);
    put(&used, "owned.invalid", 80_000_000_000);
    assert!(!policy.baseline_files_changed().unwrap());
    put(&unused, "unused.invalid", 91_000_000_000);
    assert!(policy.baseline_files_changed().unwrap());
    fs::remove_file(&unused).unwrap();
    assert!(!policy.baseline_files_changed().unwrap());
    let addon_list = directory.path().join("addon.list");
    put(&addon_list, "addon.invalid", 400_000_000_000);
    put(
        &directory.path().join("addons.yaml"),
        "lists: {addon: addon.list}",
        5_000_000_000,
    );
    put(&path, "{}", 20_000_000_000);
    let addons_only = accepted(&path, Some(&policy));
    assert_eq!(times(&addons_only).2, 0.0);
    put(&path, r#"{"lists":{"raw":"addon.list"}}"#, 20_000_000_000);
    assert!(
        addons_only.baseline_files_changed().unwrap(),
        "raw mapping is reread despite equal baseline mtime"
    );
}

#[test]
fn raw_list_decode_truthiness_temporal_and_path_errors_keep_reached_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");
    for text in [
        "null",
        "false",
        "0",
        "\"\"",
        "[]",
        "{}",
        "{",
        "NaN",
        r#"{"lists":42}"#,
    ] {
        put(&path, text, 0);
        assert_eq!(lists_max_mtime(&path).unwrap(), 0.0, "{text}");
    }
    // NaN above is an inherited native decoder gap, not a source equivalence.
    for text in ["true", "42", "\"owned\"", "[42]"] {
        put(&path, text, 0);
        assert_eq!(lists_max_mtime(&path).unwrap_err().kind, ErrorKind::Invalid);
    }
    put(&path, &json!({"lists":{"bad":"nul\0path"}}).to_string(), 0);
    assert_eq!(lists_max_mtime(&path).unwrap_err().kind, ErrorKind::Invalid);
    let list = directory.path().join("owned.list");
    put(&list, "owned.invalid", 7_000_000_000);
    let yaml = directory.path().join("policy.yaml");
    put(
        &yaml,
        "lists:\n  ordinary: owned.list\n  date: 2026-01-02\n",
        0,
    );
    assert_eq!(lists_max_mtime(&yaml).unwrap(), 7.0);
    put(&yaml, "2026-01-02", 0);
    assert_eq!(lists_max_mtime(&yaml).unwrap_err().kind, ErrorKind::Invalid);
    put(&yaml, "lists: 2026-01-02", 0);
    assert_eq!(lists_max_mtime(&yaml).unwrap(), 0.0);
    let toml = directory.path().join("policy.toml");
    put(&toml, "budget=1\nglobal_budget=2\n", 0);
    assert_eq!(lists_max_mtime(&toml).unwrap(), 0.0);
    let bad = directory.path().join("long.list");
    std::os::unix::fs::symlink("x".repeat(256), &bad).unwrap();
    put(
        &path,
        r#"{"lists":{"bad":"long.list","good":"owned.list"}}"#,
        0,
    );
    assert_eq!(
        lists_max_mtime(&path).unwrap(),
        7.0,
        "per-list OSError is omitted"
    );
}

#[test]
fn later_observation_error_preempts_changed_flag_and_cannot_partially_assign_times() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");
    let addons = directory.path().join("addons.yaml");
    put(&path, "{}", 20_000_000_000);
    let mut policy = accepted(&path, None);
    let previous = policy.clone();
    put(&path, "{}", 21_000_000_000);
    std::os::unix::fs::symlink("x".repeat(256), &addons).unwrap();
    assert_eq!(
        policy.baseline_files_changed().unwrap_err().kind,
        ErrorKind::Read
    );
    assert_eq!(
        policy
            .observe_baseline_files(Some(&previous))
            .unwrap_err()
            .kind,
        ErrorKind::Read
    );
    assert_eq!(times(&policy), times(&previous));
    fs::remove_file(&addons).unwrap();
    put(&addons, "{}", 30_000_000_000);
    put(
        &path,
        &json!({"lists":{"bad":"nul\0path"}}).to_string(),
        21_000_000_000,
    );
    assert_eq!(
        policy.baseline_files_changed().unwrap_err().kind,
        ErrorKind::Invalid
    );
    assert_eq!(
        policy
            .observe_baseline_files(Some(&previous))
            .unwrap_err()
            .kind,
        ErrorKind::Invalid
    );
    assert_eq!(times(&policy), (20.0, 0.0, 0.0));
    let mut candidate = Policy::from_path_at(&path, 0.0).unwrap();
    assert!(candidate.observe_baseline_files(Some(&previous)).is_err());
    assert!(candidate.file_times.is_none());
    fs::remove_file(&path).unwrap();
    assert_eq!(
        policy
            .observe_baseline_files(Some(&previous))
            .unwrap_err()
            .kind,
        ErrorKind::Read
    );
    assert_eq!(times(&policy), (20.0, 0.0, 0.0));
}

#[test]
fn source_mutation_and_task_changes_retain_file_observations_and_state_owners() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");
    put(&path, "{}", 10_000_000_000);
    let policy = accepted(&path, None)
        .with_task_source("permissions: []", Format::Yaml)
        .unwrap();
    let changed = policy
        .reload_from_source_at(
            r#"{"hosts":{"owned.invalid":{"egress":"allow"}}}"#,
            Format::Json,
            0.0,
        )
        .unwrap();
    assert_eq!(times(&changed), times(&policy));
    assert_eq!(changed.baseline_path, policy.baseline_path);
    assert!(Arc::ptr_eq(&changed.budgets, &policy.budgets));
    assert!(Arc::ptr_eq(&changed.evaluations, &policy.evaluations));
    assert!(Arc::ptr_eq(
        &changed.task.as_ref().unwrap().baseline,
        &policy.task.as_ref().unwrap().baseline
    ));
    assert_eq!(times(&changed.without_task()), times(&policy));
    assert_eq!(
        times(
            &changed
                .with_task_source("permissions: []", Format::Yaml)
                .unwrap()
        ),
        times(&policy)
    );
}

#[test]
fn six_frozen_source_workflows_match_watch_decisions_and_retained_observations() {
    let source: Value =
        serde_json::from_str(include_str!("../../../tests/policy_watch_source.json")).unwrap();
    let selected = [
        "baseline_strict_float_mtime_and_invalid_retry",
        "addon_lifecycle_retains_absent_watermark",
        "raw_lists_all_strings_use_one_maximum",
        "addon_only_list_is_not_watched",
        "baseline_is_its_own_addon_sibling",
        "raw_list_scan_errors_prevent_reload",
    ];
    let mut rows = 0;
    let mut iterations = 0;
    for row in source["rows"].as_array().unwrap() {
        let input = &row["input"];
        let name = input["name"].as_str().unwrap();
        if !selected.contains(&name) {
            continue;
        }
        rows += 1;
        let directory = tempfile::tempdir().unwrap();
        let write = |files: &Value| {
            if let Some(files) = files.as_object() {
                for (relative, spec) in files {
                    let contents = spec["text"]
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| spec["document"].to_string());
                    put(
                        &directory.path().join(relative),
                        &contents,
                        i128::from(spec["mtime_ns"].as_i64().unwrap()),
                    );
                }
            }
        };
        write(&input["initial_files"]);
        let path = directory
            .path()
            .join(input["baseline_path"].as_str().unwrap_or("policy.yaml"));
        let mut policy = accepted(&path, None);
        let compare = |policy: &Policy, expected: &Value| {
            let actual = times(policy);
            let expected_times = &expected["watermarks"];
            assert_eq!(
                actual,
                (
                    expected_times["baseline"].as_f64().unwrap(),
                    expected_times["addons"].as_f64().unwrap(),
                    expected_times["lists"].as_f64().unwrap()
                ),
                "{name}"
            );
            let expected_policy = &expected["policy"];
            assert_eq!(
                policy.baseline_permissions_count().unwrap() as u64,
                expected_policy["permissions_count"].as_u64().unwrap(),
                "{name}"
            );
            // Borrow source-shaped fields from the canonical model. The watch
            // implementation never serializes policy/gateway/token projections.
            let canonical = &policy.baseline.as_ref().unwrap().value;
            assert_eq!(
                canonical["metadata"]["description"], expected_policy["description"],
                "{name}"
            );
            assert_eq!(canonical["required"], expected_policy["required"], "{name}");
        };
        compare(&policy, &row["initial"]["after"]);
        let inputs = input["iterations"].as_array().unwrap();
        let outputs = row["iterations"].as_array().unwrap();
        assert_eq!(inputs.len(), outputs.len());
        for (recipe, expected) in inputs.iter().zip(outputs) {
            iterations += 1;
            write(&recipe["write"]);
            if let Some(paths) = recipe["remove"].as_array() {
                for path in paths {
                    fs::remove_file(directory.path().join(path.as_str().unwrap())).unwrap();
                }
            }
            let changed = policy.baseline_files_changed();
            if let Err(error) = &changed {
                assert_eq!(name, "raw_list_scan_errors_prevent_reload");
                assert_eq!(error.kind, ErrorKind::Invalid);
                assert!(!expected["warnings"].as_array().unwrap().is_empty());
            }
            let mut loads = Vec::new();
            if changed.is_ok_and(|changed| changed) {
                let candidate = policy
                    .reload_from_path_at(&path, 0.0)
                    .and_then(|mut candidate| {
                        candidate.observe_baseline_files(Some(&policy))?;
                        Ok(candidate)
                    });
                loads.push(candidate.is_ok());
                if let Ok(candidate) = candidate {
                    policy = candidate;
                }
            }
            assert_eq!(
                json!(loads),
                expected["loads"],
                "{name}: {}",
                recipe["name"]
            );
            compare(&policy, &expected["after"]);
        }
    }
    assert_eq!((rows, iterations), (6, 28));
    // Source fault injection, audit effects/D65, and source partial publication
    // are separate runtime evidence; no native fault API or parity claim here.
}
