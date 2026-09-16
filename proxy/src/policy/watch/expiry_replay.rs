//! Finite replay of ordinary source disk effects; injected failures stay separate.
use super::*;
use crate::policy::{Action, PolicyLoadStage, RuleEffect, parse_expiry};
use serde_json::json;
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, time::UNIX_EPOCH};

fn touch(path: &Path, nanoseconds: u64) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(
            fs::FileTimes::new()
                .set_modified(UNIX_EPOCH + std::time::Duration::from_nanos(nanoseconds)),
        )
        .unwrap();
}

fn nanoseconds(metadata: &fs::Metadata) -> i128 {
    i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec())
}

fn simple(policy: &Policy) -> BTreeMap<String, Vec<String>> {
    let mut groups = BTreeMap::<String, Vec<String>>::new();
    for rule in policy.rules.iter().filter(|rule| rule.simple()) {
        assert_eq!(rule.action, Action::Network);
        let effect = match rule.effect {
            RuleEffect::Allow => "allow",
            RuleEffect::Deny => "deny",
            RuleEffect::Prompt => "prompt",
            RuleEffect::Budget(_) => unreachable!("simple rule cannot have a budget"),
        };
        groups
            .entry(effect.into())
            .or_default()
            .push(rule.resource.clone());
    }
    for values in groups.values_mut() {
        values.sort();
        values.dedup();
    }
    groups
}

#[test]
fn seven_source_workflows_match_disk_effects_loads_and_accepted_policy() {
    let corpus: Value =
        serde_json::from_str(include_str!("../../../tests/policy_expiry_source.json")).unwrap();
    let selected = [
        "mixed_toml_expiry_and_comments",
        "no_expired_entry_no_write",
        "prune_precedes_compile_rejection",
        "yaml_prunes_without_disk_write",
        "json_prunes_without_disk_write",
        "configured_symlink_is_replaced",
        "watcher_time_alone_does_not_prune",
    ];
    let mut counts = (0, 0);
    for row in corpus["rows"].as_array().unwrap() {
        let input = &row["input"];
        let name = input["name"].as_str().unwrap();
        if !selected.contains(&name) {
            continue;
        }
        counts.0 += 1;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(input["filename"].as_str().unwrap());
        let linked = input["symlink"].as_bool().unwrap_or(false);
        let target = if linked {
            directory.path().join("target.toml")
        } else {
            path.clone()
        };
        fs::write(&target, input["text"].as_str().unwrap()).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        touch(&target, input["mtime_ns"].as_u64().unwrap());
        if linked {
            std::os::unix::fs::symlink(&target, &path).unwrap();
        }
        let mut policy: Option<Policy> = None;
        let mut saved_times = BTreeMap::<String, (i128, f64)>::new();
        let recipes = input["steps"].as_array().unwrap();
        let observations = row["steps"].as_array().unwrap();
        assert_eq!(recipes.len(), observations.len());
        for (recipe, expected) in recipes.iter().zip(observations) {
            counts.1 += 1;
            if let Some(source) = recipe["write"].as_str() {
                fs::write(&path, source).unwrap();
                touch(&path, recipe["mtime_ns"].as_u64().unwrap());
            }
            if let Some(time) = recipe["touch_ns"].as_u64() {
                touch(&path, time);
            }
            let before = fs::metadata(&path).unwrap();
            let now = recipe["now"]
                .as_str()
                .unwrap_or(input["now"].as_str().unwrap());
            let now = parse_expiry(now).unwrap().unix_timestamp_nanos() as f64 / 1_000_000.0;
            let mut loads = Vec::new();
            let should_load = recipe["operation"] == "load"
                || policy.as_ref().unwrap().baseline_files_changed().unwrap();
            if should_load {
                let result = match &policy {
                    Some(previous) => previous.reload_baseline_at(&path, None, now, true),
                    None => Policy::load_baseline_at(&path, None, now, true),
                };
                loads.push(result.is_ok());
                match result {
                    Ok(mut candidate) => {
                        candidate.observe_baseline_files(policy.as_ref()).unwrap();
                        policy = Some(candidate);
                    }
                    Err(error) => {
                        assert_eq!(name, "prune_precedes_compile_rejection");
                        assert_eq!(error.stage, PolicyLoadStage::Prepare);
                    }
                }
            }
            assert_eq!(json!(loads), expected["loads"], "{name}");
            let after = fs::metadata(&path).unwrap();
            let replaced = before.ino() != after.ino();
            assert_eq!(json!(replaced), expected["inode_replaced"], "{name}");
            let disk = &expected["after_disk"];
            let after_ns = nanoseconds(&after);
            if expected["before_disk"]["mtime_ns"] != disk["mtime_ns"] {
                assert_ne!(nanoseconds(&before), after_ns, "{name}");
            }
            if replaced {
                let label = disk["mtime_ns"].as_str().unwrap();
                assert!(
                    saved_times
                        .insert(label.into(), (after_ns, mtime(&after)))
                        .is_none()
                );
            }
            let expected_ns = disk["mtime_ns"].as_str().map_or_else(
                || i128::from(disk["mtime_ns"].as_u64().unwrap()),
                |label| saved_times[label].0,
            );
            assert_eq!(after_ns, expected_ns, "{name}");
            let saved = fs::read_to_string(&path).unwrap();
            let source_saved = disk["text"].as_str().unwrap();
            if name == "mixed_toml_expiry_and_comments" {
                // A deterministic formatter difference, not normalized
                // nondeterminism: tomlkit drops this retained date's space.
                // Native keeps the exact authored line. Every other byte must
                // still match this source save.
                let source_line = "\"date.invalid\" = { egress = \"deny\", expires = 2020-01-01}\n";
                let authored_line =
                    "\"date.invalid\" = { egress = \"deny\", expires = 2020-01-01 }\n";
                assert!(input["text"].as_str().unwrap().contains(authored_line));
                assert_eq!(source_saved.matches(source_line).count(), 1);
                assert_eq!(saved, source_saved.replacen(source_line, authored_line, 1));
            } else {
                assert_eq!(saved, source_saved, "{name}");
            }
            assert_eq!(
                format!("0o{:o}", after.permissions().mode() & 0o777),
                disk["mode"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                json!(
                    fs::symlink_metadata(&path)
                        .unwrap()
                        .file_type()
                        .is_symlink()
                ),
                disk["is_symlink"],
                "{name}"
            );
            if linked {
                assert_eq!(
                    fs::read_to_string(&target).unwrap(),
                    expected["target_disk"]["text"].as_str().unwrap()
                );
                assert_eq!(
                    fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                    0o640
                );
                assert_eq!(
                    nanoseconds(&fs::metadata(&target).unwrap()),
                    i128::from(expected["target_disk"]["mtime_ns"].as_u64().unwrap())
                );
            }
            let mut remaining: Vec<_> = fs::read_dir(directory.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            remaining.sort();
            assert_eq!(json!(remaining), expected["remaining_files"], "{name}");
            let policy = policy.as_ref().unwrap();
            let observed = &expected["policy"];
            let times = policy.file_times.unwrap();
            let baseline_time = &observed["watermarks"]["baseline"];
            assert_eq!(
                times.baseline,
                baseline_time.as_str().map_or_else(
                    || baseline_time.as_f64().unwrap(),
                    |label| saved_times[label].1
                ),
                "{name}"
            );
            assert_eq!(
                times.addons,
                observed["watermarks"]["addons"].as_f64().unwrap()
            );
            assert_eq!(
                times.lists,
                observed["watermarks"]["lists"].as_f64().unwrap()
            );
            assert_eq!(
                policy.baseline.as_ref().unwrap().value["metadata"]["description"],
                observed["description"],
                "{name}"
            );
            assert_eq!(
                policy.baseline_permissions_count().unwrap(),
                observed["permissions"].as_array().unwrap().len(),
                "{name}"
            );
            let source_simple: BTreeMap<String, Vec<String>> = observed["simple"]
                .as_array()
                .unwrap()
                .iter()
                .map(|group| {
                    assert_eq!(group["action"], "network:request");
                    (
                        group["effect"].as_str().unwrap().into(),
                        group["resources"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|resource| resource.as_str().unwrap().into())
                            .collect(),
                    )
                })
                .collect();
            assert_eq!(simple(policy), source_simple, "{name}");
        }
    }
    assert_eq!(counts, (7, 12));
    // Agent expiry is D15; source move/fsync seams are not native fault APIs.
    // Runtime controls own canonical events and authenticated publication.
}
