//! Consequences of source-declared worker settings in the existing policy
//! assessment. No proposed host path is opened and no worker is configured.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::host_agents::CONFIGURATION_FIELDS;

pub(crate) fn consequence(field: &str) -> Option<&'static str> {
    Some(match field {
        "agent_id" => {
            "This changes the durable worker identity. Same-name recreation does not inherit identity-bound grants; existing runtime and grant owners recheck identity."
        }
        "folder" => {
            "The worker receives this host directory as its writable /workspace on its next sandbox start. Contents can include real operator data. Saving policy does not create the directory or change a running mount."
        }
        "mounts" => {
            "These host directories become the selected guest paths with their declared read-only or writable access on the next sandbox start. Either mode discloses readable content; writable mounts permit changes. Target-accessible credentials, other worker homes and nested instances can extend reach."
        }
        "memory_mb" => {
            "This changes the sandbox memory allocation on its next start. It does not resize a running sandbox or establish task readiness."
        }
        "rootfs_overlay" => {
            "This changes guest root-filesystem storage on the next start. Persistence depends on the selected backend and overlay; persistent home and workspace are separate."
        }
        "nested_docker" => {
            "This changes guest mount and namespace administration for nested Docker on Linux. It grants no host root, new host mount or direct network route."
        }
        "dangerously_allow_unowned" => {
            "This changes the explicit exception to workspace ownership validation. The selected directory remains real host data; sandbox isolation does not make destructive writes harmless."
        }
        "launcher" => {
            "The host lifecycle owner uses this launcher when starting the worker. Built-in launchers and an explicitly selected host script have different effects. An omitted launcher uses the instance's current default, which is outside the policy snapshot."
        }
        "host_script" => {
            "This selects an operator-owned host setup script. Saving policy does not execute it or stage its output. The existing explicit setup owner validates the script and performs any separately authorized host effects."
        }
        "user_default_args" => {
            "These are default guest command arguments used by the existing launch owner. They are not an arbitrary host-shell operation. Explicit per-launch arguments can select a different guest command."
        }
        "lifecycle" => {
            "This selects automatic activation, intentional dormancy, optional checked self-stop and mandatory stop boundaries for this worker. The running host consumes adopted lifecycle configuration without another routine prompt. A current run retains its captured cutoff; saving a later schedule does not extend that run. Pausing disables future scheduled activation. The host retains identity, Work, home and workspace after stopping; no host commands, other-worker control or additional credentials are granted."
        }
        "network_slot" | "tailnet_port" => {
            "This changes a saved network or preview address allocation. Existing runtime owners validate the selected allocation and access; the value grants no additional network, credential or preview permission."
        }
        _ => return None,
    })
}

fn settings(value: &Value) -> Map<String, Value> {
    CONFIGURATION_FIELDS
        .iter()
        .filter_map(|field| {
            value
                .get(*field)
                .map(|value| ((*field).into(), value.clone()))
        })
        .collect()
}

fn mounts(value: &Value) -> Vec<Value> {
    let Some(specifications) = value.as_array() else {
        return if value.is_null() {
            Vec::new()
        } else {
            vec![json!({"declared":value,"status":"invalid mount list"})]
        };
    };
    specifications
        .iter()
        .map(|spec| {
            let Some(spec) = spec.as_str() else {
                return json!({"declared":spec,"status":"invalid mount syntax"});
            };
            match crate::host_boot::mount_destination(spec) {
                Ok(guest) => json!({"host_path":spec.split(':').next(),"guest_path":guest,
                    "access":if spec.ends_with(":ro"){"read_only"}else{"read_write"}}),
                Err(_) => json!({"declared":spec,"status":"invalid mount syntax"}),
            }
        })
        .collect()
}

pub(crate) fn changes(before: &Value, after: &Value) -> Vec<Value> {
    let names: BTreeSet<_> = [&before["agents"], &after["agents"]]
        .into_iter()
        .flat_map(|agents| {
            agents
                .as_object()
                .into_iter()
                .flat_map(|agents| agents.keys())
        })
        .collect();
    names
        .into_iter()
        .filter_map(|name| {
            let old = settings(&before["agents"][name]);
            let new = settings(&after["agents"][name]);
            if old == new {
                return None;
            }
            let effects: Vec<_> = CONFIGURATION_FIELDS
                .iter()
                .filter(|field| old.get(**field) != new.get(**field))
                .map(|field| json!({"field":field,"before":old.get(*field),"after":new.get(*field),
                    "consequence":consequence(field)}))
                .collect();
            Some(json!({"name":name,"operation":if old.is_empty(){"create"}else if new.is_empty(){"remove"}else{"configure"},
                "before":old,"after":new,"effects":effects,
                "workspace":{"before":before["agents"][name]["folder"],"after":after["agents"][name]["folder"],
                    "guest_path":"/workspace","access":"read_write when configured"},
                "mounts":{"before":mounts(&before["agents"][name]["mounts"]),"after":mounts(&after["agents"][name]["mounts"])},
                "lifetime":"Saved configuration persists until changed or removed. Saving does not prepare the guest home or prove a sandbox effect. Sandbox mounts, resources and launch settings take effect on a later authorized start. Adopted lifecycle settings can schedule starts and stops through the running host owner; a current run retains its captured cutoff. Changed identities or policy permissions can affect current authority immediately through their existing owners.",
                "custody":"Creating or configuring a worker gives its proposer no guest administration, approval authority, credential-store access or implicit control of that worker. Explicit support, disclosure, service and approval grants retain their own scopes and lifetimes.",
                "limitations":"This is the source-declared configuration, not filesystem inspection or installed readiness. Paths, contents, host launcher defaults, scripts, active runs and prepared guest inputs are not inspected. Existing setup/start owners validate actual host inputs. Review the accompanying authority and service reports for modeled transitive reach; mounted content can convey additional access."}))
        })
        .collect()
}
