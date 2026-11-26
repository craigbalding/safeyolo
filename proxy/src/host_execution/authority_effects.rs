//! Project concrete native permissions into the existing effect evaluator.
//! Program annotations and agent intent cannot remove this authority view.
use super::*;
use crate::services::effects::{self, assessment::Permission};

pub(super) fn assess(package: &Package, permissions: &[Permission]) -> Result<Value, Error> {
    let definitions = [
        ("execute", "Run the selected program with the represented target-account authority.", false),
        ("read_files", "Read the selected files, including writable paths. Output can disclose their contents.", true),
        ("write_files", "Change selected files. Changes can remain after authority ends.", true),
        ("connect", "Send data through the permitted outbound network direction.", true),
        ("listen", "Receive requests and send responses through the permitted listener direction or inherited listener.", true),
        ("ipc", "Use the represented local IPC or delegated service channel. Its downstream effects need separate understanding.", true),
        ("children", "Create child processes within the selected process and lifetime bounds, including explicit broader exceptions.", false),
    ].into_iter().map(|(name, description, persists)| (name, json!({
        "description":description,"persists_after_access":persists,"evidence":["native"]
    }))).collect::<BTreeMap<_,_>>();
    let mut represented = std::collections::BTreeSet::new();
    let operations = package.operations.iter().map(|(id, operation)| {
        let e = &operation.execution;
        let filesystem_broader = e.broader.contains(&BroaderBound::Filesystem);
        let effects = [
            ("execute", true),
            ("read_files", filesystem_broader || !e.filesystem.read.is_empty() || !e.filesystem.write.is_empty()),
            ("write_files", filesystem_broader || !e.filesystem.write.is_empty()),
            ("connect", !e.network.destinations.is_empty()),
            ("listen", !e.network.listeners.is_empty() || e.network.listener_handoff.is_some()),
            ("ipc", !e.network.ipc.is_empty() || !e.delegated_services.is_empty()),
            ("children", e.resources.processes > 1),
        ].into_iter().filter(|(_, present)| *present).map(|(effect, _)| {
            represented.insert(effect);
            json!({
            "effect":effect,"resource":"account","when":{"kind":"always"},"evidence":["native"]
        })}).collect::<Vec<_>>();
        Ok((id.clone(), json!({
            "method":"POST","path":format!("/operations/{id}"),"coverage":"modeled",
            "arguments":{"native:target":{"location":"body","field":"native:target","required":true,"omission":{"kind":"invalid"},"evidence":["native"]}},
            "resources":{"account":{"target":{"kind":"argument","argument":"native:target"},"principal":{"kind":"fixed","value":e.identity.principal}}},
            "effects":effects,
            "execution_authority":format!(
                "Operation execution ceiling: {}. Executable: {}. Read paths: {}. Write paths: {}. Network selectors: {}. Broader exceptions: {}. Process/resource bounds: {}. Delegated services: {}.",
                serde_json::to_string(&e.identity)?, e.executable, serde_json::to_string(&e.filesystem.read)?,
                serde_json::to_string(&e.filesystem.write)?, serde_json::to_string(&e.network)?,
                serde_json::to_string(&e.broader)?, serde_json::to_string(&e.resources)?,
                serde_json::to_string(&e.delegated_services)?),
            "evidence":["native"],
            "gaps":[
                "These are potential consequences of native authority, not a claim that the selected program performs them. Arbitrary program behavior and ambient dependencies remain uncharacterised.",
                "The enclosing target assessment supplies effective grants, narrower budgets and validity. Operation ceilings do not replace those constraints.",
                "Selectors are not an enforcement guarantee. Use the selected target's native qualification and recorded enforcement report; broader modes can reach beyond declared addresses or ports. Current enforcement and reach remain unobserved.",
                "File changes and disclosures can persist. Grant expiry or revocation does not undo them; explicit target deadlines and cancellation govern admitted jobs."
            ]
        })))
    }).collect::<Result<BTreeMap<_,_>, Error>>()?;
    let rules = [
        ("file_disclosure_outbound", vec!["read_files", "connect"], "Selected code may send readable task data through permitted outbound connections."),
        ("file_disclosure_listener", vec!["read_files", "listen"], "Selected code may expose readable task data or functions to clients of a permitted listener."),
        ("changed_task_execution", vec!["write_files", "execute"], "Written task files may change current or later code, configuration and results under this account's authority."),
    ].into_iter().filter(|(_, effects, _)| effects.iter().all(|effect| represented.contains(effect)))
    .map(|(name, effects, consequence)| (name, json!({
        "when":{"kind":"all_effects_same_scope","resource":"account","effects":effects},
        "prerequisites":["The selected program uses these permissions together; actual code/data dependencies and application behavior remain unverified."],
        "consequence":consequence,
        "explanation":"Combine the native authority of operations on the same target and execution account. This is potential exposure, not a risk ranking or an execution decision.",
        "evidence":["native"],"gaps":["No application behavior, authentication, forwarding, persistence mechanism or audience reach is inferred."]
    }))).collect::<BTreeMap<_,_>>();
    let model = json!({
        "sources":{"native":{"location":"SafeYolo native execution definitions and target-owned authority","version":"1"}},
        "resources":{"account":{"description":"Selected target execution account","identity":["target","principal"]}},
        "effects":definitions,"operations":operations,"enforcement":{},"rules":rules,
        "alternatives":{},"regressions":[],"gaps":[]
    });
    let model_revision = revision(&model);
    let service = ServiceDefinition::from_value(json!({
        "schema_version":1,"name":format!("{}:native-authority",package.name),
        "default_host":"","capabilities":{},"effect_model":model
    }))?;
    let model: &effects::EffectModel = service.effect_model.as_ref().unwrap();
    Ok(json!({"model_revision":model_revision,"model":model.assess(&service,permissions)?}))
}
