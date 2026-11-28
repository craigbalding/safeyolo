//! Read-only projections of installed parsers. Validation grants no authority.
use crate::Error;
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Definition {
    Controls,
    SupportGrant,
    Delegation,
    SupportOperation,
    DesktopPresent,
    WebPublish,
    EvidenceReads,
    ServiceEffects,
    ServiceDefinition,
    HostExecutionPackage,
    HostExecutionBinding,
}

impl Definition {
    const ALL: [Self; 11] = [
        Self::Controls,
        Self::SupportGrant,
        Self::Delegation,
        Self::SupportOperation,
        Self::DesktopPresent,
        Self::WebPublish,
        Self::EvidenceReads,
        Self::ServiceEffects,
        Self::ServiceDefinition,
        Self::HostExecutionPackage,
        Self::HostExecutionBinding,
    ];

    fn schema(self) -> Value {
        match self {
            Self::Controls => json!(schema_for!(super::native::Controls)),
            Self::SupportGrant => json!(schema_for!(super::support::Grant)),
            Self::Delegation => json!(schema_for!(super::delegation::Delegation)),
            Self::SupportOperation => json!(schema_for!(crate::peer_support::operations::Action)),
            Self::DesktopPresent => json!(schema_for!(crate::desktop_present::Parameters)),
            Self::WebPublish => json!(schema_for!(crate::desktop_present::web::Parameters)),
            Self::EvidenceReads => {
                let item = json!(schema_for!(super::evidence::EvidenceRead));
                let mut schema = json!(schema_for!(Vec<super::evidence::EvidenceRead>));
                for key in [
                    "x-scope",
                    "x-lifetime",
                    "x-effects",
                    "x-dependencies",
                    "x-gaps",
                ] {
                    schema[key] = item[key].clone();
                }
                schema
            }
            Self::ServiceEffects => json!(schema_for!(crate::services::effects::EffectModel)),
            // This owner parses a dynamic document. Do not invent a second schema.
            Self::ServiceDefinition => crate::services::ServiceDefinition::capability_schema(),
            Self::HostExecutionPackage => json!(schema_for!(crate::host_execution::Package)),
            Self::HostExecutionBinding => {
                json!(schema_for!(crate::host_execution::gateway::Binding))
            }
        }
    }

    fn owner(self) -> &'static str {
        match self {
            Self::Controls => "policy::native::Controls::validate",
            Self::SupportGrant => "policy::support::Grant::validate",
            Self::Delegation => "policy::delegation::Delegation::valid",
            Self::SupportOperation => "peer_support::operations::Action",
            Self::DesktopPresent => "desktop_present::Parameters::validate",
            Self::WebPublish => "desktop_present::web::Parameters::validate",
            Self::EvidenceReads => "policy::evidence::validate_reads",
            Self::ServiceEffects => "services::effects::EffectModel",
            Self::ServiceDefinition => "services::ServiceDefinition::from_value",
            Self::HostExecutionPackage => "host_execution::Package::validate",
            Self::HostExecutionBinding => "host_execution::gateway::Binding::validate",
        }
    }

    fn human_name(self) -> &'static str {
        match self {
            Self::Controls => "Policy controls",
            Self::SupportGrant => "Peer support grants",
            Self::Delegation => "Delegated approvals",
            Self::SupportOperation => "Peer support operations",
            Self::DesktopPresent => "Guest desktop presentation",
            Self::WebPublish => "Guest web publication",
            Self::EvidenceReads => "Diagnostic and approval evidence reads",
            Self::ServiceEffects => "Service effect descriptions",
            Self::ServiceDefinition => "Service definitions",
            Self::HostExecutionPackage => "Host execution packages (authored target operations)",
            Self::HostExecutionBinding => {
                "Host execution bindings (service access to a native target)"
            }
        }
    }

    fn description(self) -> Value {
        let schema = self.schema();
        json!({"definition":self,"owner":self.owner(),"supported":true,"scope":schema["x-scope"],"lifetime":schema["x-lifetime"],
            "declared_effects":schema["x-effects"],"dependencies":schema["x-dependencies"],"gaps":[schema["x-gaps"]],"schema":schema,
            "validator":{"tool":"validate_policy_capability","definition":self},
            "permission":{"observation":"undisclosed","granted":null,"requestable":null,"prohibited":null},
            "readiness":{"observation":"unknown","unavailable":null}})
    }
}

pub fn discover() -> Value {
    json!({"definition_version":env!("SAFEYOLO_DEFINITION_VERSION"),
        "build_revision":env!("SAFEYOLO_BUILD_REVISION"),"build_profile":env!("SAFEYOLO_BUILD_PROFILE"),
        "observation":"installed_definitions","definitions":Definition::ALL.map(Definition::description),
        "operation_definitions":crate::coord_tools::tools(),
        "operation_owner":{"definition":"coord_tools::tools","implementation":"coord_tools::Client::call","validator":"coord_tools::validate_arguments; current native Agent API operation owner"},
        "limits":["Definition schemas describe accepted types, not permission or complete candidate safety.",
            "Dynamic host rules, policy checks and full-policy disclosure have no complete generated schema here; use their existing policy compiler and read owners.",
            "Current instance observations require observe=true and the existing caller-specific disclosure authority.",
            "Reading or replaying this result performs no protected operation. Actual submissions revalidate through their current owners."]})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub definition: Definition,
    pub value: Value,
    pub definition_version: String,
}

pub fn validate(input: Candidate) -> Result<Value, Error> {
    if input.definition_version != env!("SAFEYOLO_DEFINITION_VERSION") {
        return Err("definition version changed; discover current installed definitions".into());
    }
    let mut effects = Value::Null;
    match input.definition {
        Definition::Controls => {
            serde_json::from_value::<super::native::Controls>(input.value)?.validate()?
        }
        Definition::SupportGrant => {
            serde_json::from_value::<super::support::Grant>(input.value)?.validate()?
        }
        Definition::Delegation => {
            let value: super::delegation::Delegation = serde_json::from_value(input.value)?;
            value.valid()?;
            effects = json!(value.warnings());
        }
        Definition::SupportOperation => {
            serde_json::from_value::<crate::peer_support::operations::Action>(input.value)?
                .validate()?;
        }
        Definition::DesktopPresent => {
            serde_json::from_value::<crate::desktop_present::Parameters>(input.value)?.validate()?
        }
        Definition::WebPublish => {
            serde_json::from_value::<crate::desktop_present::web::Parameters>(input.value)?
                .validate()?
        }
        Definition::EvidenceReads => super::evidence::validate_reads(Some(&input.value))?,
        Definition::ServiceEffects => {
            let _: crate::services::effects::EffectModel = serde_json::from_value(input.value)?;
        }
        Definition::ServiceDefinition => {
            crate::services::ServiceDefinition::from_value(input.value)?;
        }
        Definition::HostExecutionPackage => {
            serde_json::from_value::<crate::host_execution::Package>(input.value)?.validate()?;
        }
        Definition::HostExecutionBinding => {
            serde_json::from_value::<crate::host_execution::gateway::Binding>(input.value)?
                .validate()?;
        }
    }
    Ok(
        json!({"valid":true,"definition":input.definition,"owner":input.definition.owner(),
        "definition_version":env!("SAFEYOLO_DEFINITION_VERSION"),"declared_effects":effects,
        "assessment":"not_performed","authorized":false,"activated":false,
        "limits":"Accepted component form only. Full policy compilation, identity/reference checks, candidate assessment, operator selection and current execution checks remain with the existing owners."}),
    )
}

pub fn print(json_output: bool) -> Result<(), Error> {
    let value = discover();
    if json_output {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!(
            "Installed policy definitions {}\nBuild {} ({})",
            value["definition_version"]
                .as_str()
                .expect("definition version"),
            value["build_revision"].as_str().expect("build revision"),
            value["build_profile"].as_str().expect("build profile")
        );
        for (kind, definition) in Definition::ALL
            .into_iter()
            .zip(value["definitions"].as_array().expect("definitions"))
        {
            println!("\n{}", kind.human_name());
            for (label, field) in [
                ("Scope", "scope"),
                ("Lifetime", "lifetime"),
                ("Effects", "declared_effects"),
                ("Dependencies", "dependencies"),
                ("Coverage limits", "gaps"),
            ] {
                println!("  {label}: {}", human_metadata(&definition[field]));
            }
        }
        println!(
            "\nDefinitions describe accepted input, not permission or complete safety. Missing descriptions do not imply unrestricted scope or complete coverage. Reading or validating a definition grants no access and performs no protected operation.\nInstance permission and readiness: unknown. Use the installed agent discovery tool with observe=true for authorized current observations. Use --json for the types and validator references."
        );
    }
    Ok(())
}

fn human_metadata(value: &Value) -> String {
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .map(human_metadata)
            .collect::<Vec<_>>()
            .join("; "),
        _ => String::new(),
    };
    if text.is_empty() {
        "Not described by this installed definition.".into()
    } else {
        text.replace("Delegation::warnings", "the delegation validator")
            .replace(
                "ServiceDefinition::from_value",
                "The service definition parser",
            )
    }
}
