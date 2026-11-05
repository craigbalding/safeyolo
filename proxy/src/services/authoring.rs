//! Offline generation from a maintained, flat OpenAPI document and reviewed
//! `x-safeyolo` annotations. No network or inference occurs here.

use serde_json::{Map, Value, json};

use super::ServiceDefinition;
use crate::Error;

const METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
];

pub fn generate(source: &str) -> Result<Value, Error> {
    let spec = crate::policy::parse_yaml(source)?;
    if !spec["openapi"]
        .as_str()
        .is_some_and(|version| version.starts_with("3.0.") || version.starts_with("3.1."))
    {
        return Err("Authoring requires a flat OpenAPI 3.0 or 3.1 document".into());
    }
    reject_unresolved_schema(&spec)?;
    if spec.get("webhooks").is_some() {
        return Err("Authoring inventories paths only; supply webhook semantics separately".into());
    }
    let mut service = spec["x-safeyolo-service"]
        .as_object()
        .ok_or("OpenAPI needs reviewed x-safeyolo-service annotations")?
        .clone();
    let mut operations = Map::new();
    for (path, item) in spec["paths"]
        .as_object()
        .ok_or("OpenAPI paths must be a mapping")?
    {
        for method in METHODS {
            let Some(operation) = item.get(*method) else {
                continue;
            };
            if operation.get("callbacks").is_some() {
                return Err("Authoring does not inventory callback operations; supply a flat paths inventory".into());
            }
            let name = operation["operationId"]
                .as_str()
                .filter(|name| !name.is_empty())
                .ok_or("Every supplied operation needs a stable operationId")?;
            let evidence = operation["x-safeyolo"]["evidence"]
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![json!("spec")]);
            let mut model = if let Some(annotation) = operation.get("x-safeyolo") {
                annotation
                    .as_object()
                    .ok_or("x-safeyolo must be a mapping")?
                    .clone()
            } else {
                json!({
                    "coverage": "uncharacterised", "resources": {}, "effects": [],
                    "execution_authority": "Uncharacterised", "evidence": evidence,
                    "gaps": ["Supplied operation has no reviewed effect semantics"]
                })
                .as_object()
                .unwrap()
                .clone()
            };
            for key in ["method", "path"] {
                if model.contains_key(key) {
                    return Err(format!("{name}: {key} comes from OpenAPI, not annotations").into());
                }
            }
            let argument_notes = model.remove("arguments").unwrap_or_else(|| json!({}));
            let arguments = arguments(item, operation, &argument_notes, &evidence)?;
            model.insert("method".into(), json!(method.to_uppercase()));
            model.insert("path".into(), json!(path));
            model.insert("arguments".into(), Value::Object(arguments));
            if operations
                .insert(name.into(), Value::Object(model))
                .is_some()
            {
                return Err(format!("Duplicate operationId: {name}").into());
            }
        }
        for key in item
            .as_object()
            .ok_or("OpenAPI path item must be a mapping")?
            .keys()
        {
            if !METHODS.contains(&key.as_str())
                && !["parameters", "summary", "description", "servers"].contains(&key.as_str())
                && !key.starts_with("x-")
            {
                return Err(format!("Unsupported OpenAPI path item: {key}").into());
            }
        }
    }
    let model = service
        .get_mut("effect_model")
        .and_then(Value::as_object_mut)
        .ok_or("Service annotations need effect_model")?;
    if model
        .insert("operations".into(), Value::Object(operations.clone()))
        .is_some()
    {
        return Err("Effect operation inventory comes from OpenAPI".into());
    }
    // Current contract operations share stable OpenAPI operation references.
    // Generate their methods and paths rather than maintaining duplicate routes.
    if let Some(capabilities) = service
        .get_mut("capabilities")
        .and_then(Value::as_object_mut)
    {
        for capability in capabilities.values_mut() {
            if let Some(contract_ops) = capability
                .pointer_mut("/contract/operations")
                .and_then(Value::as_array_mut)
            {
                for contract_op in contract_ops {
                    let name = contract_op["name"]
                        .as_str()
                        .ok_or("Contract operation needs a name")?;
                    let modeled = operations
                        .get(name)
                        .ok_or_else(|| format!("Unknown contract operation: {name}"))?;
                    let request = contract_op
                        .get_mut("request")
                        .and_then(Value::as_object_mut)
                        .ok_or("Contract operation needs request constraints")?;
                    if request.contains_key("method") || request.contains_key("path") {
                        return Err("Generated contract methods/paths come from OpenAPI".into());
                    }
                    request.insert("method".into(), modeled["method"].clone());
                    request.insert("path".into(), modeled["path"].clone());
                }
            }
        }
    }
    let generated = Value::Object(service);
    ServiceDefinition::from_value(generated.clone())?;
    Ok(generated)
}

fn reject_unresolved_schema(value: &Value) -> Result<(), Error> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if ["$ref", "allOf", "oneOf", "anyOf"].contains(&key.as_str()) {
                    return Err(format!(
                        "Authoring does not resolve {key}; supply a reviewed flat specification"
                    )
                    .into());
                }
                reject_unresolved_schema(value)?;
            }
        }
        Value::Array(items) => {
            for value in items {
                reject_unresolved_schema(value)?;
            }
        }
        _ => (),
    }
    Ok(())
}

fn list(value: Option<&Value>) -> Result<&[Value], Error> {
    match value {
        None => Ok(&[]),
        Some(Value::Array(values)) => Ok(values),
        _ => Err("OpenAPI list field must be a list".into()),
    }
}

fn arguments(
    item: &Value,
    operation: &Value,
    notes: &Value,
    evidence: &[Value],
) -> Result<Map<String, Value>, Error> {
    let notes = notes
        .as_object()
        .ok_or("Argument annotations must be a mapping")?;
    let mut inputs = Map::new();
    for parameter in list(item.get("parameters"))?
        .iter()
        .chain(list(operation.get("parameters"))?)
    {
        let location = parameter["in"].as_str().ok_or("Parameter needs in")?;
        if !["path", "query"].contains(&location) {
            return Err(
                "Authoring currently supports path/query parameters and flat JSON bodies".into(),
            );
        }
        let name = parameter["name"].as_str().ok_or("Parameter needs name")?;
        if parameter.get("content").is_some() || !parameter["schema"].is_object() {
            return Err(
                "Authoring parameters need an explicit schema, not content encoding".into(),
            );
        }
        let key = format!("{location}.{name}");
        let required = parameter["required"].as_bool().unwrap_or(false);
        if location == "path" && !required {
            return Err("OpenAPI path parameter must be required".into());
        }
        inputs.insert(
            key.clone(),
            argument(
                location,
                name,
                required,
                &parameter["schema"],
                notes.get(&key),
                evidence,
            )?,
        );
    }
    if let Some(body) = operation.get("requestBody") {
        let content = body["content"]
            .as_object()
            .ok_or("Request body needs content")?;
        if content.len() != 1 || !content.contains_key("application/json") {
            return Err("Authoring currently supports application/json request bodies only".into());
        }
        let schema = &content["application/json"]["schema"];
        if schema["type"] != "object" {
            return Err("Authoring requires a flat JSON object body".into());
        }
        let required = list(schema.get("required"))?;
        if !required.is_empty() && body["required"].as_bool() != Some(true) {
            return Err("Optional bodies with required properties need body-presence semantics; this generator does not represent that condition".into());
        }
        for (name, field) in schema["properties"]
            .as_object()
            .ok_or("JSON body needs properties")?
        {
            let key = format!("body.{name}");
            inputs.insert(
                key.clone(),
                argument(
                    "body",
                    name,
                    required.contains(&json!(name)),
                    field,
                    notes.get(&key),
                    evidence,
                )?,
            );
        }
    }
    if notes.keys().any(|key| !inputs.contains_key(key)) {
        return Err("Argument annotation refers to an unknown OpenAPI argument".into());
    }
    Ok(inputs)
}

fn argument(
    location: &str,
    name: &str,
    required: bool,
    schema: &Value,
    note: Option<&Value>,
    evidence: &[Value],
) -> Result<Value, Error> {
    let omission = if let Some(default) = schema.get("default") {
        json!({"kind":"default", "value":default})
    } else if required {
        json!({"kind":"invalid"})
    } else {
        json!({"kind":"unresolved", "reason":"No omission semantics supplied"})
    };
    let mut argument = json!({"location":location, "field":name, "required":required, "omission":omission, "evidence":evidence});
    if let Some(note) = note {
        for (key, value) in note
            .as_object()
            .ok_or("Argument annotation must be a mapping")?
        {
            if !["omission", "evidence"].contains(&key.as_str()) {
                return Err(format!("Argument {key} comes from OpenAPI").into());
            }
            if key == "omission"
                && (required || schema.get("default").is_some())
                && value != &argument[key]
            {
                return Err(
                    "Argument annotation contradicts a specification requirement/default".into(),
                );
            }
            argument[key] = value.clone();
        }
    }
    Ok(argument)
}
