//! A single authenticated stats response binds aggregates to their NSM owner.

use super::*;

const SCOPE: &str = "current_runtime_aggregate";

pub(super) async fn run(args: &[String]) -> Result<(), Error> {
    // These aggregates have no agent, request, connection or retained-file filter.
    let mut instance = None;
    let mut runtime = None;
    let mut details = false;
    let mut json_output = crate::operator_output::json_requested();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json_output = true,
            "--details" => details = true,
            "--instance" | "--runtime" => {
                let value = args.next().ok_or("namespace option requires an ID")?;
                if arg == "--instance" {
                    instance = Some(value.as_str());
                } else {
                    runtime = Some(value.as_str());
                }
            }
            _ => return Err("usage: observations [--instance ID] [--runtime ID] [--details] [--json]; measurements cover the whole runtime".into()),
        }
    }
    let config_path = host_platform::config_path();
    let config = native_config::read(&config_path)
        .map_err(|_| "observation configuration unavailable or invalid")?;
    let selected = crate::command_centre::Host::from_config(&config)?
        .ok_or("selected installation identity unavailable")?
        .instance_id()
        .map_err(|_| "selected installation identity unavailable or invalid")?;
    let stats = native_client::admin(
        &config_path,
        "/stats",
        Method::GET,
        Value::Null,
        Duration::from_secs(5),
    )
    .await
    // Do not echo arbitrary API error bodies, configuration values or tokens.
    .map_err(|_| "observation report unavailable; check the selected instance's Admin API and operator token")?;
    let mut report = report(&stats, &selected, instance, runtime)?;
    report["source"]["config"] = json!(config_path);
    if json_output {
        println!("{}", context_json(&report)?);
        Ok(())
    } else {
        show(&report, details)
    }
}

fn report(
    stats: &Value,
    selected: &str,
    instance: Option<&str>,
    runtime: Option<&str>,
) -> Result<Value, Error> {
    let source = &stats["observation_source"];
    let instance_id = source["instance_id"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or("observation instance identity unavailable")?;
    let runtime_id = source["runtime_id"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or("observation runtime identity unavailable")?;
    if instance_id != selected {
        return Err("observation instance does not match the selected installation; check its config and readiness".into());
    }
    if instance.is_some_and(|expected| expected != instance_id) {
        return Err("current observation instance does not match --instance; historical aggregates are unavailable".into());
    }
    if runtime.is_some_and(|expected| expected != runtime_id) {
        return Err("current observation runtime does not match --runtime; a restart changes the namespace and historical aggregates are unavailable".into());
    }
    if !source["queue_limits"].is_object()
        || !source["payload_layers"].is_array()
        || !source["capture"]["state"].is_string()
        || !source["wire_source_active"].is_boolean()
    {
        return Err("observation availability data unavailable or incomplete".into());
    }
    let observations = &stats["observations"];
    if observations["layers"]
        .as_object()
        .is_none_or(|v| v.is_empty())
        || observations["sinks"]
            .as_object()
            .is_none_or(|v| v.is_empty())
        || !observations["wire_source"].is_object()
        || !observations["behaviour"]["series"].is_array()
        || observations["behaviour"]["series"]
            .as_array()
            .is_some_and(|series| series.iter().any(|row| !row.is_object()))
        || !observations["behaviour"]["observation_loss_total"].is_object()
        || !observations["observation_gap_ranges_total"].is_u64()
        || !observations["observation_sequence_exhausted_total"].is_u64()
    {
        return Err(
            "observation measurements unavailable or incomplete; no zero report was substituted"
                .into(),
        );
    }
    Ok(json!({"scope":SCOPE,"source":source,"observations":observations}))
}

fn counters(value: &Value) {
    if let Some(values) = value.as_object() {
        for (name, count) in values {
            println!("  {}: {}", safe(name), safe(&count.to_string()));
        }
    }
}

fn show(report: &Value, details: bool) -> Result<(), Error> {
    let source = &report["source"];
    println!(
        "Observation measurements\nConfig: {}\nInstance: {}\nRuntime: {}",
        safe(text(&source["config"])),
        safe(text(&source["instance_id"])),
        safe(text(&source["runtime_id"]))
    );
    println!(
        "Scope: current runtime aggregates across all agents, requests and connections.\nReload preserves measurements; restart resets the namespace and counters.\nCounters are sampled while traffic continues; canonical measurement can lag attempted observations."
    );
    if !details {
        show_summary(report);
        return Ok(());
    }
    println!(
        "Queue limits: {}\nPayload capture layers: {}\nCapture availability: {}\nWire source active: {}",
        context_json(&source["queue_limits"])?,
        context_json(&source["payload_layers"])?,
        context_json(&source["capture"])?,
        context_json(&source["wire_source_active"])?
    );
    let observations = &report["observations"];
    println!(
        "\nCanonical admission: attempted counters include refused observations; bus drops are canonical loss."
    );
    for (layer, values) in observations["layers"].as_object().unwrap() {
        println!("Layer {}", safe(layer));
        counters(values);
    }
    for name in [
        "observation_gap_ranges_total",
        "observation_sequence_exhausted_total",
    ] {
        println!("{}: {}", name, observations[name]);
    }
    println!(
        "\nConsumer and output counters: delivery, drops and errors are separate from canonical admission.\nZero counters do not establish sink availability or complete delivery; see capture availability."
    );
    for (sink, values) in observations["sinks"].as_object().unwrap() {
        println!("Sink {}", safe(sink));
        counters(values);
    }
    println!(
        "\nWire source counters (interface/filter scope; zero does not establish acquisition):"
    );
    counters(&observations["wire_source"]);
    println!(
        "\nTransport behaviour from canonical metadata; no anomaly threshold or per-connection verdict:"
    );
    println!("observation_loss_total by reason:");
    counters(&observations["behaviour"]["observation_loss_total"]);
    for series in observations["behaviour"]["series"].as_array().unwrap() {
        println!(
            "Series point={} layer={} transport={} direction={}",
            safe(text(&series["point"])),
            safe(text(&series["layer"])),
            safe(text(&series["transport"])),
            safe(text(&series["direction"]))
        );
        for (name, value) in series.as_object().ok_or("behaviour series unavailable")? {
            if matches!(name.as_str(), "point" | "layer" | "transport" | "direction") {
                continue;
            }
            if value.is_object() {
                let buckets = value["buckets"]
                    .as_array()
                    .ok_or("behaviour histogram buckets unavailable")?
                    .iter()
                    .map(|bucket| format!("<={}:{}", bucket["le"], bucket["count"]))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "  {}: count={} sum={} cumulative finite buckets=[{}]",
                    safe(name),
                    context_json(&value["count"])?,
                    context_json(&value["sum"])?,
                    safe(&buckets)
                );
            } else {
                println!("  {}: {}", safe(name), context_json(value)?);
            }
        }
    }
    Ok(())
}

fn show_summary(report: &Value) {
    use crate::operator_output::{rows, text};

    let source = &report["source"];
    let observations = &report["observations"];
    let payload = source["payload_layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect::<Vec<_>>();
    println!(
        "Capture: {}; payload layers: {}; wire source active: {}",
        text(&source["capture"]["state"]),
        if payload.is_empty() {
            "none".into()
        } else {
            payload.join(", ")
        },
        text(&source["wire_source_active"]),
    );
    if let Some(outputs) = source["capture"]["outputs"].as_object() {
        for (name, output) in outputs {
            println!(
                "Capture {}: configured {}; subscribed {}",
                safe(name),
                text(&output["configured"]),
                text(&output["subscribed"])
            );
        }
    }
    println!(
        "Queue limits: {} items / {} bytes",
        text(&source["queue_limits"]["items"]),
        text(&source["queue_limits"]["bytes"])
    );
    for (name, values, columns) in [
        (
            "Observation admission",
            &observations["layers"],
            &[
                ("LAYER", "name"),
                ("ATTEMPTED", "observations_total"),
                ("DROPPED", "observation_bus_dropped_total"),
                ("METADATA BYTES", "observation_metadata_bytes_total"),
                ("PAYLOAD BYTES", "observation_payload_bytes_total"),
            ][..],
        ),
        (
            "Output delivery (separate from admission)",
            &observations["sinks"],
            &[
                ("OUTPUT", "name"),
                ("BYTES", "sink_bytes_total"),
                ("DROPPED", "sink_dropped_observations_total"),
                ("ERRORS", "sink_errors_total"),
                ("DISCONNECTS", "sink_disconnects_total"),
            ][..],
        ),
    ] {
        println!("\n{name}");
        let values = values
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, counters)| {
                let mut row = json!({"name":name});
                for (_, key) in &columns[1..] {
                    row[*key] = counters[*key].clone();
                }
                row
            })
            .collect::<Vec<_>>();
        rows(&values, columns);
    }
    println!(
        "Loss: {} recorded gap ranges; {} exhausted sequences",
        text(&observations["observation_gap_ranges_total"]),
        text(&observations["observation_sequence_exhausted_total"])
    );
    let loss = &observations["behaviour"]["observation_loss_total"];
    println!(
        "Metrics loss: {} canonical admission unavailable; {} accounting capacity",
        text(&loss["canonical_admission_unavailable"]),
        text(&loss["metrics_accounting_capacity"])
    );
    println!(
        "Zero counters do not establish availability or complete delivery. Layer counts and bytes overlap.\nUse --details for wire counters, consumer metadata, loss reasons and transport histograms; --json for complete records."
    );
}
