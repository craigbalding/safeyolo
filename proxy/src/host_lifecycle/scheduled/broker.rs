//! Native JetStream schedules. No calendar calculation or guest broker credential.
use super::*;
use async_nats::jetstream::{AckKind, consumer, stream};
use futures_util::StreamExt;
use tokio::task::{JoinHandle, JoinSet};

const STREAM: &str = "SY_LIFECYCLE";
const PREFIX: &str = "SY_LIFECYCLE";

fn activation_subject(id: &str) -> String {
    format!("{PREFIX}.schedule.{id}.activation")
}

async fn stream(root: &Path) -> Result<stream::Stream, Error> {
    let js = coord_rooms::jetstream(root).await?;
    Ok(js
        .get_or_create_stream(stream::Config {
            name: STREAM.into(),
            subjects: vec![format!("{PREFIX}.>")],
            allow_message_schedules: true,
            allow_message_ttl: true,
            ..Default::default()
        })
        .await?)
}

async fn publish(
    root: &Path,
    subject: String,
    target: String,
    pattern: &str,
    timezone: Option<&str>,
    value: &Value,
) -> Result<(), Error> {
    let js = coord_rooms::jetstream(root).await?;
    let mut headers = async_nats::HeaderMap::new();
    headers.insert("Nats-Schedule", pattern);
    headers.insert("Nats-Schedule-Target", target);
    headers.insert("Nats-Schedule-TTL", "never");
    if let Some(zone) = timezone {
        headers.insert("Nats-Schedule-Time-Zone", zone);
    }
    js.publish_with_headers(subject, headers, serde_json::to_vec(value)?.into())
        .await?
        .await?;
    Ok(())
}

pub(super) async fn arm_stop(root: &Path, state: &Value, at: i64) -> Result<(), Error> {
    stream(root).await?;
    let stamp = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(at) * 1_000_000)?
        .format(&time::format_description::well_known::Rfc3339)?;
    let id = state["agent_id"]
        .as_str()
        .ok_or("missing lifecycle agent")?;
    let activation = state["activation_id"]
        .as_str()
        .ok_or("missing activation")?;
    publish(
        root,
        format!("{PREFIX}.schedule.{id}.{activation}"),
        format!("{PREFIX}.event.{id}.stop"),
        &format!("@at {stamp}"),
        None,
        &json!({"action":"stop","agent_id":id,"activation_id":activation,
            "run_id":state["run_id"],"configuration_revision":state["configuration_revision"],
            "stop_by":state["stop_by"]}),
    )
    .await
}

async fn reconcile(root: &Path) -> Result<(), Error> {
    let agents = crate::host_agents::list()?;
    let lifecycle: Vec<_> = agents.iter().filter(|a| a.lifecycle.is_some()).collect();
    let conn = coord_rooms::open(root)?;
    let retired=conn.prepare("SELECT agent_id FROM coord_lifecycle WHERE json_extract(document_json,'$.schedule_status') IS NOT NULL")?
        .query_map([],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;
    if lifecycle.is_empty() && retired.is_empty() {
        return Ok(());
    }
    let stream = stream(root).await?;
    for id in retired {
        if !lifecycle.iter().any(|a| a.id == id) {
            stream.purge().filter(activation_subject(&id)).await?;
        }
    }
    let mut errors = Vec::new();
    for agent in lifecycle {
        let result = reconcile_agent(root, &stream, agent).await;
        let mut conn = coord_rooms::open(root)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut receipt =
            load(&tx, &agent.id)?.unwrap_or_else(|| json!({"agent_id":agent.id,"name":agent.name}));
        let status = json!({"configuration_revision":revision(agent)?,
            "state":if result.is_ok(){"adopted"}else{"unavailable"},
            "error":result.as_ref().err().map(ToString::to_string)});
        if receipt["schedule_status"] != status {
            receipt["schedule_status"] = status;
            save(&tx, &agent.id, &receipt)?;
        }
        tx.commit()?;
        if let Err(error) = result {
            errors.push(format!("{}: {error}", agent.name));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; ").into())
    }
}

async fn reconcile_agent(root: &Path, stream: &stream::Stream, agent: &Agent) -> Result<(), Error> {
    let config = agent.lifecycle.as_ref().unwrap();
    let subject = activation_subject(&agent.id);
    if config.paused || config.mode != Mode::Scheduled {
        stream.purge().filter(subject).await?;
        return Ok(());
    }
    let body =
        json!({"action":"start","agent_id":agent.id,"configuration_revision":revision(agent)?});
    match stream.get_last_raw_message_by_subject(&subject).await {
        Ok(message) if message.payload.as_ref() == serde_json::to_vec(&body)? => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == stream::LastRawMessageErrorKind::NoMessageFound => {}
        Err(error) => return Err(error.into()),
    }
    publish(
        root,
        subject,
        format!("{PREFIX}.event.{}.start", agent.id),
        config.schedule.as_deref().unwrap(),
        config.timezone.as_deref(),
        &body,
    )
    .await?;
    Ok(())
}

#[derive(Default)]
pub(crate) struct Follow {
    task: Option<JoinHandle<Result<(), Error>>>,
    last_error: Option<String>,
}

impl Drop for Follow {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl Follow {
    pub(crate) async fn poll(&mut self, runtime: RuntimeState) -> Result<(), Error> {
        let config = crate::operator_actions::config_path(&runtime)?;
        let root = config
            .parent()
            .ok_or("lifecycle configuration has no instance root")?
            .to_owned();
        let agents =
            host_platform::in_config(config.clone(), async { crate::host_agents::list() }).await?;
        let has_active =
            host_platform::in_config(config.clone(), async { active_receipts(&root) }).await?;
        if agents.iter().all(|a| a.lifecycle.is_none()) && !has_active {
            return Ok(());
        }
        if self.task.as_ref().is_some_and(|t| t.is_finished()) {
            self.task.take().unwrap().await??;
        }
        if self.task.is_none() {
            self.task = Some(tokio::spawn(host_platform::in_config(
                config.clone(),
                run(root.clone(), runtime.clone()),
            )));
        }
        let result = host_platform::in_config(config, reconcile(&root)).await;
        match result {
            Ok(()) => {
                self.last_error = None;
                Ok(())
            }
            Err(error) => {
                let message = error.to_string();
                if self.last_error.as_ref() == Some(&message) {
                    return Ok(());
                }
                self.last_error = Some(message);
                Err(error)
            }
        }
    }
}

async fn run(root: std::path::PathBuf, runtime: RuntimeState) -> Result<(), Error> {
    let stream = stream(&root).await?;
    let consumer = stream
        .get_or_create_consumer(
            "host_lifecycle",
            consumer::pull::Config {
                durable_name: Some("host_lifecycle".into()),
                filter_subject: format!("{PREFIX}.event.>"),
                ack_policy: consumer::AckPolicy::Explicit,
                ..Default::default()
            },
        )
        .await?;
    let mut messages = consumer.messages().await?;
    let mut jobs = JoinSet::new();
    for agent in crate::host_agents::list()? {
        if let Some(receipt) = retained(&root, &agent.id)?
            && receipt["stop_request"]["status"] == "checking"
        {
            completion::interrupted(&agent, &receipt["stop_request"])?;
        }
    }
    loop {
        tokio::select! {
            message = messages.next() => {
                let message = message.ok_or("lifecycle schedule consumer ended")??;
                let info = message.info()?;
                let sequence = info.stream_sequence;
                let at = i64::try_from(info.published.unix_timestamp_nanos()/1_000_000)?;
                let event: Value = serde_json::from_slice(&message.payload)?;
                let headers = message.headers.as_ref().ok_or("native scheduled message headers missing")?;
                let scheduler = headers.get("Nats-Scheduler").ok_or("native schedule provenance missing")?.as_str();
                let next = headers.get("Nats-Schedule-Next").map(|h| h.as_str().to_owned());
                let agent_id = event["agent_id"].as_str().ok_or("schedule worker missing")?;
                let agent = crate::host_agents::list()?.into_iter().find(|a| a.id==agent_id);
                if let Some(agent) = agent {
                    let expected = if event["action"] == "start" {activation_subject(agent_id)}
                        else {format!("{PREFIX}.schedule.{agent_id}.{}", event["activation_id"].as_str().ok_or("cutoff activation missing")?)};
                    if scheduler != expected {
                        message.ack_with(AckKind::Term).await.map_err(|e|e.to_string())?;
                        continue;
                    }
                    if event["action"]=="start" && event["configuration_revision"]==revision(&agent)? {
                        let mut conn=coord_rooms::open(&root)?;
                        let tx=conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                        let mut receipt=load(&tx,&agent.id)?.unwrap_or_else(||json!({"agent_id":agent.id,"name":agent.name}));
                        if receipt["schedule_observation"]["sequence"].as_u64().unwrap_or(0)<sequence {
                            receipt["schedule_observation"]=json!({"configuration_revision":event["configuration_revision"],"sequence":sequence,"at":at,"next":next});
                            save(&tx,&agent.id,&receipt)?;
                        }
                        tx.commit()?;
                    }
                    // The native event is retained before its potentially uncertain effect.
                    // Activation and stop each reconcile exact current run under SetupLock.
                    let job_config = host_platform::config_path();
                    let active=runtime.clone();
                    jobs.spawn(host_platform::in_config(job_config, async move {
                        let result = if event["action"] == "start" {
                            let guard=||{
                                let current=active.read().map_err(|_|"runtime policy unavailable")?;
                                let policy=current.policy.as_ref().ok_or("runtime policy unavailable")?;
                                if policy.baseline_files_changed()? || policy.evidence_agent_id(&agent.name)!=Some(agent.id.as_str()){
                                    return Err("saved policy is not the current active lifecycle authority".into());
                                }
                                Ok(())
                            };
                            activate(&agent,"start",None,None,false,&guard,Some(Occurrence {
                                sequence,at,revision:event["configuration_revision"].as_str().ok_or("schedule revision missing")?.into(),next,
                            })).await
                        } else {
                            mandatory_stop(agent.clone(),&event).await
                        };
                        message.ack().await.map_err(|e|e.to_string())?;
                        if let Err(error) = result {
                            // Receipt remains inspectable. Redelivery is not a selected retry.
                            let conn = coord_rooms::open(&host_platform::config_dir())?;
                            if let Some(mut receipt) = load(&conn,&agent.id)? {
                                let matching=if event["action"]=="start"{
                                    receipt["occurrence"]["sequence"]==sequence
                                }else{receipt["activation_id"]==event["activation_id"] && receipt["run_id"]==event["run_id"]};
                                if matching{
                                    receipt["error"]=json!(error.to_string());
                                    save(&conn,&agent.id,&receipt)?;
                                }else if event["action"]=="start"
                                    && receipt["schedule_status"]["configuration_revision"]==event["configuration_revision"]
                                    && receipt["last_start_sequence"].as_u64().unwrap_or(0)<sequence{
                                    receipt["start_error"]=json!({"configuration_revision":event["configuration_revision"],
                                        "sequence":sequence,"at":at,"error":error.to_string()});
                                    save(&conn,&agent.id,&receipt)?;
                                }
                            }
                            eprintln!("Worker lifecycle {}: {error}", agent.name);
                        }
                        Ok::<_,Error>(())
                    }));
                } else {
                    message.ack_with(AckKind::Term).await.map_err(|e|e.to_string())?;
                }
            }
            result = jobs.join_next(), if !jobs.is_empty() => {
                result.ok_or("lifecycle action disappeared")???;
            }
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                // Typed self-stop requests are retained in the lifecycle receipt,
                // rather than converted into a second Work queue.
                for agent in crate::host_agents::list()? {
                    if let Some(receipt) = retained(&root,&agent.id)?
                        && receipt["stop_request"]["status"]=="accepted"
                    {
                        let mut conn=coord_rooms::open(&root)?;
                        let tx=conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                        let mut current=load(&tx,&agent.id)?.ok_or("lifecycle receipt disappeared")?;
                        if current["stop_request"]["status"]!="accepted" {continue;}
                        current["stop_request"]["status"]=json!("checking");
                        save(&tx,&agent.id,&current)?;
                        tx.commit()?;
                        let (job_config,state)=(host_platform::config_path(),runtime.clone());
                        jobs.spawn(host_platform::in_config(job_config,async move {
                            completion::execute(&state,&agent,&current).await
                        }));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;

    #[tokio::test]
    #[ignore = "requires the pinned native NATS binary"]
    async fn native_calendar_delivery_changed_configuration_and_cutoff() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("data")).unwrap();
        std::fs::write(root.path().join("config.toml"), "").unwrap();
        std::fs::write(
            root.path().join("data/instance_id"),
            "sy-native-calendar-proof",
        )
        .unwrap();
        let source = |schedule: &str, zone: Option<&str>| {
            format!(
                "[agents.worker]\nagent_id='ag-worker'\n[agents.worker.lifecycle]\nmode='scheduled'\nschedule={schedule:?}\n{}",
                zone.map_or(String::new(), |zone| format!("timezone={zone:?}\n"))
            )
        };
        std::fs::write(root.path().join("policy.toml"), source("@every 1s", None)).unwrap();
        let binary = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
        // The existing NATS fixture switch selects owned dynamic ports.
        assert!(std::env::var_os("SAFEYOLO_NATS_TEST_INSTANCE").is_some());
        coord_rooms::start(root.path(), Some(Path::new(&binary)), None, None)
            .await
            .unwrap();
        let result=std::panic::AssertUnwindSafe(host_platform::in_instance(root.path().to_owned(),async{
            reconcile(root.path()).await.unwrap();
            let stream=stream(root.path()).await.unwrap();
            let original=stream.get_last_raw_message_by_subject(&activation_subject("ag-worker")).await.unwrap();
            reconcile(root.path()).await.unwrap();
            assert_eq!(stream.get_last_raw_message_by_subject(&activation_subject("ag-worker")).await.unwrap().sequence,original.sequence);
            let consumer=stream.get_or_create_consumer("calendar-proof",consumer::pull::Config{
                durable_name:Some("calendar-proof".into()),filter_subject:format!("{PREFIX}.event.>"),
                ack_policy:consumer::AckPolicy::Explicit,..Default::default()
            }).await.unwrap();
            let mut messages=consumer.messages().await.unwrap();
            let message=tokio::time::timeout(Duration::from_secs(5),messages.next()).await.unwrap().unwrap().unwrap();
            assert_eq!(message.headers.as_ref().unwrap().get("Nats-Scheduler").unwrap().as_str(),activation_subject("ag-worker"));
            let next=message.headers.as_ref().unwrap().get("Nats-Schedule-Next").unwrap().as_str();
            assert!(timestamp(next).unwrap()>0);
            message.ack().await.unwrap();
            std::fs::write(root.path().join("policy.toml"),source("*/2 * * * * *",Some("Europe/Budapest"))).unwrap();
            reconcile(root.path()).await.unwrap();
            let updated=stream.get_last_raw_message_by_subject(&activation_subject("ag-worker")).await.unwrap();
            assert!(updated.sequence>original.sequence);
            assert_eq!(updated.headers.get("Nats-Schedule-Time-Zone").unwrap().as_str(),"Europe/Budapest");
            let event=json!({"agent_id":"ag-worker","activation_id":"activation-proof","run_id":"run-proof",
                "configuration_revision":"revision-proof","stop_by":now()+30_000});
            arm_stop(root.path(),&event,now()-1000).await.unwrap();
            loop {
                let message=tokio::time::timeout(Duration::from_secs(5),messages.next()).await.unwrap().unwrap().unwrap();
                let body:Value=serde_json::from_slice(&message.payload).unwrap();
                message.ack().await.unwrap();
                if body["action"]=="stop" {
                    assert_eq!(body["run_id"],"run-proof");
                    assert_eq!(body["activation_id"],"activation-proof");
                    break;
                }
            }
            std::fs::write(root.path().join("policy.toml"),source("* * * * * *",Some("Missing/Zone"))).unwrap();
            assert!(reconcile(root.path()).await.is_err());
        })).catch_unwind().await;
        coord_rooms::stop(root.path()).await.unwrap();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
}
