//! One attention wait with independent positions for selected owning instances.
use super::*;
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};

impl Client {
    pub(super) async fn resolve_attention(
        &self,
        page: Value,
        since: u64,
        limit: u64,
        expected: Option<&str>,
    ) -> Result<Value, Error> {
        let instance = text(&page, "instance_id")?;
        if expected.is_some_and(|expected| expected != instance) {
            return Err("attention position belongs to a different instance".into());
        }
        let edges = page["edges"]
            .as_array()
            .ok_or("invalid attention edge page")?;
        let next = page["next_cursor"]
            .as_u64()
            .filter(|next| *next >= since)
            .ok_or("invalid attention cursor")?;
        if edges.len() as u64 > limit {
            return Err("attention page exceeds requested limit".into());
        }
        let mut objects = Vec::new();
        let mut seen = HashSet::new();
        for edge in edges {
            let id = text(edge, "attention_id")?;
            if !attention_id(id) || !seen.insert(id) {
                return Err("invalid or duplicate attention identity".into());
            }
            let mut resolved = self
                .get(&format!(
                    "/api/coord/attention/{id}/object?instance_id={}",
                    segment(instance)
                ))
                .await?;
            if resolved.get("edge") != Some(edge) || !resolved["object"].is_object() {
                return Err("mismatched canonical attention object".into());
            }
            resolved["instance_id"] = json!(instance);
            objects.push(resolved);
        }
        Ok(json!({"objects":objects,"next_cursor":next,"instance_id":instance}))
    }

    async fn read_source(
        &self,
        instance: &str,
        since: u64,
        limit: u64,
        seconds: f64,
    ) -> Result<Value, Error> {
        let page=self.request(Method::GET,
            &format!("/api/coord/attention/wait?since={since}&limit={limit}&timeout={seconds}&instance_id={}",segment(instance)),
            Value::Null,Duration::from_secs_f64(seconds+30.0)).await?;
        self.resolve_attention(page, since, limit, Some(instance))
            .await
    }

    pub(super) async fn wait_sources(&self, args: &Value) -> Result<Value, Error> {
        if self.home.is_some() || args.get("since_sequence").is_some() {
            return Err("sources supplies each home and its own position; omit the single-source home and since_sequence".into());
        }
        let sources = args["sources"]
            .as_array()
            .filter(|sources| !sources.is_empty())
            .ok_or("select at least one attention source")?;
        let seconds = args
            .get("timeout_seconds")
            .map_or(Some(60.0), Value::as_f64)
            .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
            .ok_or("invalid timeout_seconds")?
            .min(300.0);
        let limit = integer(args, "limit", 1)?;
        let mut identities = HashSet::new();
        let mut selected = Vec::new();
        let mut results = Vec::new();
        for source in sources {
            let instance = text(source, "instance_id")?.to_owned();
            if !identities.insert(instance.clone()) {
                return Err("select each owning instance once".into());
            }
            let since = integer(source, "since_sequence", 0)?;
            let home = source
                .get("home")
                .map(|home| home.as_str().ok_or("home must be a string"))
                .transpose()?
                .map(str::to_owned);
            results.push(json!({"home":home,"instance_id":instance,"next_cursor":since,"availability":"waiting","objects":[]}));
            selected.push((
                Client {
                    home,
                    ..self.clone()
                },
                instance,
                since,
            ));
        }
        // Read every retained source once before selecting a wake. Otherwise
        // a fast, continually busy local feed can starve a remote connection.
        // Remote zero-wait reads use the existing bounded Core RPC deadline.
        let initial = futures_util::future::join_all(
            selected
                .iter()
                .map(|(client, instance, since)| client.read_source(instance, *since, limit, 0.0)),
        )
        .await;
        let mut useful = false;
        for (index, result) in initial.into_iter().enumerate() {
            useful |= record_source(&mut results[index], result);
        }
        if useful || seconds == 0.0 {
            return Ok(json!({"sources":results}));
        }
        let mut pending = FuturesUnordered::new();
        for (index, (client, instance, since)) in selected.into_iter().enumerate() {
            if results[index]["availability"] == "unavailable" {
                continue;
            }
            results[index]["availability"] = json!("waiting");
            pending.push(
                async move {
                    (
                        index,
                        client.read_source(&instance, since, limit, seconds).await,
                    )
                }
                .boxed(),
            );
        }
        while let Some((index, result)) = pending.next().await {
            if record_source(&mut results[index], result) {
                break;
            }
        }
        // Cancel only outstanding read waits. No command is submitted or
        // replayed, and every unfinished source retains its original position.
        Ok(json!({"sources":results}))
    }
}

fn record_source(source: &mut Value, result: Result<Value, Error>) -> bool {
    match result {
        Ok(page) => {
            let useful = page["objects"]
                .as_array()
                .is_some_and(|objects| !objects.is_empty())
                || page["next_cursor"] != source["next_cursor"];
            source["availability"] = json!("available");
            source["objects"] = page["objects"].clone();
            source["next_cursor"] = page["next_cursor"].clone();
            useful
        }
        Err(error) => {
            source["availability"] = json!("unavailable");
            source["error"] = json!(error.to_string());
            false
        }
    }
}
