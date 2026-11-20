//! Protected host-held NATS connections and recoverable KV current-state watches.
use super::*;
use crate::coord_rooms::federation::endpoint::Endpoint;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source {
    pub endpoint: Endpoint,
    pub username: String,
    pub credential_file: PathBuf,
    pub bucket: String,
    pub keys: String,
    pub source_id: String,
    pub max_bytes: usize,
    pub max_signals: usize,
    pub max_age_seconds: u64,
    pub retry_seconds: u64,
    #[serde(default = "follow_default")]
    pub follow: bool,
    /// Only this explicitly selected maintained list can be adopted.
    pub list: Option<String>,
}
fn follow_default() -> bool {
    true
}

impl Source {
    pub(super) fn validate(&self) -> Result<(), Error> {
        self.endpoint.origin()?;
        name(&self.source_id)?;
        if self.username.is_empty()
            || !self.credential_file.is_absolute()
            || self.bucket.is_empty()
            || !self
                .bucket
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || self.keys.is_empty()
            || self.keys.contains([' ', '\r', '\n', '\0'])
            || self.max_bytes == 0
            || self.max_bytes > (usize::MAX.saturating_sub(65536) / 4)
            || self.max_signals == 0
            || self.max_signals == usize::MAX
            || self.max_age_seconds == 0
            || self.retry_seconds == 0
            || std::time::Instant::now()
                .checked_add(Duration::from_secs(self.retry_seconds))
                .is_none()
        {
            return Err("signal source needs protected NATS, host credentials, a bucket/key filter and positive byte, age and retry limits".into());
        }
        if let Some(list) = &self.list {
            name(list)?;
        }
        Ok(())
    }

    pub(super) async fn connect(&self) -> Result<async_nats::Client, Error> {
        Ok(self
            .endpoint
            .options(self.username.clone(), self.credential_file.clone())
            .await?
            .request_timeout(Some(Duration::from_secs(5)))
            .connect(&self.endpoint.url)
            .await?)
    }

    pub(super) async fn follow(&self, root: &Path, source_name: &str) -> Result<(), Error> {
        use futures_util::StreamExt;
        let (health_root, health_source) = (root.to_owned(), source_name.to_owned());
        let client = self
            .endpoint
            .options(self.username.clone(), self.credential_file.clone())
            .await?
            .request_timeout(Some(Duration::from_secs(5)))
            .event_callback(move |event| {
                let (root, source) = (health_root.clone(), health_source.clone());
                async move {
                    let state = match event {
                        async_nats::Event::Connected => "connected",
                        async_nats::Event::Disconnected => "disconnected",
                        _ => return,
                    };
                    let _ = health(&root, &source, state, None);
                }
            })
            .connect(&self.endpoint.url)
            .await?;
        let kv = async_nats::jetstream::new(client.clone())
            .get_key_value(&self.bucket)
            .await?;
        // An ordered consumer starts with the last value for each selected key.
        // It recovers sequence gaps through JetStream, including across reconnect.
        // Recreating this worker also recovers current state, without a local cursor.
        let mut watch = kv.watch_with_history(&self.keys).await?;
        health(root, source_name, "following", None)?;
        while let Some(entry) = watch.next().await {
            let entry = entry?;
            if entry.operation != async_nats::jetstream::kv::Operation::Put {
                // A broker tombstone carries no source evidence time. Publishers
                // must retain an explicit withdrawal; deletion cannot imply safety.
                health(
                    root,
                    source_name,
                    "unavailable",
                    Some("key deleted without an explicit withdrawal"),
                )?;
                continue;
            }
            let result = accept(root, source_name, self, &entry.key, &entry.value);
            match result {
                Ok(_) => health(root, source_name, "following", None)?,
                Err(_) => health(
                    root,
                    source_name,
                    "rejected",
                    Some(
                        "invalid, stale, replayed or no longer adopted update; prior accepted evidence retained",
                    ),
                )?,
            }
        }
        Err("signal current-state watch ended".into())
    }
}
