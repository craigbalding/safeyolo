//! Explicit external reads cannot mutate or delay the local work operations.
use super::{Client, Error, segment, text};
use crate::coord_rooms::work::github::Reference;
use serde_json::{Value, json};

struct Services(Value);
impl Drop for Services {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.0);
    }
}

async fn binding(client: &Client) -> Result<zeroize::Zeroizing<String>, Error> {
    let services = Services(client.get("/gateway/services").await?);
    let github = &services.0["authorized"]["github"];
    let token = github["token"]
        .as_str()
        .filter(|s| s.starts_with("sgw_"))
        .ok_or("GitHub read service has no gateway token")?;
    Ok(zeroize::Zeroizing::new(token.to_owned()))
}

pub(super) async fn read(client: &Client, args: &Value) -> Result<Value, Error> {
    let path = format!(
        "/api/coord/rooms/{}/work?work_id={}",
        segment(text(args, "room_name")?),
        segment(text(args, "work_id")?)
    );
    let work = client.get(&path).await?;
    let reference = Reference::parse(work["external_ref"].as_str().unwrap_or(""))?;
    let acquired = async {
        let token = binding(client).await?;
        let mut document = crate::native_client::gateway_json(
            client.socket.as_deref(),
            &reference.api_url,
            &token,
        )
        .await?;
        let result = reference.metadata(&document);
        crate::credentials::wipe_json(&mut document);
        // A revoked or replaced binding must not yield newly acquired metadata.
        if *binding(client).await? != *token {
            return Err("GitHub access changed during the read".into());
        }
        Ok::<_, Error>(result?)
    }
    .await;
    // Recheck room authority and return the latest local claim/version after
    // the external await. External errors never replace the canonical work.
    let work = client.get(&path).await?;
    let external = match acquired {
        Ok(metadata) => metadata,
        Err(error) => {
            // Upstream bodies and transport errors are not external metadata.
            // Only a numeric HTTP status can cross this boundary.
            let status = error
                .downcast_ref::<crate::native_client::RestStatusError>()
                .map(|e| e.status);
            json!({"source":"github","status":"unavailable","url":reference.url,
                "http_status":status,"reason":"GitHub metadata unavailable; check the caller's service access and transport"})
        }
    };
    Ok(json!({"work":work,"external":external}))
}
