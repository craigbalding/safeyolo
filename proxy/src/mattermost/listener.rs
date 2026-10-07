//! The existing loopback callback protocol: one POST, one GET, bounded input.
use super::{Adapter, config::Actions, render::Unique};
use crate::Error;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

pub(super) async fn bind(actions: &Actions) -> Result<TcpListener, Error> {
    if !actions.host.is_loopback() {
        return Err("callback must bind to loopback".into());
    }
    Ok(TcpListener::bind((actions.host, actions.port)).await?)
}
pub(super) async fn serve(
    listener: TcpListener,
    adapter: Arc<Adapter>,
    mut cancel: watch::Receiver<bool>,
) -> Result<(), Error> {
    let mut tasks = tokio::task::JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _=cancel.changed()=>break Ok(()),
            joined=tasks.join_next(),if !tasks.is_empty()=>{if joined.is_some_and(|v|v.is_err()){eprintln!("Mattermost callback request stopped; pending actions require reconciliation");}},
            accepted=listener.accept()=>{
                let (mut stream,_)=match accepted{Ok(v)=>v,Err(_)=>break Err("Mattermost action listener failed".into())};
                if tasks.len()>=32 {continue;}
                let adapter=adapter.clone();
                tasks.spawn(async move {
                    let response=tokio::time::timeout(Duration::from_secs(5),async {
                        let response=read(&mut stream,&adapter).await.unwrap_or((400,json!({"error":"invalid request"})));
                        write(&mut stream,response.0,&response.1).await
                    }).await;
                    if response.is_err(){let _=tokio::time::timeout(Duration::from_millis(250),write(&mut stream,400,&json!({"error":"request timed out; inspect pending actions before retrying"}))).await;}
                    let _=stream.shutdown().await;
                });
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
async fn read(stream: &mut TcpStream, adapter: &Adapter) -> Result<(u16, Value), Error> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 16384 {
            return Err("request headers exceed bound".into());
        }
        head.push(stream.read_u8().await?);
    }
    if !head.is_ascii() {
        return Err("invalid header encoding".into());
    }
    let head = std::str::from_utf8(&head)?;
    let mut lines = head.split("\r\n");
    let parts: Vec<_> = lines
        .next()
        .ok_or("missing request line")?
        .split(' ')
        .collect();
    if parts.len() != 3 || !["HTTP/1.0", "HTTP/1.1"].contains(&parts[2]) {
        return Err("invalid request line".into());
    }
    let mut headers = BTreeMap::new();
    for line in lines.filter(|v| !v.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("invalid header")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
            || value.trim().bytes().any(|c| !(0x20..=0x7e).contains(&c))
        {
            return Err("invalid header".into());
        }
        if headers
            .insert(name.to_ascii_lowercase(), value.trim())
            .is_some()
        {
            return Err("duplicate header".into());
        }
    }
    let actions = adapter
        .config
        .actions
        .as_ref()
        .ok_or("callback unavailable")?;
    if parts[0] == "GET" && parts[1] == actions.health_path() {
        return Ok((200, adapter.health()?));
    }
    if parts[0] != "POST" || parts[1] != actions.callback_path() {
        return Ok((404, json!({"error":"not found"})));
    }
    if headers.contains_key("transfer-encoding")
        || !headers.get("content-type").is_some_and(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
    {
        return Err("invalid request headers".into());
    }
    let length = headers
        .get("content-length")
        .ok_or("missing content length")?;
    if length.starts_with('0') || !length.bytes().all(|c| c.is_ascii_digit()) {
        return Err("invalid content length".into());
    }
    let length = length.parse::<usize>()?;
    if !(2..=65536).contains(&length) {
        return Err("request body exceeds bound".into());
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    let payload: Unique = serde_json::from_slice(&body)?;
    if !payload.0.is_object() {
        return Err("request body must be an object".into());
    }
    Ok(adapter.callback(&payload.0).await)
}
async fn write(stream: &mut TcpStream, status: u16, body: &Value) -> Result<(), Error> {
    let body = serde_json::to_vec(body)?;
    if body.len() > 16384 {
        return Err("callback response exceeds bound".into());
    }
    let header = format!(
        "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}
