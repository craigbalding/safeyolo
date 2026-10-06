//! Loopback desktop preview owned by the native proxy.

use crate::Error;
use percent_encoding::percent_decode_str;
use serde_json::json;
use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, watch},
    task::{JoinHandle, JoinSet},
};

const GUEST_PORT: u16 = 6080;
const MAX_HEADER: usize = 128 * 1024;
const MAX_RETRY_BODY: usize = 1024 * 1024;
const MAX_UNLOCK_BODY: usize = 1024 * 1024;
const UNLOCK_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>SafeYolo Preview Unlock</title><style>body{font-family:system-ui,sans-serif;margin:3rem;max-width:32rem}input,button{font:inherit;padding:.6rem;margin-top:.5rem}</style></head><body><h1>Unlock Preview</h1><form method=\"post\" action=\"/_safeyolo_preview/unlock\"><label>Unlock code<br><input name=\"code\" autocomplete=\"one-time-code\" autofocus></label><br><button type=\"submit\">Unlock</button></form></body></html>";

struct Unlock {
    code: Option<String>,
    expires: Instant,
    failures: u8,
    locked: bool,
}

impl Unlock {
    fn new() -> Self {
        Self {
            code: Some(new_unlock_code()),
            expires: Instant::now() + Duration::from_secs(300),
            failures: 0,
            locked: false,
        }
    }

    fn renew(&mut self) -> String {
        let code = new_unlock_code();
        self.code = Some(code.clone());
        self.expires = Instant::now() + Duration::from_secs(300);
        self.failures = 0;
        self.locked = false;
        code
    }
}

fn new_unlock_code() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system randomness is required for preview unlock");
    let raw = format!("{:08}", u64::from_le_bytes(bytes) % 100_000_000);
    format!("{}-{}", &raw[..4], &raw[4..])
}

struct Access {
    agent: String,
    config: std::path::PathBuf,
    host_port: u16,
    token: String,
    cookie_name: String,
    unlock: Mutex<Unlock>,
}

pub(crate) struct Preview {
    pub(crate) url: String,
    access: Arc<Access>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    tailnet: Option<crate::tailnet::Session>,
    tailnet_port: Option<u16>,
    opened: bool,
}

impl Preview {
    pub(crate) async fn start(
        agent: &str,
        host_port: u16,
        tailnet_port: Option<u16>,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, host_port)).await?;
        let port = listener.local_addr()?.port();
        let access = Arc::new(Access {
            agent: agent.to_owned(),
            config: crate::host_platform::config_path(),
            host_port: port,
            token: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            cookie_name: format!("safeyolo_preview_token_{}", tailnet_port.unwrap_or(port)),
            unlock: Mutex::new(Unlock::new()),
        });
        let (stop, receiver) = watch::channel(false);
        let running_access = access.clone();
        let task = tokio::spawn(async move { accept(listener, running_access, receiver).await });
        let mut preview = Self {
            url: format!("http://127.0.0.1:{port}/vnc.html#autoconnect=true&resize=remote"),
            access,
            stop,
            task,
            tailnet: None,
            tailnet_port,
            opened: false,
        };
        if let Some(tailnet_port) = tailnet_port {
            match crate::tailnet::Session::start(port, tailnet_port).await {
                Ok(session) => {
                    preview.url = session.url("/vnc.html#autoconnect=true&resize=remote");
                    preview.tailnet = Some(session);
                }
                Err(error) => {
                    preview.close().await;
                    return Err(error);
                }
            }
        }
        crate::host_events::write(
            agent,
            "agent.preview_open",
            "agent",
            format!("Preview opened for {agent}:127.0.0.1:{GUEST_PORT}"),
            Some("agent-preview"),
            json!({"agent":agent,"guest_port":GUEST_PORT,"host":"127.0.0.1",
                "host_port":port,"tailnet_port":tailnet_port,"url":preview.url}),
        );
        preview.opened = true;
        Ok(preview)
    }

    pub(crate) fn is_running(&mut self) -> bool {
        !self.task.is_finished()
            && self
                .tailnet
                .as_mut()
                .is_none_or(crate::tailnet::Session::is_running)
    }

    pub(crate) async fn issue_unlock_code(&self) -> String {
        self.access.unlock.lock().await.renew()
    }

    pub(crate) async fn unlock_code(&self) -> String {
        self.access
            .unlock
            .lock()
            .await
            .code
            .clone()
            .unwrap_or_default()
    }

    pub(crate) async fn close(&mut self) {
        let _ = self.stop.send(true);
        let _ = (&mut self.task).await;
        if let Some(mut tailnet) = self.tailnet.take() {
            tailnet.stop().await;
        }
        if self.opened {
            crate::host_events::write(
                &self.access.agent,
                "agent.preview_close",
                "agent",
                format!(
                    "Preview closed for {}:127.0.0.1:{GUEST_PORT}",
                    self.access.agent
                ),
                Some("agent-preview"),
                json!({"agent":self.access.agent,"guest_port":GUEST_PORT,
                    "host_port":self.access.host_port,"tailnet_port":self.tailnet_port}),
            );
            self.opened = false;
        }
    }
}

impl Drop for Preview {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

async fn accept(listener: TcpListener, access: Arc<Access>, mut stop: watch::Receiver<bool>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((socket, _)) => {
                    let access = access.clone();
                    connections.spawn(async move {
                        crate::host_platform::in_config(access.config.clone(), async { let _ = connection(socket, access).await; }).await;
                    });
                }
                Err(_) => break,
            },
            Some(_) = connections.join_next() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

#[derive(Clone)]
struct Header {
    name: String,
    value: String,
}

struct Request {
    method: String,
    path: String,
    version: String,
    headers: Vec<Header>,
    rest: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }
    fn upgrade(&self) -> bool {
        self.header("Upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
            && self
                .header("Connection")
                .is_some_and(|value| value.to_ascii_lowercase().contains("upgrade"))
    }
}

async fn read_head<R: AsyncRead + Unpin>(stream: &mut R) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut data = Vec::new();
    loop {
        if let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            let rest = data.split_off(end + 4);
            return Ok((data, rest));
        }
        if data.len() >= MAX_HEADER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "preview headers too large",
            ));
        }
        let mut chunk = [0u8; 4096];
        let size = stream.read(&mut chunk).await?;
        if size == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "preview relay closed before response headers",
            ));
        }
        data.extend_from_slice(&chunk[..size]);
    }
}

async fn read_request(socket: &mut TcpStream) -> std::io::Result<Request> {
    let (head, rest) = read_head(socket).await?;
    // HTTP/1 header values are byte strings. Latin-1 decoding retains each
    // octet so a valid non-UTF-8 header does not become a rejected request.
    let head: String = head.into_iter().map(char::from).collect();
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or_default().split(' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let version = parts.next().unwrap_or_default().to_owned();
    if method.is_empty()
        || !path.starts_with('/')
        || !version.starts_with("HTTP/1.")
        || parts.next().is_some()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid preview request line",
        ));
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid preview header")
        })?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid preview header name",
            ));
        }
        headers.push(Header {
            name: name.to_owned(),
            value: value.trim_matches([' ', '\t']).to_owned(),
        });
    }
    Ok(Request {
        method,
        path,
        version,
        headers,
        rest,
    })
}

async fn reply(
    socket: &mut TcpStream,
    status: &str,
    headers: &[(&str, String)],
    body: &[u8],
    head_only: bool,
) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    socket.write_all(head.as_bytes()).await?;
    if !head_only {
        socket.write_all(body).await?;
    }
    Ok(())
}

async fn reply_status(
    socket: &mut TcpStream,
    status: &str,
    code: u16,
    headers: &[(&str, String)],
    body: &[u8],
    head_only: bool,
) -> std::io::Result<(u16, u64)> {
    reply(socket, status, headers, body, head_only).await?;
    Ok((code, if head_only { 0 } else { body.len() as u64 }))
}

fn cookie_token(request: &Request, cookie_name: &str) -> Option<String> {
    request.header("Cookie")?.split(';').find_map(|entry| {
        let (name, value) = entry.trim().split_once('=')?;
        (name == cookie_name).then(|| value.trim_matches('"').to_owned())
    })
}

fn authorized(request: &Request, access: &Access) -> bool {
    request
        .header("X-SafeYolo-Preview-Token")
        .map(str::to_owned)
        .or_else(|| cookie_token(request, &access.cookie_name))
        .is_some_and(|value| bool::from(value.as_bytes().ct_eq(access.token.as_bytes())))
}

fn forwarded_https(request: &Request) -> bool {
    request.header("X-Forwarded-Proto") == Some("https")
        && request
            .header("X-Forwarded-Host")
            .is_some_and(|value| !value.is_empty())
}

fn local_origin(request: &Request) -> bool {
    if matches!(
        request.header("Sec-Fetch-Site"),
        Some("cross-site" | "same-site")
    ) {
        return false;
    }
    let Some(origin) = request.header("Origin") else {
        return true;
    };
    let (scheme, host) = if forwarded_https(request) {
        (
            "https",
            request.header("X-Forwarded-Host").unwrap_or_default(),
        )
    } else {
        ("http", request.header("Host").unwrap_or_default())
    };
    origin == format!("{scheme}://{host}")
}

fn form_code(request: &Request, body: &[u8]) -> String {
    if !request
        .header("Content-Type")
        .is_some_and(|value| value.contains("application/x-www-form-urlencoded"))
    {
        return String::new();
    }
    let Ok(body) = std::str::from_utf8(body) else {
        return String::new();
    };
    body.split('&')
        .find_map(|part| {
            let (name, value) = part.split_once('=')?;
            (name == "code").then(|| {
                percent_decode_str(&value.replace('+', " "))
                    .decode_utf8_lossy()
                    .trim()
                    .to_owned()
            })
        })
        .unwrap_or_default()
}

fn log_preview(
    access: &Access,
    request: &Request,
    event: &str,
    summary: String,
    status: Option<u16>,
    started: Instant,
    bytes_out: u64,
) {
    let mut details = json!({
        "agent":access.agent,"guest_port":GUEST_PORT,"host_port":access.host_port,
        "method":request.method,"path":request.path,"bytes_in":0,"bytes_out":bytes_out,
        "duration_ms":((started.elapsed().as_secs_f64() * 10_000.0).round() / 10.0)
    });
    if let Some(status) = status {
        details["status"] = status.into();
    }
    crate::host_events::write(
        &access.agent,
        event,
        if event.starts_with("agent.") {
            "agent"
        } else {
            "traffic"
        },
        summary,
        Some("agent-preview"),
        details,
    );
}

async fn read_body(
    socket: &mut TcpStream,
    request: &Request,
    limit: usize,
) -> std::io::Result<Vec<u8>> {
    let length = request
        .header("Content-Length")
        .unwrap_or("0")
        .parse::<usize>()
        .unwrap_or(0);
    if length > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "preview body too large",
        ));
    }
    let mut body = request.rest[..request.rest.len().min(length)].to_vec();
    while body.len() < length {
        let mut chunk = vec![0u8; (length - body.len()).min(64 * 1024)];
        let size = socket.read(&mut chunk).await?;
        if size == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "preview client closed during body",
            ));
        }
        body.extend_from_slice(&chunk[..size]);
    }
    Ok(body)
}

async fn connection(mut socket: TcpStream, access: Arc<Access>) -> std::io::Result<()> {
    let started = Instant::now();
    let request = match read_request(&mut socket).await {
        Ok(request) => request,
        Err(error) => {
            let _ = reply(
                &mut socket,
                "400 Bad Request",
                &[("Content-Type", "application/json".into())],
                b"{\"error\":\"invalid preview request\"}",
                false,
            )
            .await;
            return Err(error);
        }
    };
    let head_only = request.method == "HEAD";
    if request.path.starts_with("/_safeyolo_preview") {
        if request.path != "/_safeyolo_preview/unlock" {
            return reply(
                &mut socket,
                "404 Not Found",
                &[("Content-Type", "application/json".into())],
                b"{\"error\":\"preview control path not found\"}",
                head_only,
            )
            .await;
        }
        if request.method == "GET" {
            return reply(
                &mut socket,
                "200 OK",
                &[
                    ("Content-Type", "text/html; charset=utf-8".into()),
                    ("Cache-Control", "no-store".into()),
                ],
                UNLOCK_HTML.as_bytes(),
                false,
            )
            .await;
        }
        if request.method != "POST" {
            return reply(
                &mut socket,
                "405 Method Not Allowed",
                &[("Content-Type", "application/json".into())],
                b"{\"error\":\"method not allowed\"}",
                head_only,
            )
            .await;
        }
        if !local_origin(&request) {
            let result = reply(
                &mut socket,
                "403 Forbidden",
                &[("Content-Type", "application/json".into())],
                b"{\"error\":\"unlock request rejected\"}",
                false,
            )
            .await;
            log_preview(
                &access,
                &request,
                "traffic.preview_error",
                "preview unlock origin rejected".into(),
                Some(403),
                started,
                0,
            );
            return result;
        }
        let body = match read_body(&mut socket, &request, MAX_UNLOCK_BODY).await {
            Ok(body) => body,
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                let result = reply(
                    &mut socket,
                    "413 Content Too Large",
                    &[("Content-Type", "application/json".into())],
                    b"{\"error\":\"preview unlock body too large\"}",
                    false,
                )
                .await;
                log_preview(
                    &access,
                    &request,
                    "traffic.preview_error",
                    "preview unlock body too large".into(),
                    Some(413),
                    started,
                    0,
                );
                return result;
            }
            Err(error) => return Err(error),
        };
        let code = form_code(&request, &body);
        let mut unlock = access.unlock.lock().await;
        if unlock.locked || unlock.code.is_none() {
            let result = reply(
                &mut socket,
                "423 Locked",
                &[("Content-Type", "application/json".into())],
                b"{\"error\":\"preview unlock is locked\"}",
                false,
            )
            .await;
            log_preview(
                &access,
                &request,
                "traffic.preview_error",
                "preview unlock locked".into(),
                Some(423),
                started,
                0,
            );
            return result;
        }
        if Instant::now() > unlock.expires {
            unlock.locked = true;
            let result = reply(
                &mut socket,
                "410 Gone",
                &[("Content-Type", "application/json".into())],
                b"{\"error\":\"preview unlock code expired\"}",
                false,
            )
            .await;
            log_preview(
                &access,
                &request,
                "traffic.preview_error",
                "preview unlock expired".into(),
                Some(410),
                started,
                0,
            );
            return result;
        }
        if !bool::from(
            code.as_bytes()
                .ct_eq(unlock.code.as_ref().unwrap().as_bytes()),
        ) {
            unlock.failures += 1;
            if unlock.failures >= 5 {
                unlock.locked = true;
            }
            let result = reply(
                &mut socket,
                "403 Forbidden",
                &[("Content-Type", "application/json".into())],
                b"{\"error\":\"preview unlock code invalid\"}",
                false,
            )
            .await;
            log_preview(
                &access,
                &request,
                "traffic.preview_error",
                "preview unlock code invalid".into(),
                Some(403),
                started,
                0,
            );
            return result;
        }
        unlock.code = None;
        drop(unlock);
        let secure = if forwarded_https(&request) {
            "; Secure"
        } else {
            ""
        };
        let cookie = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict{secure}",
            access.cookie_name, access.token
        );
        let result = reply(
            &mut socket,
            "303 See Other",
            &[
                (
                    "Location",
                    "/vnc.html#autoconnect=true&resize=remote".into(),
                ),
                ("Set-Cookie", cookie),
                ("Cache-Control", "no-store".into()),
            ],
            b"",
            false,
        )
        .await;
        if result.is_ok() {
            log_preview(
                &access,
                &request,
                "agent.preview_unlock",
                "preview unlocked".into(),
                Some(303),
                started,
                0,
            );
        }
        return result;
    }
    if !authorized(&request, &access) {
        let result = reply(
            &mut socket,
            "200 OK",
            &[
                ("Content-Type", "text/html; charset=utf-8".into()),
                ("Cache-Control", "no-store".into()),
            ],
            UNLOCK_HTML.as_bytes(),
            head_only,
        )
        .await;
        log_preview(
            &access,
            &request,
            "traffic.preview_error",
            "preview session missing".into(),
            Some(401),
            Instant::now(),
            0,
        );
        return result;
    }
    let started = Instant::now();
    log_preview(
        &access,
        &request,
        "traffic.preview_request",
        format!("preview {} {}", request.method, request.path),
        None,
        started,
        0,
    );
    let result = relay(socket, &request, &access.agent).await;
    match &result {
        Ok((status, bytes_out)) => log_preview(
            &access,
            &request,
            "traffic.preview_response",
            format!("preview {} {} -> {status}", request.method, request.path),
            Some(*status),
            started,
            *bytes_out,
        ),
        Err(error) => log_preview(
            &access,
            &request,
            "traffic.preview_error",
            error.to_string(),
            Some(
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                ) {
                    499
                } else {
                    502
                },
            ),
            started,
            0,
        ),
    }
    result.map(|_| ())
}

fn guest_request(request: &Request) -> Vec<u8> {
    let upgrade = request.upgrade();
    let mut result = Vec::new();
    result.extend_from_slice(request.method.as_bytes());
    result.push(b' ');
    result.extend(request.path.chars().map(|value| value as u8));
    result.push(b' ');
    result.extend_from_slice(request.version.as_bytes());
    result.extend_from_slice(format!("\r\nHost: 127.0.0.1:{GUEST_PORT}\r\n").as_bytes());
    for header in &request.headers {
        let lower = header.name.to_ascii_lowercase();
        if lower == "host"
            || lower == "x-safeyolo-preview-token"
            || lower.starts_with("tailscale-")
            || matches!(
                lower.as_str(),
                "forwarded"
                    | "x-forwarded-for"
                    | "x-forwarded-host"
                    | "x-forwarded-proto"
                    | "proxy-authorization"
                    | "proxy-authenticate"
                    | "keep-alive"
                    | "te"
                    | "trailer"
            )
            || (!upgrade && matches!(lower.as_str(), "connection" | "upgrade"))
        {
            continue;
        }
        if lower == "cookie" {
            let cookies = header
                .value
                .split(';')
                .filter(|part| !part.trim().starts_with("safeyolo_preview_token_"))
                .collect::<Vec<_>>()
                .join("; ");
            if !cookies.is_empty() {
                result.extend_from_slice(header.name.as_bytes());
                result.extend_from_slice(b": ");
                result.extend(cookies.chars().map(|value| value as u8));
                result.extend_from_slice(b"\r\n");
            }
        } else {
            result.extend_from_slice(header.name.as_bytes());
            result.extend_from_slice(b": ");
            result.extend(header.value.chars().map(|value| value as u8));
            result.extend_from_slice(b"\r\n");
        }
    }
    result.extend_from_slice(b"X-SafeYolo-Preview: 1\r\n");
    if !upgrade {
        result.extend_from_slice(b"Connection: close\r\n");
    }
    result.extend_from_slice(b"\r\n");
    result
}

async fn relay(
    mut socket: TcpStream,
    request: &Request,
    agent: &str,
) -> std::io::Result<(u16, u64)> {
    let upgrade = request.upgrade();
    // The relay reads one body length and forwards raw HTTP/1 headers. A
    // second length could make the guest parse a different request boundary.
    if request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("Content-Length"))
        .count()
        > 1
    {
        return reply_status(
            &mut socket,
            "502 Bad Gateway",
            502,
            &[("Content-Type", "application/json".into())],
            b"{\"error\":\"ambiguous preview request Content-Length\"}",
            request.method == "HEAD",
        )
        .await;
    }
    if request
        .header("Transfer-Encoding")
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return reply_status(
            &mut socket,
            "502 Bad Gateway",
            502,
            &[("Content-Type", "application/json".into())],
            b"{\"error\":\"chunked request bodies are not supported by preview\"}",
            request.method == "HEAD",
        )
        .await;
    }
    let length = match request.header("Content-Length") {
        Some(value) => match value.parse::<usize>() {
            Ok(length) => length,
            Err(_) => {
                return reply_status(
                    &mut socket,
                    "502 Bad Gateway",
                    502,
                    &[("Content-Type", "application/json".into())],
                    b"{\"error\":\"invalid preview request Content-Length\"}",
                    request.method == "HEAD",
                )
                .await;
            }
        },
        None => 0,
    };
    let retryable = !upgrade && length <= MAX_RETRY_BODY;
    let body = if retryable {
        Some(read_body(&mut socket, request, MAX_RETRY_BODY).await?)
    } else {
        None
    };
    let header = guest_request(request);
    let started = Instant::now();
    loop {
        let mut guest = match crate::host_platform::open_guest_port(agent, GUEST_PORT).await {
            Ok(guest) => guest,
            Err(error) => {
                if retryable && error.kind() == std::io::ErrorKind::ConnectionRefused {
                    if request.header("X-SafeYolo-Waiting-Room-Poll") != Some("1")
                        && started.elapsed() < Duration::from_secs(5)
                    {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                    return waiting_room(&mut socket, request, agent, upgrade).await;
                }
                return reply_status(
                    &mut socket,
                    "502 Bad Gateway",
                    502,
                    &[("Content-Type", "application/json".into())],
                    b"{\"error\":\"preview relay could not reach agent\"}",
                    request.method == "HEAD",
                )
                .await;
            }
        };
        let sent = async {
            guest.write_all(&header).await?;
            if let Some(body) = &body {
                guest.write_all(body).await?;
            } else if !upgrade {
                let initial = request.rest.len().min(length);
                guest.write_all(&request.rest[..initial]).await?;
                let mut remaining = length.saturating_sub(initial);
                while remaining > 0 {
                    let mut chunk = vec![0u8; remaining.min(64 * 1024)];
                    let size = socket.read(&mut chunk).await?;
                    if size == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "preview client closed during body",
                        ));
                    }
                    guest.write_all(&chunk[..size]).await?;
                    remaining -= size;
                }
            } else {
                guest.write_all(&request.rest).await?;
            }
            guest.flush().await
        }
        .await;
        if sent.is_err() {
            return reply_status(
                &mut socket,
                "502 Bad Gateway",
                502,
                &[("Content-Type", "application/json".into())],
                b"{\"error\":\"preview relay failed\"}",
                request.method == "HEAD",
            )
            .await;
        }
        let (head, rest) = match read_head(&mut guest).await {
            Ok(response) => response,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof && retryable => {
                if request.header("X-SafeYolo-Waiting-Room-Poll") != Some("1")
                    && started.elapsed() < Duration::from_secs(5)
                {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                return waiting_room(&mut socket, request, agent, upgrade).await;
            }
            Err(_) => {
                return reply_status(
                    &mut socket,
                    "502 Bad Gateway",
                    502,
                    &[("Content-Type", "application/json".into())],
                    b"{\"error\":\"preview relay failed\"}",
                    request.method == "HEAD",
                )
                .await;
            }
        };
        let status = head
            .split(|byte| *byte == b'\r')
            .next()
            .and_then(|line| std::str::from_utf8(line).ok())
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|code| (100..=599).contains(code));
        let Some(status) = status else {
            return reply_status(
                &mut socket,
                "502 Bad Gateway",
                502,
                &[("Content-Type", "application/json".into())],
                b"{\"error\":\"invalid preview response\"}",
                request.method == "HEAD",
            )
            .await;
        };
        let mut response = head;
        response.truncate(response.len() - 2);
        response.extend_from_slice(
            format!("X-SafeYolo-Agent: {agent}\r\nX-SafeYolo-Preview-Port: {GUEST_PORT}\r\n\r\n")
                .as_bytes(),
        );
        socket.write_all(&response).await?;
        if request.method == "HEAD" {
            return Ok((status, 0));
        }
        socket.write_all(&rest).await?;
        let transferred = if upgrade && status == 101 {
            tokio::io::copy_bidirectional(&mut socket, &mut guest)
                .await?
                .1
        } else {
            tokio::io::copy(&mut guest, &mut socket).await?
        };
        return Ok((status, rest.len() as u64 + transferred));
    }
}

async fn waiting_room(
    socket: &mut TcpStream,
    request: &Request,
    agent: &str,
    upgrade: bool,
) -> std::io::Result<(u16, u64)> {
    if upgrade
        || !request
            .header("Accept")
            .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"))
    {
        return reply_status(
            socket,
            "503 Service Unavailable",
            503,
            &[
                ("Content-Type", "application/json".into()),
                ("Retry-After", "2".into()),
                ("X-SafeYolo-Waiting-Room", "1".into()),
                ("Cache-Control", "no-store".into()),
            ],
            b"{\"error\":\"upstream not ready\"}",
            request.method == "HEAD",
        )
        .await;
    }
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"60\"><title>Waiting for {agent}</title></head><body><h1>Waiting for {agent}</h1><p>Port {GUEST_PORT} inside the sandbox has no listener. This page reloads automatically.</p><script>setInterval(async()=>{{try{{const r=await fetch(location.href,{{cache:'no-store',credentials:'include',headers:{{'X-SafeYolo-Waiting-Room-Poll':'1'}}}});if(!r.headers.get('X-SafeYolo-Waiting-Room'))location.reload()}}catch(e){{}}}},1000)</script></body></html>"
    );
    reply_status(
        socket,
        "200 OK",
        200,
        &[
            ("Content-Type", "text/html; charset=utf-8".into()),
            ("X-SafeYolo-Waiting-Room", "1".into()),
            ("Cache-Control", "no-store".into()),
        ],
        html.as_bytes(),
        request.method == "HEAD",
    )
    .await
}
