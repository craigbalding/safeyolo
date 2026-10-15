//! Real guest executable, HTTP files, WebSocket framing and a TCP VNC peer.
//! Test drivers are outside the guest executable's execution boundary.

use data_encoding::BASE64;
use std::{
    cell::RefCell,
    fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::AsRawFd,
    os::unix::fs::symlink,
    process::{Child, Command, Stdio},
    sync::{Mutex, MutexGuard, TryLockError, mpsc},
    thread,
    time::{Duration, Instant},
};
use tungstenite::{
    Message, WebSocket,
    client::IntoClientRequest,
    protocol::frame::{
        Frame,
        coding::{CloseCode, Data, OpCode},
    },
};

// A fixture releases endpoints before child bind, during restart and while
// testing a missing VNC target. Keep other fixtures from allocating them.
static DESKTOP_ENDPOINTS: Mutex<()> = Mutex::new(());

struct Desktop {
    directory: tempfile::TempDir,
    web: std::path::PathBuf,
    child: RefCell<Child>,
    address: SocketAddr,
    vnc: TcpListener,
    // Drop this after the child and sockets have been cleaned up.
    _endpoints: MutexGuard<'static, ()>,
}
impl Desktop {
    fn new() -> Self {
        let endpoints = DESKTOP_ENDPOINTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let directory = tempfile::tempdir().unwrap();
        let web = directory.path().join("web");
        fs::create_dir(&web).unwrap();
        fs::write(web.join("vnc.html"), "<html>noVNC</html>").unwrap();
        fs::write(web.join("client.js"), "export const client = true;").unwrap();
        fs::write(web.join("image.png"), [0, 255, 128, 1]).unwrap();
        fs::write(directory.path().join("private"), "private-fixture-marker").unwrap();
        symlink(directory.path().join("private"), web.join("escape")).unwrap();
        let web_reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = web_reservation.local_addr().unwrap();
        let vnc = TcpListener::bind("127.0.0.1:0").unwrap();
        drop(web_reservation);
        let child = Command::new(env!("CARGO_BIN_EXE_safeyolo-guest"))
            .arg("desktop-bridge")
            .arg("--web")
            .arg(&web)
            .arg(address.to_string())
            .arg(vnc.local_addr().unwrap().to_string())
            .env_clear()
            .env("PATH", "/nonexistent")
            .stdout(Stdio::null())
            .stderr(fs::File::create(directory.path().join("bridge-stderr")).unwrap())
            .spawn()
            .unwrap();
        let desktop = Self {
            directory,
            web,
            child: RefCell::new(child),
            address,
            vnc,
            _endpoints: endpoints,
        };
        desktop.wait_for_listener();
        desktop
    }
    fn diagnosis(&self) -> String {
        let status = self.child.borrow_mut().try_wait();
        let stderr = fs::read_to_string(self.directory.path().join("bridge-stderr"));
        format!(
            "web={} vnc={:?} bridge_status={status:?} bridge-stderr={stderr:?}",
            self.address,
            self.vnc.local_addr()
        )
    }
    fn wait_for_listener(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let connected = TcpStream::connect(self.address).is_ok();
            let status = self.child.borrow_mut().try_wait();
            assert!(
                matches!(status, Ok(None)),
                "bridge exited or its status is unavailable before readiness: {}",
                self.diagnosis()
            );
            if connected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "bridge did not listen: {}",
                self.diagnosis()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn http(&self, method: &str, path: &str) -> Vec<u8> {
        let mut socket = TcpStream::connect(self.address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            socket,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        let mut reply = Vec::new();
        socket.read_to_end(&mut reply).unwrap();
        reply
    }
    fn browser(&self, protocol: Option<&str>) -> (WebSocket<TcpStream>, TcpStream) {
        let socket = TcpStream::connect(self.address).unwrap_or_else(|error| {
            panic!("browser connection failed: {error}; {}", self.diagnosis())
        });
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = format!("ws://{}/websockify", self.address)
            .into_client_request()
            .unwrap();
        if let Some(protocol) = protocol {
            request
                .headers_mut()
                .insert("sec-websocket-protocol", protocol.parse().unwrap());
        }
        let (browser, response) = tungstenite::client(request, socket).unwrap_or_else(|error| {
            panic!("browser handshake failed: {error:?}; {}", self.diagnosis())
        });
        assert_eq!(
            response
                .headers()
                .get("sec-websocket-protocol")
                .map(|v| v.to_str().unwrap()),
            protocol
        );
        let (vnc, _) = self.vnc.accept().unwrap();
        vnc.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        vnc.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        (browser, vnc)
    }
}
impl Drop for Desktop {
    fn drop(&mut self) {
        let child = self.child.get_mut();
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn released_endpoint_cannot_be_reused_by_another_desktop_fixture() {
    let mut desktop = Desktop::new();
    desktop.child.get_mut().kill().unwrap();
    desktop.child.get_mut().wait().unwrap();

    // Force a competing fixture's VNC allocation to take the released web
    // endpoint. The real executable then reports the observed bind failure.
    let competing_vnc = TcpListener::bind(desktop.address).unwrap();
    let failed = Command::new(env!("CARGO_BIN_EXE_safeyolo-guest"))
        .arg("desktop-bridge")
        .arg("--web")
        .arg(&desktop.web)
        .arg(desktop.address.to_string())
        .arg(desktop.vnc.local_addr().unwrap().to_string())
        .env_clear()
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("Address already in use"));
    drop(competing_vnc);
    assert!(matches!(
        DESKTOP_ENDPOINTS.try_lock(),
        Err(TryLockError::WouldBlock)
    ));

    let (attempting, attempted) = mpsc::channel();
    let (ready, started) = mpsc::channel();
    let next_fixture = thread::spawn(move || {
        attempting.send(()).unwrap();
        let next = Desktop::new();
        assert!(next.http("GET", "/vnc.html").starts_with(b"HTTP/1.1 200"));
        ready.send(()).unwrap();
    });
    attempted.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(started.try_recv(), Err(mpsc::TryRecvError::Empty)));
    drop(desktop);
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    next_fixture.join().unwrap();
}

#[test]
fn a_listening_port_cannot_hide_an_exited_owned_bridge() {
    let desktop = Desktop::new();
    desktop.child.borrow_mut().kill().unwrap();
    desktop.child.borrow_mut().wait().unwrap();
    let _other_listener = TcpListener::bind(desktop.address).unwrap();
    fs::write(
        desktop.directory.path().join("bridge-stderr"),
        "owned bridge failure",
    )
    .unwrap();
    let failure =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| desktop.wait_for_listener()))
            .expect_err("an unrelated listener must not make an exited bridge ready");
    let message = failure.downcast_ref::<String>().unwrap();
    assert!(
        message.contains(&format!("web={}", desktop.address)),
        "{message}"
    );
    assert!(
        message.contains(&desktop.vnc.local_addr().unwrap().to_string()),
        "{message}"
    );
    assert!(message.contains("bridge_status=Ok(Some("), "{message}");
    assert!(message.contains("owned bridge failure"), "{message}");
}

#[test]
fn serves_page_modules_binary_files_and_head_without_file_escape() {
    let desktop = Desktop::new();
    for path in ["/", "/vnc.html?autoconnect=true"] {
        let page = desktop.http("GET", path);
        assert!(page.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(page.ends_with(b"<html>noVNC</html>"));
    }
    assert!(
        desktop
            .http("GET", "/client.js")
            .windows(15)
            .any(|v| v == b"text/javascript")
    );
    assert!(
        desktop
            .http("GET", "/image.png")
            .ends_with(&[0, 255, 128, 1])
    );
    assert!(desktop.http("HEAD", "/vnc.html").ends_with(b"\r\n\r\n"));
    for path in [
        "/../private",
        "/%2e%2e%2fprivate",
        "/%2fetc/passwd",
        "/escape",
        "/missing",
        "/%zz",
        "/%00",
    ] {
        let response = desktop.http("GET", path);
        assert!(response.starts_with(b"HTTP/1.1 404"), "path: {path}");
        assert!(!response.windows(22).any(|v| v == b"private-fixture-marker"));
    }
    assert!(
        desktop
            .http("POST", "/vnc.html")
            .starts_with(b"HTTP/1.1 405")
    );
}

#[test]
fn binary_base64_and_default_protocol_relay_live_vnc_in_both_directions() {
    for protocol in [Some("binary"), Some("base64"), None] {
        let desktop = Desktop::new();
        let (mut browser, mut vnc) = desktop.browser(protocol);
        let server = thread::spawn(move || {
            vnc.write_all(b"RFB 003.008\n").unwrap();
            let mut version = [0; 12];
            vnc.read_exact(&mut version).unwrap();
            assert_eq!(&version, b"RFB 003.008\n");
            vnc.write_all(&[1, 1]).unwrap();
            let mut selected = [0];
            vnc.read_exact(&mut selected).unwrap();
            assert_eq!(selected, [1]);
            vnc.write_all(&[0, 0, 0, 0]).unwrap();
        });
        let decode = |message: Message| match (protocol, message) {
            (Some("base64"), Message::Text(text)) => BASE64.decode(text.as_bytes()).unwrap(),
            (_, Message::Binary(bytes)) => bytes.to_vec(),
            (_, other) => panic!("unexpected VNC message: {other:?}"),
        };
        let encode = |bytes: &[u8]| {
            if protocol == Some("base64") {
                Message::Text(BASE64.encode(bytes).into())
            } else {
                Message::Binary(bytes.to_vec().into())
            }
        };
        assert_eq!(decode(browser.read().unwrap()), b"RFB 003.008\n");
        browser.send(encode(b"RFB 003.008\n")).unwrap();
        assert_eq!(decode(browser.read().unwrap()), [1, 1]);
        browser.send(encode(&[1])).unwrap();
        assert_eq!(decode(browser.read().unwrap()), [0, 0, 0, 0]);
        assert!(matches!(browser.read().unwrap(), Message::Close(_)));
        server.join().unwrap();
    }
}

#[test]
fn fragmented_binary_ping_and_client_close_retire_the_vnc_connection() {
    for pong_before_continuation in [false, true] {
        let desktop = Desktop::new();
        let (mut browser, mut vnc) = desktop.browser(Some("binary"));
        browser
            .send(Message::Frame(Frame::message(
                b"frag".to_vec(),
                OpCode::Data(Data::Binary),
                false,
            )))
            .unwrap();
        browser
            .send(Message::Ping(b"control".to_vec().into()))
            .unwrap();
        let pong = Message::Pong(b"control".to_vec().into());
        // Also force the real bridge to parse the ping while the fragmented
        // message is incomplete, before the continuation can arrive.
        if pong_before_continuation {
            assert_eq!(browser.read().unwrap(), pong);
        }
        browser
            .send(Message::Frame(Frame::message(
                b"mented".to_vec(),
                OpCode::Data(Data::Continue),
                true,
            )))
            .unwrap();
        if !pong_before_continuation {
            assert_eq!(browser.read().unwrap(), pong);
        }
        let mut bytes = [0; 10];
        vnc.read_exact(&mut bytes).unwrap_or_else(|error| {
            panic!(
                "fragmented VNC read failed: {error}; pong_before_continuation={pong_before_continuation} bytes={bytes:?}; {}",
                desktop.diagnosis()
            )
        });
        assert_eq!(&bytes, b"fragmented");
        browser.close(None).unwrap();
        assert!(matches!(browser.read().unwrap(), Message::Close(_)));
        assert_eq!(vnc.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn large_duplex_transfer_preserves_bytes_with_slow_browser_reads() {
    let desktop = Desktop::new();
    let (mut browser, mut vnc) = desktop.browser(Some("binary"));
    let payload: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let server = thread::spawn(move || {
        let mut bytes = vec![0; expected.len()];
        vnc.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, expected);
        vnc.write_all(&bytes).unwrap();
    });
    browser
        .send(Message::Binary(payload.clone().into()))
        .unwrap();
    thread::sleep(Duration::from_millis(50));
    let mut returned = Vec::new();
    while returned.len() < payload.len() {
        let Message::Binary(bytes) = browser.read().unwrap() else {
            panic!("missing VNC payload")
        };
        returned.extend_from_slice(&bytes);
    }
    assert_eq!(returned, payload);
    server.join().unwrap();
}

#[test]
fn disconnected_browser_retires_connection_even_when_vnc_is_not_reading() {
    let desktop = Desktop::new();
    let (mut browser, mut vnc) = desktop.browser(Some("binary"));
    let receive_bytes: libc::c_int = 4096;
    // Shrink only the fixture peer's TCP window, so VNC writes must encounter
    // backpressure. The native bridge does not set a product message limit.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                vnc.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&receive_bytes as *const libc::c_int).cast(),
                size_of_val(&receive_bytes) as _,
            )
        },
        0
    );
    let payload = vec![7; 8 * 1024 * 1024];
    browser.send(Message::Binary(payload.into())).unwrap();
    browser
        .get_mut()
        .shutdown(std::net::Shutdown::Both)
        .unwrap();
    drop(browser);
    let deadline = Instant::now() + Duration::from_secs(5);
    while fs::read_dir(format!("/proc/{}/task", desktop.child.borrow().id()))
        .unwrap()
        .count()
        != 1
    {
        assert!(
            Instant::now() < deadline,
            "disconnected desktop connection remained alive"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let mut delivered = Vec::new();
    vnc.read_to_end(&mut delivered).unwrap();
    assert!(delivered.len() < 8 * 1024 * 1024);
}

#[test]
fn invalid_websocket_key_and_unsupported_protocol_refuse_upgrade() {
    fn read_closed(socket: &mut TcpStream) -> (Vec<u8>, bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut response = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "peer did not close: {response:?}");
            socket.set_read_timeout(Some(remaining)).unwrap();
            let mut bytes = [0; 1024];
            match socket.read(&mut bytes) {
                Ok(0) => return (response, false),
                Ok(count) => {
                    response.extend_from_slice(&bytes[..count]);
                    assert!(response.len() <= 4096, "excess refusal bytes: {response:?}");
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                    return (response, true);
                }
                Err(error) => panic!("peer read failed: {error}; partial bytes: {response:?}"),
            }
        }
    }

    let desktop = Desktop::new();
    desktop.vnc.set_nonblocking(true).unwrap();
    let valid_control = || {
        let (mut browser, mut vnc) = desktop.browser(Some("binary"));
        vnc.write_all(b"RFB 003.008\n").unwrap();
        assert_eq!(
            browser.read().unwrap(),
            Message::Binary(b"RFB 003.008\n".to_vec().into())
        );
        browser
            .send(Message::Binary(b"control".to_vec().into()))
            .unwrap();
        let mut received = [0; 7];
        vnc.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"control");
        browser.close(None).unwrap();
        assert!(matches!(browser.read().unwrap(), Message::Close(_)));
        assert_eq!(read_closed(&mut vnc), (Vec::new(), false));
    };
    valid_control();
    for (key, protocol, trailing_data, error) in [
        (
            "aW52YWxpZA==",
            "binary",
            false,
            "WebSocket protocol error: Invalid \"Sec-WebSocket-Key\" header value",
        ),
        (
            "dGhlIHNhbXBsZSBub25jZQ==",
            "other",
            false,
            "HTTP error: 400 Bad Request",
        ),
        (
            "aW52YWxpZA==",
            "binary",
            true,
            "WebSocket protocol error: Invalid \"Sec-WebSocket-Key\" header value",
        ),
    ] {
        let mut socket = TcpStream::connect(desktop.address).unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = format!("GET /websockify HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: {protocol}\r\n\r\n").into_bytes();
        if trailing_data {
            // Leave data beyond the handshake parser's buffer. Closing with
            // unread TCP data can reset instead of reaching a clean EOF.
            request.extend_from_slice(&b"owned-no-delivery-canary".repeat(2048));
        }
        socket.write_all(&request).unwrap();
        let (response, reset) = read_closed(&mut socket);
        eprintln!(
            "key={key} protocol={protocol} trailing_data={trailing_data} \
             reset={reset} response={response:?}"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut vnc = loop {
            match desktop.vnc.accept() {
                Ok((vnc, _)) => break vnc,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "refusal never reached owned VNC");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("owned VNC accept failed: {error}"),
            }
        };
        let (delivered, vnc_reset) = read_closed(&mut vnc);
        assert!(
            delivered.is_empty(),
            "refusal delivered VNC bytes: {delivered:?}"
        );
        // A reset alone is not refusal evidence. Require the matching handshake
        // error, no upgrade/application bytes, and a closed owned VNC peer.
        let expected = format!("desktop connection failed: {error}\n");
        let deadline = Instant::now() + Duration::from_secs(5);
        let diagnosis = loop {
            let diagnosis =
                fs::read_to_string(desktop.directory.path().join("bridge-stderr")).unwrap();
            let last = diagnosis.lines().last();
            if last == Some(expected.trim_end())
                || (trailing_data
                    && last
                        == Some(
                            "desktop connection failed: WebSocket protocol error: Junk after client request",
                        ))
            {
                break diagnosis;
            }
            assert!(
                Instant::now() < deadline,
                "missing refusal cause: {diagnosis}"
            );
            thread::sleep(Duration::from_millis(10));
        };
        eprintln!(
            "key={key} protocol={protocol} vnc_reset={vnc_reset} \
             vnc_bytes={delivered:?} cause={:?}",
            diagnosis.lines().last().unwrap()
        );
        if key == "aW52YWxpZA==" {
            assert!(
                response.is_empty(),
                "invalid key upgraded: {}",
                String::from_utf8_lossy(&response)
            );
        } else {
            // Match the entire refusal, so an upgrade or appended WebSocket
            // application bytes cannot hide behind the HTTP status assertion.
            assert_eq!(
                response,
                b"HTTP/1.1 400 Bad Request\r\n\r\nSupported WebSocket protocols: binary, base64"
            );
        }
    }
    valid_control();
}

#[test]
fn malformed_frames_and_base64_close_without_delivering_vnc_bytes() {
    // Unmasked data, reserved opcode and a continuation without a message.
    for bytes in [
        vec![0x82, 1, b'x'],
        vec![0x83, 0x80, 0, 0, 0, 0],
        vec![0x80, 0x80, 0, 0, 0, 0],
    ] {
        let desktop = Desktop::new();
        let (mut browser, mut vnc) = desktop.browser(Some("binary"));
        browser.get_mut().write_all(&bytes).unwrap();
        let Message::Close(Some(close)) = browser.read().unwrap() else {
            panic!("missing protocol close")
        };
        assert_eq!(close.code, CloseCode::Protocol);
        assert_eq!(vnc.read(&mut [0]).unwrap(), 0);
        assert!(
            desktop
                .http("GET", "/vnc.html")
                .starts_with(b"HTTP/1.1 200")
        );
    }
    let desktop = Desktop::new();
    let (mut browser, mut vnc) = desktop.browser(Some("base64"));
    browser.send(Message::Text("%%%".into())).unwrap();
    let Message::Close(Some(close)) = browser.read().unwrap() else {
        panic!("missing invalid-payload close")
    };
    assert_eq!(close.code, CloseCode::Invalid);
    assert_eq!(vnc.read(&mut [0]).unwrap(), 0);
}

#[test]
fn missing_target_reports_bad_gateway_and_restart_frees_the_listener() {
    let mut desktop = Desktop::new();
    // Completed HTTP connections leave TCP TIME_WAIT state. Restart must
    // still bind the same desktop endpoint immediately.
    assert!(
        desktop
            .http("GET", "/vnc.html")
            .starts_with(b"HTTP/1.1 200")
    );
    let unavailable = desktop.vnc.local_addr().unwrap();
    // Replace the only listener with a distinct one, leaving the configured
    // original target unbound.
    desktop.vnc = TcpListener::bind("127.0.0.1:0").unwrap();
    assert_ne!(desktop.vnc.local_addr().unwrap(), unavailable);
    let request = format!("ws://{}/websockify", desktop.address);
    let socket = TcpStream::connect(desktop.address).unwrap();
    let error = tungstenite::client(request.as_str(), socket).unwrap_err();
    let tungstenite::HandshakeError::Failure(tungstenite::Error::Http(response)) = error else {
        panic!("missing HTTP failure")
    };
    assert_eq!(response.status(), 502);
    let mut raw = TcpStream::connect(desktop.address).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    raw.write_all(b"GET /websockify HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n")
        .unwrap();
    let mut diagnosis = Vec::new();
    raw.read_to_end(&mut diagnosis).unwrap();
    assert!(diagnosis.ends_with(b"VNC target unavailable\n"));
    let restored = TcpListener::bind(unavailable).unwrap();
    let mut browser = tungstenite::client(
        request.as_str(),
        TcpStream::connect(desktop.address).unwrap(),
    )
    .unwrap()
    .0;
    let (mut vnc, _) = restored.accept().unwrap();
    vnc.write_all(b"RFB 003.008\n").unwrap();
    assert_eq!(
        browser.read().unwrap(),
        Message::Binary(b"RFB 003.008\n".to_vec().into())
    );
    desktop.child.get_mut().kill().unwrap();
    desktop.child.get_mut().wait().unwrap();
    vnc.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(vnc.read(&mut [0]).unwrap(), 0);
    assert!(TcpStream::connect(desktop.address).is_err());
    desktop.child = Command::new(env!("CARGO_BIN_EXE_safeyolo-guest"))
        .arg("desktop-bridge")
        .arg("--web")
        .arg(&desktop.web)
        .arg(desktop.address.to_string())
        .arg(unavailable.to_string())
        .env_clear()
        .stderr(fs::File::create(desktop.directory.path().join("bridge-stderr")).unwrap())
        .spawn()
        .unwrap()
        .into();
    desktop.wait_for_listener();
    assert!(
        desktop
            .http("GET", "/vnc.html")
            .starts_with(b"HTTP/1.1 200")
    );
}

#[test]
fn missing_assets_and_occupied_endpoint_fail_with_the_cause() {
    let desktop = Desktop::new();
    let run = |web: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_safeyolo-guest"))
            .arg("desktop-bridge")
            .arg("--web")
            .arg(web)
            .arg(desktop.address.to_string())
            .arg(desktop.vnc.local_addr().unwrap().to_string())
            .env_clear()
            .output()
            .unwrap()
    };
    let occupied = run(&desktop.web);
    assert!(!occupied.status.success());
    assert!(String::from_utf8_lossy(&occupied.stderr).contains("Address already in use"));
    let missing = run(desktop.directory.path());
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("vnc.html"));
    assert!(
        desktop
            .http("GET", "/vnc.html")
            .starts_with(b"HTTP/1.1 200")
    );
}
