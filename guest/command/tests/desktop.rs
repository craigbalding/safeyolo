//! Real guest executable, HTTP files, WebSocket framing and a TCP VNC peer.
//! Test drivers are outside the guest executable's execution boundary.

use data_encoding::BASE64;
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::AsRawFd,
    os::unix::fs::symlink,
    process::{Child, Command, Stdio},
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

struct Desktop {
    directory: tempfile::TempDir,
    web: std::path::PathBuf,
    child: Child,
    address: SocketAddr,
    vnc: TcpListener,
}
impl Desktop {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let web = directory.path().join("web");
        fs::create_dir(&web).unwrap();
        fs::write(web.join("vnc.html"), "<html>noVNC</html>").unwrap();
        fs::write(web.join("client.js"), "export const client = true;").unwrap();
        fs::write(web.join("image.png"), [0, 255, 128, 1]).unwrap();
        fs::write(directory.path().join("private"), "private-fixture-marker").unwrap();
        symlink(directory.path().join("private"), web.join("escape")).unwrap();
        let address = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let vnc = TcpListener::bind("127.0.0.1:0").unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_safeyolo-guest"))
            .arg("desktop-bridge")
            .arg("--web")
            .arg(&web)
            .arg(address.to_string())
            .arg(vnc.local_addr().unwrap().to_string())
            .env_clear()
            .env("PATH", "/nonexistent")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut desktop = Self {
            directory,
            web,
            child,
            address,
            vnc,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(address).is_err() {
            assert!(
                desktop.child.try_wait().unwrap().is_none(),
                "bridge exited before readiness"
            );
            assert!(Instant::now() < deadline, "bridge did not listen");
            thread::sleep(Duration::from_millis(10));
        }
        desktop
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
        let socket = TcpStream::connect(self.address).unwrap();
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
        let (browser, response) = tungstenite::client(request, socket).unwrap();
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
    browser
        .send(Message::Frame(Frame::message(
            b"mented".to_vec(),
            OpCode::Data(Data::Continue),
            true,
        )))
        .unwrap();
    assert_eq!(
        browser.read().unwrap(),
        Message::Pong(b"control".to_vec().into())
    );
    let mut bytes = [0; 10];
    vnc.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"fragmented");
    browser.close(None).unwrap();
    assert!(matches!(browser.read().unwrap(), Message::Close(_)));
    assert_eq!(vnc.read(&mut [0]).unwrap(), 0);
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
    while fs::read_dir(format!("/proc/{}/task", desktop.child.id()))
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
    let desktop = Desktop::new();
    for (key, protocol) in [
        ("aW52YWxpZA==", "binary"),
        ("dGhlIHNhbXBsZSBub25jZQ==", "other"),
    ] {
        let mut socket = TcpStream::connect(desktop.address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(socket, "GET /websockify HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: {protocol}\r\n\r\n").unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).unwrap();
        if key == "aW52YWxpZA==" {
            assert!(
                response.is_empty(),
                "invalid key upgraded: {}",
                String::from_utf8_lossy(&response)
            );
        } else {
            assert!(
                response.starts_with(b"HTTP/1.1 400"),
                "{}",
                String::from_utf8_lossy(&response)
            );
        }
    }
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
    desktop.child.kill().unwrap();
    desktop.child.wait().unwrap();
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
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(desktop.address).is_err() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
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
