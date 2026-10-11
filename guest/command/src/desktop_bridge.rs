//! Guest-only HTTP assets and WebSocket-to-VNC transport for the staged desktop.
//! The host preview owns authentication; both guest endpoints stay on loopback.

use crate::Error;
use data_encoding::BASE64;
use std::{
    ffi::OsString,
    fs,
    io::{self, BufRead, BufReader, Cursor, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Duration,
};
use tungstenite::{
    Message, WebSocket,
    handshake::server::{Callback, ErrorResponse, Request, Response},
    protocol::{CloseFrame, WebSocketConfig, frame::coding::CloseCode},
};

const HEADER_BYTES: usize = 16 * 1024;
const CHUNK: usize = 64 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

fn listen_socket(address: SocketAddr) -> io::Result<TcpListener> {
    let domain = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // The returned descriptor is uniquely owned here. OwnedFd closes it on any
    // setup failure; all sockaddr/option pointers stay live for the syscall.
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let reuse: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&reuse as *const libc::c_int).cast(),
            size_of_val(&reuse) as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // Reuse retired TCP connections during desktop restart. SO_REUSEPORT is
    // deliberately absent: an occupied live listener must still fail.
    let result = match address {
        SocketAddr::V4(address) => {
            let sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&sockaddr as *const libc::sockaddr_in).cast(),
                    size_of_val(&sockaddr) as _,
                )
            }
        }
        SocketAddr::V6(address) => {
            let sockaddr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as _,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&sockaddr as *const libc::sockaddr_in6).cast(),
                    size_of_val(&sockaddr) as _,
                )
            }
        }
    };
    if result < 0 || unsafe { libc::listen(fd.as_raw_fd(), 128) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpListener::from(fd))
}

struct Browser {
    prefix: Cursor<Vec<u8>>,
    socket: TcpStream,
}

impl Read for Browser {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.prefix.read(bytes)?;
        if count != 0 {
            Ok(count)
        } else {
            self.socket.read(bytes)
        }
    }
}
impl Write for Browser {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

fn http_reply(socket: &mut TcpStream, status: &str, body: &str) -> io::Result<()> {
    write!(
        socket,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn asset_path(root: &Path, target: &str) -> Option<PathBuf> {
    // Decode once, before confinement. Encoded separators and dot segments must
    // not let an HTTP request read guest files outside the selected web root.
    let target = target.split('?').next()?.as_bytes();
    let mut decoded = Vec::new();
    let mut index = 0;
    while index < target.len() {
        if target[index] == b'%' {
            let hex = std::str::from_utf8(target.get(index + 1..index + 3)?).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(target[index]);
            index += 1;
        }
    }
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let relative = decoded.strip_prefix('/')?;
    let relative = if relative.is_empty() {
        "vnc.html"
    } else {
        relative
    };
    let path = root.join(relative).canonicalize().ok()?;
    path.starts_with(root).then_some(path)
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn serve_asset(socket: &mut TcpStream, root: &Path, method: &str, target: &str) -> io::Result<()> {
    if !matches!(method, "GET" | "HEAD") {
        return http_reply(socket, "405 Method Not Allowed", "Use GET or HEAD\n");
    }
    let Some(path) = asset_path(root, target) else {
        return http_reply(socket, "404 Not Found", "Asset not found\n");
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path);
    let Ok(file) = file else {
        return http_reply(socket, "404 Not Found", "Asset not found\n");
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return http_reply(socket, "404 Not Found", "Asset not found\n");
    }
    write!(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content_type(&path),
        metadata.len()
    )?;
    if method == "GET" {
        io::copy(&mut file.take(metadata.len()), socket)?;
    }
    Ok(())
}

fn would_block(error: &tungstenite::Error) -> bool {
    matches!(error, tungstenite::Error::Io(error) if error.kind() == io::ErrorKind::WouldBlock)
}

struct VncProtocol<'a>(&'a mut bool);

impl Callback for VncProtocol<'_> {
    fn on_request(
        self,
        request: &Request,
        mut response: Response,
    ) -> Result<Response, ErrorResponse> {
        let protocols: Vec<_> = request
            .headers()
            .get_all("sec-websocket-protocol")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .collect();
        let selected = if protocols.contains(&"binary") {
            Some("binary")
        } else if protocols.contains(&"base64") {
            *self.0 = true;
            Some("base64")
        } else {
            None
        };
        if let Some(protocol) = selected {
            response.headers_mut().insert(
                "sec-websocket-protocol",
                protocol.parse().expect("literal protocol"),
            );
        } else if !protocols.is_empty() {
            return Err(tungstenite::http::Response::builder()
                .status(400)
                .body(Some("Supported WebSocket protocols: binary, base64".into()))
                .expect("literal response"));
        }
        Ok(response)
    }
}

fn close(browser: &mut WebSocket<Browser>, code: CloseCode) {
    // Bound only the closing write, not the lifetime of an idle desktop.
    let _ = browser.get_mut().socket.set_nonblocking(false);
    let _ = browser
        .get_mut()
        .socket
        .set_write_timeout(Some(HTTP_TIMEOUT));
    let _ = browser.close(Some(CloseFrame {
        code,
        reason: "".into(),
    }));
}

fn relay(mut browser: WebSocket<Browser>, mut vnc: TcpStream, base64: bool) -> Result<(), Error> {
    browser.get_mut().socket.set_nonblocking(true)?;
    vnc.set_nonblocking(true)?;
    let mut pending = Vec::new();
    let mut written = 0;
    let mut bytes = [0; CHUNK];
    loop {
        let mut activity = false;
        let blocked = match browser.flush() {
            Ok(()) => false,
            Err(error) if would_block(&error) => true,
            Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if written < pending.len() {
            match vnc.write(&pending[written..]) {
                Ok(0) => return Err("VNC connection closed while writing".into()),
                Ok(count) => {
                    written += count;
                    activity = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                Err(error) => return Err(error.into()),
            }
        }
        if written == pending.len() {
            pending.clear();
            written = 0;
            match browser.read() {
                Ok(Message::Binary(data)) if !base64 => {
                    pending = data.to_vec();
                    activity = true;
                }
                Ok(Message::Text(data)) if base64 => {
                    match BASE64.decode(data.as_bytes()) {
                        Ok(data) => pending = data,
                        Err(_) => {
                            close(&mut browser, CloseCode::Invalid);
                            return Ok(());
                        }
                    }
                    activity = true;
                }
                Ok(Message::Ping(_) | Message::Pong(_)) => activity = true,
                Ok(Message::Close(_)) => {
                    let _ = browser.flush();
                    return Ok(());
                }
                Ok(_) => {
                    close(&mut browser, CloseCode::Unsupported);
                    return Ok(());
                }
                Err(error) if would_block(&error) => (),
                Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                    return Ok(());
                }
                Err(error) => {
                    close(
                        &mut browser,
                        if matches!(error, tungstenite::Error::Utf8(_)) {
                            CloseCode::Invalid
                        } else {
                            CloseCode::Protocol
                        },
                    );
                    return Err(error.into());
                }
            }
        }
        // One VNC chunk at a time supplies backpressure. Tungstenite retains a
        // partially written frame; do not resend it or read the next VNC chunk
        // until its buffered write has drained.
        if !blocked {
            match vnc.read(&mut bytes) {
                Ok(0) => {
                    close(&mut browser, CloseCode::Normal);
                    return Ok(());
                }
                Ok(count) => {
                    let message = if base64 {
                        Message::Text(BASE64.encode(&bytes[..count]).into())
                    } else {
                        Message::Binary(bytes[..count].to_vec().into())
                    };
                    match browser.send(message) {
                        Ok(()) => (),
                        Err(error) if would_block(&error) => (),
                        Err(error) => return Err(error.into()),
                    }
                    activity = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                Err(error) => return Err(error.into()),
            }
        }
        if activity {
            continue;
        }
        let mut descriptors = [
            libc::pollfd {
                fd: browser.get_ref().socket.as_raw_fd(),
                events: libc::POLLRDHUP
                    | (if pending.is_empty() { libc::POLLIN } else { 0 })
                    | (if blocked { libc::POLLOUT } else { 0 }),
                revents: 0,
            },
            libc::pollfd {
                fd: if blocked && pending.is_empty() {
                    -1
                } else {
                    vnc.as_raw_fd()
                },
                events: (if !blocked { libc::POLLIN } else { 0 })
                    | (if !pending.is_empty() {
                        libc::POLLOUT
                    } else {
                        0
                    }),
                revents: 0,
            },
        ];
        // The descriptors refer to live sockets held by this connection. No
        // other thread closes them, and poll does not retain the stack pointer.
        if unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        if descriptors[0].revents
            & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
            != 0
        {
            return Ok(());
        }
    }
}

fn connection(mut socket: TcpStream, root: &Path, target: SocketAddr) -> Result<(), Error> {
    socket.set_read_timeout(Some(HTTP_TIMEOUT))?;
    socket.set_write_timeout(Some(HTTP_TIMEOUT))?;
    let mut reader = BufReader::new(socket);
    let mut header = Vec::new();
    loop {
        let start = header.len();
        // take() prevents an unterminated header from allocating without bound.
        let count = reader
            .by_ref()
            .take((HEADER_BYTES + 1 - start) as u64)
            .read_until(b'\n', &mut header)?;
        if count == 0 {
            return Ok(());
        }
        if header.len() > HEADER_BYTES {
            return Ok(http_reply(
                reader.get_mut(),
                "431 Request Header Fields Too Large",
                "Header too large\n",
            )?);
        }
        if &header[start..] == b"\r\n" {
            break;
        }
    }
    let text = std::str::from_utf8(&header)?;
    let mut lines = text.split("\r\n");
    let mut request = lines
        .next()
        .ok_or("missing HTTP request")?
        .split_whitespace();
    let method = request.next().ok_or("missing HTTP method")?;
    let path = request.next().ok_or("missing HTTP path")?;
    if !matches!(request.next(), Some("HTTP/1.0" | "HTTP/1.1")) || request.next().is_some() {
        return Ok(http_reply(
            reader.get_mut(),
            "400 Bad Request",
            "Invalid HTTP request\n",
        )?);
    }
    let upgrade = lines
        .filter_map(|line| line.split_once(':'))
        .any(|(name, value)| {
            name.eq_ignore_ascii_case("upgrade") && value.trim().eq_ignore_ascii_case("websocket")
        });
    if !upgrade {
        return Ok(serve_asset(reader.get_mut(), root, method, path)?);
    }
    let vnc = match TcpStream::connect_timeout(&target, HTTP_TIMEOUT) {
        Ok(vnc) => vnc,
        Err(_) => {
            return Ok(http_reply(
                reader.get_mut(),
                "502 Bad Gateway",
                "VNC target unavailable\n",
            )?);
        }
    };
    let mut base64 = false;
    header.extend_from_slice(reader.buffer());
    socket = reader.into_inner();
    let browser = Browser {
        prefix: Cursor::new(header),
        socket,
    };
    let mut config = WebSocketConfig::default();
    // Websockify is a byte transport. Preserve its accepted message sizes
    // rather than impose Tungstenite's optional application-level limits.
    config.max_message_size = None;
    config.max_frame_size = None;
    config.write_buffer_size = 0;
    let mut browser =
        tungstenite::accept_hdr_with_config(browser, VncProtocol(&mut base64), Some(config))
            .map_err(|error| error.to_string())?;
    browser.get_mut().socket.set_read_timeout(None)?;
    browser.get_mut().socket.set_write_timeout(None)?;
    relay(browser, vnc, base64)
}

pub fn run(args: &[OsString]) -> Result<i32, Error> {
    if matches!(args, [check] if check == "check") {
        return Ok(0);
    }
    let [web, root, listen, target] = args else {
        return Err("usage: safeyolo-guest desktop-bridge --web DIRECTORY LOOPBACK:PORT VNC_LOOPBACK:PORT | check".into());
    };
    if web != "--web" {
        return Err("desktop-bridge requires --web DIRECTORY".into());
    }
    let root = Arc::new(PathBuf::from(root).canonicalize()?);
    if !root.join("vnc.html").is_file() {
        return Err("noVNC web assets (vnc.html) are missing".into());
    }
    let listen: SocketAddr = listen
        .to_str()
        .ok_or("invalid desktop listen address")?
        .parse()?;
    let target: SocketAddr = target
        .to_str()
        .ok_or("invalid VNC target address")?
        .parse()?;
    // This guest-only bridge is reached through the authenticated host preview.
    if !listen.ip().is_loopback() || !target.ip().is_loopback() {
        return Err("desktop bridge endpoints must use loopback".into());
    }
    let listener = listen_socket(listen)?;
    for stream in listener.incoming() {
        let stream = stream?;
        let root = Arc::clone(&root);
        thread::Builder::new()
            .name("desktop-connection".into())
            .spawn(move || {
                if let Err(error) = connection(stream, &root, target) {
                    eprintln!("desktop connection failed: {error}");
                }
            })?;
    }
    Ok(0)
}
