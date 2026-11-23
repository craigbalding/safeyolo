//! TLS protects remote target identity and request confidentiality. Issuer
//! signatures and native grants still authorize every protocol action.
use crate::{
    server::{self, Configuration, DeadlineStream},
    *,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    fs::File,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub listen: SocketAddr,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

fn unavailable(error: impl std::fmt::Display) -> Refusal {
    native::unavailable(format!("host HTTPS: {error}"))
}

impl Listener {
    pub(crate) fn configuration(&self) -> Result<Arc<rustls::ServerConfig>, Refusal> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        #[cfg(unix)]
        {
            server::protected(&self.certificate, false)?;
            server::protected(&self.private_key, false)?;
            require(
                std::fs::metadata(&self.private_key)
                    .map_err(unavailable)?
                    .mode()
                    & 0o077
                    == 0,
                RefusalCode::Unavailable,
                "TLS private key must be private to the executor account",
            )?;
        }
        #[cfg(windows)]
        {
            crate::windows::security::protected(&self.certificate, false)?;
            crate::windows::security::protected(&self.private_key, false)?;
        }
        let certificates =
            CertificateDer::pem_reader_iter(File::open(&self.certificate).map_err(unavailable)?)
                .collect::<Result<Vec<_>, _>>()
                .map_err(unavailable)?;
        let key = PrivateKeyDer::from_pem_file(&self.private_key).map_err(unavailable)?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(unavailable)?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(unavailable)?;
        Ok(Arc::new(config))
    }
}

// rustls can perform several socket reads inside one application read. Carry
// the absolute deadline through those calls, including a fragmented handshake.
struct DeadlineTcp {
    socket: TcpStream,
    read_until: Cell<Instant>,
    write_until: Cell<Instant>,
}
impl DeadlineTcp {
    fn new(socket: TcpStream, deadline: Instant) -> std::io::Result<Self> {
        // Windows accepts inherit the listener's nonblocking mode. TLS workers
        // use blocking I/O with the remaining absolute deadline on each call.
        socket.set_nonblocking(false)?;
        Ok(Self {
            socket,
            read_until: Cell::new(deadline),
            write_until: Cell::new(deadline),
        })
    }
}
fn remaining(until: Instant) -> std::io::Result<Duration> {
    until
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "host HTTPS deadline elapsed")
        })
}
fn until(value: Option<Duration>) -> std::io::Result<Instant> {
    value
        .and_then(|d| Instant::now().checked_add(d))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "host HTTPS requires a finite deadline",
            )
        })
}
impl Read for DeadlineTcp {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.socket
            .set_read_timeout(Some(remaining(self.read_until.get())?))?;
        self.socket.read(bytes)
    }
}
impl Write for DeadlineTcp {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.socket
            .set_write_timeout(Some(remaining(self.write_until.get())?))?;
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}
impl DeadlineStream for rustls::StreamOwned<rustls::ServerConnection, DeadlineTcp> {
    fn set_read_timeout(&mut self, value: Option<Duration>) -> std::io::Result<()> {
        self.sock.read_until.set(until(value)?);
        Ok(())
    }
    fn set_write_timeout(&mut self, value: Option<Duration>) -> std::io::Result<()> {
        self.sock.write_until.set(until(value)?);
        Ok(())
    }
}

pub(crate) fn serve(
    config: PathBuf,
    state: PathBuf,
    settings: Configuration,
) -> Result<(), Refusal> {
    let mut ledger = Ledger::open(&state, &settings.target.target_id, settings.ledger.clone())?;
    let settings = server::reconcile_configuration(&config, &state)?;
    let listener_config = settings
        .https
        .as_ref()
        .ok_or_else(|| unavailable("listener absent"))?;
    let tls = listener_config.configuration()?;
    settings.native.reconcile(&mut ledger)?;
    let listener = TcpListener::bind(listener_config.listen).map_err(unavailable)?;
    #[cfg(windows)]
    listener.set_nonblocking(true).map_err(unavailable)?;
    let ledger = Arc::new(Mutex::new(ledger));
    let (tx, rx) = mpsc::sync_channel::<TcpStream>(0);
    let rx = Arc::new(Mutex::new(rx));
    let mut workers = Vec::new();
    for _ in 0..settings.connections {
        let (rx, tls, config, state, original, ledger) = (
            rx.clone(),
            tls.clone(),
            config.clone(),
            state.clone(),
            settings.clone(),
            ledger.clone(),
        );
        workers.push(std::thread::spawn(move || {
            loop {
                let socket = match rx.lock().expect("HTTPS connection queue").recv() {
                    Ok(socket) => socket,
                    Err(_) => break,
                };
                let result = (|| {
                    let deadline = Instant::now()
                        .checked_add(Duration::from_secs(original.connection_timeout_seconds))
                        .ok_or_else(|| unavailable("deadline exceeds clock range"))?;
                    let stream = rustls::StreamOwned::new(
                        rustls::ServerConnection::new(tls.clone()).map_err(unavailable)?,
                        DeadlineTcp::new(socket, deadline).map_err(unavailable)?,
                    );
                    server::connection(stream, &config, &state, &original, &ledger)
                })();
                if let Err(error) = result {
                    eprintln!("{error}");
                }
            }
        }));
    }
    eprintln!(
        "target {} ready on https://{}",
        settings.target.target_id,
        listener.local_addr().map_err(unavailable)?
    );
    #[cfg(windows)]
    crate::windows::service::ready()?;
    let result = loop {
        #[cfg(windows)]
        if crate::windows::service::stopping() {
            break Ok(());
        }
        match listener.accept() {
            Ok((socket, _)) => {
                if let Err(error) = tx.send(socket) {
                    break Err(unavailable(error));
                }
            }
            #[cfg(windows)]
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => break Err(unavailable(error)),
        }
    };
    drop(tx);
    for worker in workers {
        worker
            .join()
            .map_err(|_| unavailable("HTTPS connection worker failed"))?;
    }
    #[cfg(windows)]
    while crate::windows::transport::executing() {
        std::thread::sleep(Duration::from_millis(10));
    }
    result
}

pub(crate) fn private_file(path: &Path, bytes: &[u8]) -> Result<(), Refusal> {
    #[cfg(windows)]
    let mut file = crate::windows::security::create_private_file(path)?;
    #[cfg(not(windows))]
    let mut file = {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path).map_err(unavailable)?
    };
    file.write_all(bytes).map_err(unavailable)?;
    file.sync_all().map_err(unavailable)
}

pub(crate) fn command(args: &[String]) -> Result<bool, Refusal> {
    if args.first().is_none_or(|s| s != "tls-create") {
        return Ok(false);
    }
    require(
        args.len() == 5 && args[1] == "--name" && args[3] == "--directory",
        RefusalCode::Arguments,
        "tls-create --name DNS_NAME --directory PRIVATE_DIRECTORY",
    )?;
    let directory = Path::new(&args[4]);
    #[cfg(unix)]
    server::protected(directory, true)?;
    #[cfg(windows)]
    crate::windows::security::protected(directory, true)?;
    let generated =
        rcgen::generate_simple_self_signed(vec![args[2].clone()]).map_err(unavailable)?;
    let certificate = directory.join("target.pem");
    let private_key = directory.join("target-key.pem");
    require(
        !certificate.try_exists().map_err(unavailable)?
            && !private_key.try_exists().map_err(unavailable)?,
        RefusalCode::Unavailable,
        "TLS files already exist; select a new private directory for rotation",
    )?;
    let secret = zeroize::Zeroizing::new(generated.signing_key.serialize_pem());
    private_file(&private_key, secret.as_bytes())?;
    private_file(&certificate, generated.cert.pem().as_bytes())?;
    let fingerprint = ring::digest::digest(&ring::digest::SHA256, generated.cert.der());
    println!(
        "{}",
        serde_json::json!({"certificate":certificate,"private_key":private_key,
        "certificate_sha256":fingerprint.as_ref().iter().map(|b|format!("{b:02x}")).collect::<String>(),
        "name":args[2],"permission_granted":false})
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;

    fn pair() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = generated.cert.der().clone();
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                .into();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        (Arc::new(server), Arc::new(client))
    }

    #[test]
    fn remote_tls_authenticates_selected_name_and_preserves_http_bytes() {
        for name in ["localhost", "another.invalid"] {
            let (server, client) = pair();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let worker = std::thread::spawn(move || {
                let socket = listener.accept().unwrap().0;
                // Reproduce Windows' inherited mode on every test platform.
                socket.set_nonblocking(true).unwrap();
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(server).unwrap(),
                    DeadlineTcp::new(socket, deadline).unwrap(),
                );
                let mut request = [0; 4];
                if stream.read_exact(&mut request).is_err() {
                    return;
                }
                assert_eq!(&request, b"POST");
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                    .unwrap();
                stream.flush().unwrap();
            });
            let socket = TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            // The server must wait for handshake/application bytes, rather
            // than close the accepted socket with WouldBlock.
            std::thread::sleep(Duration::from_millis(25));
            let mut stream = rustls::StreamOwned::new(
                rustls::ClientConnection::new(client, ServerName::try_from(name).unwrap()).unwrap(),
                socket,
            );
            let result = stream.write_all(b"POST");
            if name == "localhost" {
                result.unwrap();
                let mut body = [0; 40];
                stream.read_exact(&mut body).unwrap();
                assert!(body.ends_with(b"{}"));
            } else {
                assert!(result.is_err(), "another target name must not authenticate");
            }
            worker.join().unwrap();
        }
    }

    #[test]
    fn incomplete_tls_handshake_obeys_the_whole_connection_deadline() {
        let (server, _) = pair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let held = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let socket = listener.accept().unwrap().0;
        let deadline = Instant::now() + Duration::from_millis(40);
        let mut stream = rustls::StreamOwned::new(
            rustls::ServerConnection::new(server).unwrap(),
            DeadlineTcp::new(socket, deadline).unwrap(),
        );
        let error = stream.read(&mut [0]).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        assert!(Instant::now().duration_since(deadline) < Duration::from_secs(1));
        drop(held);
    }
}
