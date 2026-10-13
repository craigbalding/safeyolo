//! A fixed, read-only VNC greeting check inside the guest network namespace.

use serde_json::{Value, json};
use std::{
    io::{self, Read},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    time::{Duration, Instant},
};

pub(crate) fn check(address: SocketAddr) -> Value {
    let started = Instant::now();
    let (tcp, greeting) = match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
        Ok(mut socket) => {
            let mut bytes = [0; 12];
            // A slow byte stream must not renew the greeting's total deadline.
            let deadline = Instant::now() + Duration::from_secs(3);
            let result = (|| {
                let mut count = 0;
                while count < bytes.len() {
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .filter(|value| !value.is_zero())
                        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
                    socket.set_read_timeout(Some(remaining))?;
                    let size = socket.read(&mut bytes[count..])?;
                    if size == 0 {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                    }
                    count += size;
                }
                Ok(())
            })();
            let greeting = match result {
                Ok(_)
                    if &bytes[..4] == b"RFB "
                        && bytes[7] == b'.'
                        && bytes[11] == b'\n'
                        && bytes[4..7]
                            .iter()
                            .chain(&bytes[8..11])
                            .all(u8::is_ascii_digit) =>
                {
                    "valid"
                }
                Ok(_) => "invalid",
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    "timeout"
                }
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => "closed",
                Err(_) => "unknown",
            };
            // Drop the socket without completing authentication or requesting a screen.
            ("accepted", greeting)
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            ("refused", "not_checked")
        }
        Err(error) if error.kind() == io::ErrorKind::TimedOut => ("timeout", "not_checked"),
        Err(_) => ("unknown", "not_checked"),
    };
    json!({"schema_version":1,"tcp":tcp,"greeting":greeting,"duration_ms":started.elapsed().as_millis()})
}

pub(crate) fn run() -> Result<i32, crate::Error> {
    println!("{}", check((Ipv4Addr::LOCALHOST, 5900).into()));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, net::TcpListener, thread};

    #[test]
    fn greeting_requires_the_exact_bounded_protocol_shape() {
        for (banner, expected) in [(b"RFB 003.008\n", "valid"), (b"HTTP/1.1 200", "invalid")] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket.write_all(banner).unwrap();
                // The probe must close without authentication or framebuffer data.
                let mut byte = [0];
                assert_eq!(socket.read(&mut byte).unwrap(), 0);
            });
            let value = check(address);
            assert_eq!(value["tcp"], "accepted");
            assert_eq!(value["greeting"], expected);
            server.join().unwrap();
        }
    }

    #[test]
    fn silent_listener_is_distinct_from_refusal_and_eof() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).unwrap(), 0);
        });
        let value = check(address);
        assert_eq!(value["tcp"], "accepted");
        assert_eq!(value["greeting"], "timeout");
        assert!(value["duration_ms"].as_u64().unwrap() < 5000);
        server.join().unwrap();
        assert_eq!(check(address)["tcp"], "refused");

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            drop(listener.accept().unwrap());
        });
        assert_eq!(check(address)["greeting"], "closed");
        server.join().unwrap();
    }

    #[test]
    fn partial_greeting_does_not_extend_the_deadline() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            for byte in b"RFB 003.008\n" {
                if socket.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(650));
            }
        });
        let value = check(address);
        assert_eq!(value["tcp"], "accepted");
        assert_eq!(value["greeting"], "timeout");
        assert!(value["duration_ms"].as_u64().unwrap() < 4000);
        server.join().unwrap();
    }
}
