use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::net::TcpListener;

pub async fn bind() -> (TcpListener, SocketAddr) {
    let listener = match TcpListener::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).await {
        Ok(listener) => listener,
        Err(error) if error.kind() == ErrorKind::AddrNotAvailable => {
            TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
                .await
                .expect("bind IPv6 owned test endpoint")
        }
        Err(error) => panic!("bind owned test endpoint: {error}"),
    };
    let address = listener
        .local_addr()
        .expect("read owned test endpoint address");
    assert_ne!(
        address.ip(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "owned test endpoint must stay outside default loopback exclusions"
    );
    (listener, address)
}
