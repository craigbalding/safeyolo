//! One authorized stream to a named provider sandbox and guest port.

use std::io;

use crate::tunnels::BoxStream;

pub(crate) async fn open(agent: &str, port: u16) -> io::Result<BoxStream> {
    crate::host_platform::open_guest_port(agent, port).await
}
