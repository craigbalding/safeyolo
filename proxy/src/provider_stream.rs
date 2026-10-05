//! One authorized stream to a named provider sandbox and guest port.

use std::io;

use crate::tunnels::BoxStream;

pub(crate) async fn open(config: &crate::Config, agent: &str, port: u16) -> io::Result<BoxStream> {
    let stream = crate::host_platform::open_guest_port(agent, port);
    if let Some(path) = &config.native_config_path {
        return crate::host_platform::in_config(path.clone(), stream).await;
    }
    stream.await
}
