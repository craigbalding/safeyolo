//! Verify the selected node's own address, never a subnet-router destination.
use super::*;
use std::net::IpAddr;

fn selected_node<'a>(
    status: &'a Value,
    ip: IpAddr,
    node_id: &str,
    self_only: bool,
) -> Result<(&'a Value, bool), Error> {
    if status["BackendState"] != "Running" || status["TUN"] != true {
        return Err("Tailscale NATS needs a running host Tailscale network interface; check tailscale status as the SafeYolo host user".into());
    }
    let matches = |node: &Value| {
        node["ID"].as_str() == Some(node_id)
            && node["KeyExpired"] != true
            && node["TailscaleIPs"].as_array().is_some_and(|ips| {
                ips.iter().any(|value| {
                    value
                        .as_str()
                        .and_then(|value| value.parse::<IpAddr>().ok())
                        == Some(ip)
                })
            })
    };
    if matches(&status["Self"]) {
        return Ok((&status["Self"], true));
    }
    if !self_only
        && let Some(node) = status["Peer"]
            .as_object()
            .and_then(|peers| peers.values().find(|node| matches(node)))
    {
        return Ok((node, false));
    }
    Err("NATS endpoint is not an address assigned to the selected Tailscale node; use that node's own Tailscale IP and stable ID, or use TLS for a subnet-router onward leg".into())
}

fn local_interface(status: &Value) -> Result<String, Error> {
    struct Interfaces(*mut libc::ifaddrs);
    impl Drop for Interfaces {
        fn drop(&mut self) {
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
    let mut first = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let interfaces = Interfaces(first);
    let own_ips: Vec<IpAddr> = status["Self"]["TailscaleIPs"]
        .as_array()
        .ok_or("Tailscale self addresses unavailable")?
        .iter()
        .filter_map(|ip| ip.as_str()?.parse().ok())
        .collect();
    let mut current = interfaces.0;
    while !current.is_null() {
        // The address family selects the sockaddr layout. getifaddrs owns all
        // pointed-to bytes until Interfaces is dropped.
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null() && !entry.ifa_name.is_null() {
            let family = unsafe { (*entry.ifa_addr).sa_family as libc::c_int };
            let ip = match family {
                libc::AF_INET => Some(IpAddr::from(
                    unsafe {
                        (*(entry.ifa_addr as *const libc::sockaddr_in))
                            .sin_addr
                            .s_addr
                    }
                    .to_ne_bytes(),
                )),
                libc::AF_INET6 => Some(IpAddr::from(unsafe {
                    (*(entry.ifa_addr as *const libc::sockaddr_in6))
                        .sin6_addr
                        .s6_addr
                })),
                _ => None,
            };
            if ip.is_some_and(|ip| own_ips.contains(&ip)) {
                return Ok(unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }
                    .to_str()?
                    .to_owned());
            }
        }
        current = entry.ifa_next;
    }
    Err("the selected Tailscale host has no assigned local network interface; no NATS credentials sent".into())
}

async fn route_interface(ip: IpAddr) -> Result<String, Error> {
    #[cfg(target_os = "linux")]
    {
        let output = tokio::process::Command::new("ip")
            .args(["-j", "route", "get", &ip.to_string()])
            .kill_on_drop(true)
            .output()
            .await?;
        if !output.status.success() {
            return Err("cannot verify the NATS endpoint's host route with ip route get".into());
        }
        let routes: Value = serde_json::from_slice(&output.stdout)?;
        Ok(routes[0]["dev"]
            .as_str()
            .ok_or("NATS route has no network interface")?
            .to_owned())
    }
    #[cfg(target_os = "macos")]
    {
        let output = tokio::process::Command::new("/sbin/route")
            .args(["-n", "get", &ip.to_string()])
            .kill_on_drop(true)
            .output()
            .await?;
        if !output.status.success() {
            return Err("cannot verify the NATS endpoint's host route with route get".into());
        }
        String::from_utf8(output.stdout)?
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("interface:")
                    .map(|value| value.trim().to_owned())
            })
            .ok_or_else(|| "NATS route has no network interface".into())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = ip;
        Err(
            "Tailscale NATS host-route verification is unavailable on this platform; use TLS"
                .into(),
        )
    }
}

pub(crate) async fn verify(ip: IpAddr, node_id: &str, self_only: bool) -> Result<Value, Error> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let status = crate::tailnet::tailscale_json(&["status", "--json"]).await?;
        let (node, local) = selected_node(&status, ip, node_id, self_only)?;
        let interface = local_interface(&status)?;
        let local_address = status["Self"]["TailscaleIPs"].as_array()
            .and_then(|addresses|addresses.iter().filter_map(|value|value.as_str()?.parse::<IpAddr>().ok()).find(|address|address.is_ipv4()==ip.is_ipv4()))
            .ok_or("the local Tailscale node has no address for the selected endpoint's IP family")?;
        if !local {
            if route_interface(ip).await? != interface {
                return Err("NATS endpoint does not route through the host's Tailscale interface; credentials withheld. Restore that route or select TLS".into());
            }
            // TSMP traverses WireGuard and accepts DERP. It does not infer
            // protection from private/CGNAT ranges or require a direct UDP path.
            let output = tokio::process::Command::new("tailscale").args(["ping", "--tsmp", "--c=1", "--timeout=2s", &ip.to_string()]).kill_on_drop(true).output().await?;
            if !output.status.success() { return Err("selected Tailscale node is unreachable through WireGuard; restore its protected path before retrying NATS".into()); }
        }
        Ok(json!({"verified":true,"node_id":node_id,"address":ip,"local":local,"local_address":local_address,"interface":interface,"dns_name":node["DNSName"]}))
    }).await.map_err(|_| "Tailscale NATS protection verification timed out; credentials withheld")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_address_or_subnet_route_does_not_identify_a_node() {
        let mut status = json!({"BackendState":"Running","TUN":true,"Self":{"ID":"self","TailscaleIPs":["100.64.0.1"]},
            "Peer":{"key":{"ID":"peer","TailscaleIPs":["100.64.0.2"],"PrimaryRoutes":["192.168.0.0/24"]}}});
        assert!(selected_node(&status, "100.64.0.2".parse().unwrap(), "peer", false).is_ok());
        for (ip, node, local) in [
            ("192.168.0.2", "peer", false),
            ("100.64.0.3", "peer", false),
            ("100.64.0.2", "wrong", false),
            ("100.64.0.2", "peer", true),
        ] {
            assert!(selected_node(&status, ip.parse().unwrap(), node, local).is_err());
        }
        status["BackendState"] = json!("Stopped");
        assert!(selected_node(&status, "100.64.0.2".parse().unwrap(), "peer", false).is_err());
        status["BackendState"] = json!("Running");
        status["TUN"] = json!(false);
        assert!(selected_node(&status, "100.64.0.2".parse().unwrap(), "peer", false).is_err());
    }
}
