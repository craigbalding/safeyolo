use super::*;

fn host(host: &str) -> &'static str {
    if host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    {
        "localhost"
    } else {
        "*"
    }
}

fn transport(transport: NetworkTransport) -> &'static str {
    match transport {
        NetworkTransport::Tcp => "tcp",
        NetworkTransport::Udp => "udp",
    }
}

pub(super) fn validate(e: &Execution) -> Result<(), Refusal> {
    require(
        e.network.destinations.is_empty() && e.network.listeners.is_empty()
            || e.broader.contains(&BroaderBound::NetworkIpc),
        RefusalCode::Unavailable,
        "macOS sockets require explicit broader network_ipc authority: Seatbelt enforces transport, direction and port with loopback/all-address classes, not an exact IP, interface, hostname or inbound peer",
    )
}

pub(super) fn profile(e: &Execution) -> String {
    let mut profile = String::new();
    for destination in &e.network.destinations {
        profile.push_str(&format!(
            "(allow network-outbound (remote {} \"{}:{}\"))",
            transport(destination.transport),
            host(&destination.host),
            destination.port
        ));
    }
    for listener in &e.network.listeners {
        let port = if listener.port == 0 {
            "*".into()
        } else {
            listener.port.to_string()
        };
        profile.push_str(&format!(
            "(allow network-bind network-inbound (local {} \"{}:{}\"))",
            transport(listener.transport),
            host(&listener.address.to_string()),
            port
        ));
    }
    for (kind, name, protocol) in [
        ("tcp", "SOCK_STREAM", "IPPROTO_TCP"),
        ("udp", "SOCK_DGRAM", "IPPROTO_UDP"),
    ] {
        if e.network
            .destinations
            .iter()
            .any(|d| transport(d.transport) == kind)
            || e.network
                .listeners
                .iter()
                .any(|l| transport(l.transport) == kind)
        {
            profile.push_str(&format!("(allow system-socket (require-all (require-any (socket-domain AF_INET) (socket-domain AF_INET6)) (socket-type {name}) (require-any (socket-protocol 0) (socket-protocol {protocol}))))"));
        }
    }
    profile
}

pub(crate) fn disclosure(operation: &Operation) -> Vec<String> {
    let e = &operation.execution;
    if e.network.destinations.is_empty() && e.network.listeners.is_empty() {
        return vec!["Seatbelt denies ordinary workload sockets and Mach lookups; only a separately validated fixed native helper can receive its named exception.".into()];
    }
    vec![
        format!("Seatbelt TCP/UDP outbound selectors {:?}; bind/inbound selectors {:?}. Connecting does not confer listener authority; a listener does not confer arbitrary outbound authority.", e.network.destinations, e.network.listeners),
        "EXPLICIT BROADER NETWORK/IPC: each loopback selector permits the IPv4/IPv6 loopback class at its selected port; every other address or hostname permits all target-account addresses at that port. A listener port of zero permits any local port, not only kernel allocation. Exact IP/interface, hostname, address-family and inbound-peer restrictions are not enforced. Raw sockets, Unix sockets and Mach lookups remain denied to ordinary programs.".into(),
        "The workload uses the target's network context, outside the issuing proxy. DNS is not implicitly granted. Binding, application readiness, publication and audience reach are separate; routing/firewall/forwarding, authentication, application TLS and VPN/tunnel protection are unobserved unless separately established. UDP replies require matching outbound authority.".into(),
    ]
}
