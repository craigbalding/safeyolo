//! Admin-port containment, including the actual bound listener.
//!
//! The textual rule preserves AdminShield._is_local and its extra-port grammar.
//! The separate endpoint check closes proven alias access to this process's
//! listener. It does not classify remote addresses as local by port alone.

use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use crate::{policy::python_whitespace, python_text::decimal};

/// Source-visible terminal request/CONNECT response and metadata. The HTTP
/// owner supplies framing (including Content-Length) and records the markers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub status: u16,
    pub body: &'static [u8],
    pub headers: &'static [(&'static str, &'static str)],
    pub blocked_by: &'static str,
    pub block_reason: &'static str,
    pub transport_error: &'static str,
}

pub const REJECTION: Rejection = Rejection {
    status: 403,
    body: b"{\"error\": \"Forbidden\", \"message\": \"Admin API not accessible through proxy\"}",
    headers: &[
        ("Content-Type", "application/json"),
        ("X-Blocked-By", "admin-shield"),
    ],
    blocked_by: "admin-shield",
    block_reason: "admin_port_access",
    transport_error: "SafeYolo: admin API not accessible through proxy",
};

/// Content-free equivalents of errors from Python's isdigit()/int() sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    NonDecimalDigit,
    IntegerDigitLimit,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonDecimalDigit => "admin shield extra port contains a non-decimal digit",
            Self::IntegerDigitLimit => {
                "admin shield extra port exceeds the Python integer digit limit"
            }
        })
    }
}
impl std::error::Error for ConfigError {}

#[derive(Clone, Debug)]
pub struct AdminShield {
    ports: BTreeSet<u16>,
}

impl AdminShield {
    /// Parse the source option once for an accepted configuration snapshot.
    /// Source hooks parse on each call and keep the configured port protected
    /// if an extra entry is invalid. Native rejects that candidate before it
    /// can replace the current snapshot.
    pub fn new(admin_port: u16, extra_ports: &str) -> Result<Self, ConfigError> {
        let mut ports = BTreeSet::from([admin_port]);
        for token in extra_ports.split(',') {
            let token = token.trim_matches(python_whitespace);
            if token.is_empty() || !token.chars().all(is_digit) {
                continue;
            }
            let mut digits = 0usize;
            let mut number = 0u32;
            for character in token.chars() {
                let digit = decimal_digit(character).ok_or(ConfigError::NonDecimalDigit)?;
                digits += 1;
                number = number.saturating_mul(10).saturating_add(digit);
            }
            // Pinned Python 3.12 uses its default limit. Values beyond u16 but
            // within this grammar remain accepted; they cannot equal a socket
            // port and need no stored representation in this transport seam.
            if digits > 4300 {
                return Err(ConfigError::IntegerDigitLimit);
            }
            if let Ok(port) = u16::try_from(number) {
                ports.insert(port);
            }
        }
        Ok(Self { ports })
    }

    /// Run at request/CONNECT admission and for the immediate egress route.
    /// Hosts here have the source request/server-address spelling. No resolver
    /// or broader loopback-range rule is hidden inside this check.
    pub fn blocks_host(&self, host: &str, port: u16) -> bool {
        self.protects_port(port) && is_local(host)
    }

    /// Claim numeric spellings of the protected local endpoints during request
    /// admission. The egress owner still checks every resolved address. This
    /// earlier check covers only the historical IPv4 numeric grammar that the
    /// system resolver accepts, so credential admission cannot win before the
    /// bound-port shield for an equivalent local authority.
    pub fn blocks_request_destination(&self, host: &str, port: u16) -> bool {
        self.blocks_host(host, port)
            || self.protects_port(port)
                && numeric_address(host).is_some_and(is_protected_local_address)
    }

    /// Whether this route's port needs the configured local-endpoint check.
    /// The actual listener's bound port remains independently protected even
    /// when startup port zero or later option changes differ from this set.
    pub fn protects_port(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }

    /// Add the process-local operator listener after an ephemeral bind.
    /// Startup port zero is a request for an OS-selected port, so the bound
    /// port must be retained in the same shield used by request admission.
    pub(crate) fn protect_bound_port(&mut self, bound: SocketAddr) {
        self.ports.insert(bound.port());
    }

    /// Apply the source's exact local IP set to each resolved immediate-route
    /// candidate. Extra ports protect existing local control endpoints too.
    /// This closes their alias hole without classifying all loopback IPs or
    /// remote addresses on these ports as local.
    pub fn blocks_address(&self, address: SocketAddr) -> bool {
        self.protects_port(address.port()) && is_protected_local_address(address.ip())
    }
}

fn is_local(host: &str) -> bool {
    // Python lower() cannot turn other Unicode scalars into any of the ASCII
    // letters in "localhost". Prefix scalars do not affect its ASCII suffix.
    // One DNS root dot is the same local name, including under a parent route
    // where this process does not resolve the origin itself.
    let host = host.strip_suffix('.').unwrap_or(host);
    ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
        .iter()
        .any(|local| host.eq_ignore_ascii_case(local))
        || host
            .as_bytes()
            .get(host.len().saturating_sub(10)..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(b".localhost"))
}

fn is_protected_local_address(address: IpAddr) -> bool {
    match normalize_mapped(address) {
        IpAddr::V4(ip) => ip == Ipv4Addr::LOCALHOST || ip == Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(ip) => ip == std::net::Ipv6Addr::LOCALHOST,
    }
}

fn numeric_address(host: &str) -> Option<IpAddr> {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    host.parse()
        .ok()
        .or_else(|| legacy_ipv4_address(host).map(IpAddr::V4))
}

/// Parse the single-, two-, three-, and four-part IPv4 forms accepted by the
/// system resolver. A leading `0x` selects hexadecimal and a leading zero
/// selects octal, matching the forms that can otherwise resolve to the bound
/// local listener after credential admission.
fn legacy_ipv4_address(host: &str) -> Option<Ipv4Addr> {
    let parts = host
        .split('.')
        .map(legacy_ipv4_component)
        .collect::<Option<Vec<_>>>()?;
    let value = match parts.as_slice() {
        [value] => *value,
        [first, rest] if *first <= u8::MAX.into() && *rest <= 0x00ff_ffff => first << 24 | rest,
        [first, second, rest]
            if *first <= u8::MAX.into()
                && *second <= u8::MAX.into()
                && *rest <= u16::MAX.into() =>
        {
            first << 24 | second << 16 | rest
        }
        [first, second, third, fourth]
            if [first, second, third, fourth]
                .into_iter()
                .all(|part| *part <= u8::MAX.into()) =>
        {
            first << 24 | second << 16 | third << 8 | fourth
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(value.to_be_bytes()))
}

fn legacy_ipv4_component(value: &str) -> Option<u32> {
    let (digits, radix) = if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (digits, 16)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    (!digits.is_empty())
        .then(|| u32::from_str_radix(digits, radix).ok())
        .flatten()
}

/// Check each selected socket address before connecting, against the actual
/// listener address retained by the runtime. Resolve only once in the caller.
/// This check also applies when the immediate route is a configured parent.
/// An origin beyond that parent is not a socket opened by this process.
///
/// Source gaps covered: textual aliases, IPv4-mapped IPv6, and the witnessed
/// IPv4 unspecified destination that reaches a listener on 127.0.0.1. Other
/// loopback addresses and remote hosts on the same port stay outside this rule.
pub fn targets_listener(selected: SocketAddr, bound: SocketAddr) -> bool {
    if selected.port() != bound.port() {
        return false;
    }
    let selected = normalize_mapped(selected.ip());
    let bound = normalize_mapped(bound.ip());
    selected == bound
        || selected == IpAddr::V4(Ipv4Addr::UNSPECIFIED) && bound == IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn normalize_mapped(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

fn decimal_digit(character: char) -> Option<u32> {
    if character.is_ascii_digit() {
        Some(character as u32 - '0' as u32)
    } else {
        decimal(character)
    }
}

fn is_digit(character: char) -> bool {
    decimal_digit(character).is_some() || nondecimal_digit(character as u32)
}

fn nondecimal_digit(point: u32) -> bool {
    NONDECIMAL_DIGITS
        .iter()
        .any(|(start, end)| (*start..=*end).contains(&point))
}

// Generated from Python 3.12.14 / Unicode 15.0.0:
// chr(cp).isdigit() and not chr(cp).isdecimal(). The source oracle records all
// 128 scalars/20 ranges and a SHA256 over all 0x110000 scalar positions.
// Existing pinned python_text data supplies decimal values; no second table
// or resolver is used for them. Python/Unicode provenance is in the fixture.
const NONDECIMAL_DIGITS: &[(u32, u32)] = &[
    (0x00b2, 0x00b3),
    (0x00b9, 0x00b9),
    (0x1369, 0x1371),
    (0x19da, 0x19da),
    (0x2070, 0x2070),
    (0x2074, 0x2079),
    (0x2080, 0x2089),
    (0x2460, 0x2468),
    (0x2474, 0x247c),
    (0x2488, 0x2490),
    (0x24ea, 0x24ea),
    (0x24f5, 0x24fd),
    (0x24ff, 0x24ff),
    (0x2776, 0x277e),
    (0x2780, 0x2788),
    (0x278a, 0x2792),
    (0x10a40, 0x10a43),
    (0x10e60, 0x10e68),
    (0x11052, 0x1105a),
    (0x1f100, 0x1f10a),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_local_aliases_are_claimed_before_credential_admission() {
        let shield = AdminShield::new(43123, "").unwrap();
        for host in [
            "127.1",
            "127.1.",
            "2130706433",
            "2130706433.",
            "0x7f000001",
            "0x7f000001.",
            "0177.0.0.1",
            "0177.0.0.1.",
            "[::ffff:127.0.0.1]",
        ] {
            assert!(!shield.blocks_host(host, 43123));
            assert!(shield.blocks_request_destination(host, 43123));
        }
        for host in ["127.0.0.2", "127.0.0.2.", "0x7f000002", "0177.0.0.2"] {
            assert!(!shield.blocks_request_destination(host, 43123));
        }
        assert!(!shield.blocks_request_destination("127.1", 43124));
    }

    #[test]
    fn root_dot_local_names_are_claimed_before_parent_egress() {
        let shield = AdminShield::new(43123, "").unwrap();
        for host in ["localhost.", "LOCALHOST.", "admin.localhost.", "127.0.0.1."] {
            assert!(shield.blocks_request_destination(host, 43123));
        }
        assert!(!shield.blocks_request_destination("127.0.0.2.", 43123));
        assert!(!shield.blocks_request_destination("localhost..", 43123));
    }

    #[test]
    fn nondecimal_digits_match_every_pinned_python_scalar() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/admin_shield_source.json")).unwrap();
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        for point in 0..0x110000 {
            digest.update(&[u8::from(super::nondecimal_digit(point))]);
        }
        let actual: String = digest
            .finish()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            actual,
            fixture["nondecimal_digit_all_scalars_sha256"]
                .as_str()
                .unwrap()
        );
    }
}
