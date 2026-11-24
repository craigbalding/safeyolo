use super::*;
use std::{
    ffi::CStr,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub fn command(args: &[String]) -> Option<Result<(), Error>> {
    if args.first().map(String::as_str) != Some(INSPECT_COMMAND) {
        return None;
    }
    Some((|| {
        let [_, value] = args else {
            return Err("inspect-endpoint needs one typed endpoint selection".into());
        };
        let selection: EndpointSelection =
            serde_json::from_str(value).map_err(|_| "invalid typed endpoint selection")?;
        if !selection.validate() {
            return Err("invalid typed endpoint selection".into());
        }
        let result = inspect(&selection);
        println!("{}", serde_json::to_string(&result)?);
        Ok(())
    })())
}

fn failure(c: &EndpointCandidate, status: EndpointStatus, reason: &str) -> EndpointObservation {
    EndpointObservation {
        status,
        observed_at: now(),
        selected: c.clone(),
        binding: None,
        interface: None,
        reason: reason.into(),
        os_error: None,
        reservation: false,
        application_ready: None,
        reachable_audience: None,
    }
}

fn native_error(mut result: EndpointObservation, error: io::Error) -> EndpointObservation {
    result.os_error = error.raw_os_error();
    let (status, reason) = match error.raw_os_error() {
        Some(libc::EADDRINUSE) => (
            EndpointStatus::Conflict,
            "selected endpoint conflicts at observation",
        ),
        Some(libc::EACCES | libc::EPERM) => (
            EndpointStatus::Denied,
            "native permission denied for the selected endpoint",
        ),
        Some(libc::EADDRNOTAVAIL | libc::ENODEV | libc::ENXIO) => (
            EndpointStatus::Unavailable,
            "selected address or interface is unavailable",
        ),
        Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ENOPROTOOPT) => (
            EndpointStatus::Unavailable,
            "selected transport, family or socket option is unavailable",
        ),
        _ => (
            EndpointStatus::Unknown,
            "native endpoint observation is incomplete",
        ),
    };
    result.status = status;
    result.reason = reason.into();
    result.observed_at = now();
    result
}

struct Interfaces(*mut libc::ifaddrs);
impl Drop for Interfaces {
    fn drop(&mut self) {
        // SAFETY: this list was returned by getifaddrs and has one owner.
        unsafe { libc::freeifaddrs(self.0) }
    }
}

// Only the selected interface and family are copied out of the native list.
// Neither native error strings nor unfiltered inventory enter output.
fn resolve(
    c: &EndpointCandidate,
) -> Result<(SocketAddr, Option<SelectedInterface>), Box<EndpointObservation>> {
    let mut result = failure(
        c,
        EndpointStatus::Unavailable,
        "selected interface or address is absent",
    );
    let Some(name) = &c.interface else {
        return Ok((
            SocketAddr::new(c.address.expect("validated address"), c.port),
            None,
        ));
    };
    let mut list = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes the list pointer on success.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(Box::new(native_error(result, io::Error::last_os_error())));
    }
    let list = Interfaces(list);
    let mut next = list.0;
    while !next.is_null() {
        // SAFETY: next follows the getifaddrs-owned linked list; non-null
        // sockaddr pointers are read according to their reported family.
        let entry = unsafe { &*next };
        next = entry.ifa_next;
        if entry.ifa_name.is_null()
            || entry.ifa_addr.is_null()
            || unsafe { CStr::from_ptr(entry.ifa_name) }.to_bytes() != name.as_bytes()
        {
            continue;
        }
        let family = unsafe { (*entry.ifa_addr).sa_family } as i32;
        let address = match (&c.family, family) {
            (AddressFamily::Ipv4, libc::AF_INET) => {
                let v4 = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                IpAddr::V4(std::net::Ipv4Addr::from(v4.sin_addr.s_addr.to_ne_bytes()))
            }
            (AddressFamily::Ipv6, libc::AF_INET6) => {
                let v6 = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in6>() };
                IpAddr::V6(std::net::Ipv6Addr::from(v6.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        if c.address.is_some_and(|selected| selected != address) {
            continue;
        }
        let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
        if index == 0 {
            return Err(Box::new(native_error(result, io::Error::last_os_error())));
        }
        let interface = SelectedInterface {
            name: name.clone(),
            index,
            up: entry.ifa_flags & libc::IFF_UP as u32 != 0,
        };
        if !interface.up {
            result.reason = "selected interface is down".into();
            result.interface = Some(interface);
            return Err(Box::new(result));
        }
        let mut binding = SocketAddr::new(address, c.port);
        if let SocketAddr::V6(v6) = &mut binding {
            // Link-local addresses need the selected interface's native index.
            if v6.ip().is_unicast_link_local() {
                v6.set_scope_id(index)
            }
        }
        return Ok((binding, Some(interface)));
    }
    Err(Box::new(result))
}

fn option(fd: &OwnedFd, level: i32, name: i32, value: bool) -> io::Result<()> {
    let value: libc::c_int = value.into();
    // SAFETY: the descriptor is owned and value has the native integer ABI.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as _,
        )
    } != 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn probe(c: &EndpointCandidate) -> EndpointObservation {
    let (binding, interface) = match resolve(c) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let mut result = failure(
        c,
        EndpointStatus::Unknown,
        "endpoint observation did not complete",
    );
    result.binding = Some(binding);
    result.interface = interface;
    let (kind, protocol) = match c.transport {
        NetworkTransport::Tcp => (libc::SOCK_STREAM, libc::IPPROTO_TCP),
        NetworkTransport::Udp => (libc::SOCK_DGRAM, libc::IPPROTO_UDP),
    };
    // SAFETY: socket returns a new descriptor; OwnedFd closes every probe path.
    let raw = unsafe {
        libc::socket(
            if binding.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            },
            kind,
            protocol,
        )
    };
    if raw < 0 {
        return native_error(result, io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let observe = (|| -> io::Result<SocketAddr> {
        option(&fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, c.reuse_address)?;
        option(&fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, c.reuse_port)?;
        if binding.is_ipv6() {
            option(&fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, c.ipv6_only)?
        }
        let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let length = match binding {
            SocketAddr::V4(v4) => {
                let addr = unsafe {
                    &mut *(&mut address as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>()
                };
                addr.sin_family = libc::AF_INET as _;
                #[cfg(target_os = "macos")]
                {
                    addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as _;
                }
                addr.sin_port = v4.port().to_be();
                addr.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                std::mem::size_of::<libc::sockaddr_in>()
            }
            SocketAddr::V6(v6) => {
                let addr = unsafe {
                    &mut *(&mut address as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
                };
                addr.sin6_family = libc::AF_INET6 as _;
                #[cfg(target_os = "macos")]
                {
                    addr.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as _;
                }
                addr.sin6_port = v6.port().to_be();
                addr.sin6_addr.s6_addr = v6.ip().octets();
                addr.sin6_scope_id = v6.scope_id();
                std::mem::size_of::<libc::sockaddr_in6>()
            }
        };
        // SAFETY: address contains the family-specific initialized structure.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_storage).cast(),
                length as _,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if matches!(c.transport, NetworkTransport::Tcp)
            && unsafe { libc::listen(fd.as_raw_fd(), 1) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
        // SAFETY: getsockname receives a full sockaddr_storage output buffer.
        if unsafe {
            libc::getsockname(
                fd.as_raw_fd(),
                (&mut address as *mut libc::sockaddr_storage).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let port = if binding.is_ipv4() {
            unsafe {
                u16::from_be(
                    (*(&address as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>())
                        .sin_port,
                )
            }
        } else {
            unsafe {
                u16::from_be(
                    (*(&address as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>())
                        .sin6_port,
                )
            }
        };
        let mut selected = binding;
        selected.set_port(port);
        Ok(selected)
    })();
    // Release before recording success: the result never carries a reservation.
    drop(fd);
    match observe {
        Ok(binding) => {
            result.status = EndpointStatus::AvailableAtObservation;
            result.binding = Some(binding);
            result.observed_at = now();
            result.reason = "selected endpoint bound successfully; probe released; the service's later bind remains authoritative".into();
            result
        }
        Err(error) => native_error(result, error),
    }
}

fn inspect(selection: &EndpointSelection) -> EndpointObservation {
    let mut failure = None;
    for candidate in &selection.candidates {
        let observation = probe(candidate);
        if observation.status == EndpointStatus::AvailableAtObservation {
            return observation;
        }
        // A conflict in one alternative cannot conceal an incomplete check.
        if failure
            .as_ref()
            .is_none_or(|prior: &EndpointObservation| prior.status == EndpointStatus::Conflict)
        {
            failure = Some(observation);
        }
    }
    failure.expect("validated nonempty selection")
}
