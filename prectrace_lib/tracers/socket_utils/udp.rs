use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    ffi::CStr,
    io,
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
};
use tokio::net::UdpSocket;
use tracing::{debug, trace};

#[tracing::instrument]
pub async fn new(
    is_v4: bool,
    bind_address: Option<IpAddr>,
    interface: Option<&CStr>,
) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        if is_v4 { Domain::IPV4 } else { Domain::IPV6 },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if let Some(address) = bind_address {
        trace!("binding socket to {address}");
        assert!(
            address.is_ipv4() == is_v4,
            "consistency check failed: mismatching address families (this is a bug!)"
        );
        socket.bind(&SockAddr::from(SocketAddr::new(address, 0)))?;
    } else if is_v4 {
        socket.bind(&SockAddr::from(SocketAddr::from(([0, 0, 0, 0], 0))))?;
    } else {
        socket.bind(&SockAddr::from(SocketAddr::from(([0u8; 16], 0))))?;
    };

    if let Some(interface) = interface {
        super::raw::bind_interface(&socket, is_v4, interface)?;
    }
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket.into())?;
    debug!("created UDP socket on {:?}", socket.local_addr());
    Ok(socket)
}

pub fn set_ttl(sock: &UdpSocket, ttl: u32, is_v4: bool) -> io::Result<()> {
    if is_v4 {
        sock.set_ttl(ttl)?;
    } else {
        // Technically we can rewrite the entire codebase to use `socket2` but
        // that's too much work.
        // see socket2::Socket::set_unicast_hops_v6 and std::sys::net::connection::socket::setsockopt
        let fd = libc::c_int::from(sock.as_raw_fd());
        let option = libc::c_int::try_from(ttl).map_err(|_|
            io::ErrorKind::InvalidInput
        )?;
        let option_ptr = (&raw const option) as *const libc::c_void;
        let option_len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY:
        // - `sock` is opened for the duration of this call since we have a valid reference.
        // - `option_len` is the correct length of the value we passed in, a c_int.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
                option_ptr,
                option_len,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
