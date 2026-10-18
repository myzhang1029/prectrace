use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    ffi::CStr,
    io,
    net::{IpAddr, SocketAddr},
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
