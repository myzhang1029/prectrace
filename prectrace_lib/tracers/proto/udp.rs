use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    ffi::CStr,
    io,
    net::{IpAddr, SocketAddr},
};
use tokio::net::UdpSocket;

#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy_derive::TryFromBytes,
    zerocopy_derive::Immutable,
    zerocopy_derive::KnownLayout,
)]
#[repr(C)]
pub struct UdpPacket {
    pub source_port: [u8; 2],
    pub dest_port: [u8; 2],
    pub length: [u8; 2],
    pub checksum: [u8; 2],
    pub data: [u8],
}
impl UdpPacket {
    #[must_use]
    pub const fn source_port(&self) -> u16 {
        u16::from_be_bytes(self.source_port)
    }
    #[must_use]
    pub const fn dest_port(&self) -> u16 {
        u16::from_be_bytes(self.dest_port)
    }
}

pub async fn new_socket(
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
        super::raw_socket::bind_interface(&socket, is_v4, interface)?;
    }
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}
