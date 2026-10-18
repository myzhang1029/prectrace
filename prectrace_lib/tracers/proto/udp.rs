use std::{io, net::SocketAddr};
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

pub async fn new_socket(is_v4: bool) -> io::Result<UdpSocket> {
    let addr = if is_v4 {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    UdpSocket::bind(addr).await
}
