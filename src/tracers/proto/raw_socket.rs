use core::mem::MaybeUninit;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::unix::AsyncFd;
use tracing::trace;

pub type RawSocket = AsyncFd<Socket>;

pub fn new_socket(is_v4: bool) -> io::Result<RawSocket> {
    let socket = if is_v4 {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
    } else {
        Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
    }?;
    socket.set_nonblocking(true)?;
    // SAFETY: `Socket.as_raw_fd` returns a fd because
    // "This type [Socket] simply wraps an instance of a file descriptor"
    // We just created it above and will not close it, so it remains a valid one.
    // (actually `socket2` provides no mechanism to close it.)
    // Since this type owns the `Socket` instance, the lifetime guarantee is
    // also satisfied.
    Ok(unsafe { AsyncFd::register(socket)? })
}

pub async fn receive_packet(socket: &RawSocket) -> io::Result<(Vec<u8>, SocketAddr, Instant)> {
    let do_recv_callback = |socket: &RawSocket| {
        let mut buffer = [const { MaybeUninit::uninit() }; 4096];
        let (length, source) = socket.get_ref().recv_from(&mut buffer)?;
        let timestamp = Instant::now();
        let bytes = buffer[..length]
            .iter()
            // SAFETY: `recv_from` initializes the read part.
            .map(|itm| unsafe { itm.assume_init() })
            .collect();
        let source = source
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid ICMP source"))?;
        trace!("received packet from {source} len={length}: {bytes:02x?}");
        Ok((bytes, source, timestamp))
    };

    loop {
        let mut readiness = socket.readable().await?;
        if let Ok(packet) = readiness.try_io(do_recv_callback) {
            return packet;
        }
    }
}
