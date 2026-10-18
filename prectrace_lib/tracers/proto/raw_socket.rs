use core::mem::MaybeUninit;
use socket2::{Domain, Protocol, Socket, Type};
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use tokio::io::unix::AsyncFd;
use tracing::trace;

pub type RawSocket = AsyncFd<Socket>;

pub fn new_socket(
    is_v4: bool,
    bind_address: Option<IpAddr>,
    interface: Option<&CStr>,
) -> io::Result<RawSocket> {
    let socket = if is_v4 {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
    } else {
        Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
    }?;
    if let Some(address) = bind_address {
        socket.bind(&socket2::SockAddr::from(SocketAddr::new(address, 0)))?;
    }
    if let Some(interface) = interface {
        bind_interface(&socket, is_v4, interface)?;
    }
    socket.set_nonblocking(true)?;
    // SAFETY: `Socket.as_raw_fd` returns a fd because
    // "This type [Socket] simply wraps an instance of a file descriptor"
    // We just created it above and will not close it, so it remains a valid one.
    // (actually `socket2` provides no mechanism to close it.)
    // Since this type owns the `Socket` instance, the lifetime guarantee is
    // also satisfied.
    Ok(unsafe { AsyncFd::register(socket)? })
}

#[cfg(any(
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "linux",
    target_os = "android",
))]
pub fn bind_interface(socket: &Socket, is_v4: bool, interface: &CStr) -> io::Result<()> {
    let ptr = interface.as_ptr();
    // SAFETY: just a normal C FFI call.
    let ifidx = unsafe { libc::if_nametoindex(ptr) };
    let ifidx = std::num::NonZeroU32::try_from(ifidx).map_err(|_| io::ErrorKind::InvalidInput)?;
    if is_v4 {
        socket.bind_device_by_index_v4(Some(ifidx))?;
    } else {
        socket.bind_device_by_index_v6(Some(ifidx))?;
    }
    Ok(())
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
