use crate::tracers::proto::{icmp4, icmp6};
use crate::tracers::socket_utils::raw as raw_socket;
use crate::tracers::{self, ResponseState};
use socket2::{SockAddr, Socket};
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::unix::AsyncFd;
use tracing::debug;
use zerocopy::{IntoBytes, TryFromBytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Probe {
    hop: u8,
    id: u32,
    sent_time: Instant,
}

impl crate::tracers::Probe for Probe {
    fn get_sent_time(&self) -> Instant {
        self.sent_time
    }
    fn get_num_hops(&self) -> u8 {
        self.hop
    }
    fn get_id(&self) -> u32 {
        self.id
    }
}

// Get (identifier: u16) and (sequence: u16)
const fn get_icmp_param(id: u32) -> (u16, u16) {
    let Ok(identifier) = u16::try_from(id >> 16) else {
        panic!("u16 conversion failed (this is a bug!)");
    };
    let Ok(sequence) = u16::try_from(id & 0xffff) else {
        panic!("u16 conversion failed (this is a bug!)");
    };
    (identifier, sequence)
}

// See `IcmpTracer::classify` for what this macro is for.
macro_rules! gen_classify_arms_for_proto {
    ($proto:ident, $matcher:ident, $probe:ident, $packet:ident) => {{
        let (icmp_hdr, payload) = $proto::Response::parse($packet).ok()?;
        let (identifier, sequence) = get_icmp_param($probe.id);
        match icmp_hdr {
            $proto::Response::Echo(echo)
                if (echo.identifier() == identifier && echo.sequence() == sequence) =>
            {
                Some(ResponseState::Reached)
            }
            $proto::Response::TimeExceeded(_) | $proto::Response::DestinationUnreachable(_) => {
                let (error_embedded_hdr, error_embedded_payload) =
                    $proto::IpHeader::try_parse_ref_skip_option(payload).ok()?;
                if !error_embedded_hdr.is_icmp() {
                    // The error is not for us
                    return None;
                }
                // Embedded packet not under the ICMP codes we care about
                let Ok((echo, _)) =
                    $proto::IcmpEchoHeader::try_ref_from_prefix(error_embedded_payload)
                else {
                    return None;
                };
                if echo.header.icmp_type != $proto::IcmpType::EchoRequest
                    || echo.identifier() != identifier
                    || echo.sequence() != sequence
                {
                    return None;
                }
                Some(icmp_hdr.to_response_state())
            }
            // Either not the ICMP types we expect, or the packet is not in response to `probe`
            _ => None,
        }
    }};
}

#[derive(Debug, Clone)]
pub struct IcmpTracer {
    socket: Arc<raw_socket::RawSocket>,
    target: SocketAddr,
}

impl tracers::Tracer for IcmpTracer {
    type Probe = Probe;
    type ReceivedPacket = Vec<u8>;
    type AdditionalInfo = ();

    #[tracing::instrument(level = "info", skip(self), fields(target = %self.target))]
    async fn send_probe(&self, num_hops: u8, id: u32) -> io::Result<Self::Probe> {
        let (identifier, sequence) = get_icmp_param(id);
        // All captured stuff are `Copy` so we make the closure once outside the loop
        let sender = |sock: &AsyncFd<Socket>| {
            // Don't create the packet until we know the socket is writable
            // (I wonder how big this Future is..)
            let inner = sock.get_ref();
            if self.target.is_ipv4() {
                let pkt = icmp4::IcmpEchoHeader::echo_request(identifier, sequence);
                inner.set_ttl_v4(u32::from(num_hops))?;
                inner.send_to(pkt.as_bytes(), &SockAddr::from(self.target))?;
            } else {
                let pkt = icmp6::IcmpEchoHeader::echo_request(identifier, sequence);
                inner.set_unicast_hops_v6(u32::from(num_hops))?;
                inner.send_to(pkt.as_bytes(), &SockAddr::from(self.target))?;
            }
            Ok(Instant::now())
        };
        let sent_time = loop {
            let mut readiness = self.socket.writable().await?;
            if let Ok(r) = readiness.try_io(sender) {
                break r?;
            }
            // else WouldBlock
        };
        debug!("sent probe at {sent_time:?}");

        Ok(Probe {
            hop: num_hops,
            id,
            sent_time,
        })
    }

    /// Wait until a packet is received on the socket and return the packet, peer address, and timestamp.
    async fn receive_packet(&self) -> io::Result<(Self::ReceivedPacket, SocketAddr, Instant)> {
        raw_socket::receive_packet(&self.socket).await
    }

    fn match_probe_to_response(
        &self,
        probe: &Self::Probe,
        packet: &Self::ReceivedPacket,
        source: SocketAddr,
        received_time: Instant,
    ) -> Option<tracers::Response<Self::Probe, Self::AdditionalInfo>> {
        let state = if self.target.is_ipv4() {
            gen_classify_arms_for_proto!(icmp4, matches_probe_v4, probe, packet)
        } else {
            gen_classify_arms_for_proto!(icmp6, matches_probe_v6, probe, packet)
        }?;
        Some(tracers::Response {
            for_probe: *probe,
            source: Some(source),
            received_time: Some(received_time),
            state,
            additional_info: Some(()),
        })
    }

    fn get_target(&self) -> Option<SocketAddr> {
        Some(self.target)
    }
}

impl IcmpTracer {
    /// Create a new `IcmpTracer` for the given target IP address.
    pub fn new(
        target: IpAddr,
        bind_address: Option<IpAddr>,
        interface: Option<&CStr>,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: Arc::new(raw_socket::new(target.is_ipv4(), bind_address, interface)?),
            target: SocketAddr::new(target, 0),
        })
    }
}
