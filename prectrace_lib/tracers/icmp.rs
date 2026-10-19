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
    identifier: u16,
    sequence: u16,
    sent_time: Instant,
}

impl crate::tracers::Probe for Probe {
    fn get_sent_time(&self) -> Instant {
        self.sent_time
    }
    fn get_num_hops(&self) -> u8 {
        self.hop
    }
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

    async fn send_probe(&self, num_hops: u8, id: u32) -> io::Result<Self::Probe> {
        let identifier = u16::try_from(id >> 16).expect("u16 conversion failed (this is a bug!)");
        let sequence = u16::try_from(id & 0xffff).expect("u16 conversion failed (this is a bug!)");
        self.send_probe(num_hops, identifier, sequence).await
    }

    async fn receive_packet(&self) -> io::Result<(Self::ReceivedPacket, SocketAddr, Instant)> {
        self.receive_packet().await
    }

    fn match_probe_to_response(
        &self,
        probe: &Self::Probe,
        packet: &Self::ReceivedPacket,
        source: SocketAddr,
        received_time: Instant,
    ) -> Option<tracers::Response<Self::Probe, Self::AdditionalInfo>> {
        self.match_probe_to_response(probe, packet, source, received_time)
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

    #[tracing::instrument(level = "info", skip(self), fields(target = %self.target))]
    pub async fn send_probe(
        &self,
        num_hops: u8,
        identifier: u16,
        sequence: u16,
    ) -> io::Result<Probe> {
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
            identifier,
            sequence,
            sent_time,
        })
    }

    /// Wait until a packet is received on the socket and return the packet, peer address, and timestamp.
    pub async fn receive_packet(&self) -> io::Result<(Vec<u8>, SocketAddr, Instant)> {
        raw_socket::receive_packet(&self.socket).await
    }
}

// See `IcmpTracer::classify` for what this macro is for.
macro_rules! gen_classify_arms_for_proto {
    ($proto:ident, $matcher:ident, $probe:ident, $packet:ident) => {{
        let (icmp_hdr, payload) = $proto::Response::parse($packet).ok()?;
        match icmp_hdr {
            $proto::Response::Echo(echo)
                if (echo.identifier() == $probe.identifier
                    && echo.sequence() == $probe.sequence) =>
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
                    || echo.identifier() != $probe.identifier
                    || echo.sequence() != $probe.sequence
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

impl IcmpTracer {
    #[must_use]
    pub fn match_probe_to_response(
        &self,
        probe: &Probe,
        packet: &[u8],
        source: SocketAddr,
        received_time: Instant,
    ) -> Option<tracers::Response<Probe, ()>> {
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
}
