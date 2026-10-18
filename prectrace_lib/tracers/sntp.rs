use crate::tracers::constants::L4PROTO_UDP;
use crate::tracers::proto::{raw_socket, retain_icmp_errors_cvt_resp, udp};
use crate::tracers::{self, ResponseState};
use ntp::formats::{Mode, ReferenceIdentifier, timestamp::TimestampFormat};
use ntp::packet::Packet;
use std::ffi::CStr;
use std::io::{self, Cursor};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tracing::trace;
use zerocopy::TryFromBytes;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SntpInfo {
    pub source: SocketAddr,
    pub leap_indicator: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub delay: u32,
    pub dispersion: u32,
    pub reference_identifier: ReferenceIdentifier,
    pub reference_timestamp: TimestampFormat,
    pub originate_timestamp: TimestampFormat,
    pub receive_timestamp: TimestampFormat,
    pub transmit_timestamp: TimestampFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Probe {
    hop: u8,
    transmit_timestamp: u64,
    source_port: u16,
    sent_time: Instant,
}

impl tracers::Probe for Probe {
    fn get_sent_time(&self) -> Instant {
        self.sent_time
    }

    fn get_num_hops(&self) -> u8 {
        self.hop
    }
}

#[derive(Debug, Clone)]
pub struct SntpTracer {
    socket: Arc<UdpSocket>,
    icmp_socket: Arc<raw_socket::RawSocket>,
    target: SocketAddr,
}

impl tracers::Tracer for SntpTracer {
    type Probe = Probe;
    type ReceivedPacket = ReceivedPacket;
    type AdditionalInfo = SntpInfo;

    async fn send_probe(&self, num_hops: u8, _id: u32) -> io::Result<Self::Probe> {
        self.send_probe(num_hops).await
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedPacket {
    Sntp(Vec<u8>),
    Icmp(Vec<u8>),
}

impl SntpTracer {
    /// Creates an SNTP tracer that sends requests to UDP port 123.
    pub async fn new(
        target: SocketAddr,
        bind_address: Option<IpAddr>,
        interface: Option<&CStr>,
    ) -> io::Result<Self> {
        let udpsock = udp::new_socket(target.is_ipv4(), bind_address, interface).await?;
        let rawsock = raw_socket::new_socket(target.is_ipv4(), bind_address, interface)?;
        Ok(Self {
            socket: Arc::new(udpsock),
            icmp_socket: Arc::new(rawsock),
            target,
        })
    }

    async fn send_probe(&self, num_hops: u8) -> io::Result<Probe> {
        self.socket.set_ttl(u32::from(num_hops))?;
        let request = Packet::new_client();
        let transmit_timestamp = u64::from(request.transmit_time);
        let pkt: Vec<u8> = request.into();
        self.socket.send_to(&pkt, self.target).await?;

        Ok(Probe {
            hop: num_hops,
            transmit_timestamp,
            source_port: self.socket.local_addr()?.port(),
            sent_time: Instant::now(),
        })
    }

    async fn receive_packet(&self) -> io::Result<(ReceivedPacket, SocketAddr, Instant)> {
        let mut bytes = [0u8; 4096];
        tokio::select! {
            biased;
            result = self.socket.recv_from(&mut bytes) => {
                let received_time = Instant::now();
                let (length, source) = result?;
                Ok((ReceivedPacket::Sntp(bytes[..length].to_vec()), source, received_time))
            }
            result = raw_socket::receive_packet(&self.icmp_socket) => {
                let (packet, source, received_time) = result?;
                Ok((ReceivedPacket::Icmp(packet), source, received_time))
            }
        }
    }

    fn match_probe_to_response(
        &self,
        probe: &Probe,
        packet: &ReceivedPacket,
        source: SocketAddr,
        received_time: Instant,
    ) -> Option<tracers::Response<Probe, SntpInfo>> {
        match packet {
            ReceivedPacket::Sntp(bytes) => {
                let packet = parse_packet(bytes).ok()?;
                if source.ip() != self.target.ip()
                    || packet.mode != Mode::Server
                    || u64::from(packet.orig_time) != probe.transmit_timestamp
                {
                    return None;
                }
                Some(tracers::Response {
                    for_probe: *probe,
                    source: Some(source),
                    received_time: Some(received_time),
                    state: ResponseState::Reached,
                    additional_info: Some(sntp_info(packet, source)),
                })
            }
            ReceivedPacket::Icmp(bytes) => {
                self.match_icmp_error(probe, bytes, source, received_time)
            }
        }
    }

    fn match_icmp_error(
        &self,
        probe: &Probe,
        packet: &[u8],
        source: SocketAddr,
        received_time: Instant,
    ) -> Option<tracers::Response<Probe, SntpInfo>> {
        let filter = |udp_packet| {
            let Ok(udp_packet) = udp::UdpPacket::try_ref_from_bytes(udp_packet) else {
                return false;
            };
            trace!("received ICMP for UDP: {udp_packet:?}");
            if udp_packet.source_port() != probe.source_port
                || udp_packet.dest_port() != self.target.port()
            {
                return false;
            }
            // If the sending host does not support RFC 4884, then the UDP header
            // is all that they'll pass back to us. Otherwise, let's check
            // the Origin Timestamp to determine if the packet is ours like what we
            // do above for NTP responses
            let Ok(pkt) = Packet::try_from(&udp_packet.data) else {
                return false;
            };
            u64::from(pkt.orig_time) == probe.transmit_timestamp
        };
        let state = retain_icmp_errors_cvt_resp(self.target.ip(), packet, L4PROTO_UDP, filter)?;

        Some(tracers::Response {
            for_probe: *probe,
            source: Some(source),
            received_time: Some(received_time),
            state,
            additional_info: None,
        })
    }
}

fn parse_packet(bytes: &[u8]) -> io::Result<Packet> {
    Packet::try_from(Cursor::new(bytes))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn sntp_info(packet: Packet, source: SocketAddr) -> SntpInfo {
    SntpInfo {
        source,
        leap_indicator: packet.li as u8,
        version: packet.vn as u8,
        mode: packet.mode as u8,
        stratum: packet.stratum.get_value(),
        poll: packet.poll,
        precision: packet.precision,
        delay: packet.delay.into(),
        dispersion: packet.dispersion.into(),
        reference_identifier: packet.ref_id,
        reference_timestamp: packet.ref_time,
        originate_timestamp: packet.orig_time,
        receive_timestamp: packet.recv_time,
        transmit_timestamp: packet.transmit_time,
    }
}
