//! DNS-over-UDP tracing support

use crate::tracers::constants::L4PROTO_UDP;
use crate::tracers::proto::{icmp4, icmp6, raw_socket};
use crate::tracers::{self, ResponseState};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tracing::{info, trace};
use zerocopy::TryFromBytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedPacket {
    Dns(Message),
    Icmp(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Probe {
    hop: u8,
    id: u16,
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
pub struct DnsTracer {
    socket: Arc<UdpSocket>,
    icmp_socket: Arc<raw_socket::RawSocket>,
    target: SocketAddr,
    query: Query,
}

impl tracers::Tracer for DnsTracer {
    type Probe = Probe;
    type ReceivedPacket = ReceivedPacket;
    type AdditionalInfo = Message;

    async fn send_probe(&self, num_hops: u8, sequence: u16) -> io::Result<Self::Probe> {
        self.send_probe(num_hops, sequence).await
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

impl DnsTracer {
    /// Create a tracer for `query`, sending it to `target` over UDP
    pub async fn new(target: SocketAddr, query: Query) -> io::Result<Self> {
        let socket = UdpSocket::bind(if target.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        })
        .await?;
        Ok(Self {
            socket: Arc::new(socket),
            icmp_socket: raw_socket::new_socket(target.ip())?,
            target,
            query,
        })
    }

    async fn send_probe(&self, num_hops: u8, sequence: u16) -> io::Result<Probe> {
        let id = sequence;
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(self.query.clone());

        let mut bytes = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut bytes);
        message.emit(&mut encoder).map_err(protocol_error)?;

        self.socket.set_ttl(u32::from(num_hops))?;
        self.socket.send_to(&bytes, self.target).await?;

        Ok(Probe {
            hop: num_hops,
            id,
            source_port: self.socket.local_addr()?.port(),
            sent_time: Instant::now(),
        })
    }

    async fn receive_packet(&self) -> io::Result<(ReceivedPacket, SocketAddr, Instant)> {
        let mut dns_bytes = [0u8; 4096];
        tokio::select! {
            biased;
            result = self.socket.recv_from(&mut dns_bytes) => {
                let time = Instant::now();
                let (length, source) = result?;
                let message = Message::from_vec(&dns_bytes[..length]).map_err(protocol_error)?;
                Ok((ReceivedPacket::Dns(message), source, time))
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
    ) -> Option<tracers::Response<Probe, Message>> {
        match packet {
            ReceivedPacket::Dns(packet)
                if packet.id == probe.id && source.ip() == self.target.ip() =>
            {
                if packet.message_type == MessageType::Response {
                    Some(tracers::Response {
                        for_probe: *probe,
                        source: Some(source),
                        received_time: Some(received_time),
                        state: ResponseState::Reached,
                        additional_info: Some(packet.clone()),
                    })
                } else {
                    info!("Received a `Query` from the destination??");
                    None
                }
            }
            ReceivedPacket::Dns(_) => None,
            ReceivedPacket::Icmp(packet) => {
                self.match_icmp_time_exceeded(probe, packet, source, received_time)
            }
        }
    }

    fn match_icmp_time_exceeded(
        &self,
        probe: &Probe,
        packet: &[u8],
        source: SocketAddr,
        received_time: Instant,
    ) -> Option<tracers::Response<Probe, Message>> {
        let udp_inner_payload = if self.target.is_ipv4() {
            let (response, payload) = icmp4::parse(packet).ok()?;
            if !matches!(response, icmp4::Response::TimeExceeded(_)) {
                return None;
            }
            let (header, payload) = icmp4::IpHeader::try_parse_ref_skip_option(payload).ok()?;
            if header.protocol != L4PROTO_UDP
                || IpAddr::V4(header.destination_ip()) != self.target.ip()
            {
                return None;
            }
            payload
        } else {
            let (response, payload) = icmp6::parse(packet).ok()?;
            if !matches!(response, icmp6::Response::TimeExceeded(_)) {
                return None;
            }
            let (header, payload) = icmp6::IpHeader::try_parse_ref_skip_option(payload).ok()?;
            if header.next_header != L4PROTO_UDP
                || IpAddr::V6(header.destination_ip()) != self.target.ip()
            {
                return None;
            }
            payload
        };
        let udp_packet = UdpPacket::try_ref_from_bytes(udp_inner_payload).ok()?;
        trace!("received ICMP for UDP: {udp_packet:?}");

        if udp_packet.source_port() != probe.source_port
            || udp_packet.dest_port() != self.target.port()
        {
            return None;
        }
        let message = Message::from_vec(&udp_packet.data).ok()?;
        if message.id != probe.id {
            return None;
        }

        Some(tracers::Response {
            for_probe: *probe,
            source: Some(source),
            received_time: Some(received_time),
            state: ResponseState::OnTheWay,
            additional_info: None,
        })
    }
}

fn protocol_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

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
    #[must_use]
    pub const fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }
    #[must_use]
    pub const fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }
}
