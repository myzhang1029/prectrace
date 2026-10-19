//! DNS-over-UDP tracing support

use crate::tracers::constants::L4PROTO_UDP;
use crate::tracers::proto::{retain_icmp_errors_cvt_resp, udp};
use crate::tracers::socket_utils::{raw as raw_socket, udp as udp_socket};
use crate::tracers::{self, ResponseState};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::ffi::CStr;
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

    async fn send_probe(&self, num_hops: u8, id: u32) -> io::Result<Self::Probe> {
        let id = u16::try_from((id >> 24) | (id & 0xff))
            .expect("u16 conversion failed (this is a bug!)");
        self.send_probe(num_hops, id).await
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

impl DnsTracer {
    /// Create a tracer for `query`, sending it to `target` over UDP
    pub async fn new(
        target: SocketAddr,
        query: Query,
        bind_address: Option<IpAddr>,
        interface: Option<&CStr>,
    ) -> io::Result<Self> {
        let udpsock = udp_socket::new(target.is_ipv4(), bind_address, interface).await?;
        let rawsock = raw_socket::new(target.is_ipv4(), bind_address, interface)?;
        Ok(Self {
            socket: Arc::new(udpsock),
            icmp_socket: Arc::new(rawsock),
            target,
            query,
        })
    }

    async fn send_probe(&self, num_hops: u8, id: u16) -> io::Result<Probe> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(self.query.clone());

        let mut bytes = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut bytes);
        message.emit(&mut encoder).map_err(protocol_error)?;

        udp_socket::set_ttl(&self.socket, u32::from(num_hops), self.target.is_ipv4())?;
        trace!("sending to {}", self.target);
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
                self.match_icmp_error(probe, packet, source, received_time)
            }
        }
    }

    fn match_icmp_error(
        &self,
        probe: &Probe,
        packet: &[u8],
        source: SocketAddr,
        received_time: Instant,
    ) -> Option<tracers::Response<Probe, Message>> {
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
            // is all that they'll pass back to us. In this case, we'd fail right
            // here in the `Message` decoding process.
            let Some(message) = Message::from_vec(&udp_packet.data).ok() else {
                return false;
            };
            message.id == probe.id
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

fn protocol_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
