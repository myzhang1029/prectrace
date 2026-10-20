use crate::tracers::constants::L4PROTO_UDP;
use crate::tracers::proto::{retain_icmp_errors_cvt_resp, udp};
use crate::tracers::socket_utils::{raw as raw_socket, udp as udp_socket};
use crate::tracers::{self, ResponseState};
use ntp_proto::protocol::{
    ConstPackedSizeBytes, FromBytes, Mode, Packet, ShortFormat, TimestampFormat, ToBytes,
};
use serde::Serialize;
use serde::ser::SerializeMap;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tracing::{debug, trace};
use zerocopy::TryFromBytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SntpInfo(Packet, TimestampFormat, SocketAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Probe {
    hop: u8,
    transmit_timestamp: TimestampFormat,
    // unused in probe identification
    id: u32,
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
    fn get_id(&self) -> u32 {
        self.id
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

    #[tracing::instrument(level = "info", skip(self), fields(target = %self.target))]
    async fn send_probe(&self, num_hops: u8, id: u32) -> io::Result<Self::Probe> {
        udp_socket::set_ttl(&self.socket, u32::from(num_hops), self.target.is_ipv4())?;
        let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
        let transmit_timestamp = ntp_proto::unix_time::Instant::now().into();
        let request = Packet {
            transmit_timestamp,
            ..Default::default()
        };
        request
            .to_bytes(&mut buf)
            .expect("bad buffer size (this is a bug!)");
        trace!("sending to {}", self.target);
        self.socket.send_to(&buf, self.target).await?;

        Ok(Probe {
            hop: num_hops,
            transmit_timestamp,
            id,
            source_port: self.socket.local_addr()?.port(),
            sent_time: Instant::now(),
        })
    }

    async fn receive_packet(&self) -> io::Result<(Self::ReceivedPacket, SocketAddr, Instant)> {
        let mut bytes = [0u8; 4096];
        loop {
            tokio::select! {
                biased;
                result = self.socket.recv_from(&mut bytes) => {
                    let ntp_t3: TimestampFormat = ntp_proto::unix_time::Instant::now().into();
                    let received_time = Instant::now();
                    let (length, source) = result?;
                    if source.ip() != self.target.ip() {
                        continue;
                    }
                    let Ok((packet, _size)) = Packet::from_bytes(&bytes[..length]) else {
                        debug!("received malformed NTP response from server");
                        continue;
                    };
                    if packet.mode == Mode::Server {
                        break Ok((ReceivedPacket::Sntp(packet, ntp_t3), source, received_time));
                    }
                    debug!("received a {:?} from the destination??", packet.mode);
                }
                result = raw_socket::receive_packet(&self.icmp_socket) => {
                    let (packet, source, received_time) = result?;
                    break Ok((ReceivedPacket::Icmp(packet), source, received_time));
                }
            }
        }
    }

    fn match_probe_to_response(
        &self,
        probe: &Self::Probe,
        packet: &Self::ReceivedPacket,
        source: SocketAddr,
        received_time: Instant,
    ) -> Option<tracers::Response<Self::Probe, Self::AdditionalInfo>> {
        match packet {
            ReceivedPacket::Sntp(packet, t3)
                if packet.origin_timestamp == probe.transmit_timestamp =>
            {
                Some(tracers::Response {
                    for_probe: *probe,
                    source: Some(source),
                    received_time: Some(received_time),
                    state: ResponseState::Reached,
                    additional_info: Some(SntpInfo(*packet, *t3, source)),
                })
            }
            ReceivedPacket::Sntp(..) => None,
            ReceivedPacket::Icmp(bytes) => {
                self.match_icmp_error(probe, bytes, source, received_time)
            }
        }
    }

    fn get_target(&self) -> Option<SocketAddr> {
        Some(self.target)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedPacket {
    Sntp(Packet, TimestampFormat),
    Icmp(Vec<u8>),
}

impl SntpTracer {
    /// Creates an SNTP tracer that sends requests to UDP port 123.
    ///
    /// # Errors
    ///
    /// If the required UDP and raw sockets cannot be created or bound.
    pub async fn new(
        target: SocketAddr,
        bind_address: Option<IpAddr>,
        interface: Option<&CStr>,
    ) -> io::Result<Self> {
        let udpsock = udp_socket::new(target.is_ipv4(), bind_address, interface).await?;
        let rawsock = raw_socket::new(target.is_ipv4(), bind_address, interface)?;
        Ok(Self {
            socket: Arc::new(udpsock),
            icmp_socket: Arc::new(rawsock),
            target,
        })
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
            let Ok((pkt, _size)) = Packet::from_bytes(&udp_packet.data) else {
                return false;
            };
            pkt.transmit_timestamp == probe.transmit_timestamp
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

const fn ser_shortfmt(sf: ShortFormat) -> (u16, u16) {
    (sf.seconds, sf.fraction)
}
const fn ser_tsfmt(ts: TimestampFormat) -> (u32, u32) {
    (ts.seconds, ts.fraction)
}

impl Serialize for SntpInfo {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(14))?;
        map.serialize_entry("source", &self.2)?;
        map.serialize_entry("leap_indicator", &(self.0.leap_indicator as u8))?;
        map.serialize_entry("version", &self.0.version.value())?;
        map.serialize_entry("mode", &(self.0.mode as u8))?;
        map.serialize_entry("stratum", &self.0.stratum.0)?;
        map.serialize_entry("poll", &self.0.poll)?;
        map.serialize_entry("precision", &self.0.precision)?;
        map.serialize_entry("root_delay", &ser_shortfmt(self.0.root_delay))?;
        map.serialize_entry("root_dispersion", &ser_shortfmt(self.0.root_dispersion))?;
        map.serialize_entry("reference_id", &self.0.reference_id.as_bytes())?;
        map.serialize_entry(
            "reference_timestamp",
            &ser_tsfmt(self.0.reference_timestamp),
        )?;
        map.serialize_entry("t0", &ser_tsfmt(self.0.origin_timestamp))?;
        map.serialize_entry("t1", &ser_tsfmt(self.0.receive_timestamp))?;
        map.serialize_entry("t2", &ser_tsfmt(self.0.transmit_timestamp))?;
        map.serialize_entry("t3", &ser_tsfmt(self.1))?;
        map.end()
    }
}
