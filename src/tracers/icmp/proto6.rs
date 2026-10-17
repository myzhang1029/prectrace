use std::net::Ipv6Addr;
use zerocopy::TryFromBytes;

pub const ICMP6_NH_NUMBER: u8 = 58;

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    //#[error("ICMPv6 checksum mismatch")]
    //BadIcmpChecksum,
    #[error("Unexpected ICMPv6 echo request")]
    UnexpectedEchoRequest,
    #[error("Parsing error at {0}: {1}")]
    ParseError(&'static str, String),
}

#[derive(
    zerocopy_derive::TryFromBytes,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::Immutable,
    zerocopy_derive::KnownLayout,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[repr(C)]
pub struct Ip6Header {
    pub version_traffic_class_flow_label: [u8; 4],
    pub payload_length: [u8; 2],
    pub next_header: u8,
    pub hop_limit: u8,
    pub source_ip: [u8; 16],
    pub destination_ip: [u8; 16],
}

#[allow(dead_code)]
impl Ip6Header {
    pub const fn version(&self) -> u8 {
        self.version_traffic_class_flow_label[0] >> 4
    }
    pub const fn payload_length(&self) -> u16 {
        u16::from_be_bytes(self.payload_length)
    }
    pub const fn source_ip(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.source_ip)
    }
    pub const fn destination_ip(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.destination_ip)
    }
}

#[derive(
    zerocopy_derive::TryFromBytes,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::Immutable,
    zerocopy_derive::KnownLayout,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Icmp6Type {
    DestinationUnreachable = 1,
    TimeExceeded = 3,
    EchoRequest = 128,
    EchoReply = 129,
}

#[derive(
    zerocopy_derive::TryFromBytes,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::Immutable,
    zerocopy_derive::KnownLayout,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[repr(C)]
pub struct Icmp6Header {
    pub icmp_type: Icmp6Type,
    pub code: u8,
    pub checksum: [u8; 2],
}

#[derive(
    zerocopy_derive::TryFromBytes,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::Immutable,
    zerocopy_derive::KnownLayout,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[repr(C)]
pub struct Icmp6EchoHeader {
    pub header: Icmp6Header,
    pub identifier: [u8; 2],
    pub sequence: [u8; 2],
}

#[derive(
    zerocopy_derive::TryFromBytes,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::Immutable,
    zerocopy_derive::KnownLayout,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[repr(C)]
pub struct Icmp6TimeExceededOrUnreachableHeader {
    pub header: Icmp6Header,
    pub data: [u8; 4],
    pub original_ip_header: Ip6Header,
}

impl Icmp6EchoHeader {
    pub const fn identifier(&self) -> u16 {
        u16::from_be_bytes(self.identifier)
    }

    pub const fn sequence(&self) -> u16 {
        u16::from_be_bytes(self.sequence)
    }

    pub const fn echo_request(identifier: u16, sequence: u16) -> Self {
        Self {
            header: Icmp6Header {
                icmp_type: Icmp6Type::EchoRequest,
                code: 0,
                checksum: [0, 0],
            },
            identifier: identifier.to_be_bytes(),
            sequence: sequence.to_be_bytes(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Response<'data> {
    Echo(&'data Icmp6EchoHeader),
    DestinationUnreachable(&'data Icmp6TimeExceededOrUnreachableHeader),
    TimeExceeded(&'data Icmp6TimeExceededOrUnreachableHeader),
}

pub fn parse(packet: &[u8]) -> Result<(Response<'_>, &[u8]), Error> {
    // Note that `socket2` strips away the IPv6 header (but doesn't strip away the IPv4 header). Why??
    let (icmp_header, _) = Icmp6Header::try_ref_from_prefix(packet)
        .map_err(|e| Error::ParseError("Icmp6Header", e.to_string()))?;
    match icmp_header.icmp_type {
        Icmp6Type::EchoReply => {
            let (echo, rest) = Icmp6EchoHeader::try_ref_from_prefix(packet)
                .map_err(|e| Error::ParseError("Icmp6Echo", e.to_string()))?;
            Ok((Response::Echo(echo), rest))
        }
        Icmp6Type::EchoRequest => Err(Error::UnexpectedEchoRequest),
        Icmp6Type::DestinationUnreachable => {
            let (error, rest) =
                Icmp6TimeExceededOrUnreachableHeader::try_ref_from_prefix(packet)
                    .map_err(|e| Error::ParseError("Icmp6DestinationUnreachable", e.to_string()))?;
            Ok((Response::DestinationUnreachable(error), rest))
        }
        Icmp6Type::TimeExceeded => {
            let (error, rest) =
                Icmp6TimeExceededOrUnreachableHeader::try_ref_from_prefix(packet)
                    .map_err(|e| Error::ParseError("Icmp6TimeExceeded", e.to_string()))?;
            Ok((Response::TimeExceeded(error), rest))
        }
    }
}
