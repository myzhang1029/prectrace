use super::common::{Error, convert_error};
use crate::tracers::constants::L4PROTO_ICMP6;
use std::net::Ipv6Addr;
use zerocopy::TryFromBytes;

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
pub struct IpHeader {
    pub version_traffic_class_flow_label: [u8; 4],
    pub payload_length: [u8; 2],
    pub next_header: u8,
    pub hop_limit: u8,
    pub source_ip: [u8; 16],
    pub destination_ip: [u8; 16],
}

#[allow(dead_code)]
impl IpHeader {
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
    pub const fn is_icmp(&self) -> bool {
        self.next_header == L4PROTO_ICMP6
    }
    /// Exactly `try_ref_from_prefix` with a check for the version field.
    /// The suffix `_skip_option` is meaningless and just to match the IPv4 counterpart.
    pub fn try_parse_ref_skip_option(packet: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (header, packet) = Self::try_ref_from_prefix(packet).map_err(convert_error)?;
        if header.version() != 6 {
            return Err(Error::NotIp6);
        }
        Ok((*header, packet))
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
pub enum IcmpType {
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
pub struct IcmpHeader {
    pub icmp_type: IcmpType,
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
pub struct IcmpEchoHeader {
    pub header: IcmpHeader,
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
pub struct IcmpTimeExceededOrUnreachableHeader {
    pub header: IcmpHeader,
    _unused: [u8; 4],
}

impl IcmpEchoHeader {
    pub const fn identifier(self) -> u16 {
        u16::from_be_bytes(self.identifier)
    }

    pub const fn sequence(self) -> u16 {
        u16::from_be_bytes(self.sequence)
    }

    pub const fn echo_request(identifier: u16, sequence: u16) -> Self {
        Self {
            header: IcmpHeader {
                icmp_type: IcmpType::EchoRequest,
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
    Echo(&'data IcmpEchoHeader),
    DestinationUnreachable(&'data IcmpTimeExceededOrUnreachableHeader),
    TimeExceeded(&'data IcmpTimeExceededOrUnreachableHeader),
}

pub fn parse(packet: &[u8]) -> Result<(Response<'_>, &[u8]), Error> {
    // Note that `socket2` strips away the IPv6 header (but doesn't strip away the IPv4 header). Why??
    let (icmp_header, _) = IcmpHeader::try_ref_from_prefix(packet).map_err(convert_error)?;
    match icmp_header.icmp_type {
        IcmpType::EchoReply => {
            let (echo, rest) =
                IcmpEchoHeader::try_ref_from_prefix(packet).map_err(convert_error)?;
            Ok((Response::Echo(echo), rest))
        }
        IcmpType::EchoRequest => Err(Error::UnexpectedEchoRequest),
        IcmpType::DestinationUnreachable => {
            let (error, rest) = IcmpTimeExceededOrUnreachableHeader::try_ref_from_prefix(packet)
                .map_err(convert_error)?;
            Ok((Response::DestinationUnreachable(error), rest))
        }
        IcmpType::TimeExceeded => {
            let (error, rest) = IcmpTimeExceededOrUnreachableHeader::try_ref_from_prefix(packet)
                .map_err(convert_error)?;
            Ok((Response::TimeExceeded(error), rest))
        }
    }
}
