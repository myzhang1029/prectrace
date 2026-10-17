//! Limited implementation of RFC 792 and RFC 4443
//!
//! Implementation notes:
//! Every layer of the protocol stack is represented by a Header struct,
//! and subsequent layers includes the previous layer's header except that the L4
//! header does not include the IPv[46] header. This is because `socket2`'s API
//! will create its own L3 header.

use std::net::Ipv4Addr;
use zerocopy::{IntoBytes, TryFromBytes};

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Not an IPv4 packet")]
    NotIp4,
    #[error("Bad IPv4 IHL: {0}")]
    BadIp4Ihl(u8),
    #[error("IHL jumps past the end of the packet")]
    PacketTooShort,
    #[error("ICMP checksum mismatch")]
    BadIcmpChecksum,
    #[error("Unexpected ICMP echo request")]
    UnexpectedEchoRequest,
    #[error("Parsing error at {0}: {1}")]
    ParseError(&'static str, String),
}

// The Internet Checksum (RFC 1071)
fn checksum(packet: &[u8], mut additional_data: &[u8]) -> u16 {
    let (chunks, remainder) = packet.as_chunks::<2>();
    let mut sum: u32 = chunks
        .iter()
        .map(|chunk| u16::from_be_bytes(*chunk) as u32)
        .sum();
    if !remainder.is_empty() {
        let rh = remainder[0] as u32;
        sum += rh << 8;
        if !additional_data.is_empty() {
            sum += additional_data[0] as u32;
            additional_data = &additional_data[1..];
        }
    }
    let (chunks, remainder) = additional_data.as_chunks::<2>();
    sum += chunks
        .iter()
        .map(|chunk| u16::from_be_bytes(*chunk) as u32)
        .sum::<u32>();
    if !remainder.is_empty() {
        let rh = remainder[0] as u32;
        sum += rh << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// ICMP type codes.
///
/// <https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml>
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
pub enum Icmp4Type {
    EchoReply = 0,
    DestinationUnreachable = 3,
    EchoRequest = 8,
    TimeExceeded = 11,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    zerocopy_derive::TryFromBytes,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::Immutable,
    zerocopy_derive::KnownLayout,
)]
#[repr(C)]
pub struct Ip4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: [u8; 2],
    pub identification: [u8; 2],
    pub flags_fragment_offset: [u8; 2],
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: [u8; 2],
    pub source_ip: [u8; 4],
    pub destination_ip: [u8; 4],
}

#[allow(dead_code)]
impl Ip4Header {
    pub const fn version(&self) -> u8 {
        self.version_ihl >> 4
    }
    pub const fn ihl(&self) -> u8 {
        self.version_ihl & 0x0f
    }
    pub const fn dscp(&self) -> u8 {
        self.dscp_ecn >> 2
    }
    pub const fn ecn(&self) -> u8 {
        self.dscp_ecn & 0x03
    }
    pub const fn total_length(&self) -> u16 {
        u16::from_be_bytes(self.total_length)
    }
    pub const fn identification(&self) -> u16 {
        u16::from_be_bytes(self.identification)
    }
    pub const fn flags(&self) -> u8 {
        self.flags_fragment_offset[0] >> 5
    }
    pub const fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes(self.flags_fragment_offset) & 0x1fff
    }
    pub const fn source_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from_octets(self.source_ip)
    }
    pub const fn destination_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from_octets(self.destination_ip)
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    zerocopy_derive::TryFromBytes,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::Immutable,
    zerocopy_derive::KnownLayout,
)]
#[repr(C)]
pub struct Icmp4Header {
    pub icmp_type: Icmp4Type,
    pub code: u8,
    pub checksum: [u8; 2],
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    zerocopy_derive::TryFromBytes,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::Immutable,
    zerocopy_derive::KnownLayout,
)]
#[repr(C)]
pub struct Icmp4EchoHeader {
    pub header: Icmp4Header,
    pub identifier: [u8; 2],
    pub sequence: [u8; 2],
}

impl Icmp4EchoHeader {
    pub const fn identifier(&self) -> u16 {
        u16::from_be_bytes(self.identifier)
    }
    pub const fn sequence(&self) -> u16 {
        u16::from_be_bytes(self.sequence)
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    zerocopy_derive::TryFromBytes,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::Immutable,
    zerocopy_derive::KnownLayout,
)]
#[repr(C)]
pub struct Icmp4TimeExceededOrUnreachableHeaderAndNextHeader {
    pub header: Icmp4Header,
    pub unused: u32,
    pub original_ip_header: Ip4Header,
}

impl Icmp4EchoHeader {
    pub fn echo_request(identifier: u16, sequence: u16) -> Self {
        let mut header = Self {
            header: Icmp4Header {
                icmp_type: Icmp4Type::EchoRequest,
                code: 0,
                checksum: [0, 0],
            },
            identifier: identifier.to_be_bytes(),
            sequence: sequence.to_be_bytes(),
        };
        let csum = checksum(header.as_bytes(), &[]);
        header.header.checksum = csum.to_be_bytes();
        header
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Response<'data> {
    Echo(&'data Icmp4EchoHeader),
    TimeExceeded(&'data Icmp4TimeExceededOrUnreachableHeaderAndNextHeader),
    DestinationUnreachable(&'data Icmp4TimeExceededOrUnreachableHeaderAndNextHeader),
    WhateverNotIcmp(u8),
}

pub fn parse<'data>(packet: &'data [u8]) -> Result<(Response<'data>, &'data [u8]), Error> {
    let (ip_header, packet) = Ip4Header::try_ref_from_prefix(packet)
        .map_err(|e| Error::ParseError("Ip4Header", e.to_string()))?;
    if ip_header.version() != 4 {
        return Err(Error::NotIp4);
    }
    if ip_header.protocol != 1 {
        return Ok((Response::WhateverNotIcmp(ip_header.protocol), packet));
    }
    if ip_header.ihl() < 5 {
        return Err(Error::BadIp4Ihl(ip_header.ihl()));
    }
    let options_length = (usize::from(ip_header.ihl()) - 5) * 4;
    let packet = packet
        .get(options_length..)
        .ok_or_else(|| Error::PacketTooShort)?;
    // Note that the Icmp type headers expect the ICMP header to still be present,
    // so subsequent steps use `packet` instead of what is given here.
    let (icmp_header, remaining) = Icmp4Header::try_ref_from_prefix(packet)
        .map_err(|e| Error::ParseError("Icmp4Header", e.to_string()))?;
    match icmp_header.icmp_type {
        Icmp4Type::EchoReply => {
            if checksum(icmp_header.as_bytes(), remaining) != 0 {
                return Err(Error::BadIcmpChecksum);
            }
            let (eh, rest) = Icmp4EchoHeader::try_ref_from_prefix(packet)
                .map_err(|e| Error::ParseError("Icmp4EchoHeader", e.to_string()))?;
            Ok((Response::Echo(eh), rest))
        }
        Icmp4Type::TimeExceeded => {
            let (teh, rest) =
                Icmp4TimeExceededOrUnreachableHeaderAndNextHeader::try_ref_from_prefix(packet)
                    .map_err(|e| {
                        Error::ParseError(
                            "Icmp4TimeExceededOrUnreachableHeaderAndNextHeader",
                            e.to_string(),
                        )
                    })?;
            Ok((Response::TimeExceeded(teh), rest))
        }
        Icmp4Type::DestinationUnreachable => {
            let (duh, rest) =
                Icmp4TimeExceededOrUnreachableHeaderAndNextHeader::try_ref_from_prefix(packet)
                    .map_err(|e| {
                        Error::ParseError(
                            "Icmp4TimeExceededOrUnreachableHeaderAndNextHeader",
                            e.to_string(),
                        )
                    })?;
            Ok((Response::DestinationUnreachable(duh), rest))
        }
        Icmp4Type::EchoRequest => Err(Error::UnexpectedEchoRequest),
    }
}

mod tests {
    #[test]
    fn test_checksum() {
        let data = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x0_0, 0x0_0, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let expected_checksum = 0xb861;
        assert_eq!(super::checksum(&data, &[]), expected_checksum);
        let data_split1 = [0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40];
        let data_split2 = [
            0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(
            super::checksum(&data_split1, &data_split2),
            expected_checksum
        );
    }
}
