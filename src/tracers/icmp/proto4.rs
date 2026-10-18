//! Limited implementation of RFC 792 and RFC 4443
//!
//! Implementation notes:
//! Every layer of the protocol stack is represented by a Header struct,
//! and subsequent layers includes the previous layer's header except that the L4
//! header does not include the `IPv[46]` header. This is because `socket2`'s API
//! will create its own L3 header.

use super::common::{Error, convert_error};
use std::net::Ipv4Addr;
use zerocopy::{IntoBytes, TryFromBytes};

pub const ICMP_PROTO_NUMBER: u8 = 1;

// The Internet Checksum (RFC 1071)
fn checksum(packet: &[u8], mut additional_data: &[u8]) -> u16 {
    let (chunks, remainder) = packet.as_chunks::<2>();
    let mut sum: u32 = chunks
        .iter()
        .map(|chunk| u32::from(u16::from_be_bytes(*chunk)))
        .sum();
    if !remainder.is_empty() {
        let rh = u32::from(remainder[0]);
        sum += rh << 8;
        if !additional_data.is_empty() {
            sum += u32::from(additional_data[0]);
            additional_data = &additional_data[1..];
        }
    }
    let (chunks, remainder) = additional_data.as_chunks::<2>();
    sum += chunks
        .iter()
        .map(|chunk| u32::from(u16::from_be_bytes(*chunk)))
        .sum::<u32>();
    if !remainder.is_empty() {
        let rh = u32::from(remainder[0]);
        sum += rh << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation)]
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
pub enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    EchoRequest = 8,
    TimeExceeded = 11,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    zerocopy_derive::TryFromBytes,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::Immutable,
    zerocopy_derive::KnownLayout,
)]
#[repr(C)]
pub struct IpHeader {
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
impl IpHeader {
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
    pub const fn is_icmp(&self) -> bool {
        self.protocol == ICMP_PROTO_NUMBER
    }
    /// Like `try_ref_from_prefix`, but skips over the IP options if present.
    ///
    /// # Returns
    ///
    /// (`Ip4Header`, payload) if successful, or whatever error encountered.
    pub fn try_parse_ref_skip_option(packet: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (header, _) = Self::try_ref_from_prefix(packet).map_err(convert_error)?;
        if header.ihl() < 5 {
            return Err(Error::BadIp4Ihl(header.ihl()));
        }
        let options_length = usize::from(header.ihl()) * 4;
        let packet = packet.get(options_length..).ok_or(Error::PacketTooShort)?;
        if header.version() != 4 {
            return Err(Error::NotIp4);
        }
        Ok((*header, packet))
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
pub struct IcmpHeader {
    pub icmp_type: IcmpType,
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
pub struct IcmpEchoHeader {
    pub header: IcmpHeader,
    pub identifier: [u8; 2],
    pub sequence: [u8; 2],
}

impl IcmpEchoHeader {
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
pub struct IcmpTimeExceededOrUnreachableHeaderAndNextHeader {
    pub header: IcmpHeader,
    _unused: u32,
}

impl IcmpEchoHeader {
    pub fn echo_request(identifier: u16, sequence: u16) -> Self {
        let mut header = Self {
            header: IcmpHeader {
                icmp_type: IcmpType::EchoRequest,
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
    Echo(&'data IcmpEchoHeader),
    TimeExceeded(&'data IcmpTimeExceededOrUnreachableHeaderAndNextHeader),
    DestinationUnreachable(&'data IcmpTimeExceededOrUnreachableHeaderAndNextHeader),
    IpProtoNotIcmp(u8),
}

pub fn parse(packet: &[u8]) -> Result<(Response<'_>, &[u8]), Error> {
    let (ip_header, packet) = IpHeader::try_parse_ref_skip_option(packet)?;
    if ip_header.protocol != ICMP_PROTO_NUMBER {
        return Ok((Response::IpProtoNotIcmp(ip_header.protocol), packet));
    }
    // Note that the Icmp type headers expect the ICMP header to still be present,
    // so subsequent steps use `packet` instead of what is given here.
    let (icmp_header, remaining) =
        IcmpHeader::try_ref_from_prefix(packet).map_err(convert_error)?;
    match icmp_header.icmp_type {
        IcmpType::EchoReply => {
            if checksum(icmp_header.as_bytes(), remaining) != 0 {
                return Err(Error::BadIcmpChecksum);
            }
            let (eh, rest) = IcmpEchoHeader::try_ref_from_prefix(packet).map_err(convert_error)?;
            Ok((Response::Echo(eh), rest))
        }
        IcmpType::TimeExceeded => {
            let (teh, rest) =
                IcmpTimeExceededOrUnreachableHeaderAndNextHeader::try_ref_from_prefix(packet)
                    .map_err(convert_error)?;
            Ok((Response::TimeExceeded(teh), rest))
        }
        IcmpType::DestinationUnreachable => {
            let (duh, rest) =
                IcmpTimeExceededOrUnreachableHeaderAndNextHeader::try_ref_from_prefix(packet)
                    .map_err(convert_error)?;
            Ok((Response::DestinationUnreachable(duh), rest))
        }
        IcmpType::EchoRequest => Err(Error::UnexpectedEchoRequest),
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
