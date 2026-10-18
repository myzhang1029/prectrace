//! Protocol-level stuff for `ICMPv[46]` and various socket utilities.
//!
//! Note that, unlike the unfair convention in RFCs or other packages with
//! historical considerations, where `ICMP` refers to `ICMP4` and `ICMP6`
//! requires the numeric suffix, in this crate, both versions are treated as
//! completely equal and not suffixed wherever possible.

use crate::tracers::ResponseState;
use std::net::IpAddr;

mod common;
pub mod icmp4;
pub mod icmp6;
pub mod raw_socket;
pub mod udp;

/// Check the content of a IP payload (i.e. begins with the L4 header) `packet` and
/// convert matching ICMP errors to [`ResponseState`].
///
/// This function checks that `packet` contains an `ICMP[46]` Time Exceeded or
/// Destination Unreachable payload, and if so, continues to check that it has an
/// embedded IP header destined for `target` specifying proto/nh `l4_proto`.
///
/// Finally, if both of the previous two checks succeed, run `l4_filter` on the inner
/// IP's payload (may be only 8 bytes if the sending host does not support RFC 4884).
///
/// # Returns
/// `None` if `packet` does not match the description or `l4_filter` returns `false`.
/// `Some` containing the appropriate [`ResponseState`] value (as determined by
/// `to_response_state`) if it does match and `l4_filter` subsequently returns `true`.
pub fn retain_icmp_errors_cvt_resp<'a>(
    target: IpAddr,
    packet: &'a [u8],
    l4_proto: u8,
    l4_filter: impl FnOnce(&'a [u8]) -> bool,
) -> Option<ResponseState> {
    match target {
        IpAddr::V4(ip) => {
            use icmp4::Response;
            let (icmprsp, payload) = Response::parse(packet).ok()?;
            if !matches!(
                icmprsp,
                Response::TimeExceeded(_) | Response::DestinationUnreachable(_)
            ) {
                return None;
            }
            let (header, payload) = icmp4::IpHeader::try_parse_ref_skip_option(payload).ok()?;
            if header.protocol != l4_proto || header.destination_ip() != ip || !l4_filter(payload) {
                return None;
            }
            Some(icmprsp.to_response_state())
        }
        IpAddr::V6(ip) => {
            use icmp6::Response;
            let (icmprsp, payload) = Response::parse(packet).ok()?;
            if !matches!(
                icmprsp,
                Response::TimeExceeded(_) | Response::DestinationUnreachable(_)
            ) {
                return None;
            }
            let (header, payload) = icmp6::IpHeader::try_parse_ref_skip_option(payload).ok()?;
            if header.next_header != l4_proto
                || header.destination_ip() != ip
                || !l4_filter(payload)
            {
                return None;
            }
            Some(icmprsp.to_response_state())
        }
    }
}
