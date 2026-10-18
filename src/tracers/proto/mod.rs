//! `ICMPv[46]` support stuff.
//!
//! Note that, unlike the unfair convention in RFCs or other packages with
//! historical considerations, where `ICMP` refers to `ICMP4` and `ICMP6`
//! requires the numeric suffix, in this crate, both versions are treated as
//! completely equal and not suffixed wherever possible.

pub mod common;
pub mod icmp4;
pub mod icmp6;
pub mod raw_socket;
