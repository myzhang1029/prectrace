mod proto;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tracing::{debug, trace, warn};
use zerocopy::IntoBytes;

use crate::tracers::icmp::proto::{Icmp4EchoHeader, Response4};
use zerocopy::TryFromBytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub hop: u8,
    pub address: Option<SocketAddr>,
    pub round_trip_time: Option<Duration>,
    pub reached: bool,
}

pub struct Tracer {
    tokio_socket: AsyncFd<Socket>,
    target: SocketAddr,
    identifier: u16,
    sequence: u16,
}

impl Tracer {
    pub fn new(target: IpAddr) -> io::Result<Self> {
        let raw_socket = match target {
            IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?,
            IpAddr::V6(_) => Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?,
        };
        raw_socket.set_nonblocking(true)?;

        Self::new_with_socket(raw_socket, target)
    }

    // Requires that the socket is already set to non-blocking mode.
    // We take ownership of the socket to satisfy the requirements of `AsyncFd`,
    // which requires that the underlying file descriptor remains valid for the
    // lifetime of the `AsyncFd`.
    pub fn new_with_socket(socket: Socket, target: IpAddr) -> io::Result<Self> {
        // SAFETY: the validity of the fd returned by `socket.into_raw_fd()` is guaranteed by
        // the `Socket` type, the fact that we will hold its ownership, and that we will not close
        // the fd.
        let tokio_socket = unsafe { AsyncFd::register(socket)? };

        Ok(Self {
            tokio_socket,
            target: SocketAddr::new(target, 0),
            identifier: rand::random(),
            sequence: 0,
        })
    }

    pub fn into_inner(self) -> (Socket, IpAddr) {
        (self.tokio_socket.into_inner(), self.target.ip())
    }

    pub async fn trace(&mut self, max_hops: u8, timeout: Duration) -> io::Result<Vec<Hop>> {
        let mut hops = Vec::with_capacity(max_hops as usize);

        for hop in 1..=max_hops {
            let sequence = self.sequence;
            self.sequence = self.sequence.wrapping_add(1);

            if self.target.is_ipv4() {
                self.tokio_socket.get_ref().set_ttl_v4(u32::from(hop))?;
            } else {
                self.tokio_socket
                    .get_ref()
                    .set_unicast_hops_v6(u32::from(hop))?;
            }
            tracing::Span::current().record("hop", &hop);
            tracing::Span::current().record("sequence", &sequence);

            let packet = proto::Icmp4EchoHeader::echo_request(self.identifier, sequence);
            let started = Instant::now();
            debug!("sending ICMP echo request to {}", self.target);
            self.tokio_socket
                .get_ref()
                .send_to(packet.as_bytes(), &SockAddr::from(self.target))?;

            let response = self.receive_response(sequence, timeout, started).await?;
            let Some(response) = response else {
                debug!("Hop {hop} timed out");
                hops.push(Hop {
                    hop,
                    address: None,
                    round_trip_time: None,
                    reached: false,
                });
                continue;
            };
            debug!(
                "received response from {:?} in {:?}, reached: {}",
                response.address, response.round_trip_time, response.reached
            );
            let reached = response.reached;
            hops.push(Hop {
                hop,
                address: Some(response.address),
                round_trip_time: Some(response.round_trip_time),
                reached,
            });

            if reached {
                break;
            }
        }

        Ok(hops)
    }

    async fn receive_response(
        &self,
        sequence: u16,
        timeout: Duration,
        started: Instant,
    ) -> io::Result<Option<ReceivedResponse>> {
        let deadline = started + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }

            let Ok(r) = tokio::time::timeout(remaining, self.receive_packet()).await else {
                // Timed out
                return Ok(None);
            };
            let (packet, source) = r?;
            let (response, payload) = match proto::parse_v4(&packet) {
                Ok(r) => r,
                Err(e) => {
                    warn!("Failed to parse ICMP response from {source}: {e}");
                    continue;
                }
            };
            match response {
                Response4::Echo(echo) => {
                    if echo.identifier() == self.identifier && echo.sequence() == sequence {
                        return Ok(Some(ReceivedResponse {
                            address: source,
                            round_trip_time: started.elapsed(),
                            reached: true,
                        }));
                    } else {
                        debug!(
                            "received echo reply from {source} with mismatched identifier/sequence: {echo:?}"
                        );
                    }
                }
                Response4::TimeExceeded(te) => {
                    if matches_probe(&te.original_ip_header, payload, self.identifier, sequence) {
                        return Ok(Some(ReceivedResponse {
                            address: source,
                            round_trip_time: started.elapsed(),
                            reached: false,
                        }));
                    }
                }
                Response4::DestinationUnreachable(du) => {
                    if matches_probe(&du.original_ip_header, payload, self.identifier, sequence) {
                        return Ok(Some(ReceivedResponse {
                            address: source,
                            round_trip_time: started.elapsed(),
                            reached: false,
                        }));
                    }
                }
                Response4::WhateverNotIcmp(_) => {
                    debug!("received non-ICMP packet from {source}");
                }
            }
        }
    }

    async fn receive_packet(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        loop {
            let mut readiness = self.tokio_socket.readable().await?;
            if let Ok(packet) = readiness.try_io(do_recv_callback) {
                return packet;
            }
            // else: WouldBlock
        }
    }
}

fn matches_probe(
    original_ip_header: &proto::Ip4Header,
    payload: &[u8],
    identifier: u16,
    sequence: u16,
) -> bool {
    if original_ip_header.protocol != 1 || original_ip_header.ihl() < 5 {
        return false;
    }

    let options_length = (usize::from(original_ip_header.ihl()) - 5) * 4;
    let Ok((echo, _)) =
        Icmp4EchoHeader::try_ref_from_prefix(payload.get(options_length..).unwrap_or_default())
    else {
        return false;
    };

    echo.header.icmp_type == proto::Icmp4Type::EchoRequest
        && echo.identifier() == identifier
        && echo.sequence() == sequence
}

#[tracing::instrument(level = "debug", skip_all)]
#[inline]
fn do_recv_callback(inner: &AsyncFd<Socket>) -> Result<(Vec<u8>, SocketAddr), io::Error> {
    let mut buffer = [MaybeUninit::<u8>::uninit(); 4096];
    let (length, source) = inner.get_ref().recv_from(&mut buffer)?;
    let source = source
        .as_socket()
        .expect("This `SockAddr` should be always a `SocketAddr` (this is a bug!)");
    // SAFETY: these `length` bytes are initialized by `recv_from`.
    let bytes = buffer[..length]
        .iter()
        .map(|b| unsafe { b.assume_init() })
        .collect::<Vec<u8>>();
    trace!("received {length} bytes from {source}: {bytes:02x?}");
    Ok((bytes, source))
}

pub struct ReceivedResponse {
    pub address: SocketAddr,
    pub round_trip_time: Duration,
    pub reached: bool,
}
