pub(crate) mod constants;
pub mod dns;
pub mod icmp;
pub(crate) mod proto;
pub mod sntp;

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const CHAN_SIZE: usize = 256;

/// States that the response can be in
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseState {
    Reached,
    OnTheWay,
    Unreachable,
    Lost,
}

impl ResponseState {
    #[must_use]
    pub const fn is_on_the_way(&self) -> bool {
        matches!(self, Self::OnTheWay)
    }
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !self.is_on_the_way()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TraceConfig {
    pub cycle_interval: Duration,
    pub min_send_spacing: Duration,
    pub timeout: Duration,
    pub max_hops: u8,
}

/// A [`Response`] is constructed for each received packet that matches a [`Probe`] we sent out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Response<P, A> {
    for_probe: P,
    source: Option<SocketAddr>,
    received_time: Option<Instant>,
    state: ResponseState,
    additional_info: Option<A>,
}

impl<P, A> Response<P, A> {
    pub const fn probe(&self) -> &P {
        &self.for_probe
    }
    pub const fn source(&self) -> Option<SocketAddr> {
        self.source
    }
    pub const fn state(&self) -> ResponseState {
        self.state
    }
    pub const fn additional_info(&self) -> Option<&A> {
        self.additional_info.as_ref()
    }
}

impl<P: Probe, A> std::fmt::Display for Response<P, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rtt = self.received_time.map_or_else(
            || String::from("???"),
            |recvd| {
                let rtt = recvd.duration_since(self.for_probe.get_sent_time());
                format!("{:.3} ms", rtt.as_secs_f64() * 1000.0)
            },
        );
        f.write_fmt(format_args!(
            "{:<3} {:<30} {:?}\trtt {rtt}",
            self.for_probe.get_num_hops(),
            self.source
                .map_or_else(|| String::from("???"), |s| s.to_string()),
            self.state,
        ))
    }
}

/// A [`Probe`] represents something that we sent out and are hoping to get a response for.
/// The response will be represented by a [`Response`] when it arrives.
///
/// A [`Probe`] is typically created by [`Tracer::send_probe`].
///
/// # Implementation
///
/// A typical implementation records some form of the `id` value passed by [`Tracer::send_probe`],
/// so that [`Tracer::match_probe_to_response`] can identify the correct response.
pub trait Probe: Clone + Send {
    fn get_sent_time(&self) -> Instant;
    fn get_num_hops(&self) -> u8;
}

/// A [`Tracer`] is a controller of a socket (or a set of sockets) that can actively send out
/// probes and receive them from the network.
///
/// This struct should NOT keep internal state of the list of sent probes (that's the job of
/// the [`Traceroute`] runner), to the extent possible.
///
/// The absolute minimum information a response needs to provide are
/// - Timestamp of reception
/// - The peer that sent the response
/// - The state of the probe ([`ResponseState`]).
///
/// It may, optionally, provide additional information described by its `AdditionalInfo`
/// associated type.
pub trait Tracer: Send + Sync + 'static {
    /// Type that holds a record per sent probe
    type Probe: Probe;
    /// Whatever raw information this tracer receives from the network
    type ReceivedPacket;
    /// Additional information that this tracer can provide
    type AdditionalInfo: Send;

    /// Send a probe to the target through the network.
    ///
    /// The function should return the [`Probe`] instance that got sent.
    ///
    /// # Arguments
    ///
    /// - `num_hops`: the TTL (IPv4) or Hop Limit (IPv6) to use for this probe
    /// - `id`: an opaque 32-bit identified for the probe. Successive probes MUST
    ///   have distinct `id` values. The current [`Traceroute`] implementation passes
    ///   a counter with random initial upper 16 bits.
    fn send_probe(
        &self,
        num_hops: u8,
        id: u32,
    ) -> impl Future<Output = io::Result<Self::Probe>> + Send;

    /// Listen for a packet on the network, possibly unrelated to any sent probes.
    ///
    /// # Implementation
    ///
    /// This function MAY return all packets it sees. Actually matching packets to probes
    /// is the job of `match_probe_to_response`.
    /// Despite so, a good implementation SHOULD filter out completely irrelevant packets
    /// that is, e.g., for a different L3/L4 protocol, because `match_probe_to_response`
    /// will be invoked on all sent packets.
    fn receive_packet(
        &self,
    ) -> impl Future<Output = io::Result<(Self::ReceivedPacket, SocketAddr, Instant)>> + Send;

    /// Check that, if `packet` matches `probe`, return a completed `Response`. Otherwise,
    /// return `None`.
    fn match_probe_to_response(
        &self,
        probe: &Self::Probe,
        packet: &Self::ReceivedPacket,
        source: SocketAddr,
        received_time: Instant,
    ) -> Option<Response<Self::Probe, Self::AdditionalInfo>>;
}

trait TracerExt: Tracer {
    async fn send_worker(
        self: Arc<Self>,
        config: TraceConfig,
        active_hops: Arc<AtomicU8>,
        probe_tx: mpsc::Sender<Self::Probe>,
    ) -> io::Result<()> {
        let mut id = 0xffff_0000 & rand::random::<u32>();
        let mut last_send: Option<Instant> = None;

        loop {
            let cycle_limit = active_hops.load(Ordering::Relaxed);
            let mut hop = 1;
            while hop <= cycle_limit {
                if let Some(sent_at) = last_send {
                    let spacing = config.min_send_spacing.saturating_sub(sent_at.elapsed());
                    if !spacing.is_zero() {
                        tokio::time::sleep(spacing).await;
                    }
                }

                let probe = self.send_probe(hop, id).await?;
                last_send = Some(probe.get_sent_time());
                probe_tx
                    .send(probe)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "receiver stopped"))?;
                id = id.wrapping_add(1);
                hop += 1;

                if hop > active_hops.load(Ordering::Relaxed) {
                    break;
                }
            }
            tokio::time::sleep(config.cycle_interval).await;
        }
    }

    async fn receive_worker(
        self: Arc<Self>,
        config: TraceConfig,
        active_hops: Arc<AtomicU8>,
        mut probe_rx: mpsc::Receiver<Self::Probe>,
        record_tx: mpsc::UnboundedSender<Response<Self::Probe, Self::AdditionalInfo>>,
    ) -> io::Result<()> {
        let mut pending = VecDeque::new();
        let mut cleanup = tokio::time::interval(Duration::from_millis(25));

        loop {
            tokio::select! {
                probe = probe_rx.recv() => {
                    let Some(probe) = probe else { return Ok(()); };
                    pending.push_back(probe);
                }
                packet = self.receive_packet() => {
                    let (packet, source, received_time) = packet?;
                    pending.retain(|probe| {
                        if let Some(matched_resp) = self.match_probe_to_response(probe, &packet, source, received_time) {
                            if matched_resp.state.is_terminal() {
                                active_hops.fetch_min(probe.get_num_hops(), Ordering::Relaxed);
                            }
                            // If `record_rx` is dropped, no one cares about the result anymore
                            record_tx.send(matched_resp).ok();
                            false
                        } else{
                            true
                        }
                    });
                }
                _ = cleanup.tick() => {
                    let now = Instant::now();
                    pending.retain(|probe| {
                        if now.duration_since(probe.get_sent_time()) > config.timeout {
                            let lost_resp = Response {
                                for_probe: probe.clone(),
                                source: None,
                                received_time: None,
                                state: ResponseState::Lost,
                                additional_info: None,
                            };
                            // If `record_rx` is dropped, no one cares about the result anymore
                            record_tx.send(lost_resp).ok();
                            false
                        } else {
                            true
                        }
                    });
                }
            }
        }
    }
}

impl<T: Tracer> TracerExt for T {}

pub struct Traceroute<T> {
    tracer: Arc<T>,
    config: TraceConfig,
}

impl<T: Tracer> Traceroute<T> {
    pub fn new(tracer: T, config: TraceConfig) -> Self {
        Self {
            tracer: Arc::new(tracer),
            config,
        }
    }

    pub async fn run(self) -> io::Result<()> {
        let (probe_tx, probe_rx) = mpsc::channel(CHAN_SIZE);
        let (record_tx, mut record_rx) = mpsc::unbounded_channel();
        let active_hops = Arc::new(AtomicU8::new(self.config.max_hops));

        let sender_config = self.config;
        let sender_active_hops = active_hops.clone();
        tokio::spawn(
            self.tracer
                .clone()
                .send_worker(sender_config, sender_active_hops, probe_tx),
        );

        let receiver_config = self.config;
        let receiver_active_hops = active_hops;
        tokio::spawn(self.tracer.receive_worker(
            receiver_config,
            receiver_active_hops,
            probe_rx,
            record_tx,
        ));

        while let Some(record) = record_rx.recv().await {
            println!("{record}");
        }

        Ok(())
    }
}
