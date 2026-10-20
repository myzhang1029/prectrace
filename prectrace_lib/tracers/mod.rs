pub(crate) mod constants;
pub mod dns;
pub mod icmp;
pub(crate) mod proto;
pub mod sntp;
pub(crate) mod socket_utils;

use std::collections::VecDeque;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::trace;

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

/// A [`Response`] is constructed for each received packet that matches a [`Probe`] we sent out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Response<P, A> {
    for_probe: P,
    source: Option<SocketAddr>,
    received_time: Option<Instant>,
    state: ResponseState,
    additional_info: Option<A>,
}

impl<P: Probe, A> Response<P, A> {
    pub const fn new_lost(for_probe: P) -> Self {
        Self {
            for_probe,
            source: None,
            received_time: None,
            state: ResponseState::Lost,
            additional_info: None,
        }
    }
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
    pub fn sent_time(&self) -> Instant {
        self.for_probe.get_sent_time()
    }
    pub const fn received_time(&self) -> Option<Instant> {
        self.received_time
    }
    pub fn rtt(&self) -> Option<Duration> {
        self.received_time
            .map(|received| received.duration_since(self.for_probe.get_sent_time()))
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
/// so that [`Tracer::match_probe_to_response`] can identify the correct response and [`Self::get_id`]
/// can recover that value (for output generation).
pub const trait Probe: Clone + Send {
    fn get_sent_time(&self) -> Instant;
    fn get_num_hops(&self) -> u8;
    fn get_id(&self) -> u32;
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
    #[must_use]
    fn match_probe_to_response(
        &self,
        probe: &Self::Probe,
        packet: &Self::ReceivedPacket,
        source: SocketAddr,
        received_time: Instant,
    ) -> Option<Response<Self::Probe, Self::AdditionalInfo>>;

    /// If known, return the target of the trace.
    fn get_target(&self) -> Option<SocketAddr>;
}

trait TracerExt: Tracer {
    async fn send_worker(
        self: Arc<Self>,
        cycle_interval: Duration,
        min_send_spacing: Duration,
        num_to_reach: u8,
        active_hops: Arc<AtomicU8>,
        probe_tx: mpsc::Sender<Self::Probe>,
    ) -> io::Result<()> {
        let mut id = 0xffff_0000 & rand::random::<u32>();
        let mut last_send: Option<Instant> = None;

        loop {
            let cycle_limit = active_hops.load(Ordering::Relaxed);
            let mut hop = 1;
            while hop < cycle_limit + num_to_reach {
                if let Some(sent_at) = last_send {
                    let spacing = min_send_spacing.saturating_sub(sent_at.elapsed());
                    if !spacing.is_zero() {
                        tokio::time::sleep(spacing).await;
                    }
                }
                trace!("{}: sending probe {id:x}", std::any::type_name::<Self>());
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
            tokio::time::sleep(cycle_interval).await;
        }
    }

    async fn receive_worker(
        self: Arc<Self>,
        timeout: Duration,
        active_hops: Arc<AtomicU8>,
        max_hops: u8,
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
                    trace!("{}: got response", std::any::type_name::<Self>());
                    let (packet, source, received_time) = packet?;
                    pending.retain(|probe| {
                        let probe_hops = probe.get_num_hops();
                        if let Some(matched_resp) = self.match_probe_to_response(probe, &packet, source, received_time) {
                            if matched_resp.state.is_terminal() {
                                // The probe reached and/or was blocked by a firewall
                                // We can decrement what we think is the number of hops on the path
                                active_hops.fetch_min(probe_hops, Ordering::Relaxed);
                            } else if probe.get_num_hops() <= max_hops {
                                // `is_on_the_way` is `!is_terminal` so `else` implies `is_on_the_way`
                                // The probe did not reach, and we are still allowed to send probes that
                                // can travel further (`max_hops`).
                                // let's see if the current `active_hops` needs to be raised
                                active_hops.fetch_max(probe_hops, Ordering::Relaxed);
                            }
                            // If `record_rx` is dropped, no one cares about the result anymore
                            record_tx.send(matched_resp).ok();
                            false
                        } else {
                            true
                        }
                    });
                }
                _ = cleanup.tick() => {
                    pending.retain(|probe| {
                        if Instant::now().duration_since(probe.get_sent_time()) > timeout {
                            let lost_resp = Response::new_lost(probe.clone());
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

/// A [`Traceroute`] instance administers a [`Tracer`].
///
/// # Operation
///
#[derive(Debug, Clone)]
pub struct Traceroute<T: Tracer> {
    /// The underlying tracer
    tracer: Arc<T>,
    /// Delay between the end of the one trace and the start of another
    cycle_interval: Duration,
    /// Delay between successive packets in a trace
    min_send_spacing: Duration,
    /// How long to wait for a packet to arrive
    timeout: Duration,
    /// Number of packets sent above the critical number of hops
    num_to_reach: u8,
    /// Current probed number of hops
    active_hops: Arc<AtomicU8>,
    /// Absolute maximum of `active_hops`
    max_hops: u8,
}

impl<T: Tracer + Clone> Traceroute<T> {
    pub async fn run(self) -> io::Result<!> {
        self.run_with_output(crate::outputs::TextOutput).await
    }

    pub async fn run_with_output<O>(self, mut output: O) -> io::Result<!>
    where
        O: crate::outputs::Output<T>,
        <O as crate::outputs::Output<T>>::Error: std::error::Error + Send + Sync + 'static,
    {
        let (probe_tx, probe_rx) = mpsc::channel(CHAN_SIZE);
        let (record_tx, mut record_rx) = mpsc::unbounded_channel();
        let mut tasks = JoinSet::new();

        tasks.spawn(self.tracer.clone().send_worker(
            self.cycle_interval,
            self.min_send_spacing,
            self.num_to_reach,
            self.active_hops.clone(),
            probe_tx,
        ));
        tasks.spawn(self.tracer.clone().receive_worker(
            self.timeout,
            self.active_hops.clone(),
            self.max_hops,
            probe_rx,
            record_tx,
        ));
        loop {
            tokio::select! {
                Some(record) = record_rx.recv() => output.write(&record, self.export_config()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
                Some(r) = tasks.join_next() => r.expect("sender panicked (this is a bug)")?,
            }
        }
        // We always hold one `record_tx`, so `record_rx.recv` will never return `None`
    }

    fn export_config(&self) -> serde_json::Value {
        serde_json::json!({
            "target": self.tracer.get_target(),
            "type": std::any::type_name::<T>(),
            "cycle_interval": self.cycle_interval,
            "min_send_spacing": self.min_send_spacing,
            "timeout": self.timeout,
            "current_max_hops": self.active_hops.load(Ordering::Relaxed),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Config<'a> {
    pub cycle_interval: Duration,
    pub min_send_spacing: Duration,
    pub timeout: Duration,
    pub num_to_reach: u8,
    pub initial_hops: u8,
    pub max_hops: u8,
    pub bind_address: Option<IpAddr>,
    pub bind_interface: Option<&'a CStr>,
}

#[derive(Debug, Clone)]
pub enum Traceroutes {
    Icmp(Traceroute<icmp::IcmpTracer>),
    Dns(Traceroute<dns::DnsTracer>),
    Sntp(Traceroute<sntp::SntpTracer>),
}

impl Traceroutes {
    #[inline]
    pub fn new_icmp(target: IpAddr, config: Config<'_>) -> impl Future<Output = io::Result<Self>> {
        std::future::ready(Self::do_new_icmp(target, config))
    }

    fn do_new_icmp(target: IpAddr, config: Config<'_>) -> io::Result<Self> {
        let t = icmp::IcmpTracer::new(target, config.bind_address, config.bind_interface)?;
        Ok(Self::Icmp(Traceroute {
            tracer: Arc::new(t),
            cycle_interval: config.cycle_interval,
            min_send_spacing: config.min_send_spacing,
            timeout: config.timeout,
            num_to_reach: config.num_to_reach,
            active_hops: Arc::new(AtomicU8::new(config.initial_hops)),
            max_hops: config.max_hops,
        }))
    }
    pub async fn new_dns(
        target: SocketAddr,
        query: hickory_proto::op::Query,
        config: Config<'_>,
    ) -> io::Result<Self> {
        let t =
            dns::DnsTracer::new(target, query, config.bind_address, config.bind_interface).await?;
        Ok(Self::Dns(Traceroute {
            tracer: Arc::new(t),
            cycle_interval: config.cycle_interval,
            min_send_spacing: config.min_send_spacing,
            timeout: config.timeout,
            num_to_reach: config.num_to_reach,
            active_hops: Arc::new(AtomicU8::new(config.initial_hops)),
            max_hops: config.max_hops,
        }))
    }
    pub async fn new_sntp(target: SocketAddr, config: Config<'_>) -> io::Result<Self> {
        let t = sntp::SntpTracer::new(target, config.bind_address, config.bind_interface).await?;
        Ok(Self::Sntp(Traceroute {
            tracer: Arc::new(t),
            cycle_interval: config.cycle_interval,
            min_send_spacing: config.min_send_spacing,
            timeout: config.timeout,
            num_to_reach: config.num_to_reach,
            active_hops: Arc::new(AtomicU8::new(config.initial_hops)),
            max_hops: config.max_hops,
        }))
    }
}
