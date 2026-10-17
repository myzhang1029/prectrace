mod dns;
pub mod icmp;
pub mod icmp_tracer;

use std::collections::HashMap;
use std::fmt::Display;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const CHAN_SIZE: usize = 256;

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Icmp,
}

/// States that the response can be in
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseState {
    Reached,
    OnTheWay,
    Unreachable,
    Lost,
}

impl ResponseState {
    pub const fn is_on_the_way(&self) -> bool {
        matches!(self, ResponseState::OnTheWay)
    }
    pub const fn is_terminal(&self) -> bool {
        !self.is_on_the_way()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TraceConfig {
    pub protocol: Protocol,
    pub cycle_interval: Duration,
    pub min_send_spacing: Duration,
    pub timeout: Duration,
    pub max_hops: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct TraceRecord {
    pub protocol: Protocol,
    pub hop: u8,
    pub sequence: u16,
    pub sent_time: Instant,
    pub received_time: Option<Instant>,
    pub source: Option<SocketAddr>,
    pub state: ResponseState,
}

impl Display for TraceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rtt = if let Some(received) = self.received_time {
            let rtt = received.duration_since(self.sent_time);
            format!("{:.3} ms", rtt.as_secs_f64() * 1000.0)
        } else {
            String::from("???")
        };
        f.write_fmt(format_args!(
            "{:<3} {:<30} {:?}\trtt {rtt}, seq {}",
            self.hop,
            self.source
                .map(|s| s.to_string())
                .unwrap_or_else(|| String::from("???")),
            self.state,
            self.sequence,
        ))
    }
}

pub struct Tracer {
    target: IpAddr,
    config: TraceConfig,
}

impl Tracer {
    pub const fn new(target: IpAddr, config: TraceConfig) -> Self {
        Self { target, config }
    }

    pub async fn run(self) -> io::Result<()> {
        let icmp = icmp::IcmpTracer::new(self.target)?;
        let (probe_tx, probe_rx) = mpsc::channel(CHAN_SIZE);
        let (record_tx, mut record_rx) = mpsc::channel(CHAN_SIZE);
        let active_hops = Arc::new(AtomicU8::new(self.config.max_hops));

        let sender_config = self.config;
        let sender_icmp = icmp.clone();
        let sender_active_hops = active_hops.clone();
        tokio::spawn(async move {
            send_worker(sender_icmp, sender_config, sender_active_hops, probe_tx).await
        });

        let receiver_config = self.config;
        let receiver_active_hops = active_hops;
        tokio::spawn(receive_worker(
            icmp,
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

async fn send_worker(
    icmp: icmp::IcmpTracer,
    config: TraceConfig,
    active_hops: Arc<AtomicU8>,
    probe_tx: mpsc::Sender<icmp::Probe>,
) -> io::Result<()> {
    let mut sequence = 0u16;
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

            let probe = icmp.send_probe(hop, sequence).await?;
            last_send = Some(probe.sent_time);
            probe_tx
                .send(probe)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "receiver stopped"))?;
            sequence = sequence.wrapping_add(1);
            hop += 1;

            if hop > active_hops.load(Ordering::Relaxed) {
                break;
            }
        }
        tokio::time::sleep(config.cycle_interval).await;
    }
}

async fn receive_worker(
    icmp: icmp::IcmpTracer,
    config: TraceConfig,
    active_hops: Arc<AtomicU8>,
    mut probe_rx: mpsc::Receiver<icmp::Probe>,
    record_tx: mpsc::Sender<TraceRecord>,
) -> io::Result<()> {
    let mut pending = HashMap::new();
    let mut cleanup = tokio::time::interval(Duration::from_millis(25));

    loop {
        tokio::select! {
            probe = probe_rx.recv() => {
                let Some(probe) = probe else { return Ok(()); };
                pending.insert(probe.sequence, probe);
            }
            packet = icmp.receive_packet() => {
                let (packet, source, received_time) = packet?;
                let matched = pending.iter().find_map(|(sequence, probe)| {
                    icmp.classify(*probe, &packet, source, received_time)
                        .map(|response| (*sequence, response))
                });
                if let Some((sequence, response)) = matched {
                    let probe = pending.remove(&sequence).expect("pending probe disappeared");
                    if response.state.is_terminal() {
                        active_hops.fetch_min(probe.hop, Ordering::Relaxed);
                    }
                    record_tx.send(TraceRecord {
                        protocol: config.protocol,
                        hop: probe.hop,
                        sequence: probe.sequence,
                        sent_time: probe.sent_time,
                        received_time: Some(response.received_time),
                        source: Some(response.source),
                        state: response.state,
                    }).await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "output stopped"))?;
                }
            }
            _ = cleanup.tick() => {
                let expired = pending.extract_if(|_, probe| probe.sent_time.elapsed() >= config.timeout)
                    .map(|(_, probe)| probe)
                    .collect::<Vec<_>>();
                for probe in expired {
                    if probe.hop == active_hops.load(Ordering::Relaxed)
                        && probe.hop < config.max_hops
                    {
                        active_hops.fetch_max(probe.hop + 1, Ordering::Relaxed);
                    }
                    record_tx.send(TraceRecord {
                        protocol: config.protocol,
                        hop: probe.hop,
                        sequence: probe.sequence,
                        sent_time: probe.sent_time,
                        received_time: None,
                        source: None,
                        state: ResponseState::Lost,
                    }).await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "output stopped"))?;
                }
            }
        }
    }
}
