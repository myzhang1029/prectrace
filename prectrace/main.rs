//! Traceroute tools designed for internet measurements.
//
// This work is conducted at Carnegie Mellon University
// SPDX-License-Identifier: Apache-2.0

mod args;

use anyhow::Context;
use clap::Parser;
use prectrace_lib::tracers::{self, TraceConfig};
use std::net::{IpAddr, SocketAddr};
use tokio::task::JoinSet;
use tracing::{info, trace};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::args::{Cli, TraceSpec};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();

    let mut cli = Cli::parse();

    if let Some(addr) = cli.address {
        if addr.is_ipv4() {
            if cli.ipv6 {
                anyhow::bail!("specified `ipv6` and an IPv4 `--address` to bind to")
            }
            cli.ipv4 = true;
        }
        if addr.is_ipv6() {
            if cli.ipv4 {
                anyhow::bail!("specified `ipv4` and an IPv6 `--address` to bind to")
            }
            cli.ipv6 = true;
        }
    }

    let mut traces = Vec::new();

    for spec in cli.icmp {
        let target = resolve_destination(&spec.destination, 0, cli.ipv4, cli.ipv6).await?;
        let tracer =
            tracers::icmp::IcmpTracer::new(target.ip(), cli.address, cli.interface.as_deref())?;
        traces.push(PreparedTrace::Icmp {
            tracer,
            config: trace_config(&spec, cli.timeout, cli.max_hops),
        });
    }

    for spec in cli.dns {
        let target = resolve_destination(&spec.destination, 53, cli.ipv4, cli.ipv6).await?;
        let tracer = tracers::dns::DnsTracer::new(
            target,
            cli.dns_query.clone(),
            cli.address,
            cli.interface.as_deref(),
        )
        .await?;
        traces.push(PreparedTrace::Dns {
            tracer,
            config: trace_config(&spec, cli.timeout, cli.max_hops),
        });
    }

    for spec in cli.sntp {
        let target = resolve_destination(&spec.destination, 123, cli.ipv4, cli.ipv6).await?;
        let tracer =
            tracers::sntp::SntpTracer::new(target, cli.address, cli.interface.as_deref()).await?;
        traces.push(PreparedTrace::Sntp {
            tracer,
            config: trace_config(&spec, cli.timeout, cli.max_hops),
        });
    }

    if traces.is_empty() {
        anyhow::bail!("at least one trace must be specified");
    }

    let mut tasks = JoinSet::new();
    for trace in traces {
        tasks.spawn(async move {
            trace!("spawned {trace:?}");
            match trace {
                PreparedTrace::Icmp { tracer, config } => {
                    tracers::Traceroute::new(tracer, config).run().await?;
                }
                PreparedTrace::Dns { tracer, config } => {
                    tracers::Traceroute::new(tracer, config).run().await?;
                }
                PreparedTrace::Sntp { tracer, config } => {
                    tracers::Traceroute::new(tracer, config).run().await?;
                }
            }
            Ok::<(), std::io::Error>(())
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.context("trace task failed")??;
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum PreparedTrace {
    Icmp {
        tracer: tracers::icmp::IcmpTracer,
        config: TraceConfig,
    },
    Dns {
        tracer: tracers::dns::DnsTracer,
        config: TraceConfig,
    },
    Sntp {
        tracer: tracers::sntp::SntpTracer,
        config: TraceConfig,
    },
}

const fn trace_config(spec: &TraceSpec, timeout: std::time::Duration, max_hops: u8) -> TraceConfig {
    TraceConfig {
        cycle_interval: spec.interval,
        min_send_spacing: spec.spacing,
        timeout,
        max_hops,
    }
}

fn validate_address_family(address: IpAddr, ipv4: bool, ipv6: bool) -> anyhow::Result<()> {
    if (ipv4 && address.is_ipv6()) || (ipv6 && address.is_ipv4()) {
        trace!("bad address {address}: wanted 4={ipv4} 6={ipv6}");
        anyhow::bail!("destination {address} does not match the requested IP family");
    }
    trace!("good address {address}");
    Ok(())
}

async fn resolve_destination(
    destination: &str,
    default_port: u16,
    ipv4: bool,
    ipv6: bool,
) -> anyhow::Result<SocketAddr> {
    if let Ok(address) = destination.parse::<SocketAddr>() {
        validate_address_family(address.ip(), ipv4, ipv6)?;
        return Ok(address);
    }
    if let Ok(address) = destination.parse::<IpAddr>() {
        validate_address_family(address, ipv4, ipv6)?;
        return Ok((address, default_port).into());
    }

    let mut result = tokio::net::lookup_host(destination)
        .await
        .map(std::iter::Iterator::collect::<Vec<SocketAddr>>);
    if result.is_err() {
        result = tokio::net::lookup_host((destination, default_port))
            .await
            .map(std::iter::Iterator::collect::<Vec<SocketAddr>>);
    }
    let mut counter = 0;
    let address = result
        .with_context(|| format!("could not resolve destination {destination:?}"))?
        .into_iter()
        .find(|address| {
            let good =
                (!ipv4 && !ipv6) || (ipv4 && address.is_ipv4()) || (ipv6 && address.is_ipv6());
            if good {
                counter += 1;
            }
            good
        });

    info!(
        "Destination {destination:} resolves to {counter} eligible address(es). Using {}",
        address.map_or_else(|| String::from("none"), |a| a.to_string())
    );

    address.with_context(|| {
        format!("destination {destination:?} resolves to no address in the requested IP family")
    })
}
