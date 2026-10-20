//! Traceroute tools designed for internet measurements.
//
// This work is conducted at Carnegie Mellon University
// SPDX-License-Identifier: Apache-2.0

mod args;
mod resolution;

use clap::Parser;
use prectrace_lib::tracers::{Config as TraceConfig, Traceroutes};
use tokio::task::JoinSet;
use tracing::{error, trace};
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

    for spec in &cli.icmp {
        let target =
            resolution::resolve_destination(&spec.destination, 0, cli.ipv4, cli.ipv6).await?;
        let config = make_trace_config(spec, &cli);
        traces.push(Traceroutes::new_icmp(target.ip(), config).await?);
    }

    for spec in &cli.dns {
        let target =
            resolution::resolve_destination(&spec.destination, 53, cli.ipv4, cli.ipv6).await?;
        let config = make_trace_config(spec, &cli);
        traces.push(Traceroutes::new_dns(target, cli.dns_query.clone(), config).await?);
    }

    for spec in &cli.sntp {
        let target =
            resolution::resolve_destination(&spec.destination, 123, cli.ipv4, cli.ipv6).await?;
        let config = make_trace_config(spec, &cli);
        traces.push(Traceroutes::new_sntp(target, config).await?);
    }

    if traces.is_empty() {
        anyhow::bail!("at least one trace must be specified");
    }

    let mut tasks = JoinSet::new();

    for trace in traces {
        tasks.spawn(async move {
            trace!("spawned {trace:?}");
            match trace {
                Traceroutes::Icmp(t) => t.run_with_output(cli.output).await,
                Traceroutes::Dns(t) => t.run_with_output(cli.output).await,
                Traceroutes::Sntp(t) => t.run_with_output(cli.output).await,
            }
        });
    }
    while let Some(result) = tasks.join_next().await {
        let e = result
            .expect("Tracer panicked (this is a bug!)")
            .unwrap_err();
        error!("Tracer errored: {e:?}");
    }
    Ok(())
}

fn make_trace_config<'a>(spec: &TraceSpec, cli: &'a Cli) -> TraceConfig<'a> {
    TraceConfig {
        cycle_interval: spec.interval,
        min_send_spacing: spec.spacing,
        timeout: cli.timeout,
        num_to_reach: cli.num_to_reach,
        initial_hops: cli.initial_hops,
        max_hops: cli.max_hops,
        bind_address: cli.address,
        bind_interface: cli.interface.as_deref(),
    }
}
