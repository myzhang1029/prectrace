//! Traceroute tools designed for internet measurements.
//
// This work is conducted at Carnegie Mellon University
// SPDX-License-Identifier: Apache-2.0

mod outputs;
mod tracers;

use std::net::IpAddr;
use std::time::Duration;
use tracers::{Protocol, TraceConfig};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
    //let target = "fdc0:d227:306:2c01:0:5d2:2:ad10".parse::<IpAddr>().unwrap();
    let target = "8.8.4.4".parse::<IpAddr>().unwrap();
    let tc = TraceConfig {
        protocol: Protocol::Icmp,
        cycle_interval: Duration::from_secs(1),
        min_send_spacing: Duration::from_millis(100),
        timeout: Duration::from_secs(4),
        max_hops: 30,
    };

    tracers::Tracer::new(target, tc).run().await?;
    Ok(())
}
