//! Traceroute tools designed for internet measurements.
//
// This work is conducted at Carnegie Mellon University
// SPDX-License-Identifier: Apache-2.0

mod outputs;
mod tracers;

use std::net::IpAddr;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
    let target = "fdc0:d227:306:2c01:0:5d2:2:ad10".parse::<IpAddr>().unwrap();
    let mut tracer = tracers::icmp::Tracer::new(target)?;
    let results = tracer.trace(30, std::time::Duration::from_secs(4)).await?;
    println!("Results: {results:?}");
    Ok(())
}
