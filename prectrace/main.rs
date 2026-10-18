//! Traceroute tools designed for internet measurements.
//
// This work is conducted at Carnegie Mellon University
// SPDX-License-Identifier: Apache-2.0

use prectrace_lib::tracers::{self, TraceConfig};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
    //let target = "fdc0:d227:306:2c01:0:5d2:2:ad10".parse::<IpAddr>()?;
    //let target = "8.8.4.4".parse::<IpAddr>()?;
    //let target = "[fd42:23eb:6cf::161]:123".parse::<SocketAddr>()?;
    let target = "44.30.70.1:123".parse::<SocketAddr>()?;
    let mut query = hickory_proto::op::Query::new();
    query
        .set_name(hickory_proto::rr::Name::from_str("example.com.")?)
        .set_query_type(hickory_proto::rr::RecordType::AAAA);
    let tc = TraceConfig {
        cycle_interval: Duration::from_secs(1),
        min_send_spacing: Duration::from_millis(100),
        timeout: Duration::from_secs(4),
        max_hops: 30,
    };
    //let tracer = tracers::icmp::IcmpTracer::new(target)?;
    //let tracer = tracers::dns::DnsTracer::new(target, query).await?;
    let tracer = tracers::sntp::SntpTracer::new(target).await?;

    tracers::Traceroute::new(tracer, tc).run().await?;
    Ok(())
}
