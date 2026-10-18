use anyhow::Context;
use clap::{Parser, ValueEnum};
use std::{ffi::CString, net::IpAddr, str::FromStr, time::Duration};

const DEFAULT_TIMEOUT: &str = "4s";
const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_SPACING: Duration = Duration::from_millis(100);
const DEFAULT_MAX_HOPS: u8 = 30;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Json,
    Text,
}

fn parse_duration(value: &str) -> Result<Duration, &'static str> {
    let value = value.trim();
    let Some(first_nondigit) = value.find(|c: char| !c.is_ascii_digit() && c != '.') else {
        return Err("must end with a unit and be an integer");
    };

    let (number, unit) = value.split_at(first_nondigit);
    let num = number
        .parse::<u64>()
        .map_err(|_| "must start with an integer representable as `u64`")?;
    if num == 0 {
        return Err("must not be zero");
    }
    match unit {
        "ms" => Ok(Duration::from_millis(num)),
        "s" | "sec" | "second" | "seconds" => Ok(Duration::from_secs(num)),
        "m" | "min" | "mins" | "minute" | "minutes" => Ok(Duration::from_mins(num)),
        "h" | "hr" | "hrs" | "hour" | "hours" => Ok(Duration::from_hours(num)),
        _ => Err("must end with a unit: ms, s, min, etc"),
    }
}

#[derive(Debug, Clone)]
pub struct TraceSpec {
    pub destination: String,
    pub interval: Duration,
    pub spacing: Duration,
}

impl FromStr for TraceSpec {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let fields = value.split(',').collect::<Vec<_>>();
        if fields.len() > 3 || fields.is_empty() {
            return Err("expected DEST[,INTERVAL[,SPACING]] (for example 8.8.8.8,1s,100ms)");
        }
        let interval = fields
            .get(1)
            .map_or(Ok(DEFAULT_INTERVAL), |v| parse_duration(v))?;
        let spacing = fields
            .get(2)
            .map_or(Ok(DEFAULT_SPACING), |v| parse_duration(v))?;

        if fields[0].is_empty() {
            return Err("destination must not be empty");
        }

        Ok(Self {
            destination: fields[0].to_owned(),
            interval,
            spacing,
        })
    }
}

fn parse_dns_query(value: &str) -> anyhow::Result<hickory_proto::op::Query> {
    let (name, record_type) = value
        .split_once(',')
        .with_context(|| "DNS query must given in the form of NAME,TYPE")?;
    let name = hickory_proto::rr::Name::from_str_relaxed(name.trim())?;
    let record_type = hickory_proto::rr::RecordType::from_str(record_type.trim())
        .map_err(|_| anyhow::anyhow!("invalid DNS record type {record_type}"))?;
    Ok(hickory_proto::op::Query::query(name, record_type))
}

#[derive(Debug, Parser)]
#[command(author, about, long_about = None)]
pub struct Cli {
    /// ICMP trace specification  (may be supplied more than once).
    /// The expected format is DEST[,INTERVAL[,SPACING]].
    #[arg(short = 'I', long)]
    pub icmp: Vec<TraceSpec>,
    /// DNS trace specification (may be supplied more than once).
    /// The expected format is DEST[,INTERVAL[,SPACING]].
    #[arg(short = 'D', long)]
    pub dns: Vec<TraceSpec>,
    /// SNTP trace specification (may be supplied more than once).
    /// The expected format is DEST[,INTERVAL[,SPACING]].
    #[arg(short = 'T', long)]
    pub sntp: Vec<TraceSpec>,
    /// Query name for DNS traces, in the form of NAME,QTYPE.
    #[arg(short = 'n', long, value_parser = parse_dns_query,default_value = "example.com,A")]
    pub dns_query: hickory_proto::op::Query,
    /// Timeout for each packet.
    #[arg(short = 't', long, value_parser = parse_duration, default_value = DEFAULT_TIMEOUT)]
    pub timeout: Duration,
    /// Maximum TTL/number of hops in all traces.
    #[arg(short = 'm', long, default_value_t = DEFAULT_MAX_HOPS)]
    pub max_hops: u8,
    /// Restrict resolution to IPv4.
    #[arg(short = '4', long, conflicts_with = "ipv6")]
    pub ipv4: bool,
    /// Restrict resolution to IPv6.
    #[arg(short = '6', long, conflicts_with = "ipv4")]
    pub ipv6: bool,
    /// Local address to bind all trace sockets to.
    /// Setting this option will implicitly set one of `ipv4` and `opv6`
    #[arg(short = 'a', long)]
    pub address: Option<IpAddr>,
    /// Network interface to bind all trace sockets to.
    #[arg(short = 'i', long)]
    pub interface: Option<CString>,
    /// Output format for trace responses.
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    pub output: OutputFormat,
}
