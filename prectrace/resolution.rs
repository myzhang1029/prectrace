use anyhow::Context;
use tracing::info;

use std::net::SocketAddr;

use tracing::trace;

use std::net::IpAddr;

pub(crate) fn validate_address_family(
    address: IpAddr,
    ipv4: bool,
    ipv6: bool,
) -> anyhow::Result<()> {
    if (ipv4 && address.is_ipv6()) || (ipv6 && address.is_ipv4()) {
        trace!("bad address {address}: wanted 4={ipv4} 6={ipv6}");
        anyhow::bail!("destination {address} does not match the requested IP family");
    }
    trace!("good address {address}");
    Ok(())
}

pub(crate) async fn resolve_destination(
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
