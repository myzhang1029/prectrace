use super::Output;
use super::time_conversion::Converter;
use crate::tracers::{Probe, Response, Tracer};
use std::io;

#[derive(Debug, Default, Clone, Copy)]
pub struct TextOutput;

impl<T: Tracer> Output<T> for TextOutput {
    fn write(&mut self, response: &Response<T::Probe, T::AdditionalInfo>) -> io::Result<()> {
        let converter = Converter::init_or_get_global();
        let sent_time = converter
            .instant_datetime(response.sent_time())
            .expect("system time saturated (nothing we can do)");
        let rtt = response.received_time().map_or_else(
            || String::from("???"),
            |recvd| {
                let rtt = recvd.duration_since(response.sent_time());
                format!("{:.3} ms", rtt.as_secs_f64() * 1000.0)
            },
        );
        println!(
            "{:<3} {:<30} {:?}\trtt {rtt}\tsent {}",
            response.probe().get_num_hops(),
            response
                .source()
                .map_or_else(|| String::from("???"), |s| s.to_string()),
            response.state(),
            sent_time.naive_local().format("%Y-%m-%d %H:%M:%S%.f"),
        );
        Ok(())
    }
}
