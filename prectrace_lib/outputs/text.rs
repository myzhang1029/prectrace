use super::Output;
use crate::tracers::{Probe, Response, Tracer};
use std::io;

#[derive(Debug, Default, Clone, Copy)]
pub struct TextOutput;

impl<T: Tracer> Output<T> for TextOutput {
    fn write(&mut self, response: &Response<T::Probe, T::AdditionalInfo>) -> io::Result<()> {
        let rtt = response.received_time().map_or_else(
            || String::from("???"),
            |recvd| {
                let rtt = recvd.duration_since(response.sent_time());
                format!("{:.3} ms", rtt.as_secs_f64() * 1000.0)
            },
        );
        println!(
            "{:<3} {:<30} {:?}\trtt {rtt}",
            response.probe().get_num_hops(),
            response
                .source()
                .map_or_else(|| String::from("???"), |s| s.to_string()),
            response.state(),
        );
        Ok(())
    }
}
