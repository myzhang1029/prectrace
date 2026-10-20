use super::Output;
use crate::time::conversion::Converter;
use crate::tracers::{Probe, Response, Tracer};

#[derive(Debug, Default, Clone, Copy)]
pub struct TextOutput;

impl<T: Tracer> Output<T> for TextOutput {
    type Error = !;

    fn write(
        &mut self,
        response: &Response<T::Probe, T::AdditionalInfo>,
        trace_info: serde_json::Value,
    ) -> Result<(), !> {
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
            "{:<3} {:<30} {:?}\trtt {rtt}\tsent {}\tdistance {}",
            response.probe().get_num_hops(),
            response
                .source()
                .map_or_else(|| String::from("???"), |s| s.to_string()),
            response.state(),
            sent_time.naive_local().format("%Y-%m-%d %H:%M:%S%.f"),
            trace_info.get("current_max_hops").unwrap_or_default()
        );
        Ok(())
    }
}
