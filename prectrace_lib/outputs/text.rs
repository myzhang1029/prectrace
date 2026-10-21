use super::Output;
use crate::time::conversion::Converter;
use crate::tracers::{Probe, Response, Tracer};
use chrono::Local;
use std::string::ToString;
use std::sync::atomic::Ordering;
use std::sync::{OnceLock, atomic::AtomicUsize};

#[derive(Debug, Default, Clone, Copy)]
pub struct TextOutput;

static SOURCE_FIELD_WIDTH: OnceLock<AtomicUsize> = OnceLock::new();

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
        let rtt = response.received_time().map_or(f64::INFINITY, |recvd| {
            let rtt = recvd.duration_since(response.sent_time());
            rtt.as_millis_f64()
        });
        let source = response
            .source()
            .as_ref()
            .map_or_else(|| String::from("???"), ToString::to_string);
        // Cap the width to [11, 52] no matter what
        let this_source_width = source.len().clamp(12, 47);
        let last_source_width = SOURCE_FIELD_WIDTH
            .get_or_init(|| AtomicUsize::new(this_source_width))
            .fetch_max(this_source_width, Ordering::Relaxed);
        let source_width = last_source_width.max(this_source_width);

        println!(
            "{:>2} {source:>source_width$} {:^11} rtt {rtt:8.3} ms sent {} distance {}",
            response.probe().get_num_hops(),
            format!("{:?}", response.state()),
            sent_time.with_timezone(&Local).format("%H:%M:%S%.3f"),
            trace_info.get("current_max_hops").unwrap_or_default()
        );
        Ok(())
    }
}
