use super::Output;
use super::time_conversion::Converter;
use crate::tracers::{Probe, Response, Tracer};
use chrono::SecondsFormat;
use serde::Serialize;
use serde_json::json;
use std::io;

#[derive(Debug, Default, Clone, Copy)]
pub struct JsonOutput;

impl<T> Output<T> for JsonOutput
where
    T: Tracer,
    T::AdditionalInfo: Serialize,
{
    fn write(
        &mut self,
        response: &Response<T::Probe, T::AdditionalInfo>,
        trace_info: serde_json::Value,
    ) -> io::Result<()> {
        let converter = Converter::init_or_get_global();
        let sent_time = converter
            .instant_datetime(response.sent_time())
            .expect("system time saturated (nothing we can do)");
        let value = json!({
            "hop": response.probe().get_num_hops(),
            "source": response.source(),
            "state": format!("{:?}", response.state()),
            "sent": sent_time.to_rfc3339_opts(SecondsFormat::AutoSi, true),
            "rtt_ms": response.rtt().map(|s| s.as_secs_f64()*1000.0),
            "id": response.probe().get_id(),
            "additional_info": response.additional_info(),
            "trace_info": trace_info,
        });
        serde_json::to_writer(io::stdout().lock(), &value)
            .map_err(|error| io::Error::other(error.to_string()))?;
        println!();
        Ok(())
    }
}
