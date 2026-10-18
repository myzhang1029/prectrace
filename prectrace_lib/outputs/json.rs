use super::{Output, SerializableInfo};
use crate::tracers::{Probe, Response, Tracer};
use serde_json::json;
use std::io;

#[derive(Debug, Default, Clone, Copy)]
pub struct JsonOutput;

impl<T> Output<T> for JsonOutput
where
    T: Tracer,
    T::AdditionalInfo: SerializableInfo,
{
    fn write(&mut self, response: &Response<T::Probe, T::AdditionalInfo>) -> io::Result<()> {
        let value = json!({
            "hop": response.probe().get_num_hops(),
            "source": response.source(),
            "state": format!("{:?}", response.state()),
            "rtt_ms": response.rtt().map(|s| s.as_secs_f64()*1000.0),
            "additional_info": response.additional_info().map(SerializableInfo::json),
        });
        serde_json::to_writer(io::stdout().lock(), &value)
            .map_err(|error| io::Error::other(error.to_string()))?;
        println!();
        Ok(())
    }
}
