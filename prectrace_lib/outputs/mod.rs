mod impls;
mod json;
mod text;
mod time_conversion;

use crate::tracers::{Response, Tracer};
pub use json::JsonOutput;
use serde_json::Value;
use std::io;
pub use text::TextOutput;

pub trait SerializableInfo {
    fn json(&self) -> Value;
}

pub trait Output<T: Tracer> {
    fn write(
        &mut self,
        response: &Response<T::Probe, T::AdditionalInfo>,
        trace_info: serde_json::Value,
    ) -> io::Result<()>;
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputKind {
    Json,
    Text,
}

impl<T> Output<T> for OutputKind
where
    T: Tracer,
    T::AdditionalInfo: SerializableInfo,
{
    fn write(
        &mut self,
        response: &Response<T::Probe, T::AdditionalInfo>,
        trace_info: serde_json::Value,
    ) -> io::Result<()> {
        match self {
            Self::Json => <JsonOutput as Output<T>>::write(&mut JsonOutput, response, trace_info),
            Self::Text => <TextOutput as Output<T>>::write(&mut TextOutput, response, trace_info),
        }
    }
}
