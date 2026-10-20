mod json;
mod text;

use crate::tracers::{Response, Tracer};
pub use json::JsonOutput;
use serde::Serialize;
use std::io;
pub use text::TextOutput;

pub trait Output<T>
where
    T: Tracer,
{
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
    T::AdditionalInfo: Serialize,
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
