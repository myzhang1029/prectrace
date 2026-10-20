mod json;
mod text;

use crate::tracers::{Response, Tracer};
pub use json::JsonOutput;
use serde::Serialize;
pub use text::TextOutput;

pub trait Output<T: Tracer> {
    /// Type of the error that can occur while writing outputs
    type Error;

    /// Write the results of `response` to the tty
    ///
    /// # Errors
    ///
    /// Return the reason if a write cannot be performed (e.g. content
    /// cannot be formatted for this output type or IO operations failed.
    fn write(
        &mut self,
        response: &Response<T::Probe, T::AdditionalInfo>,
        trace_info: serde_json::Value,
    ) -> Result<(), Self::Error>;
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
    type Error = serde_json::Error;

    fn write(
        &mut self,
        response: &Response<T::Probe, T::AdditionalInfo>,
        trace_info: serde_json::Value,
    ) -> Result<(), serde_json::Error> {
        match self {
            Self::Json => <JsonOutput as Output<T>>::write(&mut JsonOutput, response, trace_info),
            Self::Text => <TextOutput as Output<T>>::write(&mut TextOutput, response, trace_info)
                .map_err(|_| unreachable!()),
        }
    }
}
