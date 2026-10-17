use zerocopy::{KnownLayout, TryCastError, TryFromBytes};

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Not an IPv4 packet")]
    NotIp4,
    #[error("Not an IPv6 packet")]
    NotIp6,
    #[error("Bad IPv4 IHL: {0}")]
    BadIp4Ihl(u8),
    #[error("IHL jumps past the end of the packet")]
    PacketTooShort,
    #[error("ICMP(6) checksum mismatch")]
    BadIcmpChecksum,
    #[error("Unexpected ICMP echo request")]
    UnexpectedEchoRequest,
    #[error("Parsing error at {0}: {1}")]
    ParseError(&'static str, String),
}

/// Convert a [`TryCastError`] into an owned type to get rid of the lifetime parameter
/// and implement [`std::error::Error`].
pub fn convert_error<Target: TryFromBytes + KnownLayout>(e: TryCastError<&[u8], Target>) -> Error {
    let typename = std::any::type_name::<Target>();
    // Depending on the log level, we either include the full error message
    // (with a representation of the bytes), or just a reason for the failure.
    if tracing::event_enabled!(tracing::Level::DEBUG) {
        Error::ParseError(typename, e.to_string())
    } else {
        match e {
            TryCastError::Size(_) => Error::ParseError(typename, String::from("size mismatch")),
            TryCastError::Alignment(_) => {
                Error::ParseError(typename, String::from("alignment mismatch"))
            }
            TryCastError::Validity(_) => Error::ParseError(typename, String::from("invalid value")),
        }
    }
}
