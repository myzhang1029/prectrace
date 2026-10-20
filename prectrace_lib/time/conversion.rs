//! This module roughly converts `Instants` to human times.
//!
//! The conversion is exact close to "now" but might drift away as the system time
//! drifts or gets adjusted.
//!
//! This module is only for printing outputs and is so-designed because the actual
//! tracing part must use a more steady source of time to calculate rtt, etc.
//! The unreliability of this module is a feature not a bug :)

use chrono::{DateTime, Utc};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime};
use tracing::warn;

static GLOBAL_CONVERTER: OnceLock<Converter> = OnceLock::new();

#[derive(Debug)]
pub struct Converter {
    instant_epoch: Instant,
}

impl Converter {
    pub fn new() -> Self {
        let st_epoch = SystemTime::UNIX_EPOCH;
        let st_now = SystemTime::now();
        let inst_now = Instant::now();

        let instant_epoch = match st_now.duration_since(st_epoch) {
            Ok(diff) => inst_now
                .checked_sub(diff)
                .expect("time difference out of range (nothing we can do)"),
            Err(e) => {
                warn!("System time before the Unix epoch");
                inst_now + e.duration()
            }
        };
        Self { instant_epoch }
    }
    #[must_use]
    pub fn instant_unix_timestamp(&self, instant: Instant) -> Option<(u64, u32)> {
        let diff = instant.checked_duration_since(self.instant_epoch)?;
        let sec_part = diff.as_secs();
        let ns_part = diff.subsec_nanos();
        Some((sec_part, ns_part))
    }

    #[must_use]
    pub fn instant_datetime(&self, instant: Instant) -> Option<DateTime<Utc>> {
        self.instant_unix_timestamp(instant)
            .and_then(|(secs, nsecs)| {
                let secs = i64::try_from(secs).ok()?;
                DateTime::from_timestamp(secs, nsecs)
            })
    }

    pub fn init_or_get_global() -> &'static Self {
        GLOBAL_CONVERTER.get_or_init(Self::default)
    }
}

impl Default for Converter {
    fn default() -> Self {
        Self::new()
    }
}
