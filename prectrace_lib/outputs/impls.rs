use super::SerializableInfo;
use serde_json::{Value, json};

impl SerializableInfo for () {
    fn json(&self) -> Value {
        Value::Null
    }
}

impl SerializableInfo for hickory_proto::op::Message {
    fn json(&self) -> Value {
        json!({
            "debug": format!("{self:?}"),
        })
    }
}

impl SerializableInfo for crate::tracers::sntp::SntpInfo {
    fn json(&self) -> Value {
        json!({
            "source": self.source,
            "leap_indicator": self.leap_indicator,
            "version": self.version,
            "mode": self.mode,
            "stratum": self.stratum,
            "poll": self.poll,
            "precision": self.precision,
            "delay": self.delay,
            "dispersion": self.dispersion,
            "reference_identifier": format!("{:?}", self.reference_identifier),
            "reference_timestamp": {
                "seconds": self.reference_timestamp.sec,
                "fraction": self.reference_timestamp.frac,
            },
            "originate_timestamp": {
                "seconds": self.originate_timestamp.sec,
                "fraction": self.originate_timestamp.frac,
            },
            "receive_timestamp": {
                "seconds": self.receive_timestamp.sec,
                "fraction": self.receive_timestamp.frac,
            },
            "transmit_timestamp": {
                "seconds": self.transmit_timestamp.sec,
                "fraction": self.transmit_timestamp.frac,
            },
        })
    }
}
