use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default)]
pub struct Metrics {
    pub phases: BTreeMap<String, u128>,
    pub counters: BTreeMap<String, u64>,
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn time<T>(&mut self, name: &str, f: impl FnOnce() -> T) -> T {
        let start = std::time::Instant::now();
        let result = f();
        let ns = start.elapsed().as_nanos();
        *self.phases.entry(name.to_string()).or_default() += ns;
        result
    }

    pub fn record(&mut self, name: &str, ns: u128) {
        *self.phases.entry(name.to_string()).or_default() += ns;
    }

    pub fn count(&mut self, name: &str, v: u64) {
        *self.counters.entry(name.to_string()).or_default() += v;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StaticMetrics {
    pub proof_field_elems: u64,
    pub circuit_constraints: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct Row {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    pub scheme: String,
    pub axes: crate::axes::Axes,
    pub run: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    pub phases_ns: BTreeMap<String, u128>,
    pub counters: BTreeMap<String, u64>,
    #[serde(rename = "static")]
    pub static_: StaticMetrics,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_records_something() {
        let mut m = Metrics::new();
        let v = m.time("test_phase", || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            42
        });
        assert_eq!(v, 42);
        assert!(m.phases.contains_key("test_phase"));
        assert!(m.phases["test_phase"] > 0);
    }
}
