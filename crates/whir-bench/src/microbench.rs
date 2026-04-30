//! Microbench trait — for isolated measurements that don't fit the
//! setup / prove / verify FoldingScheme pattern.
//!
//! Each microbench sweeps its own axis (e.g. fold arity, log_size) and
//! emits one `MicrobenchRow` per axis point. Rows land in the same JSONL
//! file as scheme rows; `kind` = `"microbench"` distinguishes them.

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct MicrobenchRow {
    pub kind: &'static str, // always "microbench"
    pub name: String,
    pub axes: BTreeMap<String, serde_json::Value>,
    pub values: BTreeMap<String, serde_json::Value>,
}

impl MicrobenchRow {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            kind: "microbench",
            name: name.to_string(),
            axes: BTreeMap::new(),
            values: BTreeMap::new(),
        }
    }
    #[must_use]
    pub fn with_axis(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.axes.insert(key.to_string(), value.into());
        self
    }
    #[must_use]
    pub fn with_value(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.values.insert(key.to_string(), value.into());
        self
    }
}

/// Configuration axes available to microbenches. Not every axis is used by
/// every microbench — each picks the ones it needs.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct MicrobenchAxes {
    /// Fold arities to sweep (used by FS scaling, fold verifier, circuit size).
    #[serde(default = "default_arities")]
    pub arity: Vec<usize>,
    /// Constraint-matrix log size (log_m), used by FS / fold verifier benches.
    #[serde(default = "default_log_m")]
    pub log_m: usize,
    /// Codeword log size (log_n), used by FS / fold verifier benches.
    #[serde(default = "default_log_n")]
    pub log_n: usize,
    /// Witness log sizes to sweep (used by terminal WHIR + WHIR-in-circuit estimate).
    #[serde(default = "default_log_sizes")]
    pub log_size: Vec<usize>,
    /// Number of terminal-WHIR iterations averaged per log_size.
    #[serde(default = "default_terminal_repeats")]
    pub terminal_repeats: u32,
    /// Instance counts to sweep for the `warp_vs_whir` microbench.
    #[serde(default = "default_n_instances")]
    pub n_instances: Vec<usize>,
    /// Witness/constraint log sizes to sweep for the `warp_vs_whir`
    /// microbench. Each value generates one set of rows (one per
    /// `n_instances`), so the headline panel shows scaling in both axes.
    #[serde(
        default = "default_aggregate_log_n",
        deserialize_with = "deser_log_n_axis"
    )]
    pub aggregate_log_n: Vec<usize>,
}

/// Accept either a scalar (legacy) or a list for `aggregate_log_n`.
fn deser_log_n_axis<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<usize>, D::Error> {
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Scalar(usize),
        List(Vec<usize>),
    }
    Ok(match Either::deserialize(d)? {
        Either::Scalar(v) => vec![v],
        Either::List(v) => v,
    })
}

fn default_arities() -> Vec<usize> {
    vec![2, 4, 8, 16, 32, 64]
}
fn default_log_m() -> usize {
    16
}
fn default_log_n() -> usize {
    17
}
fn default_log_sizes() -> Vec<usize> {
    vec![14, 15, 16]
}
fn default_terminal_repeats() -> u32 {
    3
}
fn default_n_instances() -> Vec<usize> {
    vec![1, 2, 4, 8, 16, 32]
}
fn default_aggregate_log_n() -> Vec<usize> {
    vec![14]
}

/// A microbench runs a single measurement type against a shared axis config
/// and emits one or more rows.
pub trait Microbench {
    const NAME: &'static str;
    fn run(axes: &MicrobenchAxes) -> Vec<MicrobenchRow>;
}
