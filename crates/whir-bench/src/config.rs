use std::path::PathBuf;

use serde::Deserialize;

use crate::{axes::AxesMatrix, microbench::MicrobenchAxes};

#[derive(Debug, Deserialize)]
pub struct BenchConfig {
    pub axes: AxesMatrix,
    #[serde(default)]
    pub schemes: Vec<String>,
    #[serde(default)]
    pub microbenches: Vec<String>,
    #[serde(default)]
    pub microbench_axes: MicrobenchAxes,
    #[serde(default = "default_warmup")]
    pub warmup: u32,
    pub repeats: u32,
    pub output: PathBuf,
}

fn default_warmup() -> u32 {
    0
}
