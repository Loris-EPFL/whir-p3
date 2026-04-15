use std::path::PathBuf;

use serde::Deserialize;

use crate::axes::AxesMatrix;

#[derive(Debug, Deserialize)]
pub struct BenchConfig {
    pub axes: AxesMatrix,
    pub schemes: Vec<String>,
    #[serde(default = "default_warmup")]
    pub warmup: u32,
    pub repeats: u32,
    pub output: PathBuf,
}

fn default_warmup() -> u32 {
    0
}
