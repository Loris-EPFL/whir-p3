use std::path::PathBuf;

use serde::Deserialize;

use crate::{
    axes::{Axes, AxesMatrix},
    microbench::MicrobenchAxes,
};

#[derive(Debug, Deserialize)]
pub struct BenchConfig {
    #[serde(default)]
    pub axes: Option<AxesMatrix>,
    #[serde(default)]
    pub schemes: Vec<String>,
    #[serde(default)]
    pub workloads: Vec<BenchWorkload>,
    #[serde(default)]
    pub microbenches: Vec<String>,
    #[serde(default)]
    pub microbench_axes: MicrobenchAxes,
    #[serde(default = "default_warmup")]
    pub warmup: u32,
    #[serde(default = "default_repeats")]
    pub repeats: u32,
    pub output: PathBuf,
    #[serde(default)]
    pub render_pdf: bool,
    pub pdf_output: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct BenchWorkload {
    pub name: String,
    pub axes: Option<AxesMatrix>,
    #[serde(default)]
    pub points: Vec<Axes>,
    #[serde(default)]
    pub schemes: Vec<String>,
    #[serde(default)]
    pub microbenches: Vec<String>,
    pub warmup: Option<u32>,
    pub repeats: Option<u32>,
}

fn default_warmup() -> u32 {
    0
}

fn default_repeats() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_config_carries_points_and_cartesian_axes() {
        let cfg: BenchConfig = toml::from_str(include_str!("../configs/dashboard.toml")).unwrap();
        assert!(cfg.render_pdf);
        assert_eq!(cfg.workloads.len(), 3);

        let family_a = &cfg.workloads[0];
        assert_eq!(family_a.points.len(), 4);
        assert_eq!(family_a.axes.as_ref().unwrap().iter_cartesian().count(), 16);

        let recursive = &cfg.workloads[2];
        assert_eq!(recursive.points.len(), 3);
        assert_eq!(
            recursive.axes.as_ref().unwrap().iter_cartesian().count(),
            12
        );
    }
}
