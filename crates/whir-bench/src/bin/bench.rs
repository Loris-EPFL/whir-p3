use std::{path::PathBuf, process::Command};

use clap::{Parser, ValueEnum};
use whir_bench::harness::{TerminalMode, WorkloadMode};

#[derive(Parser)]
#[command(about = "Unified WHIR benchmark harness")]
struct Args {
    /// How [[workloads]] are expanded: explicit plotted points or full axes cross-product.
    #[arg(long, value_enum, default_value_t = WorkloadModeArg::Points)]
    workload_mode: WorkloadModeArg,

    /// Which WARP terminal variants to run: witness-aware decider, WARP+terminal-WHIR, or both.
    #[arg(long, value_enum, default_value_t = TerminalModeArg::Both)]
    terminal_mode: TerminalModeArg,

    /// Path to a TOML config file
    config: PathBuf,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum WorkloadModeArg {
    Points,
    Cartesian,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TerminalModeArg {
    Decider,
    Succinct,
    Both,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let text = std::fs::read_to_string(&args.config)?;
    let cfg: whir_bench::config::BenchConfig = toml::from_str(&text)?;
    whir_bench::harness::run_matrix_with_options(
        &cfg,
        args.workload_mode.into(),
        args.terminal_mode.into(),
    )?;
    if cfg.render_pdf {
        render_pdf(&cfg)?;
    }
    Ok(())
}

impl From<WorkloadModeArg> for WorkloadMode {
    fn from(value: WorkloadModeArg) -> Self {
        match value {
            WorkloadModeArg::Points => WorkloadMode::Points,
            WorkloadModeArg::Cartesian => WorkloadMode::Cartesian,
        }
    }
}

impl From<TerminalModeArg> for TerminalMode {
    fn from(value: TerminalModeArg) -> Self {
        match value {
            TerminalModeArg::Decider => TerminalMode::Decider,
            TerminalModeArg::Succinct => TerminalMode::Succinct,
            TerminalModeArg::Both => TerminalMode::Both,
        }
    }
}

fn render_pdf(cfg: &whir_bench::config::BenchConfig) -> anyhow::Result<()> {
    let pdf_output = cfg
        .pdf_output
        .clone()
        .unwrap_or_else(|| cfg.output.with_extension("pdf"));
    if let Some(parent) = pdf_output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let plot_script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/plot.py");
    let status = Command::new("uv")
        .arg("run")
        .arg("--with")
        .arg("matplotlib")
        .arg("--with")
        .arg("pandas")
        .arg("--with")
        .arg("numpy")
        .arg(plot_script)
        .arg(&cfg.output)
        .arg("--out")
        .arg(&pdf_output)
        .status()
        .map_err(|err| anyhow::anyhow!("failed to run uv plot command: {err}"))?;

    if !status.success() {
        anyhow::bail!("plot command failed with status {status}");
    }
    Ok(())
}
