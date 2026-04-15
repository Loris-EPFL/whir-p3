use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(about = "Unified WHIR benchmark harness")]
struct Args {
    /// Path to a TOML config file
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let text = std::fs::read_to_string(&args.config)?;
    let cfg: whir_bench::config::BenchConfig = toml::from_str(&text)?;
    whir_bench::harness::run_matrix(&cfg)
}
