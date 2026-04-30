use std::io::Write;

use crate::{
    axes::Axes,
    config::{BenchConfig, BenchWorkload},
    emit::{write_microbench_row, write_row},
    metrics::{Metrics, Row},
    microbench::Microbench,
    microbenches,
    scheme::FoldingScheme,
    schemes,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadMode {
    Points,
    Cartesian,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalMode {
    Decider,
    Succinct,
    Both,
}

pub fn run_matrix(cfg: &BenchConfig) -> anyhow::Result<()> {
    run_matrix_with_mode(cfg, WorkloadMode::Cartesian)
}

pub fn run_matrix_with_mode(cfg: &BenchConfig, mode: WorkloadMode) -> anyhow::Result<()> {
    run_matrix_with_options(cfg, mode, TerminalMode::Both)
}

pub fn run_matrix_with_options(
    cfg: &BenchConfig,
    mode: WorkloadMode,
    terminal_mode: TerminalMode,
) -> anyhow::Result<()> {
    if let Some(parent) = cfg.output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut out = std::io::BufWriter::new(std::fs::File::create(&cfg.output)?);
    if cfg.workloads.is_empty() {
        let axes_matrix = cfg.axes.as_ref().ok_or_else(|| {
            anyhow::anyhow!("missing [axes] or [[workloads]] in benchmark config")
        })?;
        for axes in axes_matrix.iter_cartesian() {
            for scheme in &cfg.schemes {
                if terminal_mode.includes_scheme(scheme) {
                    dispatch(None, scheme, &axes, cfg.warmup, cfg.repeats, &mut out)?;
                }
            }
        }
    } else {
        for workload in &cfg.workloads {
            run_workload(cfg, workload, mode, terminal_mode, &mut out)?;
        }
    }
    // Microbenches have their own axes (independent of the scheme sweep) and
    // run once per BenchConfig invocation.
    for mb in &cfg.microbenches {
        dispatch_microbench(mb, &cfg.microbench_axes, &mut out)?;
    }
    Ok(())
}

impl TerminalMode {
    fn includes_scheme(self, scheme: &str) -> bool {
        if scheme == "independent_whir" {
            return true;
        }
        let is_succinct = scheme.ends_with("_succinct");
        match self {
            TerminalMode::Decider => !is_succinct,
            TerminalMode::Succinct => is_succinct,
            TerminalMode::Both => true,
        }
    }
}

fn run_workload(
    cfg: &BenchConfig,
    workload: &BenchWorkload,
    mode: WorkloadMode,
    terminal_mode: TerminalMode,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let schemes = if workload.schemes.is_empty() {
        &cfg.schemes
    } else {
        &workload.schemes
    };
    let warmup = workload.warmup.unwrap_or(cfg.warmup);
    let repeats = workload.repeats.unwrap_or(cfg.repeats);
    for axes in workload_axes(workload, mode)? {
        for scheme in schemes {
            if terminal_mode.includes_scheme(scheme) {
                dispatch(
                    Some(workload.name.as_str()),
                    scheme,
                    &axes,
                    warmup,
                    repeats,
                    out,
                )?;
            }
        }
    }
    for mb in &workload.microbenches {
        dispatch_microbench(mb, &cfg.microbench_axes, out)?;
    }
    Ok(())
}

fn workload_axes(workload: &BenchWorkload, mode: WorkloadMode) -> anyhow::Result<Vec<Axes>> {
    if mode == WorkloadMode::Points && !workload.points.is_empty() {
        return Ok(workload.points.clone());
    }
    let axes = workload.axes.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "workload `{}` has no [workloads.axes] for cartesian expansion",
            workload.name
        )
    })?;
    Ok(axes.iter_cartesian().collect())
}

fn dispatch_microbench(
    name: &str,
    axes: &crate::microbench::MicrobenchAxes,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let rows = match name {
        "fs_scaling" => microbenches::fs_scaling::FsScaling::run(axes),
        "fold_verify" => microbenches::fold_verifier::FoldVerifier::run(axes),
        "circuit_size_arity" => microbenches::circuit_size_arity::CircuitSizeArity::run(axes),
        "circuit_sizes_l2" => microbenches::circuit_sizes_l2::CircuitSizesL2::run(axes),
        "terminal_whir" => microbenches::terminal_whir::TerminalWhir::run(axes),
        "warp_vs_whir" => microbenches::warp_vs_whir::WarpVsWhir::run(axes),
        "whir_in_circuit_estimate" => {
            microbenches::whir_in_circuit_estimate::WhirInCircuitEstimate::run(axes)
        }
        other => anyhow::bail!("unknown microbench: {other}"),
    };
    for r in rows {
        write_microbench_row(out, &r)?;
    }
    Ok(())
}

fn dispatch(
    workload: Option<&str>,
    name: &str,
    axes: &crate::axes::Axes,
    warmup: u32,
    repeats: u32,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    match name {
        "independent_whir" => run::<schemes::IndependentWhir>(workload, axes, warmup, repeats, out),
        "warp_standard" => run::<schemes::WarpStandard>(workload, axes, warmup, repeats, out),
        "warp_standard_succinct" => {
            run::<schemes::WarpStandardSuccinct>(workload, axes, warmup, repeats, out)
        }
        "warp_union" => {
            if axes.arity < 2 || !axes.arity.is_power_of_two() {
                skip(
                    workload,
                    out,
                    name,
                    axes,
                    "union fold needs power-of-two arity>=2",
                );
                Ok(())
            } else {
                run::<schemes::WarpUnion>(workload, axes, warmup, repeats, out)
            }
        }
        "warp_union_succinct" => {
            if axes.arity < 2 || !axes.arity.is_power_of_two() {
                skip(
                    workload,
                    out,
                    name,
                    axes,
                    "union fold needs power-of-two arity>=2",
                );
                Ok(())
            } else {
                run::<schemes::WarpUnionSuccinct>(workload, axes, warmup, repeats, out)
            }
        }
        "pure_warp" => run::<schemes::PureWarp>(workload, axes, warmup, repeats, out),
        "pure_warp_succinct" => {
            run::<schemes::PureWarpSuccinct>(workload, axes, warmup, repeats, out)
        }
        "warp_recursive_standard" => {
            run::<schemes::WarpRecursiveStandard>(workload, axes, warmup, repeats, out)
        }
        "warp_recursive_standard_succinct" => {
            run::<schemes::WarpRecursiveStandardSuccinct>(workload, axes, warmup, repeats, out)
        }
        "warp_recursive_standard_arity" => {
            if axes.arity < 2 || !axes.arity.is_power_of_two() {
                skip(
                    workload,
                    out,
                    name,
                    axes,
                    "standard arity fold needs power-of-two arity>=2",
                );
                Ok(())
            } else {
                run::<schemes::WarpRecursiveStandardArity>(workload, axes, warmup, repeats, out)
            }
        }
        "warp_recursive_standard_arity_succinct" => {
            if axes.arity < 2 || !axes.arity.is_power_of_two() {
                skip(
                    workload,
                    out,
                    name,
                    axes,
                    "standard arity fold needs power-of-two arity>=2",
                );
                Ok(())
            } else {
                run::<schemes::WarpRecursiveStandardAritySuccinct>(
                    workload, axes, warmup, repeats, out,
                )
            }
        }
        "quasar_warp" => {
            if axes.arity < 2 || !axes.arity.is_power_of_two() {
                skip(
                    workload,
                    out,
                    name,
                    axes,
                    "union fold needs power-of-two arity>=2",
                );
                Ok(())
            } else {
                run::<schemes::QuasarWarp>(workload, axes, warmup, repeats, out)
            }
        }
        "quasar_warp_succinct" => {
            if axes.arity < 2 || !axes.arity.is_power_of_two() {
                skip(
                    workload,
                    out,
                    name,
                    axes,
                    "union fold needs power-of-two arity>=2",
                );
                Ok(())
            } else {
                run::<schemes::QuasarWarpSuccinct>(workload, axes, warmup, repeats, out)
            }
        }
        #[cfg(feature = "symphony")]
        "symphony" => run::<schemes::Symphony>(workload, axes, warmup, repeats, out),
        #[cfg(not(feature = "symphony"))]
        "symphony" => {
            skip(workload, out, "symphony", axes, "symphony feature disabled");
            Ok(())
        }
        #[cfg(feature = "symphony")]
        "symphony_succinct" => {
            run::<schemes::SymphonySuccinct>(workload, axes, warmup, repeats, out)
        }
        #[cfg(feature = "symphony")]
        "symphony_standard_arity" => {
            if axes.arity < 2 || !axes.arity.is_power_of_two() {
                skip(
                    workload,
                    out,
                    name,
                    axes,
                    "standard arity fold needs power-of-two arity>=2",
                );
                Ok(())
            } else {
                run::<schemes::SymphonyStandardArity>(workload, axes, warmup, repeats, out)
            }
        }
        #[cfg(feature = "symphony")]
        "symphony_standard_arity_succinct" => {
            if axes.arity < 2 || !axes.arity.is_power_of_two() {
                skip(
                    workload,
                    out,
                    name,
                    axes,
                    "standard arity fold needs power-of-two arity>=2",
                );
                Ok(())
            } else {
                run::<schemes::SymphonyStandardAritySuccinct>(workload, axes, warmup, repeats, out)
            }
        }
        #[cfg(not(feature = "symphony"))]
        "symphony_succinct" => {
            skip(
                workload,
                out,
                "symphony_succinct",
                axes,
                "symphony feature disabled",
            );
            Ok(())
        }
        #[cfg(not(feature = "symphony"))]
        "symphony_standard_arity" => {
            skip(
                workload,
                out,
                "symphony_standard_arity",
                axes,
                "symphony feature disabled",
            );
            Ok(())
        }
        #[cfg(not(feature = "symphony"))]
        "symphony_standard_arity_succinct" => {
            skip(
                workload,
                out,
                "symphony_standard_arity_succinct",
                axes,
                "symphony feature disabled",
            );
            Ok(())
        }
        #[cfg(feature = "symphony")]
        "quasar_symphony" => {
            if axes.arity < 2 || !axes.arity.is_power_of_two() {
                skip(
                    workload,
                    out,
                    name,
                    axes,
                    "union fold needs power-of-two arity>=2",
                );
                Ok(())
            } else {
                run::<schemes::QuasarSymphony>(workload, axes, warmup, repeats, out)
            }
        }
        #[cfg(feature = "symphony")]
        "quasar_symphony_succinct" => {
            if axes.arity < 2 || !axes.arity.is_power_of_two() {
                skip(
                    workload,
                    out,
                    name,
                    axes,
                    "union fold needs power-of-two arity>=2",
                );
                Ok(())
            } else {
                run::<schemes::QuasarSymphonySuccinct>(workload, axes, warmup, repeats, out)
            }
        }
        #[cfg(not(feature = "symphony"))]
        "quasar_symphony" => {
            skip(
                workload,
                out,
                "quasar_symphony",
                axes,
                "symphony feature disabled",
            );
            Ok(())
        }
        #[cfg(not(feature = "symphony"))]
        "quasar_symphony_succinct" => {
            skip(
                workload,
                out,
                "quasar_symphony_succinct",
                axes,
                "symphony feature disabled",
            );
            Ok(())
        }
        other => anyhow::bail!("unknown scheme: {other}"),
    }
}

fn run<S: FoldingScheme>(
    workload: Option<&str>,
    axes: &crate::axes::Axes,
    warmup: u32,
    repeats: u32,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let s = S::setup(axes);
    for _ in 0..warmup {
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        s.verify(&p, &mut m)?;
    }
    for run in 0..repeats {
        let mut m = Metrics::new();
        let p = s.prove(&mut m);
        s.verify(&p, &mut m)?;
        let r = Row {
            workload: workload.map(ToOwned::to_owned),
            scheme: S::NAME.to_string(),
            axes: axes.clone(),
            run,
            skipped: None,
            phases_ns: m.phases,
            counters: m.counters,
            static_: s.static_metrics(&p),
        };
        write_row(out, &r)?;
    }
    Ok(())
}

fn skip(
    workload: Option<&str>,
    out: &mut impl Write,
    scheme: &str,
    axes: &crate::axes::Axes,
    reason: &str,
) {
    let r = Row {
        workload: workload.map(ToOwned::to_owned),
        scheme: scheme.to_string(),
        axes: axes.clone(),
        run: 0,
        skipped: Some(reason.to_string()),
        phases_ns: Default::default(),
        counters: Default::default(),
        static_: crate::metrics::StaticMetrics {
            proof_field_elems: 0,
            circuit_constraints: None,
        },
    };
    let _ = write_row(out, &r);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::axes::AxesMatrix;

    fn point(log_n: usize, total_instances: Option<usize>) -> Axes {
        Axes {
            log_n,
            arity: 4,
            batch: 8,
            ivc_steps: 1,
            step_muls: 100,
            seed: 42,
            total_instances,
            total_step_circuits: None,
        }
    }

    #[test]
    fn points_mode_prefers_explicit_workload_points() {
        let workload = BenchWorkload {
            name: "test".to_string(),
            axes: Some(AxesMatrix {
                log_n: vec![14, 16],
                arity: vec![4],
                batch: vec![8],
                ivc_steps: vec![1],
                step_muls: vec![100],
                total_instances: vec![48, 96],
                total_step_circuits: Vec::new(),
                seed: 42,
            }),
            points: vec![point(14, Some(48)), point(16, Some(96))],
            schemes: Vec::new(),
            microbenches: Vec::new(),
            warmup: None,
            repeats: None,
        };

        let axes = workload_axes(&workload, WorkloadMode::Points).unwrap();
        assert_eq!(axes.len(), 2);
        assert_eq!(axes[0].log_n, 14);
        assert_eq!(axes[1].total_instances, Some(96));
    }

    #[test]
    fn cartesian_mode_uses_axes_matrix() {
        let workload = BenchWorkload {
            name: "test".to_string(),
            axes: Some(AxesMatrix {
                log_n: vec![14, 16],
                arity: vec![4],
                batch: vec![8],
                ivc_steps: vec![1],
                step_muls: vec![100],
                total_instances: vec![48, 96],
                total_step_circuits: Vec::new(),
                seed: 42,
            }),
            points: vec![point(14, Some(48)), point(16, Some(96))],
            schemes: Vec::new(),
            microbenches: Vec::new(),
            warmup: None,
            repeats: None,
        };

        let axes = workload_axes(&workload, WorkloadMode::Cartesian).unwrap();
        assert_eq!(axes.len(), 4);
    }

    #[test]
    fn terminal_mode_filters_warp_variants_but_keeps_whir_baseline() {
        assert!(TerminalMode::Decider.includes_scheme("independent_whir"));
        assert!(TerminalMode::Succinct.includes_scheme("independent_whir"));

        assert!(TerminalMode::Decider.includes_scheme("warp_standard"));
        assert!(!TerminalMode::Decider.includes_scheme("warp_standard_succinct"));

        assert!(!TerminalMode::Succinct.includes_scheme("warp_standard"));
        assert!(TerminalMode::Succinct.includes_scheme("warp_standard_succinct"));

        assert!(TerminalMode::Both.includes_scheme("warp_standard"));
        assert!(TerminalMode::Both.includes_scheme("warp_standard_succinct"));
    }
}
