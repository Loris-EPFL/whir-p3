use std::io::Write;

use crate::{
    config::BenchConfig,
    emit::write_row,
    metrics::{Metrics, Row},
    scheme::FoldingScheme,
    schemes,
};

pub fn run_matrix(cfg: &BenchConfig) -> anyhow::Result<()> {
    let mut out = std::io::BufWriter::new(std::fs::File::create(&cfg.output)?);
    for axes in cfg.axes.iter_cartesian() {
        for scheme in &cfg.schemes {
            dispatch(scheme, &axes, cfg.warmup, cfg.repeats, &mut out)?;
        }
    }
    Ok(())
}

fn dispatch(
    name: &str,
    axes: &crate::axes::Axes,
    warmup: u32,
    repeats: u32,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    match name {
        "independent_whir" => run::<schemes::IndependentWhir>(axes, warmup, repeats, out),
        "warp_batch" => run::<schemes::WarpBatch>(axes, warmup, repeats, out),
        "warp_union" => {
            if axes.arity < 4 {
                skip(out, name, axes, "arity<4, union fold needs arity>=4");
                Ok(())
            } else {
                run::<schemes::WarpUnion>(axes, warmup, repeats, out)
            }
        }
        "pure_warp" => run::<schemes::PureWarp>(axes, warmup, repeats, out),
        "quasar_warp" => {
            if axes.arity < 4 {
                skip(out, name, axes, "arity<4, union fold needs arity>=4");
                Ok(())
            } else if axes.ivc_steps % (axes.arity - 1) != 0 {
                skip(
                    out,
                    name,
                    axes,
                    &format!(
                        "ivc_steps={} not divisible by arity-1={}",
                        axes.ivc_steps,
                        axes.arity - 1
                    ),
                );
                Ok(())
            } else {
                run::<schemes::QuasarWarp>(axes, warmup, repeats, out)
            }
        }
        #[cfg(feature = "symphony")]
        "symphony" => run::<schemes::Symphony>(axes, warmup, repeats, out),
        #[cfg(not(feature = "symphony"))]
        "symphony" => {
            skip(out, "symphony", axes, "symphony feature disabled");
            Ok(())
        }
        #[cfg(feature = "symphony")]
        "quasar_symphony" => {
            if axes.arity < 4 {
                skip(out, name, axes, "arity<4, union fold needs arity>=4");
                Ok(())
            } else if axes.ivc_steps % (axes.arity - 1) != 0 {
                skip(
                    out,
                    name,
                    axes,
                    &format!(
                        "ivc_steps={} not divisible by arity-1={}",
                        axes.ivc_steps,
                        axes.arity - 1
                    ),
                );
                Ok(())
            } else {
                run::<schemes::QuasarSymphony>(axes, warmup, repeats, out)
            }
        }
        #[cfg(not(feature = "symphony"))]
        "quasar_symphony" => {
            skip(out, "quasar_symphony", axes, "symphony feature disabled");
            Ok(())
        }
        other => anyhow::bail!("unknown scheme: {other}"),
    }
}

fn run<S: FoldingScheme>(
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

fn skip(out: &mut impl Write, scheme: &str, axes: &crate::axes::Axes, reason: &str) {
    let r = Row {
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
