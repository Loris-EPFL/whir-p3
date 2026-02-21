use std::collections::BTreeMap;
use std::fs::{File, create_dir_all, read_to_string};
use std::io::Write;
use std::path::Path;

#[derive(Clone)]
struct MetricRow {
    shape: String,
    log_m: usize,
    num_cons: usize,
    num_vars: usize,
    nnz_per_row: usize,
    nnz_per_matrix_global: usize,
    total_nnz_global: usize,
    prover_ms: f64,
    verifier_ms: f64,
}

#[derive(Clone)]
struct OpeningRow {
    shape: String,
    log_m: usize,
    nnz_per_row: usize,
    nnz_per_matrix_global: usize,
    queries: usize,
    unbatched_us: f64,
    batched_us: f64,
    unbatched_field_ops: usize,
    batched_field_ops: usize,
    unbatched_serialized_fields: usize,
    batched_serialized_fields: usize,
    unbatched_full_proof_bytes: usize,
    batched_full_proof_bytes: usize,
}

#[derive(Clone)]
struct VerifierQueryRow {
    shape: String,
    log_m: usize,
    queries: usize,
    verifier_unbatched_us: f64,
    verifier_batched_us: f64,
}

#[derive(Clone)]
struct Series {
    name: String,
    points: Vec<(f64, f64)>,
}

fn main() {
    let root = Path::new("output/benchmarks/spartan_spark");
    create_dir_all(root).expect("create benchmark output dir");

    let metrics = parse_metrics(&root.join("metrics.csv"));
    let opening = parse_opening(&root.join("opening_batch_compare.csv"));
    let verifier_queries = parse_verifier_queries(&root.join("verifier_query_compare.csv"));

    if metrics.is_empty() || opening.is_empty() || verifier_queries.is_empty() {
        eprintln!("Missing benchmark data. Run `cargo run --bin spartan_spark_bench` first.");
        std::process::exit(1);
    }

    write_summary(root, &metrics, &opening, &verifier_queries);
    write_prover_verifier_plot(root, &metrics);
    write_opening_runtime_plot(root, &opening);
    write_opening_payload_plot(root, &opening);
    write_full_proof_size_plot(root, &opening);
    let verifier_plot_files = write_verifier_vs_queries_plots(root, &verifier_queries);
    append_verifier_plot_list(root, &verifier_plot_files);

    println!("Wrote report artifacts under {}", root.to_string_lossy());
}

fn parse_metrics(path: &Path) -> Vec<MetricRow> {
    let text = read_to_string(path).expect("read metrics.csv");
    text.lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let c: Vec<&str> = line.split(',').collect();
            MetricRow {
                shape: c[0].to_string(),
                log_m: c[1].parse().unwrap(),
                num_cons: c[2].parse().unwrap(),
                num_vars: c[3].parse().unwrap(),
                nnz_per_row: c[4].parse().unwrap(),
                nnz_per_matrix_global: c[5].parse().unwrap(),
                total_nnz_global: c[6].parse().unwrap(),
                prover_ms: c[7].parse().unwrap(),
                verifier_ms: c[8].parse().unwrap(),
            }
        })
        .collect()
}

fn parse_opening(path: &Path) -> Vec<OpeningRow> {
    let text = read_to_string(path).expect("read opening_batch_compare.csv");
    text.lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let c: Vec<&str> = line.split(',').collect();
            OpeningRow {
                shape: c[0].to_string(),
                log_m: c[1].parse().unwrap(),
                nnz_per_row: c[4].parse().unwrap(),
                nnz_per_matrix_global: c[5].parse().unwrap(),
                queries: c[6].parse().unwrap(),
                unbatched_us: c[7].parse().unwrap(),
                batched_us: c[8].parse().unwrap(),
                unbatched_field_ops: c[9].parse().unwrap(),
                batched_field_ops: c[10].parse().unwrap(),
                unbatched_serialized_fields: c[11].parse().unwrap(),
                batched_serialized_fields: c[12].parse().unwrap(),
                unbatched_full_proof_bytes: c[13].parse().unwrap(),
                batched_full_proof_bytes: c[14].parse().unwrap(),
            }
        })
        .collect()
}

fn parse_verifier_queries(path: &Path) -> Vec<VerifierQueryRow> {
    let text = read_to_string(path).expect("read verifier_query_compare.csv");
    text.lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let c: Vec<&str> = line.split(',').collect();
            VerifierQueryRow {
                shape: c[0].to_string(),
                log_m: c[1].parse().unwrap(),
                queries: c[6].parse().unwrap(),
                verifier_unbatched_us: c[7].parse().unwrap(),
                verifier_batched_us: c[8].parse().unwrap(),
            }
        })
        .collect()
}

fn write_summary(
    root: &Path,
    metrics: &[MetricRow],
    opening: &[OpeningRow],
    verifier_queries: &[VerifierQueryRow],
) {
    let mut out = File::create(root.join("summary.md")).expect("create summary.md");

    writeln!(out, "# Spartan+WHIR SPARK Benchmark Report").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "## Inputs").unwrap();
    writeln!(
        out,
        "- Cost sweep dimensions: `nnz_per_row`, `nnz_per_matrix_global`, `total_nnz_global`, `log m`, and shape (`square|tall|wide`)."
    )
    .unwrap();
    writeln!(
        out,
        "- Runtime comparison includes unbatched vs batched sparse opening evaluation."
    )
    .unwrap();
    writeln!(
        out,
        "- Full proof-size model includes sum-check payload, transcript overhead, and Merkle authentication-path hashes."
    )
    .unwrap();
    writeln!(out).unwrap();

    writeln!(out, "## Prover/Verifier Cost Table").unwrap();
    writeln!(
        out,
        "| shape | log_m | num_cons | num_vars | nnz_per_row | nnz_per_matrix_global | total_nnz_global | prover_ms | verifier_ms |"
    )
    .unwrap();
    writeln!(out, "|---|---:|---:|---:|---:|---:|---:|---:|---:|").unwrap();

    let mut sorted = metrics.to_vec();
    sorted.sort_by_key(|r| (r.shape.clone(), r.log_m, r.nnz_per_row));
    for r in &sorted {
        writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} | {:.4} | {:.4} |",
            r.shape,
            r.log_m,
            r.num_cons,
            r.num_vars,
            r.nnz_per_row,
            r.nnz_per_matrix_global,
            r.total_nnz_global,
            r.prover_ms,
            r.verifier_ms
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    let mut by_shape_log: BTreeMap<(String, usize), (usize, usize, usize)> = BTreeMap::new();
    for row in opening {
        let key = (row.shape.clone(), row.log_m);
        let entry = by_shape_log
            .entry(key)
            .or_insert((usize::MAX, usize::MAX, usize::MAX));
        if row.batched_us <= row.unbatched_us {
            entry.0 = entry.0.min(row.queries);
        }
        if row.batched_serialized_fields <= row.unbatched_serialized_fields {
            entry.1 = entry.1.min(row.queries);
        }
        if row.batched_full_proof_bytes <= row.unbatched_full_proof_bytes {
            entry.2 = entry.2.min(row.queries);
        }
    }

    writeln!(out, "## Crossover Thresholds").unwrap();
    writeln!(
        out,
        "| shape | log_m | runtime crossover queries | payload-fields crossover queries | full-proof-bytes crossover queries |"
    )
    .unwrap();
    writeln!(out, "|---|---:|---:|---:|---:|").unwrap();
    for ((shape, log_m), (runtime_q, payload_q, proof_q)) in by_shape_log {
        let runtime_cell = if runtime_q == usize::MAX {
            "none".to_string()
        } else {
            runtime_q.to_string()
        };
        let payload_cell = if payload_q == usize::MAX {
            "none".to_string()
        } else {
            payload_q.to_string()
        };
        let proof_cell = if proof_q == usize::MAX {
            "none".to_string()
        } else {
            proof_q.to_string()
        };
        writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            shape, log_m, runtime_cell, payload_cell, proof_cell
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    let mut verifier_shape_lines: BTreeMap<(String, usize), (f64, f64)> = BTreeMap::new();
    for row in verifier_queries {
        let key = (row.shape.clone(), row.log_m);
        let entry = verifier_shape_lines.entry(key).or_insert((0.0, 0.0));
        entry.0 += row.verifier_unbatched_us;
        entry.1 += row.verifier_batched_us;
    }

    writeln!(out, "## Verifier Query Sweep").unwrap();
    writeln!(
        out,
        "- Per-`log_m` plots are generated to show verifier-time scaling with query count."
    )
    .unwrap();
    writeln!(out).unwrap();

    writeln!(out, "## Plots").unwrap();
    writeln!(
        out,
        "- `prover_verifier_vs_total_nnz_global.svg` (cost vs true global nnz)"
    )
    .unwrap();
    writeln!(
        out,
        "- `opening_runtime_vs_queries.svg` (batched vs unbatched runtime)"
    )
    .unwrap();
    writeln!(
        out,
        "- `opening_payload_vs_queries.svg` (batched vs unbatched serialized field elements)"
    )
    .unwrap();
    writeln!(
        out,
        "- `full_proof_bytes_vs_queries.svg` (batched vs unbatched full proof size in bytes)"
    )
    .unwrap();
}

fn append_verifier_plot_list(root: &Path, plot_files: &[String]) {
    let path = root.join("summary.md");
    let mut out = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open summary for append");

    for plot in plot_files {
        writeln!(
            out,
            "- `{}` (verifier time vs queries at fixed log_m)",
            plot
        )
        .unwrap();
    }
}

fn write_prover_verifier_plot(root: &Path, rows: &[MetricRow]) {
    let mut grouped: BTreeMap<(String, usize), Vec<&MetricRow>> = BTreeMap::new();
    for row in rows {
        grouped
            .entry((row.shape.clone(), row.log_m))
            .or_default()
            .push(row);
    }

    let mut series = Vec::new();
    for ((shape, log_m), mut points) in grouped {
        points.sort_by_key(|r| r.total_nnz_global);
        series.push(Series {
            name: format!("{}-log{} prover", shape, log_m),
            points: points
                .iter()
                .map(|r| (r.total_nnz_global as f64, r.prover_ms))
                .collect(),
        });
        series.push(Series {
            name: format!("{}-log{} verifier", shape, log_m),
            points: points
                .iter()
                .map(|r| (r.total_nnz_global as f64, r.verifier_ms))
                .collect(),
        });
    }

    write_line_plot_svg(
        &root.join("prover_verifier_vs_total_nnz_global.svg"),
        "Prover/Verifier Cost vs Total nnz (Global)",
        "total_nnz_global",
        "time (ms)",
        &series,
        None,
    );
}

fn write_opening_runtime_plot(root: &Path, rows: &[OpeningRow]) {
    let mut by_q: BTreeMap<usize, (f64, f64, usize)> = BTreeMap::new();
    for row in rows {
        let e = by_q.entry(row.queries).or_insert((0.0, 0.0, 0));
        e.0 += row.unbatched_us;
        e.1 += row.batched_us;
        e.2 += 1;
    }

    let mut unbatched = Vec::new();
    let mut batched = Vec::new();
    let mut crossover_x = None;
    for (q, (u, b, n)) in by_q {
        let u_avg = u / n as f64;
        let b_avg = b / n as f64;
        if crossover_x.is_none() && b_avg <= u_avg {
            crossover_x = Some(q as f64);
        }
        unbatched.push((q as f64, u_avg));
        batched.push((q as f64, b_avg));
    }

    write_line_plot_svg(
        &root.join("opening_runtime_vs_queries.svg"),
        "Opening Runtime vs Query Batch Size",
        "queries",
        "time (us)",
        &[
            Series {
                name: "unbatched".to_string(),
                points: unbatched,
            },
            Series {
                name: "batched".to_string(),
                points: batched,
            },
        ],
        crossover_x,
    );
}

fn write_opening_payload_plot(root: &Path, rows: &[OpeningRow]) {
    let mut by_q: BTreeMap<usize, (f64, f64, usize)> = BTreeMap::new();
    for row in rows {
        let e = by_q.entry(row.queries).or_insert((0.0, 0.0, 0));
        e.0 += row.unbatched_serialized_fields as f64;
        e.1 += row.batched_serialized_fields as f64;
        e.2 += 1;
    }

    let mut unbatched = Vec::new();
    let mut batched = Vec::new();
    let mut crossover_x = None;
    for (q, (u, b, n)) in by_q {
        let u_avg = u / n as f64;
        let b_avg = b / n as f64;
        if crossover_x.is_none() && b_avg <= u_avg {
            crossover_x = Some(q as f64);
        }
        unbatched.push((q as f64, u_avg));
        batched.push((q as f64, b_avg));
    }

    write_line_plot_svg(
        &root.join("opening_payload_vs_queries.svg"),
        "Opening Payload Size vs Query Batch Size",
        "queries",
        "serialized field elements",
        &[
            Series {
                name: "unbatched".to_string(),
                points: unbatched,
            },
            Series {
                name: "batched".to_string(),
                points: batched,
            },
        ],
        crossover_x,
    );
}

fn write_full_proof_size_plot(root: &Path, rows: &[OpeningRow]) {
    let mut by_q: BTreeMap<usize, (f64, f64, usize)> = BTreeMap::new();
    for row in rows {
        let e = by_q.entry(row.queries).or_insert((0.0, 0.0, 0));
        e.0 += row.unbatched_full_proof_bytes as f64;
        e.1 += row.batched_full_proof_bytes as f64;
        e.2 += 1;
    }

    let mut unbatched = Vec::new();
    let mut batched = Vec::new();
    let mut crossover_x = None;
    for (q, (u, b, n)) in by_q {
        let u_avg = u / n as f64;
        let b_avg = b / n as f64;
        if crossover_x.is_none() && b_avg <= u_avg {
            crossover_x = Some(q as f64);
        }
        unbatched.push((q as f64, u_avg));
        batched.push((q as f64, b_avg));
    }

    write_line_plot_svg(
        &root.join("full_proof_bytes_vs_queries.svg"),
        "Full Proof Size vs Query Batch Size",
        "queries",
        "bytes",
        &[
            Series {
                name: "unbatched".to_string(),
                points: unbatched,
            },
            Series {
                name: "batched".to_string(),
                points: batched,
            },
        ],
        crossover_x,
    );
}

fn write_verifier_vs_queries_plots(root: &Path, rows: &[VerifierQueryRow]) -> Vec<String> {
    let mut log_set = BTreeMap::<usize, Vec<&VerifierQueryRow>>::new();
    for row in rows {
        log_set.entry(row.log_m).or_default().push(row);
    }

    let mut files = Vec::new();
    for (log_m, subset) in log_set {
        let mut by_q: BTreeMap<usize, (f64, f64, usize)> = BTreeMap::new();
        for row in subset {
            let e = by_q.entry(row.queries).or_insert((0.0, 0.0, 0));
            e.0 += row.verifier_unbatched_us;
            e.1 += row.verifier_batched_us;
            e.2 += 1;
        }

        let mut unbatched = Vec::new();
        let mut batched = Vec::new();
        for (q, (u, b, n)) in by_q {
            unbatched.push((q as f64, u / n as f64));
            batched.push((q as f64, b / n as f64));
        }

        let file = format!("verifier_vs_queries_logm{}.svg", log_m);
        write_line_plot_svg(
            &root.join(&file),
            &format!("Verifier Time vs Queries (fixed log_m={})", log_m),
            "queries",
            "verifier time (us)",
            &[
                Series {
                    name: "unbatched".to_string(),
                    points: unbatched,
                },
                Series {
                    name: "batched".to_string(),
                    points: batched,
                },
            ],
            None,
        );
        files.push(file);
    }

    files
}

fn write_line_plot_svg(
    path: &Path,
    title: &str,
    x_label: &str,
    y_label: &str,
    series: &[Series],
    crossover_x: Option<f64>,
) {
    let width = 1100.0;
    let height = 700.0;
    let left = 90.0;
    let right = 290.0;
    let top = 70.0;
    let bottom = 110.0;

    let mut x_min = f64::INFINITY;
    let mut x_max = f64::NEG_INFINITY;
    let mut y_min = f64::INFINITY;
    let mut y_max = f64::NEG_INFINITY;

    for s in series {
        for (x, y) in &s.points {
            x_min = x_min.min(*x);
            x_max = x_max.max(*x);
            y_min = y_min.min(*y);
            y_max = y_max.max(*y);
        }
    }

    if (x_max - x_min).abs() < f64::EPSILON {
        x_max += 1.0;
    }
    if (y_max - y_min).abs() < f64::EPSILON {
        y_max += 1.0;
    }

    let plot_w = width - left - right;
    let plot_h = height - top - bottom;
    let sx = |x: f64| left + (x - x_min) / (x_max - x_min) * plot_w;
    let sy = |y: f64| top + plot_h - (y - y_min) / (y_max - y_min) * plot_h;

    let colors = [
        "#005f73", "#0a9396", "#94d2bd", "#ee9b00", "#ca6702", "#bb3e03", "#ae2012", "#9b2226",
        "#264653", "#2a9d8f", "#e76f51", "#3a86ff",
    ];

    let mut f = File::create(path).expect("create svg");
    writeln!(
        f,
        "<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}'>"
    )
    .unwrap();
    writeln!(
        f,
        "<rect x='0' y='0' width='{width}' height='{height}' fill='#fffaf2' />"
    )
    .unwrap();
    writeln!(
        f,
        "<text x='{:.1}' y='32' font-size='24' fill='#222' font-family='Georgia'>{}</text>",
        left, title
    )
    .unwrap();

    writeln!(
        f,
        "<line x1='{left}' y1='{top}' x2='{left}' y2='{}' stroke='#333' stroke-width='2'/>",
        top + plot_h
    )
    .unwrap();
    writeln!(
        f,
        "<line x1='{left}' y1='{}' x2='{}' y2='{}' stroke='#333' stroke-width='2'/>",
        top + plot_h,
        left + plot_w,
        top + plot_h
    )
    .unwrap();

    for i in 0..=5 {
        let t = i as f64 / 5.0;
        let yv = y_min + t * (y_max - y_min);
        let y = sy(yv);
        writeln!(
            f,
            "<line x1='{left}' y1='{y:.2}' x2='{}' y2='{y:.2}' stroke='#ddd' stroke-width='1'/>",
            left + plot_w
        )
        .unwrap();
        writeln!(
            f,
            "<text x='10' y='{:.2}' font-size='12' fill='#444' font-family='monospace'>{:.3}</text>",
            y + 4.0,
            yv
        )
        .unwrap();
    }

    for i in 0..=5 {
        let t = i as f64 / 5.0;
        let xv = x_min + t * (x_max - x_min);
        let x = sx(xv);
        writeln!(
            f,
            "<line x1='{x:.2}' y1='{top}' x2='{x:.2}' y2='{}' stroke='#eee' stroke-width='1'/>",
            top + plot_h
        )
        .unwrap();
        writeln!(
            f,
            "<text x='{:.2}' y='{}' font-size='12' fill='#444' font-family='monospace'>{:.2}</text>",
            x - 12.0,
            top + plot_h + 20.0,
            xv
        )
        .unwrap();
    }

    if let Some(cx) = crossover_x {
        let x = sx(cx);
        writeln!(
            f,
            "<line x1='{x:.2}' y1='{top}' x2='{x:.2}' y2='{}' stroke='#111' stroke-dasharray='6 6' stroke-width='2'/>",
            top + plot_h
        )
        .unwrap();
        writeln!(
            f,
            "<text x='{:.2}' y='{}' font-size='12' fill='#111' font-family='monospace'>crossover={:.1}</text>",
            x + 6.0,
            top + 18.0,
            cx
        )
        .unwrap();
    }

    for (idx, s) in series.iter().enumerate() {
        let color = colors[idx % colors.len()];
        let mut d = String::new();
        for (i, (x, y)) in s.points.iter().enumerate() {
            let px = sx(*x);
            let py = sy(*y);
            if i == 0 {
                d.push_str(&format!("M {:.2} {:.2}", px, py));
            } else {
                d.push_str(&format!(" L {:.2} {:.2}", px, py));
            }
        }
        writeln!(
            f,
            "<path d='{d}' stroke='{color}' stroke-width='2.5' fill='none'/>"
        )
        .unwrap();
        for (x, y) in &s.points {
            writeln!(
                f,
                "<circle cx='{:.2}' cy='{:.2}' r='2.8' fill='{color}'/>",
                sx(*x),
                sy(*y)
            )
            .unwrap();
        }
    }

    let legend_x = left + plot_w + 30.0;
    let mut legend_y = top + 20.0;
    for (idx, s) in series.iter().enumerate() {
        let color = colors[idx % colors.len()];
        writeln!(
            f,
            "<line x1='{legend_x}' y1='{legend_y}' x2='{}' y2='{legend_y}' stroke='{color}' stroke-width='3'/>",
            legend_x + 20.0
        )
        .unwrap();
        writeln!(
            f,
            "<text x='{}' y='{}' font-size='12' fill='#222' font-family='monospace'>{}</text>",
            legend_x + 28.0,
            legend_y + 4.0,
            s.name
        )
        .unwrap();
        legend_y += 18.0;
    }

    writeln!(
        f,
        "<text x='{}' y='{}' font-size='14' fill='#222' font-family='Georgia'>{}</text>",
        left + plot_w / 2.0 - 80.0,
        height - 30.0,
        x_label
    )
    .unwrap();
    writeln!(
        f,
        "<text transform='translate(24,{}) rotate(-90)' font-size='14' fill='#222' font-family='Georgia'>{}</text>",
        top + plot_h / 2.0 + 80.0,
        y_label
    )
    .unwrap();

    writeln!(f, "</svg>").unwrap();
}
