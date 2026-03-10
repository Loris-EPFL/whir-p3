use std::collections::BTreeMap;
use std::fs::{create_dir_all, read_to_string, File};
use std::io::Write;
use std::path::Path;

use serde::Deserialize;

#[derive(Clone, Debug)]
struct BenchRow {
    variant: String,
    size_label: String,
    log_size: usize,
    claims: usize,
    time_ms: f64,
}

#[derive(Deserialize)]
struct Estimates {
    median: Statistic,
}

#[derive(Deserialize)]
struct Statistic {
    point_estimate: f64,
}

fn main() {
    let criterion_root = Path::new("target/criterion/spartan_whir_vs_warp");
    let out_root = Path::new("output/benchmarks/accumulation");
    create_dir_all(out_root).expect("create accumulation benchmark output directory");

    let rows = collect_rows(criterion_root);
    if rows.is_empty() {
        eprintln!(
            "Missing accumulation benchmark data. Run `cargo bench --bench accumulation` first."
        );
        std::process::exit(1);
    }

    write_summary(out_root, &rows);
    write_absolute_time_plot(out_root, &rows, "prove");
    write_absolute_time_plot(out_root, &rows, "verify");
    write_speedup_plot(out_root, &rows, "prove");
    write_speedup_plot(out_root, &rows, "verify");

    println!(
        "Wrote accumulation report artifacts under {}",
        out_root.display()
    );
}

fn collect_rows(root: &Path) -> Vec<BenchRow> {
    let mut rows = Vec::new();
    for variant in [
        "regular_prove",
        "regular_verify",
        "accumulated_prove",
        "accumulated_verify",
    ] {
        let variant_dir = root.join(variant);
        let Ok(entries) = std::fs::read_dir(&variant_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some((log_size, claims)) = parse_case_name(&name) {
                let estimates_path = path.join("new/estimates.json");
                if let Some(time_ms) = read_estimate_ms(&estimates_path) {
                    rows.push(BenchRow {
                        variant: variant.to_string(),
                        size_label: format!("2^{log_size}"),
                        log_size,
                        claims,
                        time_ms,
                    });
                }
            }
        }
    }
    rows.sort_by_key(|row| (row.log_size, row.claims, row.variant.clone()));
    rows
}

fn parse_case_name(name: &str) -> Option<(usize, usize)> {
    let parts: Vec<_> = name.split('_').collect();
    if parts.len() != 3
        || parts[0] != "2"
        || !parts[1].starts_with('1') && !parts[1].starts_with('8')
    {
        if !name.starts_with("2_") {
            return None;
        }
    }
    let prefix = name.strip_prefix("2_")?;
    let (log_str, k_str) = prefix.split_once("_k=")?;
    Some((log_str.parse().ok()?, k_str.parse().ok()?))
}

fn read_estimate_ms(path: &Path) -> Option<f64> {
    let text = read_to_string(path).ok()?;
    let estimates: Estimates = serde_json::from_str(&text).ok()?;
    Some(estimates.median.point_estimate / 1_000_000.0)
}

fn write_summary(root: &Path, rows: &[BenchRow]) {
    let mut out = File::create(root.join("summary.md")).expect("create accumulation summary");
    writeln!(out, "# Accumulation Benchmark Report").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "| size | claims | regular_prove_ms | accumulated_prove_ms | prove_speedup | regular_verify_ms | accumulated_verify_ms | verify_speedup |")
        .unwrap();
    writeln!(out, "|---|---:|---:|---:|---:|---:|---:|---:|").unwrap();

    let mut table: BTreeMap<(usize, usize), BTreeMap<String, f64>> = BTreeMap::new();
    for row in rows {
        table
            .entry((row.log_size, row.claims))
            .or_default()
            .insert(row.variant.clone(), row.time_ms);
    }

    for ((log_size, claims), vals) in &table {
        let rp = vals["regular_prove"];
        let ap = vals["accumulated_prove"];
        let rv = vals["regular_verify"];
        let av = vals["accumulated_verify"];
        writeln!(
            out,
            "| 2^{} | {} | {:.3} | {:.3} | {:.2}x | {:.3} | {:.3} | {:.2}x |",
            log_size,
            claims,
            rp,
            ap,
            rp / ap,
            rv,
            av,
            rv / av
        )
        .unwrap();
    }

    writeln!(out).unwrap();
    writeln!(
        out,
        "Generated from Criterion estimates in `target/criterion/spartan_whir_vs_warp/`."
    )
    .unwrap();
}

fn write_speedup_plot(root: &Path, rows: &[BenchRow], mode: &str) {
    let filename = format!("{}_speedup.svg", mode);
    let path = root.join(filename);
    let mut out = File::create(path).expect("create svg plot");

    let mut series: BTreeMap<usize, Vec<(usize, f64)>> = BTreeMap::new();
    let mut table: BTreeMap<(usize, usize), BTreeMap<String, f64>> = BTreeMap::new();
    for row in rows {
        table
            .entry((row.log_size, row.claims))
            .or_default()
            .insert(row.variant.clone(), row.time_ms);
    }
    for ((log_size, claims), vals) in table {
        let regular = vals[&format!("regular_{mode}")];
        let accumulated = vals[&format!("accumulated_{mode}")];
        series
            .entry(log_size)
            .or_default()
            .push((claims, regular / accumulated));
    }

    let width = 720.0;
    let height = 420.0;
    let left = 70.0;
    let right = 20.0;
    let top = 30.0;
    let bottom = 55.0;
    let plot_w = width - left - right;
    let plot_h = height - top - bottom;
    let max_x = rows.iter().map(|r| r.claims).max().unwrap_or(1) as f64;
    let max_y = series
        .values()
        .flat_map(|pts| pts.iter().map(|(_, y)| *y))
        .fold(1.0_f64, f64::max)
        * 1.15;

    writeln!(out, r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">"#).unwrap();
    writeln!(out, r#"<rect width="100%" height="100%" fill="white"/>"#).unwrap();
    writeln!(out, r#"<text x="{}" y="20" font-size="18" font-family="sans-serif">{} speedup: regular / accumulated</text>"#, left, capitalize(mode)).unwrap();
    writeln!(
        out,
        r#"<line x1="{left}" y1="{}" x2="{}" y2="{}" stroke="black"/>"#,
        top + plot_h,
        left + plot_w,
        top + plot_h
    )
    .unwrap();
    writeln!(
        out,
        r#"<line x1="{left}" y1="{top}" x2="{left}" y2="{}" stroke="black"/>"#,
        top + plot_h
    )
    .unwrap();

    for tick in [1.0, (max_y / 2.0).max(1.0), max_y] {
        let y = top + plot_h - (tick / max_y) * plot_h;
        writeln!(
            out,
            r##"<line x1="{left}" y1="{y}" x2="{}" y2="{y}" stroke="#ddd"/>"##,
            left + plot_w
        )
        .unwrap();
        writeln!(
            out,
            r#"<text x="{}" y="{}" font-size="12" font-family="sans-serif">{:.2}x</text>"#,
            10,
            y + 4.0,
            tick
        )
        .unwrap();
    }

    for claims in [2usize, 4usize] {
        let x = left + ((claims as f64 - 1.0) / (max_x - 1.0).max(1.0)) * plot_w;
        writeln!(
            out,
            r##"<line x1="{x}" y1="{top}" x2="{x}" y2="{}" stroke="#eee"/>"##,
            top + plot_h
        )
        .unwrap();
        writeln!(
            out,
            r#"<text x="{}" y="{}" font-size="12" font-family="sans-serif">{}</text>"#,
            x - 6.0,
            top + plot_h + 20.0,
            claims
        )
        .unwrap();
    }

    let colors = ["#1f77b4", "#d62728", "#2ca02c", "#ff7f0e"];
    for (idx, (log_size, pts)) in series.iter().enumerate() {
        let color = colors[idx % colors.len()];
        let mut d = String::new();
        for (j, (claims, speedup)) in pts.iter().enumerate() {
            let x = left + ((*claims as f64 - 1.0) / (max_x - 1.0).max(1.0)) * plot_w;
            let y = top + plot_h - (*speedup / max_y) * plot_h;
            if j == 0 {
                d.push_str(&format!("M {:.2} {:.2}", x, y));
            } else {
                d.push_str(&format!(" L {:.2} {:.2}", x, y));
            }
            writeln!(
                out,
                r#"<circle cx="{:.2}" cy="{:.2}" r="4" fill="{}"/>"#,
                x, y, color
            )
            .unwrap();
        }
        writeln!(
            out,
            r#"<path d="{}" fill="none" stroke="{}" stroke-width="2"/>"#,
            d, color
        )
        .unwrap();
        let legend_y = 40.0 + idx as f64 * 18.0;
        writeln!(
            out,
            r#"<rect x="{}" y="{}" width="10" height="10" fill="{}"/>"#,
            width - 150.0,
            legend_y - 8.0,
            color
        )
        .unwrap();
        writeln!(
            out,
            r#"<text x="{}" y="{}" font-size="12" font-family="sans-serif">size 2^{}</text>"#,
            width - 135.0,
            legend_y,
            log_size
        )
        .unwrap();
    }

    writeln!(
        out,
        r#"<text x="{}" y="{}" font-size="13" font-family="sans-serif">number of claims k</text>"#,
        left + plot_w / 2.0 - 50.0,
        height - 15.0
    )
    .unwrap();
    writeln!(out, "</svg>").unwrap();
}

fn write_absolute_time_plot(root: &Path, rows: &[BenchRow], mode: &str) {
    let filename = format!("{}_times.svg", mode);
    let path = root.join(filename);
    let mut out = File::create(path).expect("create svg plot");

    let mut series: BTreeMap<(usize, &'static str), Vec<(usize, f64)>> = BTreeMap::new();
    for row in rows {
        let kind = match row.variant.as_str() {
            "regular_prove" if mode == "prove" => Some("regular"),
            "accumulated_prove" if mode == "prove" => Some("folded"),
            "regular_verify" if mode == "verify" => Some("regular"),
            "accumulated_verify" if mode == "verify" => Some("folded"),
            _ => None,
        };
        if let Some(kind) = kind {
            series
                .entry((row.log_size, kind))
                .or_default()
                .push((row.claims, row.time_ms));
        }
    }

    let width = 760.0;
    let height = 440.0;
    let left = 70.0;
    let right = 20.0;
    let top = 30.0;
    let bottom = 55.0;
    let plot_w = width - left - right;
    let plot_h = height - top - bottom;
    let max_x = rows.iter().map(|r| r.claims).max().unwrap_or(1) as f64;
    let max_y = series
        .values()
        .flat_map(|pts| pts.iter().map(|(_, y)| *y))
        .fold(1.0_f64, f64::max)
        * 1.15;

    writeln!(out, r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">"#).unwrap();
    writeln!(out, r#"<rect width="100%" height="100%" fill="white"/>"#).unwrap();
    writeln!(out, r#"<text x="{}" y="20" font-size="18" font-family="sans-serif">{} absolute time (ms)</text>"#, left, capitalize(mode)).unwrap();
    writeln!(
        out,
        r#"<line x1="{left}" y1="{}" x2="{}" y2="{}" stroke="black"/>"#,
        top + plot_h,
        left + plot_w,
        top + plot_h
    )
    .unwrap();
    writeln!(
        out,
        r#"<line x1="{left}" y1="{top}" x2="{left}" y2="{}" stroke="black"/>"#,
        top + plot_h
    )
    .unwrap();

    for tick in [0.0, max_y / 2.0, max_y] {
        let y = top + plot_h - (tick / max_y.max(1.0)) * plot_h;
        writeln!(
            out,
            r##"<line x1="{left}" y1="{y}" x2="{}" y2="{y}" stroke="#ddd"/>"##,
            left + plot_w
        )
        .unwrap();
        writeln!(
            out,
            r#"<text x="10" y="{}" font-size="12" font-family="sans-serif">{:.2}</text>"#,
            y + 4.0,
            tick
        )
        .unwrap();
    }

    for claims in [2usize, 4usize] {
        let x = left + ((claims as f64 - 1.0) / (max_x - 1.0).max(1.0)) * plot_w;
        writeln!(
            out,
            r##"<line x1="{x}" y1="{top}" x2="{x}" y2="{}" stroke="#eee"/>"##,
            top + plot_h
        )
        .unwrap();
        writeln!(
            out,
            r#"<text x="{}" y="{}" font-size="12" font-family="sans-serif">{}</text>"#,
            x - 6.0,
            top + plot_h + 20.0,
            claims
        )
        .unwrap();
    }

    let colors = [
        ("#1f77b4", "solid"),
        ("#1f77b4", "dashed"),
        ("#d62728", "solid"),
        ("#d62728", "dashed"),
    ];
    for (idx, ((log_size, kind), pts)) in series.iter().enumerate() {
        let (color, style) = colors[idx % colors.len()];
        let mut d = String::new();
        for (j, (claims, time_ms)) in pts.iter().enumerate() {
            let x = left + ((*claims as f64 - 1.0) / (max_x - 1.0).max(1.0)) * plot_w;
            let y = top + plot_h - (*time_ms / max_y) * plot_h;
            if j == 0 {
                d.push_str(&format!("M {:.2} {:.2}", x, y));
            } else {
                d.push_str(&format!(" L {:.2} {:.2}", x, y));
            }
            let fill = if *kind == "regular" { color } else { "white" };
            writeln!(
                out,
                r#"<circle cx="{:.2}" cy="{:.2}" r="4" fill="{}" stroke="{}" stroke-width="2"/>"#,
                x, y, fill, color
            )
            .unwrap();
        }
        let dash = if style == "dashed" {
            " stroke-dasharray=\"6,4\""
        } else {
            ""
        };
        writeln!(
            out,
            r#"<path d="{}" fill="none" stroke="{}" stroke-width="2"{}/>"#,
            d, color, dash
        )
        .unwrap();
        let legend_y = 40.0 + idx as f64 * 18.0;
        let fill = if *kind == "regular" { color } else { "white" };
        writeln!(
            out,
            r#"<circle cx="{}" cy="{}" r="5" fill="{}" stroke="{}" stroke-width="2"/>"#,
            width - 180.0,
            legend_y - 4.0,
            fill,
            color
        )
        .unwrap();
        writeln!(
            out,
            r#"<text x="{}" y="{}" font-size="12" font-family="sans-serif">size 2^{} {}</text>"#,
            width - 165.0,
            legend_y,
            log_size,
            kind
        )
        .unwrap();
    }

    writeln!(
        out,
        r#"<text x="{}" y="{}" font-size="13" font-family="sans-serif">number of claims k</text>"#,
        left + plot_w / 2.0 - 50.0,
        height - 15.0
    )
    .unwrap();
    writeln!(out, "</svg>").unwrap();
}

fn capitalize(mode: &str) -> &'static str {
    match mode {
        "prove" => "Prover",
        "verify" => "Verifier",
        _ => "",
    }
}
