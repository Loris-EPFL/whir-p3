use std::collections::BTreeMap;
use std::fs::{create_dir_all, read_to_string, File};
use std::io::Write;
use std::path::Path;

use serde::Deserialize;

#[derive(Clone, Debug)]
struct BenchRow {
    group: String,
    variant: String,
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

/// All variant names we look for inside each criterion group directory.
const VARIANTS: &[&str] = &[
    "no_fold_prove",
    "no_fold_verify",
    "raw_fold_prove",
    "raw_fold_verify",
    "quasar_squash_prove",
    "quasar_squash_verify",
];

/// Criterion group directories we scan.
const GROUPS: &[&str] = &["accumulation", "accumulation_scaling"];

fn main() {
    let criterion_root = Path::new("target/criterion");
    let out_root = Path::new("output/benchmarks/accumulation");
    create_dir_all(out_root).expect("create output directory");

    let rows = collect_all_rows(criterion_root);
    if rows.is_empty() {
        eprintln!("No benchmark data found. Run `cargo bench --bench accumulation` first.");
        std::process::exit(1);
    }

    write_unified_summary(out_root, &rows);
    write_scaling_summary(out_root, &rows);

    println!(
        "Wrote accumulation report to {}",
        out_root.join("summary.md").display()
    );
}

fn collect_all_rows(criterion_root: &Path) -> Vec<BenchRow> {
    let mut rows = Vec::new();
    for &group in GROUPS {
        let group_dir = criterion_root.join(group);
        for &variant in VARIANTS {
            let variant_dir = group_dir.join(variant);
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
                            group: group.to_string(),
                            variant: variant.to_string(),
                            log_size,
                            claims,
                            time_ms,
                        });
                    }
                }
            }
        }
    }
    rows.sort_by_key(|r| (r.log_size, r.claims, r.variant.clone()));
    rows
}

fn parse_case_name(name: &str) -> Option<(usize, usize)> {
    // Criterion encodes "2^12/k=8" as "2_12_k=8" (^ → _)
    let prefix = name.strip_prefix("2_")?;
    let (log_str, k_str) = prefix.split_once("_k=")?;
    Some((log_str.parse().ok()?, k_str.parse().ok()?))
}

fn read_estimate_ms(path: &Path) -> Option<f64> {
    let text = read_to_string(path).ok()?;
    let estimates: Estimates = serde_json::from_str(&text).ok()?;
    Some(estimates.median.point_estimate / 1_000_000.0)
}

type CaseKey = (usize, usize); // (log_size, claims)
type VariantMap = BTreeMap<String, f64>;

fn build_table(rows: &[BenchRow]) -> BTreeMap<CaseKey, VariantMap> {
    let mut table: BTreeMap<CaseKey, VariantMap> = BTreeMap::new();
    for row in rows {
        table
            .entry((row.log_size, row.claims))
            .or_default()
            .insert(row.variant.clone(), row.time_ms);
    }
    table
}

fn fmt_ms(val: Option<&f64>) -> String {
    match val {
        Some(v) => format!("{v:.3}"),
        None => "—".to_string(),
    }
}

fn fmt_speedup(baseline: Option<&f64>, candidate: Option<&f64>) -> String {
    match (baseline, candidate) {
        (Some(b), Some(c)) if *c > 0.0 => format!("{:.2}x", b / c),
        _ => "—".to_string(),
    }
}

/// Main comparison table: no_fold vs raw_fold vs quasar_warp (total).
fn write_unified_summary(root: &Path, rows: &[BenchRow]) {
    let table = build_table(rows);
    let mut out = File::create(root.join("summary.md")).expect("create summary.md");

    writeln!(out, "# Accumulation Benchmark Report\n").unwrap();

    // ── Prove comparison ──
    writeln!(out, "## Prover Time (ms)\n").unwrap();
    writeln!(
        out,
        "| size | k | no_fold | raw_fold | quasar_squash | raw_fold speedup | quasar speedup |"
    )
    .unwrap();
    writeln!(out, "|---|---:|---:|---:|---:|---:|---:|").unwrap();

    for ((log_size, claims), vals) in &table {
        let nf = vals.get("no_fold_prove");
        let rf = vals.get("raw_fold_prove");
        let qs = vals.get("quasar_squash_prove");

        writeln!(
            out,
            "| 2^{log_size} | {claims} | {} | {} | {} | {} | {} |",
            fmt_ms(nf),
            fmt_ms(rf),
            fmt_ms(qs),
            fmt_speedup(nf, rf),
            fmt_speedup(nf, qs),
        )
        .unwrap();
    }

    // ── Verify comparison ──
    writeln!(out, "\n## Verifier Time (ms)\n").unwrap();
    writeln!(
        out,
        "| size | k | no_fold | raw_fold | quasar_squash | raw_fold speedup | quasar speedup |"
    )
    .unwrap();
    writeln!(out, "|---|---:|---:|---:|---:|---:|---:|").unwrap();

    for ((log_size, claims), vals) in &table {
        let nf = vals.get("no_fold_verify");
        let rf = vals.get("raw_fold_verify");
        let qs = vals.get("quasar_squash_verify");

        writeln!(
            out,
            "| 2^{log_size} | {claims} | {} | {} | {} | {} | {} |",
            fmt_ms(nf),
            fmt_ms(rf),
            fmt_ms(qs),
            fmt_speedup(nf, rf),
            fmt_speedup(nf, qs),
        )
        .unwrap();
    }

    writeln!(out).unwrap();
    writeln!(
        out,
        "> Speedup = no_fold / pipeline. Higher is better."
    )
    .unwrap();
    writeln!(
        out,
        "\nGenerated from Criterion estimates in `target/criterion/`."
    )
    .unwrap();
}

/// Detailed breakdown for the quasar_scaling group showing squash vs fold phases.
fn write_scaling_summary(root: &Path, rows: &[BenchRow]) {
    let scaling_rows: Vec<_> = rows.iter().filter(|r| r.group == "accumulation_scaling").collect();
    if scaling_rows.is_empty() {
        return;
    }

    let mut table: BTreeMap<CaseKey, VariantMap> = BTreeMap::new();
    for row in &scaling_rows {
        table
            .entry((row.log_size, row.claims))
            .or_default()
            .insert(row.variant.clone(), row.time_ms);
    }

    let mut out =
        File::create(root.join("scaling_breakdown.md")).expect("create scaling_breakdown.md");

    writeln!(out, "# Accumulation Scaling\n").unwrap();
    writeln!(out, "Compares pipelines at larger polynomial sizes and higher k.\n").unwrap();

    // ── Prove ──
    writeln!(out, "## Prover Time (ms)\n").unwrap();
    writeln!(
        out,
        "| size | k | no_fold | raw_fold | quasar_squash | best pipeline |"
    )
    .unwrap();
    writeln!(out, "|---|---:|---:|---:|---:|---|").unwrap();

    for ((log_size, claims), vals) in &table {
        let nf = vals.get("no_fold_prove");
        let rf = vals.get("raw_fold_prove");
        let qs = vals.get("quasar_squash_prove");

        let best = pick_best(&[
            ("no_fold", nf),
            ("raw_fold", rf),
            ("quasar_squash", qs),
        ]);

        writeln!(
            out,
            "| 2^{log_size} | {claims} | {} | {} | {} | **{best}** |",
            fmt_ms(nf),
            fmt_ms(rf),
            fmt_ms(qs),
        )
        .unwrap();
    }

    // ── Verify ──
    writeln!(out, "\n## Verifier Time (ms)\n").unwrap();
    writeln!(
        out,
        "| size | k | no_fold | raw_fold | quasar_squash | best pipeline |"
    )
    .unwrap();
    writeln!(out, "|---|---:|---:|---:|---:|---|").unwrap();

    for ((log_size, claims), vals) in &table {
        let nf = vals.get("no_fold_verify");
        let rf = vals.get("raw_fold_verify");
        let qs = vals.get("quasar_squash_verify");

        let best = pick_best(&[
            ("no_fold", nf),
            ("raw_fold", rf),
            ("quasar_squash", qs),
        ]);

        writeln!(
            out,
            "| 2^{log_size} | {claims} | {} | {} | {} | **{best}** |",
            fmt_ms(nf),
            fmt_ms(rf),
            fmt_ms(qs),
        )
        .unwrap();
    }

    writeln!(out).unwrap();
    writeln!(
        out,
        "\nGenerated from Criterion estimates in `target/criterion/accumulation_scaling/`."
    )
    .unwrap();
}

fn pick_best<'a>(candidates: &[(&'a str, Option<&f64>)]) -> &'a str {
    candidates
        .iter()
        .filter_map(|(name, val)| val.map(|v| (*name, *v)))
        .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
        .map(|(name, _)| name)
        .unwrap_or("—")
}
