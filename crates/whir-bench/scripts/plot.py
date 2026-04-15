#!/usr/bin/env python3
"""Plot benchmark results from JSONL output.

Usage:
    python scripts/plot.py <input.jsonl> --figure <figure_type> --out <path.pdf>

Figure types:
    time_vs_log_n     Prove time vs log_n for each scheme
    verifier_vs_arity Verify time vs fold arity for each scheme
    batch_speedup     Speedup from batching (quasar_* vs pure_*) vs batch size
    time_vs_steps     Prove time vs IVC steps for each scheme
"""
import argparse
import json
import sys
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def load_jsonl(path: str) -> pd.DataFrame:
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("skipped"):
                continue
            flat = {
                "scheme": obj["scheme"],
                "run": obj["run"],
                **obj["axes"],
            }
            for k, v in obj.get("phases_ns", {}).items():
                flat[f"phase_{k}"] = v
            for k, v in obj.get("counters", {}).items():
                flat[f"counter_{k}"] = v
            for k, v in obj.get("static", {}).items():
                flat[f"static_{k}"] = v
            rows.append(flat)
    return pd.DataFrame(rows)


def bootstrap_ci(values, n_boot=2000, ci=0.95):
    """Compute bootstrap confidence interval for the median."""
    rng = np.random.default_rng(42)
    medians = np.array(
        [np.median(rng.choice(values, size=len(values), replace=True)) for _ in range(n_boot)]
    )
    alpha = (1 - ci) / 2
    return np.percentile(medians, [100 * alpha, 100 * (1 - alpha)])


def aggregate(df: pd.DataFrame, group_cols: list[str], metric: str) -> pd.DataFrame:
    """Group by scheme + group_cols, compute median + 95% bootstrap CI."""
    records = []
    for key, grp in df.groupby(["scheme"] + group_cols):
        vals = grp[metric].values
        med = np.median(vals)
        if len(vals) >= 3:
            lo, hi = bootstrap_ci(vals)
        else:
            lo, hi = med, med
        row = dict(zip(["scheme"] + group_cols, key if isinstance(key, tuple) else [key]))
        row["median"] = med
        row["ci_lo"] = lo
        row["ci_hi"] = hi
        records.append(row)
    return pd.DataFrame(records)


SCHEME_STYLES = {
    "pure_warp": {"color": "#1f77b4", "marker": "o", "label": "Pure WARP"},
    "quasar_warp": {"color": "#ff7f0e", "marker": "s", "label": "Quasar + WARP"},
    "symphony": {"color": "#2ca02c", "marker": "^", "label": "Symphony"},
    "quasar_symphony": {"color": "#d62728", "marker": "D", "label": "Quasar + Symphony"},
}


def style_for(scheme: str) -> dict:
    return SCHEME_STYLES.get(scheme, {"color": "gray", "marker": "x", "label": scheme})


def plot_time_vs_log_n(df: pd.DataFrame, out: str):
    agg = aggregate(df, ["log_n"], "phase_prove_total")
    fig, ax = plt.subplots(figsize=(8, 5))
    for scheme, grp in agg.groupby("scheme"):
        grp = grp.sort_values("log_n")
        s = style_for(scheme)
        yerr = np.array([grp["median"] - grp["ci_lo"], grp["ci_hi"] - grp["median"]])
        ax.errorbar(
            grp["log_n"], grp["median"] / 1e6,
            yerr=yerr / 1e6,
            label=s["label"], color=s["color"], marker=s["marker"],
            capsize=3, linewidth=1.5,
        )
    ax.set_xlabel("log₂(constraints)")
    ax.set_ylabel("Prove time (ms)")
    ax.set_title("Prove Time vs Constraint Size")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"Saved: {out}")


def plot_verifier_vs_arity(df: pd.DataFrame, out: str):
    agg = aggregate(df, ["arity"], "phase_verify_total")
    fig, ax = plt.subplots(figsize=(8, 5))
    for scheme, grp in agg.groupby("scheme"):
        grp = grp.sort_values("arity")
        s = style_for(scheme)
        yerr = np.array([grp["median"] - grp["ci_lo"], grp["ci_hi"] - grp["median"]])
        ax.errorbar(
            grp["arity"], grp["median"] / 1e6,
            yerr=yerr / 1e6,
            label=s["label"], color=s["color"], marker=s["marker"],
            capsize=3, linewidth=1.5,
        )
    ax.set_xlabel("Fold arity")
    ax.set_ylabel("Verify time (ms)")
    ax.set_title("Verify Time vs Fold Arity")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"Saved: {out}")


def plot_batch_speedup(df: pd.DataFrame, out: str):
    agg = aggregate(df, ["batch"], "phase_prove_total")
    fig, ax = plt.subplots(figsize=(8, 5))
    for scheme, grp in agg.groupby("scheme"):
        grp = grp.sort_values("batch")
        if len(grp) < 2:
            continue
        s = style_for(scheme)
        ax.plot(
            grp["batch"], grp["median"] / 1e6,
            label=s["label"], color=s["color"], marker=s["marker"],
            linewidth=1.5,
        )
    ax.set_xlabel("Batch size")
    ax.set_ylabel("Prove time (ms)")
    ax.set_title("Prove Time vs Batch Size")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"Saved: {out}")


def plot_time_vs_steps(df: pd.DataFrame, out: str):
    agg = aggregate(df, ["ivc_steps"], "phase_prove_total")
    fig, ax = plt.subplots(figsize=(8, 5))
    for scheme, grp in agg.groupby("scheme"):
        grp = grp.sort_values("ivc_steps")
        s = style_for(scheme)
        yerr = np.array([grp["median"] - grp["ci_lo"], grp["ci_hi"] - grp["median"]])
        ax.errorbar(
            grp["ivc_steps"], grp["median"] / 1e6,
            yerr=yerr / 1e6,
            label=s["label"], color=s["color"], marker=s["marker"],
            capsize=3, linewidth=1.5,
        )
    ax.set_xlabel("IVC steps")
    ax.set_ylabel("Prove time (ms)")
    ax.set_title("Prove Time vs IVC Steps")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"Saved: {out}")


FIGURE_FUNCS = {
    "time_vs_log_n": plot_time_vs_log_n,
    "verifier_vs_arity": plot_verifier_vs_arity,
    "batch_speedup": plot_batch_speedup,
    "time_vs_steps": plot_time_vs_steps,
}


def cmd_aggregate(df: pd.DataFrame):
    """Print median prove_total per scheme as text table."""
    agg = aggregate(df, ["log_n", "batch", "ivc_steps"], "phase_prove_total")
    print(agg.to_string(index=False))


def main():
    parser = argparse.ArgumentParser(description="Plot whir-bench results")
    parser.add_argument("input", help="Path to JSONL file")
    parser.add_argument("--figure", choices=list(FIGURE_FUNCS.keys()), help="Figure type")
    parser.add_argument("--out", help="Output path (PDF/PNG)")
    parser.add_argument("--aggregate", action="store_true", help="Print median table")
    args = parser.parse_args()

    df = load_jsonl(args.input)
    if df.empty:
        print("No non-skipped rows in input.", file=sys.stderr)
        sys.exit(1)

    if args.aggregate:
        cmd_aggregate(df)
        return

    if not args.figure or not args.out:
        parser.error("--figure and --out are required when not using --aggregate")

    FIGURE_FUNCS[args.figure](df, args.out)


if __name__ == "__main__":
    main()
