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


ALL_AXES = ["log_n", "arity", "batch", "ivc_steps", "step_muls"]


def _varies(df: pd.DataFrame, col: str) -> bool:
    return col in df.columns and df[col].nunique() > 1


def _draw_axis_panel(df, ax, x_axis: str, metric: str, xlabel: str, ylabel: str, title: str):
    """Aggregate over runs only; all other axes are held fixed within each scheme."""
    fixed_axes = [a for a in ALL_AXES if a != x_axis and a in df.columns]
    agg = aggregate(df, [x_axis] + fixed_axes, metric)
    plotted = False
    for (scheme, *_fixed), grp in agg.groupby(["scheme"] + fixed_axes):
        grp = grp.sort_values(x_axis)
        if len(grp) < 2:
            continue
        s = style_for(scheme)
        yerr = np.array([grp["median"] - grp["ci_lo"], grp["ci_hi"] - grp["median"]])
        ax.errorbar(grp[x_axis], grp["median"] / 1e6, yerr=yerr / 1e6,
                    label=s["label"], color=s["color"], marker=s["marker"],
                    capsize=3, linewidth=1.5)
        plotted = True
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    if not plotted:
        ax.text(0.5, 0.5, f"(not swept: {x_axis})", transform=ax.transAxes,
                ha="center", va="center", color="gray")
        ax.set_xticks([])
        ax.set_yticks([])


def plot_all(df: pd.DataFrame, out: str):
    """Render all four figures on a single 2x2 panel."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    panels = [
        ("log_n",     "phase_prove_total",  "log₂(constraints)", "Prove time (ms)", "Prove Time vs Constraint Size",  axes[0, 0]),
        ("ivc_steps", "phase_prove_total",  "IVC steps",         "Prove time (ms)", "Prove Time vs IVC Steps",        axes[0, 1]),
        ("arity",     "phase_verify_total", "Fold arity",        "Verify time (ms)","Verify Time vs Fold Arity",      axes[1, 0]),
        ("batch",     "phase_prove_total",  "Batch size",        "Prove time (ms)", "Prove Time vs Batch Size",       axes[1, 1]),
    ]
    for x_axis, metric, xl, yl, title, ax in panels:
        _draw_axis_panel(df, ax, x_axis, metric, xl, yl, title)
        ax.grid(True, alpha=0.3)
        handles, _ = ax.get_legend_handles_labels()
        if handles:
            ax.legend(fontsize=8)
    fig.suptitle("whir-bench results", fontsize=13)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"Saved: {out}")


FIGURE_FUNCS["all"] = plot_all


# ─────────────────────────────────────────────────────────────────────────────
# compare_bench JSONL support
# Rows have a `table` key: "apples" | "recursive" | "terminal_whir" |
# "fs_scaling" | "circuit_sizes" | "whir_circuit_estimate".
# Loaded separately from the whir-bench schema.
# ─────────────────────────────────────────────────────────────────────────────


def load_compare_jsonl(path: str) -> dict[str, pd.DataFrame]:
    """Return dict of table_name -> DataFrame for a compare_bench JSONL."""
    buckets: dict[str, list] = defaultdict(list)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            t = obj.get("table")
            if t is None:
                continue
            buckets[t].append(obj)
    return {k: pd.DataFrame(v) for k, v in buckets.items()}


APPLES_STYLES = {
    "indep_us":  {"color": "#1f77b4", "marker": "o", "label": "independent WHIR"},
    "direct_us": {"color": "#ff7f0e", "marker": "s", "label": "direct fold"},
    "batch_us":  {"color": "#2ca02c", "marker": "^", "label": "batch + fold"},
}
LOG_SIZE_LINESTYLES = ["-", "--", ":", "-.", (0, (3, 1, 1, 1)), (0, (5, 2))]


def _plot_apples(df, ax):
    """Absolute prove time vs IVC steps. One curve per (scheme, log_size)."""
    if df.empty:
        ax.text(0.5, 0.5, "(no apples data)", transform=ax.transAxes, ha="center", color="gray")
        return
    log_sizes = sorted(df["log_size"].unique())
    for li, log_size in enumerate(log_sizes):
        sub = df[df["log_size"] == log_size].sort_values("num_steps")
        ls = LOG_SIZE_LINESTYLES[li % len(LOG_SIZE_LINESTYLES)]
        for col, st in APPLES_STYLES.items():
            ax.plot(sub["num_steps"], sub[col] / 1e3,
                    linestyle=ls, marker=st["marker"], color=st["color"],
                    linewidth=1.3, markersize=5,
                    label=f"{st['label']} (log_n={log_size})")
    ax.set(xlabel="IVC steps", ylabel="Prove time (ms, post-Spartan)",
           title="Apples-to-Apples absolute prove time",
           xscale="log", yscale="log")
    ax.legend(fontsize=6, ncol=len(log_sizes), loc="upper left")


def _plot_apples_speedup(df, ax, ratio_col, title):
    """Grouped bar chart: one bar per (num_steps, log_size) combo."""
    if df.empty:
        ax.text(0.5, 0.5, "(no apples data)", transform=ax.transAxes, ha="center", color="gray")
        return
    log_sizes = sorted(df["log_size"].unique())
    step_counts = sorted(df["num_steps"].unique())
    n_log = len(log_sizes)
    width = 0.8 / max(n_log, 1)
    x_base = np.arange(len(step_counts))
    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"]
    for i, log_size in enumerate(log_sizes):
        sub = df[df["log_size"] == log_size].sort_values("num_steps")
        vals = [
            sub[sub["num_steps"] == s][ratio_col].median() if not sub[sub["num_steps"] == s].empty else np.nan
            for s in step_counts
        ]
        offset = (i - (n_log - 1) / 2) * width
        ax.bar(x_base + offset, vals, width,
               color=colors[i % len(colors)], label=f"log_n={log_size}")
        for xi, v in zip(x_base + offset, vals):
            if not np.isnan(v):
                ax.text(xi, v, f"{v:.2f}×", ha="center", va="bottom", fontsize=6)
    ax.axhline(1.0, color="gray", linestyle=":", linewidth=0.8)
    ax.set_xticks(x_base)
    ax.set_xticklabels([str(s) for s in step_counts])
    ax.set(xlabel="IVC steps", ylabel="speedup (×)", title=title)
    ax.legend(fontsize=8)


PATH_STYLES = {
    "A": {"color": "#1f77b4", "marker": "o", "label": "A: WARP (l=2)"},
    "B": {"color": "#ff7f0e", "marker": "s", "label": "B: WARP+Quasar (l=4)"},
    "C": {"color": "#2ca02c", "marker": "^", "label": "C: Symphony (l=2)"},
    "D": {"color": "#d62728", "marker": "D", "label": "D: Symphony+Quasar (l=4)"},
}


def _plot_recursive(df, ax, y_col="ms_per_circuit", ylabel="ms / circuit",
                    title="Recursive IVC: ms per step circuit"):
    if df.empty:
        ax.text(0.5, 0.5, "(no recursive data)", transform=ax.transAxes, ha="center", color="gray")
        return
    for path, grp in df.groupby("path"):
        grp = grp.sort_values("log_size")
        s = PATH_STYLES.get(path, {"color": "gray", "marker": "x", "label": path})
        ax.plot(grp["log_size"], grp[y_col], "-",
                marker=s["marker"], color=s["color"], label=s["label"], linewidth=1.5)
    ax.set(xlabel="log₂(constraints)", ylabel=ylabel, title=title)
    ax.legend(fontsize=8)


def _plot_recursive_speedup_bars(df, ax):
    """Grouped bars: for each log_size, one bar per path showing speedup vs A."""
    if df.empty:
        ax.text(0.5, 0.5, "(no recursive data)", transform=ax.transAxes, ha="center", color="gray")
        return
    log_sizes = sorted(df["log_size"].unique())
    paths = ["A", "B", "C", "D"]
    n_paths = len(paths)
    width = 0.8 / n_paths
    x_base = np.arange(len(log_sizes))
    for i, path in enumerate(paths):
        vals = []
        for ls in log_sizes:
            sub = df[(df["log_size"] == ls) & (df["path"] == path)]
            vals.append(sub["vs_a"].median() if not sub.empty else np.nan)
        offset = (i - (n_paths - 1) / 2) * width
        st = PATH_STYLES.get(path, {"color": "gray", "label": path})
        bars = ax.bar(x_base + offset, vals, width,
                      color=st["color"], label=st["label"])
        for xi, v in zip(x_base + offset, vals):
            if not np.isnan(v):
                ax.text(xi, v, f"{v:.2f}×", ha="center", va="bottom", fontsize=6)
    ax.axhline(1.0, color="gray", linestyle=":", linewidth=0.8)
    ax.set_xticks(x_base)
    ax.set_xticklabels([f"log_n={ls}" for ls in log_sizes])
    ax.set(ylabel="speedup vs A (×)",
           title="Recursive IVC — speedup vs A (WARP l=2)")
    ax.legend(fontsize=7)


def _plot_fs_scaling_abs(df, ax):
    if df.empty:
        ax.text(0.5, 0.5, "(no fs_scaling data)", transform=ax.transAxes, ha="center", color="gray")
        return
    grp = df.sort_values("arity")
    ax.plot(grp["arity"], grp["standard_us"], "o-",
            color="#1f77b4", label="standard: absorb O(ℓ) roots", linewidth=1.5)
    ax.plot(grp["arity"], grp["union_us"], "s-",
            color="#d62728", label="union: absorb O(1) root", linewidth=1.5)
    ax.set(xlabel="Fold arity ℓ", ylabel="FS derivation (µs)",
           title="FS challenge derivation (both sample O(ℓ·log_m) betas)",
           xscale="log", yscale="log")
    ax.legend(fontsize=8)


def _plot_fs_scaling_speedup(df, ax):
    if df.empty:
        ax.text(0.5, 0.5, "(no fs_scaling data)", transform=ax.transAxes, ha="center", color="gray")
        return
    grp = df.sort_values("arity")
    bars = ax.bar(grp["arity"].astype(str), grp["speedup"],
                  color="#d62728", alpha=0.75)
    for b, v in zip(bars, grp["speedup"]):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.2f}×",
                ha="center", va="bottom", fontsize=7)
    ax.axhline(1.0, color="gray", linestyle=":", linewidth=0.8)
    ax.set(xlabel="Fold arity ℓ", ylabel="speedup standard ÷ union",
           title="FS derivation speedup (standard ÷ union)")


def _plot_fold_verify_speedup(df, ax):
    """Bar chart: full fold verifier speedup (standard ÷ union) vs arity."""
    if df.empty:
        ax.text(0.5, 0.5, "(no fold_verify data)", transform=ax.transAxes, ha="center", color="gray")
        return
    grp = df.sort_values("arity")
    bars = ax.bar(grp["arity"].astype(str), grp["speedup"],
                  color="#2ca02c", alpha=0.75)
    for b, v in zip(bars, grp["speedup"]):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.2f}×",
                ha="center", va="bottom", fontsize=7)
    ax.axhline(1.0, color="gray", linestyle=":", linewidth=0.8)
    ax.set(xlabel="Fold arity ℓ", ylabel="speedup standard ÷ union",
           title="Full fold verify speedup (standard ÷ union)")


def _plot_circuit_size_arity_speedup(df, ax):
    """Bar chart: in-circuit constraint reduction = poseidon2_union / algebraic_union."""
    if df.empty:
        ax.text(0.5, 0.5, "(no circuit_size_arity data)", transform=ax.transAxes, ha="center", color="gray")
        return
    p2 = df[df["variant"] == "poseidon2_union"].set_index("arity")["constraints"]
    alg = df[df["variant"] == "algebraic_union"].set_index("arity")["constraints"]
    common = sorted(set(p2.index) & set(alg.index))
    if not common:
        ax.text(0.5, 0.5, "(symphony feature disabled — no algebraic data)",
                transform=ax.transAxes, ha="center", color="gray")
        return
    ratios = [p2.loc[a] / alg.loc[a] for a in common]
    bars = ax.bar([str(a) for a in common], ratios, color="#9467bd", alpha=0.8)
    for b, v in zip(bars, ratios):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.0f}×",
                ha="center", va="bottom", fontsize=7)
    ax.set(xlabel="Fold arity ℓ",
           ylabel="Poseidon2 ÷ algebraic",
           title="In-circuit size reduction (Poseidon2 ÷ algebraic, union)")
    ax.grid(axis="y", alpha=0.3)


def _plot_terminal_whir(df, ax):
    if df.empty:
        ax.text(0.5, 0.5, "(no terminal_whir data)", transform=ax.transAxes, ha="center", color="gray")
        return
    grp = df.sort_values("log_size")
    ax2 = ax.twinx()
    ax.plot(grp["log_size"], grp["prove_us"] / 1e3, "o-", color="#1f77b4",
            label="prove (ms)", linewidth=1.5)
    ax.plot(grp["log_size"], grp["verify_us"] / 1e3, "s-", color="#ff7f0e",
            label="verify (ms)", linewidth=1.5)
    ax2.plot(grp["log_size"], grp["proof_kb"], "^--", color="#2ca02c",
             label="proof size (KB)", linewidth=1.5)
    ax.set(xlabel="log₂(constraints)", ylabel="time (ms)",
           title="Terminal WHIR prove / verify / proof size", yscale="log")
    ax2.set_ylabel("proof size (KB)")
    l1, lbl1 = ax.get_legend_handles_labels()
    l2, lbl2 = ax2.get_legend_handles_labels()
    ax.legend(l1 + l2, lbl1 + lbl2, fontsize=8, loc="upper left")


def _plot_whir_estimate(df, ax):
    if df.empty:
        ax.text(0.5, 0.5, "(no whir_circuit_estimate data)", transform=ax.transAxes, ha="center", color="gray")
        return
    grp = df.sort_values("log_size")
    bottom = np.zeros(len(grp))
    xs = grp["log_size"].astype(str).values
    for col, color in [("fs", "#1f77b4"), ("sumcheck", "#ff7f0e"),
                       ("merkle", "#2ca02c"), ("queries", "#d62728")]:
        ax.bar(xs, grp[col], bottom=bottom, label=col, color=color)
        bottom = bottom + grp[col].values
    ax.set(xlabel="log₂(constraints)", ylabel="constraints (in-circuit)",
           title="WHIR-in-circuit estimated cost (stacked)", yscale="log")
    ax.legend(fontsize=8)


def _plot_circuit_sizes(df, ax):
    if df.empty:
        ax.text(0.5, 0.5, "(no circuit_sizes data)", transform=ax.transAxes, ha="center", color="gray")
        return
    # Friendly labels for the variant names
    label_map = {
        "poseidon2_non_union_l2": "Poseidon2 non-union (l=2)",
        "algebraic_non_union_l2": "Algebraic non-union (l=2)",
    }
    variants = [label_map.get(v, v) for v in df["variant"].tolist()]
    constraints = df["constraints"].astype(float).tolist()
    colors = ["#1f77b4", "#d62728", "#2ca02c", "#ff7f0e"]
    bars = ax.bar(variants, constraints,
                  color=colors[:len(variants)], alpha=0.85)
    for b, v in zip(bars, constraints):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{int(v):,}",
                ha="center", va="bottom", fontsize=8)
    ax.set(ylabel="constraints",
           title="Non-union fold verifier circuit size (l=2 only)",
           yscale="log")
    ax.grid(axis="y", alpha=0.3)


def _plot_fold_verify_full(df, ax):
    """Total native fold-verifier cost (FS + target + sumcheck) vs arity."""
    if df.empty:
        ax.text(0.5, 0.5, "(no fold_verify data)", transform=ax.transAxes, ha="center", color="gray")
        return
    grp = df.sort_values("arity")
    ax.plot(grp["arity"], grp["standard_us"], "o-",
            color="#1f77b4", label="standard (ℓ roots absorbed)", linewidth=1.5)
    ax.plot(grp["arity"], grp["union_us"], "s-",
            color="#d62728", label="union (1 root absorbed)", linewidth=1.5)
    ax.set(xlabel="Fold arity ℓ",
           ylabel="Full fold verify (µs)",
           title="Native fold verifier (FS + initial target + sumcheck)",
           xscale="log", yscale="log")
    ax.legend(fontsize=8)


def _plot_circuit_size_arity(df, ax):
    """In-circuit fold-verifier size vs arity — Quasar's real payoff."""
    if df.empty:
        ax.text(0.5, 0.5, "(no circuit_size_arity data)", transform=ax.transAxes, ha="center", color="gray")
        return
    styles = {
        "poseidon2_union": {"color": "#1f77b4", "marker": "o",
                            "label": "Poseidon2 + Quasar union"},
        "algebraic_union": {"color": "#d62728", "marker": "s",
                            "label": "Algebraic + Quasar union"},
    }
    for variant, grp in df.groupby("variant"):
        grp = grp.sort_values("arity")
        st = styles.get(variant, {"color": "gray", "marker": "x", "label": variant})
        ax.plot(grp["arity"], grp["constraints"], "-",
                marker=st["marker"], color=st["color"], label=st["label"], linewidth=1.5)
    ax.set(xlabel="Fold arity ℓ",
           ylabel="R1CS constraints (unified circuit)",
           title="In-circuit verifier size vs arity (union variants)",
           xscale="log", yscale="log")
    ax.legend(fontsize=8)


def plot_compare_all(path: str, out: str):
    """Render every compare_bench table on a single 5×3 multi-panel figure."""
    tables = load_compare_jsonl(path)
    apples = tables.get("apples", pd.DataFrame())
    recursive = tables.get("recursive", pd.DataFrame())
    fs = tables.get("fs_scaling", pd.DataFrame())
    fold_verify = tables.get("fold_verify", pd.DataFrame())
    circuit_sizes = tables.get("circuit_sizes", pd.DataFrame())
    circuit_size_arity = tables.get("circuit_size_arity", pd.DataFrame())
    terminal = tables.get("terminal_whir", pd.DataFrame())
    whir_est = tables.get("whir_circuit_estimate", pd.DataFrame())

    fig, axes = plt.subplots(5, 3, figsize=(20, 22))

    # Row 1 — Apples speedup bars (the 3 ratios from the original text table)
    _plot_apples_speedup(apples, axes[0, 0], "fold_vs_ind",
                         "fold / independent (>1 = fold wins)")
    _plot_apples_speedup(apples, axes[0, 1], "batch_vs_ind",
                         "batch+fold / independent")
    _plot_apples_speedup(apples, axes[0, 2], "batch_vs_fold",
                         "batch+fold / fold")

    # Row 2 — Apples absolute + Recursive absolute + Recursive speedup vs A
    _plot_apples(apples, axes[1, 0])
    _plot_recursive(recursive, axes[1, 1], y_col="ms_per_circuit",
                    ylabel="ms / step circuit",
                    title="Recursive IVC — absolute ms/circuit")
    _plot_recursive_speedup_bars(recursive, axes[1, 2])

    # Row 3 — Native verifier (FS + full fold verify) absolute + speedup bars
    _plot_fs_scaling_abs(fs, axes[2, 0])
    _plot_fold_verify_full(fold_verify, axes[2, 1])
    _plot_fs_scaling_speedup(fs, axes[2, 2])

    # Row 4 — In-circuit verifier: absolute + two size comparisons + speedup
    _plot_circuit_size_arity(circuit_size_arity, axes[3, 0])
    _plot_circuit_sizes(circuit_sizes, axes[3, 1])
    _plot_circuit_size_arity_speedup(circuit_size_arity, axes[3, 2])

    # Row 5 — Terminal WHIR + in-circuit WHIR estimate + full fold speedup
    _plot_terminal_whir(terminal, axes[4, 0])
    _plot_whir_estimate(whir_est, axes[4, 1])
    _plot_fold_verify_speedup(fold_verify, axes[4, 2])

    for row in axes:
        for ax in row:
            ax.grid(True, alpha=0.3)
    fig.suptitle("compare_bench dashboard", fontsize=15)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"Saved: {out}")


def cmd_aggregate(df: pd.DataFrame):
    """Print median prove_total per scheme as text table."""
    agg = aggregate(df, ["log_n", "batch", "ivc_steps"], "phase_prove_total")
    print(agg.to_string(index=False))


SCHEME_REPORT_LABEL = {
    "pure_warp":       "A: WARP (l=2)",
    "quasar_warp":     "B: WARP+Quasar (l=arity)",
    "symphony":        "C: Symphony (l=2)",
    "quasar_symphony": "D: Symphony+Quasar (l=arity)",
}


def cmd_report(df: pd.DataFrame):
    """Print the 'Recursive IVC Throughput' table in the old compare_bench format."""
    fixed = [a for a in ["log_n", "arity", "batch", "ivc_steps", "step_muls"] if a in df.columns]
    prove = aggregate(df, fixed, "phase_prove_total")
    verify = aggregate(df, fixed, "phase_verify_total")

    proof_rows = df.groupby(["scheme"] + fixed)["static_proof_field_elems"].median().reset_index()
    constr_rows = df.groupby(["scheme"] + fixed)["static_circuit_constraints"].median().reset_index()

    print("Recursive IVC Throughput (Fair Comparison)")
    print("==========================================")
    print("All paths prove the SAME total ivc_steps of step circuits.")
    print("Metric: ms per circuit proved (lower = better).\n")

    axes_cols = [c for c in ["log_n", "arity", "batch", "step_muls"] if c in df.columns]
    for axes_key, grp_prove in prove.groupby(axes_cols):
        if not isinstance(axes_key, tuple):
            axes_key = (axes_key,)
        axes_desc = ", ".join(f"{k}={v}" for k, v in zip(axes_cols, axes_key))
        print(f"=== {axes_desc} ===\n")
        header = f"{'path':<28} {'steps':>6} {'prove(ms)':>12} {'verify(ms)':>12} {'ms/step':>10} {'proof(KB)':>10} {'constraints':>12} {'vs A':>8}"
        print(header)
        print("-" * len(header))

        baseline_ms_per_step = None
        subset = grp_prove.sort_values(["scheme", "ivc_steps"])
        for scheme in ["pure_warp", "quasar_warp", "symphony", "quasar_symphony"]:
            scheme_rows = subset[subset["scheme"] == scheme]
            if scheme_rows.empty:
                continue
            for _, r in scheme_rows.iterrows():
                steps = int(r["ivc_steps"])
                prove_ms = r["median"] / 1e6
                ms_per = prove_ms / steps
                match = verify[(verify["scheme"] == scheme) & (verify["ivc_steps"] == steps)]
                verify_ms = match["median"].iloc[0] / 1e6 if not match.empty else float("nan")
                pf = proof_rows[(proof_rows["scheme"] == scheme) & (proof_rows["ivc_steps"] == steps)]
                proof_kb = (pf["static_proof_field_elems"].iloc[0] * 4) / 1024 if not pf.empty else float("nan")
                cc = constr_rows[(constr_rows["scheme"] == scheme) & (constr_rows["ivc_steps"] == steps)]
                constraints = int(cc["static_circuit_constraints"].iloc[0]) if not cc.empty and pd.notna(cc["static_circuit_constraints"].iloc[0]) else 0
                if scheme == "pure_warp" and baseline_ms_per_step is None:
                    baseline_ms_per_step = ms_per
                ratio = (baseline_ms_per_step / ms_per) if baseline_ms_per_step else float("nan")
                ratio_s = "baseline" if scheme == "pure_warp" else f"{ratio:.2f}x"
                label = SCHEME_REPORT_LABEL.get(scheme, scheme)
                print(f"{label:<28} {steps:>6} {prove_ms:>12.1f} {verify_ms:>12.2f} {ms_per:>10.1f} {proof_kb:>10.1f} {constraints:>12} {ratio_s:>8}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Plot whir-bench results")
    parser.add_argument("input", help="Path to JSONL file")
    parser.add_argument("--figure", choices=list(FIGURE_FUNCS.keys()), help="Figure type")
    parser.add_argument("--out", help="Output path (PDF/PNG)")
    parser.add_argument("--aggregate", action="store_true", help="Print median table")
    parser.add_argument("--report", action="store_true",
                        help="Print compare_bench-style Recursive IVC Throughput report")
    parser.add_argument("--compare", action="store_true",
                        help="Input is a compare_bench JSONL; requires --out for the multi-panel figure")
    args = parser.parse_args()

    # Auto-detect format: compare_bench rows carry a "table" field,
    # whir-bench rows carry "phases_ns"/"axes".
    def _is_compare_bench(path: str) -> bool:
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    return "table" in obj
        except OSError:
            return False
        return False

    if args.compare or _is_compare_bench(args.input):
        if not args.out:
            parser.error("compare_bench JSONL requires --out")
        plot_compare_all(args.input, args.out)
        return

    df = load_jsonl(args.input)
    if df.empty:
        print("No non-skipped rows in input.", file=sys.stderr)
        sys.exit(1)

    if args.report:
        cmd_report(df)
        return

    if args.aggregate:
        cmd_aggregate(df)
        return

    if not args.figure or not args.out:
        parser.error("--figure and --out are required when not using --aggregate")

    FIGURE_FUNCS[args.figure](df, args.out)


if __name__ == "__main__":
    main()
