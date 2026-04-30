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
    """Load scheme rows (kind=='scheme') from a unified JSONL."""
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("kind") and obj.get("kind") != "scheme":
                continue
            if obj.get("skipped"):
                continue
            flat = {
                "workload": obj.get("workload") or "legacy",
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


def load_microbenches(path: str) -> dict[str, pd.DataFrame]:
    """Load microbench rows (kind=='microbench'), grouped by `name`."""
    buckets: dict[str, list] = defaultdict(list)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("kind") != "microbench":
                continue
            flat = {**obj.get("axes", {}), **obj.get("values", {})}
            buckets[obj["name"]].append(flat)
    return {k: pd.DataFrame(v) for k, v in buckets.items()}


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
    "symphony_standard_arity": {"color": "#2ca02c", "marker": "v", "label": "Symphony standard"},
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
    """Bar chart: Quasar's in-circuit speedup per arity.

    Two grouped bars per arity:
      - Poseidon2 standard ÷ union (how much does Quasar save on hash path?)
      - Algebraic standard ÷ union (CP-SNARK path — typically ≈1, since the
        algebraic verifier defers hashing to the terminal decider)
    """
    if df.empty:
        ax.text(0.5, 0.5, "(no circuit_size_arity data)", transform=ax.transAxes, ha="center", color="gray")
        return

    def series(variant):
        sub = df[df["variant"] == variant]
        return sub.set_index("arity")["constraints"] if not sub.empty else None

    p2_std = series("poseidon2_standard")
    p2_un  = series("poseidon2_union")
    al_std = series("algebraic_standard")
    al_un  = series("algebraic_union")
    if p2_std is None or p2_un is None:
        ax.text(0.5, 0.5, "(no standard/union pair present)",
                transform=ax.transAxes, ha="center", color="gray")
        return

    arities = sorted(set(p2_std.index) & set(p2_un.index))
    width = 0.35
    x_base = np.arange(len(arities))
    p2_ratios = [p2_std.loc[a] / p2_un.loc[a] for a in arities]
    bars1 = ax.bar(x_base - width / 2, p2_ratios, width,
                   color="#1f77b4", alpha=0.85, label="Poseidon2 std ÷ union")
    for b, v in zip(bars1, p2_ratios):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.1f}×",
                ha="center", va="bottom", fontsize=7)

    if al_std is not None and al_un is not None:
        al_arities = sorted(set(al_std.index) & set(al_un.index) & set(arities))
        al_ratios = [al_std.loc[a] / al_un.loc[a] for a in al_arities]
        al_idx = [arities.index(a) for a in al_arities]
        bars2 = ax.bar(np.array(al_idx) + width / 2, al_ratios, width,
                       color="#d62728", alpha=0.85, label="Algebraic std ÷ union")
        for b, v in zip(bars2, al_ratios):
            ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.1f}×",
                    ha="center", va="bottom", fontsize=7)

    ax.axhline(1.0, color="gray", linestyle=":", linewidth=0.8)
    ax.set_xticks(x_base)
    ax.set_xticklabels([str(a) for a in arities])
    ax.set(xlabel="Fold arity ℓ",
           ylabel="standard ÷ union (×)",
           title="Quasar in-circuit speedup vs arity (std ÷ union)")
    ax.legend(fontsize=7)
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
    """In-circuit fold-verifier size vs arity — Quasar's real payoff.

    Plots four lines when all variants are present:
      - poseidon2_standard (dashed, blue): absorbs ℓ roots → linear in ℓ
      - poseidon2_union    (solid,  blue): absorbs 1 union root → sub-linear
      - algebraic_standard (dashed, red ): ℓ-1 chained l=2 folds → linear
      - algebraic_union    (solid,  red ): union algebraic → +8 per doubling
    The gap between each solid/dashed pair is the Quasar win at that arity.
    """
    if df.empty:
        ax.text(0.5, 0.5, "(no circuit_size_arity data)", transform=ax.transAxes, ha="center", color="gray")
        return
    styles = {
        "poseidon2_standard": {"color": "#1f77b4", "marker": "o", "linestyle": "--",
                               "label": "Poseidon2 standard (ℓ roots)"},
        "poseidon2_union":    {"color": "#1f77b4", "marker": "o", "linestyle": "-",
                               "label": "Poseidon2 + Quasar union (1 root)"},
        "algebraic_standard": {"color": "#d62728", "marker": "s", "linestyle": "--",
                               "label": "Algebraic standard (ℓ-1 chained folds)"},
        "algebraic_union":    {"color": "#d62728", "marker": "s", "linestyle": "-",
                               "label": "Algebraic + Quasar union"},
    }
    for variant, grp in df.groupby("variant"):
        grp = grp.sort_values("arity")
        st = styles.get(variant, {"color": "gray", "marker": "x",
                                   "linestyle": ":", "label": variant})
        ax.plot(grp["arity"], grp["constraints"],
                linestyle=st["linestyle"], marker=st["marker"],
                color=st["color"], label=st["label"], linewidth=1.5)
    ax.set(xlabel="Fold arity ℓ",
           ylabel="R1CS constraints (unified circuit)",
           title="In-circuit verifier size vs arity (standard vs Quasar)",
           xscale="log", yscale="log")
    ax.legend(fontsize=7)


_WV_LOG_N_LINESTYLES = ["-", "--", ":", "-."]


def _plot_warp_vs_whir_prove(df, ax):
    """Total prover time vs N, one line group per log_n.

    Two colors: WHIR (blue), WARP-direct (red).
    One linestyle per log_n value so the witness-size scaling is visible.
    """
    if df.empty:
        ax.text(0.5, 0.5, "(no warp_vs_whir data)", transform=ax.transAxes,
                ha="center", color="gray")
        return
    log_ns = sorted(df["log_n"].unique())
    for li, ln in enumerate(log_ns):
        ls = _WV_LOG_N_LINESTYLES[li % len(_WV_LOG_N_LINESTYLES)]
        g = df[df["log_n"] == ln].sort_values("n_instances")
        ax.plot(g["n_instances"], g["whir_prove_us"] / 1e3,
                linestyle=ls, marker="o", color="#1f77b4", linewidth=1.4,
                label=f"WHIR  log_n={ln}")
        ax.plot(g["n_instances"], g["warp_direct_prove_us"] / 1e3,
                linestyle=ls, marker="s", color="#d62728", linewidth=1.4,
                label=f"WARP-direct  log_n={ln}")
    ax.set(xlabel="N (instances proved)", ylabel="prover time (ms)",
           title="Prover: aggregated WARP vs N independent WHIR proofs",
           xscale="log", yscale="log")
    ax.legend(fontsize=6, ncol=len(log_ns), loc="upper left")


def _plot_warp_vs_whir_verify(df, ax):
    if df.empty:
        ax.text(0.5, 0.5, "(no warp_vs_whir data)", transform=ax.transAxes,
                ha="center", color="gray")
        return
    log_ns = sorted(df["log_n"].unique())
    for li, ln in enumerate(log_ns):
        ls = _WV_LOG_N_LINESTYLES[li % len(_WV_LOG_N_LINESTYLES)]
        g = df[df["log_n"] == ln].sort_values("n_instances")
        ax.plot(g["n_instances"], g["whir_verify_us"] / 1e3,
                linestyle=ls, marker="o", color="#1f77b4", linewidth=1.4,
                label=f"WHIR  log_n={ln}")
        ax.plot(g["n_instances"], g["warp_direct_verify_us"] / 1e3,
                linestyle=ls, marker="s", color="#d62728", linewidth=1.4,
                label=f"WARP-direct  log_n={ln}")
    ax.set(xlabel="N (instances verified)", ylabel="verifier time (ms)",
           title="Verifier: aggregated WARP vs N independent WHIR proofs",
           xscale="log", yscale="log")
    ax.legend(fontsize=6, ncol=len(log_ns), loc="upper left")


def _plot_warp_vs_whir_speedup(df, ax):
    """Grouped bars: WARP-direct prover speedups per (log_n, N) cell."""
    if df.empty:
        ax.text(0.5, 0.5, "(no warp_vs_whir data)", transform=ax.transAxes,
                ha="center", color="gray")
        return
    g = df.copy()
    g["prove_sp"] = g["whir_prove_us"] / g["warp_direct_prove_us"]
    log_ns = sorted(g["log_n"].unique())
    n_vals = sorted(g["n_instances"].unique())
    n_log = len(log_ns)
    n_n = len(n_vals)
    # Per cell: 2 bars (prover, verifier). Group cells by N, color by log_n.
    width = 0.8 / max(n_log, 1)
    x_base = np.arange(n_n)
    palette = ["#1f77b4", "#d62728", "#2ca02c", "#ff7f0e"]
    for i, ln in enumerate(log_ns):
        sub = g[g["log_n"] == ln]
        prove_vals = [
            sub[sub["n_instances"] == nn]["prove_sp"].median() if not sub[sub["n_instances"] == nn].empty else np.nan
            for nn in n_vals
        ]
        offset = (i - (n_log - 1) / 2) * width
        ax.bar(x_base + offset, prove_vals, width,
               color=palette[i % len(palette)], alpha=0.85,
               label=f"prover  log_n={ln}")
        for xi, v in zip(x_base + offset, prove_vals):
            if not np.isnan(v):
                ax.text(xi, v, f"{v:.1f}×",
                        ha="center", va="bottom", fontsize=6)
    ax.axhline(1.0, color="gray", linestyle=":", linewidth=0.8)
    ax.set_xticks(x_base)
    ax.set_xticklabels([str(n) for n in n_vals])
    ax.set(xlabel="N (instances)",
           ylabel="prover speedup WHIR ÷ WARP-direct (×)",
           title="WARP-direct prover speedup vs N independent WHIR (≥1× = WARP wins)")
    ax.legend(fontsize=6, loc="upper left")
    ax.grid(axis="y", alpha=0.3)


def plot_unified_dashboard(path: str, out: str):
    """Unified dashboard: scheme rows (prover comparisons) + microbench rows
    (verifier/circuit/terminal microbenches) in one 6×3 figure."""
    df_scheme = load_jsonl(path)
    mb = load_microbenches(path)

    fig, axes = plt.subplots(6, 3, figsize=(22, 28))

    if "workload" in df_scheme.columns and (df_scheme["workload"] != "legacy").any():
        # Row 1 — Family A, exact same number of R1CS instances.
        # The default dashboard points pair log_n and total_instances (for
        # example 14/48, 16/96, ...). Filtering to max(log_n) and then plotting
        # by total_instances leaves a single x-value, so Row 1 uses log_n as the
        # varying axis for paired points. Cartesian data still uses N at max
        # log_n to avoid aggregating unlike workloads.
        family_a_x, family_a_fixed, family_a_scope = _family_a_axis_plan(df_scheme)
        _plot_workload_metric(
            df_scheme, axes[0, 0], "family_a_same_n", family_a_x, "phase_e2e_prove",
            f"Family A same-N — E2E prover ({family_a_scope})",
            "prove time (ms, log scale)", fixed=family_a_fixed,
            schemes=[
                "independent_whir",
                "pure_warp", "pure_warp_succinct",
                "warp_standard", "warp_standard_succinct",
                "warp_union", "warp_union_succinct",
            ],
        )
        _plot_workload_metric(
            df_scheme, axes[0, 1], "family_a_same_n", family_a_x,
            "phase_post_spartan_prove",
            f"Family A same-N — post-Spartan prover ({family_a_scope})",
            "prove time (ms, log scale)", fixed=family_a_fixed,
            schemes=[
                "independent_whir",
                "pure_warp", "pure_warp_succinct",
                "warp_standard", "warp_standard_succinct",
                "warp_union", "warp_union_succinct",
            ],
        )
        _plot_workload_verify(
            df_scheme, axes[0, 2], "family_a_same_n", family_a_x,
            f"Family A same-N — terminal verify total ({family_a_scope})",
            fixed=family_a_fixed,
            schemes=[
                "independent_whir",
                "pure_warp", "pure_warp_succinct",
                "warp_standard", "warp_standard_succinct",
                "warp_union", "warp_union_succinct",
            ],
        )

        # Row 2 — Quasar claim in the full workload: same N, same arity.
        quasar_fixed = {"log_n": "max", "total_instances": "max"}
        _plot_workload_metric(
            df_scheme, axes[1, 0], "quasar_arity", "arity", "phase_e2e_prove",
            "Full WARP arity sweep — standard vs Quasar union prover",
            "prove time (ms, log scale)", fixed=quasar_fixed,
            schemes=[
                "warp_standard", "warp_standard_succinct",
                "warp_union", "warp_union_succinct",
            ],
        )
        _plot_workload_verify(
            df_scheme, axes[1, 1], "quasar_arity", "arity",
            "Full WARP arity sweep — terminal decider verify",
            fixed=quasar_fixed,
            schemes=[
                "warp_standard", "warp_standard_succinct",
                "warp_union", "warp_union_succinct",
            ],
            metric="phase_terminal_decider",
            ylabel="terminal decider time (ms, log scale)",
        )
        _plot_speedup(
            df_scheme, axes[1, 2], "quasar_arity", "arity",
            "warp_standard_succinct", "warp_union_succinct", "phase_terminal_decider",
            "Full WARP terminal-decider speedup: standard / union",
            fixed=quasar_fixed,
        )

        # Row 3 — Recursive IVC, exact same number of step circuits.
        recursive_fixed = {"arity": "max", "step_muls": "max"}
        _plot_workload_metric(
            df_scheme, axes[2, 0], "recursive_ivc", "total_step_circuits",
            "phase_e2e_prove",
            "Recursive same-step workload — prover (Poseidon2/Symphony × Quasar)",
            "prove time (ms, log scale)", fixed=recursive_fixed,
            schemes=[
                "warp_recursive_standard_arity", "warp_recursive_standard_arity_succinct",
                "quasar_warp", "quasar_warp_succinct",
                "symphony_standard_arity", "symphony_standard_arity_succinct",
                "quasar_symphony", "quasar_symphony_succinct",
            ],
        )
        _plot_workload_metric_per_unit(
            df_scheme, axes[2, 1], "recursive_ivc", "total_step_circuits",
            "phase_e2e_prove",
            "total_step_circuits",
            "Recursive same-step workload — prover per step circuit",
            "ms / step circuit (log scale)", fixed=recursive_fixed,
            schemes=[
                "warp_recursive_standard_arity", "warp_recursive_standard_arity_succinct",
                "quasar_warp", "quasar_warp_succinct",
                "symphony_standard_arity", "symphony_standard_arity_succinct",
                "quasar_symphony", "quasar_symphony_succinct",
            ],
        )
        _plot_workload_verify(
            df_scheme, axes[2, 2], "recursive_ivc", "total_step_circuits",
            "Recursive same-step workload — terminal verify",
            fixed=recursive_fixed,
            schemes=[
                "warp_recursive_standard_arity", "warp_recursive_standard_arity_succinct",
                "quasar_warp", "quasar_warp_succinct",
                "symphony_standard_arity", "symphony_standard_arity_succinct",
                "quasar_symphony", "quasar_symphony_succinct",
            ],
        )
    else:
        # Legacy rows: kept for old JSONL files, but these panels are not
        # apples-to-apples because schemes interpret `ivc_steps` differently.
        _plot_scheme_prove(df_scheme, axes[0, 0], family_counter="counter_family_a",
                           title="LEGACY Family A — mixed workload prover")
        _plot_scheme_normalized(df_scheme, axes[0, 1], family_counter="counter_family_a",
                                title="LEGACY Family A — normalized post-Spartan")
        _plot_scheme_verify(df_scheme, axes[0, 2], family_counter="counter_family_a",
                            title="LEGACY Family A — mixed workload verify")
        _plot_scheme_prove(df_scheme, axes[1, 0], family_counter="counter_family_b",
                           title="LEGACY Family B — mixed workload prover")
        _plot_scheme_normalized(df_scheme, axes[1, 1], family_counter="counter_family_b",
                                title="LEGACY Family B — normalized")
        _plot_scheme_verify(df_scheme, axes[1, 2], family_counter="counter_family_b",
                            title="LEGACY Family B — verify")
        _plot_fs_scaling_abs(mb.get("fs_scaling", pd.DataFrame()), axes[2, 0])
        _plot_fold_verify_full(mb.get("fold_verify", pd.DataFrame()), axes[2, 1])
        _plot_fs_scaling_speedup(mb.get("fs_scaling", pd.DataFrame()), axes[2, 2])

    # Row 4 — In-circuit verifier microbenches
    _plot_circuit_size_arity(mb.get("circuit_size_arity", pd.DataFrame()), axes[3, 0])
    _plot_circuit_sizes(mb.get("circuit_sizes_l2", pd.DataFrame()), axes[3, 1])
    _plot_circuit_size_arity_speedup(mb.get("circuit_size_arity", pd.DataFrame()),
                                     axes[3, 2])

    # Row 5 — Terminal + in-circuit WHIR estimate + fold_verify speedup
    _plot_terminal_whir(mb.get("terminal_whir", pd.DataFrame()), axes[4, 0])
    _plot_whir_estimate(mb.get("whir_in_circuit_estimate", pd.DataFrame()), axes[4, 1])
    _plot_fold_verify_speedup(mb.get("fold_verify", pd.DataFrame()), axes[4, 2])

    # Row 6 — Headline: aggregated WARP vs N independent WHIR proofs.
    _plot_warp_vs_whir_prove(mb.get("warp_vs_whir", pd.DataFrame()), axes[5, 0])
    _plot_warp_vs_whir_verify(mb.get("warp_vs_whir", pd.DataFrame()), axes[5, 1])
    _plot_warp_vs_whir_speedup(mb.get("warp_vs_whir", pd.DataFrame()), axes[5, 2])

    for row in axes:
        for ax in row:
            ax.grid(True, alpha=0.3)
    # No figure-level suptitle: the top strip was blocking the Row-1 panels.
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"Saved: {out}")


# ─────────────────────────────────────────────────────────────────────────────
# Scheme-row panels for the unified dashboard
# ─────────────────────────────────────────────────────────────────────────────

SCHEME_STYLES_FULL = {
    "independent_whir": {"color": "#7f7f7f", "marker": "x", "label": "independent_whir"},
    "pure_warp":        {"color": "#1f77b4", "marker": "o", "label": "pure_warp"},
    "pure_warp_succinct": {"color": "#1f77b4", "marker": "o", "linestyle": "--", "label": "pure_warp + WHIR"},
    "warp_standard":    {"color": "#9467bd", "marker": "P", "label": "warp_standard"},
    "warp_standard_succinct": {"color": "#9467bd", "marker": "P", "linestyle": "--", "label": "warp_standard + WHIR"},
    "warp_union":       {"color": "#2ca02c", "marker": "^", "label": "warp_union"},
    "warp_union_succinct": {"color": "#2ca02c", "marker": "^", "linestyle": "--", "label": "warp_union + WHIR"},
    "warp_recursive_standard": {"color": "#8c564b", "marker": "v", "label": "warp_recursive_standard"},
    "warp_recursive_standard_succinct": {"color": "#8c564b", "marker": "v", "linestyle": "--", "label": "warp_recursive_standard + WHIR"},
    "warp_recursive_standard_arity": {"color": "#9467bd", "marker": "P", "label": "standard WARP (arity)"},
    "warp_recursive_standard_arity_succinct": {"color": "#9467bd", "marker": "P", "linestyle": "--", "label": "standard WARP (arity) + WHIR"},
    "quasar_warp":      {"color": "#1f77b4", "marker": "o", "label": "quasar_warp"},
    "quasar_warp_succinct": {"color": "#1f77b4", "marker": "o", "linestyle": "--", "label": "quasar_warp + WHIR"},
    "symphony":         {"color": "#2ca02c", "marker": "^", "label": "symphony"},
    "symphony_succinct": {"color": "#2ca02c", "marker": "^", "linestyle": "--", "label": "symphony + WHIR"},
    "symphony_standard_arity": {"color": "#17becf", "marker": "v", "label": "symphony standard (arity)"},
    "symphony_standard_arity_succinct": {"color": "#17becf", "marker": "v", "linestyle": "--", "label": "symphony standard (arity) + WHIR"},
    "quasar_symphony":  {"color": "#d62728", "marker": "D", "label": "quasar_symphony"},
    "quasar_symphony_succinct": {"color": "#d62728", "marker": "D", "linestyle": "--", "label": "quasar_symphony + WHIR"},
}


def _phase(df: pd.DataFrame, name: str) -> pd.Series:
    col = f"phase_{name}"
    if col in df.columns:
        return df[col].fillna(0)
    return pd.Series(0, index=df.index)


def _counter(df: pd.DataFrame, name: str) -> pd.Series:
    col = f"counter_{name}"
    if col in df.columns:
        return df[col].fillna(0)
    return pd.Series(0, index=df.index)


def _with_e2e(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["phase_e2e_prove"] = _phase(out, "prove_total") + _phase(out, "spartan")
    out["phase_post_spartan_prove"] = _phase(out, "prove_total")
    return out


def _workload(df: pd.DataFrame, name: str) -> pd.DataFrame:
    if "workload" not in df.columns:
        return df.iloc[0:0]
    return df[df["workload"] == name].copy()


def _select_fixed(sub: pd.DataFrame, fixed: dict[str, str]) -> pd.DataFrame:
    out = sub
    for col, mode in fixed.items():
        if col not in out.columns or out.empty:
            continue
        value = out[col].max() if mode == "max" else out[col].min()
        out = out[out[col] == value]
    return out


def _family_a_axis_plan(df: pd.DataFrame) -> tuple[str, dict[str, str] | None, str]:
    sub = _workload(df, "family_a_same_n")
    if {"log_n", "total_instances"}.issubset(sub.columns):
        pairs = sub[["log_n", "total_instances"]].dropna().drop_duplicates()
        if not pairs.empty:
            log_count = pairs["log_n"].nunique()
            n_count = pairs["total_instances"].nunique()
            per_log = pairs.groupby("log_n")["total_instances"].nunique()
            per_n = pairs.groupby("total_instances")["log_n"].nunique()
            is_paired_sweep = log_count > 1 and per_log.max() == 1 and per_n.max() == 1
            if is_paired_sweep:
                return "log_n", None, "paired N"
            if n_count > 1:
                return "total_instances", {"log_n": "max"}, "max log_n"
    return "log_n", None, "paired N"


def _plot_workload_metric(
    df: pd.DataFrame,
    ax,
    workload: str,
    x_col: str,
    metric: str,
    title: str,
    ylabel: str,
    *,
    fixed: dict[str, str] | None = None,
    schemes: list[str] | None = None,
    yscale: str = "log",
):
    sub = _with_e2e(_workload(df, workload))
    if fixed:
        sub = _select_fixed(sub, fixed)
    if schemes:
        sub = sub[sub["scheme"].isin(schemes)]
    if sub.empty or x_col not in sub.columns or metric not in sub.columns:
        ax.text(0.5, 0.5, f"(no {workload} data)",
                transform=ax.transAxes, ha="center", color="gray")
        ax.set(title=title)
        return

    agg = sub.groupby(["scheme", x_col])[metric].median().reset_index()
    for scheme, g in agg.groupby("scheme"):
        g = g.sort_values(x_col)
        if len(g) < 2:
            continue
        st = SCHEME_STYLES_FULL.get(scheme, {"color": "gray", "marker": "x", "label": scheme})
        ax.plot(g[x_col], g[metric] / 1e6, st.get("linestyle", "-"),
                marker=st["marker"], color=st["color"], label=st["label"], linewidth=1.5)
    ax.set(xlabel=x_col, ylabel=ylabel, title=title, yscale=yscale)
    handles, _ = ax.get_legend_handles_labels()
    if handles:
        ax.legend(fontsize=7)
    else:
        ax.text(0.5, 0.5, f"(only one {x_col} point)",
                transform=ax.transAxes, ha="center", color="gray")


def _plot_workload_metric_per_unit(
    df: pd.DataFrame,
    ax,
    workload: str,
    x_col: str,
    metric: str,
    unit_col: str,
    title: str,
    ylabel: str,
    *,
    fixed: dict[str, str] | None = None,
    schemes: list[str] | None = None,
    yscale: str = "log",
):
    sub = _with_e2e(_workload(df, workload))
    if fixed:
        sub = _select_fixed(sub, fixed)
    if schemes:
        sub = sub[sub["scheme"].isin(schemes)]

    if unit_col not in sub.columns and f"counter_{unit_col}" in sub.columns:
        unit_col = f"counter_{unit_col}"
    if (
        sub.empty
        or x_col not in sub.columns
        or metric not in sub.columns
        or unit_col not in sub.columns
    ):
        ax.text(0.5, 0.5, f"(no {workload} data)",
                transform=ax.transAxes, ha="center", color="gray")
        ax.set(title=title)
        return

    sub = sub.copy()
    sub = sub[sub[unit_col].fillna(0) > 0]
    sub["metric_per_unit"] = sub[metric] / sub[unit_col]
    agg = sub.groupby(["scheme", x_col])["metric_per_unit"].median().reset_index()
    for scheme, g in agg.groupby("scheme"):
        g = g.sort_values(x_col)
        if len(g) < 2:
            continue
        st = SCHEME_STYLES_FULL.get(scheme, {"color": "gray", "marker": "x", "label": scheme})
        ax.plot(g[x_col], g["metric_per_unit"] / 1e6, st.get("linestyle", "-"),
                marker=st["marker"], color=st["color"], label=st["label"], linewidth=1.5)
    ax.set(xlabel=x_col, ylabel=ylabel, title=title, yscale=yscale)
    handles, _ = ax.get_legend_handles_labels()
    if handles:
        ax.legend(fontsize=7)
    else:
        ax.text(0.5, 0.5, f"(only one {x_col} point)",
                transform=ax.transAxes, ha="center", color="gray")


def _plot_workload_verify(
    df: pd.DataFrame,
    ax,
    workload: str,
    x_col: str,
    title: str,
    *,
    fixed: dict[str, str] | None = None,
    schemes: list[str] | None = None,
    metric: str = "phase_verify_total",
    ylabel: str = "verify time (ms, log scale)",
):
    _plot_workload_metric(
        df,
        ax,
        workload,
        x_col,
        metric,
        title,
        ylabel,
        fixed=fixed,
        schemes=schemes,
    )


def _plot_speedup(
    df: pd.DataFrame,
    ax,
    workload: str,
    x_col: str,
    numerator_scheme: str,
    denominator_scheme: str,
    metric: str,
    title: str,
    *,
    fixed: dict[str, str] | None = None,
):
    sub = _with_e2e(_workload(df, workload))
    if fixed:
        sub = _select_fixed(sub, fixed)
    if sub.empty or x_col not in sub.columns or metric not in sub.columns:
        ax.text(0.5, 0.5, f"(no {workload} data)",
                transform=ax.transAxes, ha="center", color="gray")
        ax.set(title=title)
        return
    agg = sub.groupby(["scheme", x_col])[metric].median().reset_index()
    pivot = agg.pivot(index=x_col, columns="scheme", values=metric).dropna()
    if numerator_scheme not in pivot or denominator_scheme not in pivot:
        alt_num = numerator_scheme.removesuffix("_succinct")
        alt_den = denominator_scheme.removesuffix("_succinct")
        if alt_num in pivot and alt_den in pivot:
            numerator_scheme, denominator_scheme = alt_num, alt_den
        else:
            ax.text(0.5, 0.5, "(missing schemes)",
                    transform=ax.transAxes, ha="center", color="gray")
            ax.set(title=title)
            return
    if numerator_scheme not in pivot or denominator_scheme not in pivot:
        ax.text(0.5, 0.5, "(missing schemes)",
                transform=ax.transAxes, ha="center", color="gray")
        ax.set(title=title)
        return
    speedup = pivot[numerator_scheme] / pivot[denominator_scheme]
    ax.bar(speedup.index.astype(str), speedup.values, color="#d62728", alpha=0.75)
    for i, v in enumerate(speedup.values):
        ax.text(i, v, f"{v:.2f}x", ha="center", va="bottom", fontsize=8)
    ax.set(xlabel=x_col, ylabel="speedup (x)", title=title)


def _filter_family(df: pd.DataFrame, family_counter: str) -> pd.DataFrame:
    if family_counter in df.columns:
        return df[df[family_counter].fillna(0) > 0]
    return df.iloc[0:0]


def _plot_scheme_prove(df, ax, family_counter: str, title: str):
    sub = _filter_family(df, family_counter)
    if sub.empty:
        ax.text(0.5, 0.5, "(no data in this family)",
                transform=ax.transAxes, ha="center", color="gray")
        return
    agg = sub.groupby(["scheme", "log_n"])["phase_prove_total"].median().reset_index()
    for scheme, g in agg.groupby("scheme"):
        g = g.sort_values("log_n")
        st = SCHEME_STYLES_FULL.get(scheme, {"color": "gray", "marker": "x", "label": scheme})
        ax.plot(g["log_n"], g["phase_prove_total"] / 1e6, st.get("linestyle", "-"),
                marker=st["marker"], color=st["color"], label=st["label"], linewidth=1.5)
    # Log y-scale: O(n·log n) curves read as near-straight lines instead of
    # looking "exponential" on a linear axis. Small absolute differences at
    # the small-log_n end aren't visually compressed into a flat line.
    ax.set(xlabel="log₂(constraints)", ylabel="prove_total (ms, log scale)",
           title=title, yscale="log")
    ax.legend(fontsize=7)


def _plot_scheme_verify(df, ax, family_counter: str, title: str):
    sub = _filter_family(df, family_counter)
    if sub.empty:
        ax.text(0.5, 0.5, "(no data in this family)",
                transform=ax.transAxes, ha="center", color="gray")
        return
    agg = sub.groupby(["scheme", "log_n"])["phase_verify_total"].median().reset_index()
    for scheme, g in agg.groupby("scheme"):
        g = g.sort_values("log_n")
        st = SCHEME_STYLES_FULL.get(scheme, {"color": "gray", "marker": "x", "label": scheme})
        ax.plot(g["log_n"], g["phase_verify_total"] / 1e3, st.get("linestyle", "-"),
                marker=st["marker"], color=st["color"], label=st["label"], linewidth=1.5)
    ax.set(xlabel="log₂(constraints)", ylabel="verify_total (µs)",
           title=title, yscale="log")
    ax.legend(fontsize=7)


def _plot_scheme_normalized(df, ax, family_counter: str, title: str):
    """Prove time per instance: phase_prove_total / counter_total_instances."""
    sub = _filter_family(df, family_counter)
    if sub.empty or "counter_total_instances" not in sub.columns:
        ax.text(0.5, 0.5, "(no instance counter)",
                transform=ax.transAxes, ha="center", color="gray")
        return
    sub = sub.copy()
    sub["ms_per_instance"] = (sub["phase_prove_total"] / 1e6) / sub["counter_total_instances"]
    agg = sub.groupby(["scheme", "log_n"])["ms_per_instance"].median().reset_index()
    for scheme, g in agg.groupby("scheme"):
        g = g.sort_values("log_n")
        st = SCHEME_STYLES_FULL.get(scheme, {"color": "gray", "marker": "x", "label": scheme})
        ax.plot(g["log_n"], g["ms_per_instance"], st.get("linestyle", "-"),
                marker=st["marker"], color=st["color"], label=st["label"], linewidth=1.5)
    ax.set(xlabel="log₂(constraints)", ylabel="ms / instance (log scale)",
           title=title, yscale="log")
    ax.legend(fontsize=7)


def plot_compare_all(path: str, out: str):
    """Legacy compare_bench renderer — still works for old compare_bench JSONL."""
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
    # No figure-level suptitle: the top strip was blocking the Row-1 panels.
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
    "warp_recursive_standard_arity": "A: WARP standard (l=arity)",
    "quasar_warp":     "B: WARP+Quasar (l=arity)",
    "symphony":        "C: Symphony (l=2)",
    "symphony_standard_arity": "C: Symphony standard (l=arity)",
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
        for scheme in [
            "warp_recursive_standard_arity",
            "quasar_warp",
            "symphony_standard_arity",
            "quasar_symphony",
            "pure_warp",
            "symphony",
        ]:
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

    # Auto-detect JSONL format:
    #   - compare_bench legacy format → rows have top-level `table` field
    #   - unified format → rows have `kind` in {"scheme", "microbench"}
    def _detect_format(path: str) -> str:
        try:
            with open(path) as f:
                has_compare = False
                has_microbench = False
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    if "table" in obj:
                        has_compare = True
                    if obj.get("kind") == "microbench":
                        has_microbench = True
                if has_compare and not has_microbench:
                    return "compare_bench"
                if has_microbench:
                    return "unified"
                return "whir_bench_scheme_only"
        except OSError:
            return "unknown"

    fmt = _detect_format(args.input)

    if args.compare or fmt == "compare_bench":
        if not args.out:
            parser.error("compare_bench JSONL requires --out")
        plot_compare_all(args.input, args.out)
        return

    if fmt == "unified":
        if not args.out:
            parser.error("unified JSONL requires --out")
        plot_unified_dashboard(args.input, args.out)
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
