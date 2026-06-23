#!/usr/bin/env python3
"""RQ-P4 figures from `run_tpm_cost_experiments.py` output.

  F-P4a  per-extend cost distribution (microbenchmark)
  F-P4b  the saving / decision curve: PCR extends for final-summary,
         policy-triggered, and extend-everything vs the suspicious fraction,
         with the policy-triggered saving shaded — the novelty figure.

`extract_*` is pure (testable without matplotlib); `render_*` draws.
"""

from __future__ import annotations

import argparse
import statistics
import sys
from typing import Any

import plotlib

STRATEGIES = ("final-summary", "policy-triggered", "extend-everything")

# Friendly legend labels for the wall-clock overhead figure — bridge the reader's
# "everything / suspicious / nothing" framing to the report's strategy vocabulary.
LABELS = {
    "final-summary": "no per-event extend (final-summary)",
    "policy-triggered": "extend on suspicious (policy-triggered)",
    "extend-everything": "extend on every event (extend-everything)",
}


# --------------------------------------------------------------------- extract
def extract_extend_cost(result: dict[str, Any]) -> dict[str, Any] | None:
    """Per-extend cost samples + stats, or None if the microbenchmark wasn't run."""
    ec = result.get("extend_cost")
    if not ec:
        return None
    return {
        "raw": [float(x) for x in ec.get("raw_per_extend_ms", [])],
        "stats": ec.get("per_extend_ms", {}),
        "ci": ec.get("per_extend_ms_ci", {}),
        "tcti": ec.get("tcti"),
    }


def extract_saving_curve(result: dict[str, Any]) -> dict[str, Any]:
    """The extends/wall-clock curves vs suspicious fraction at the largest swept N."""
    projection = result["model"]["projection"]
    if not projection:
        raise ValueError("model.projection is empty; nothing to plot")
    totals = sorted({row["total_events"] for row in projection})
    chosen = totals[-1]
    rows = sorted(
        (r for r in projection if r["total_events"] == chosen),
        key=lambda r: r["suspicious_fraction"],
    )
    fractions = [r["suspicious_fraction"] for r in rows]
    extends = {s: [r["extends"][s] for r in rows] for s in STRATEGIES}
    wall_ms = {s: [r["wall_ms"][s] for r in rows] for s in STRATEGIES}
    saving = [r["policy_triggered_saving_vs_extend_everything"]["extends"] for r in rows]
    return {
        "total_events": chosen,
        "fractions": fractions,
        "extends": extends,
        "wall_ms": wall_ms,
        "saving_extends": saving,
        "extend_cost_ms": result["model"]["extend_cost_ms"],
    }


def extract_overhead_vs_n(result: dict[str, Any], fraction: float = 0.05) -> dict[str, Any]:
    """Wall-clock overhead per strategy across the swept event counts, at the
    swept suspicious fraction nearest ``fraction`` — the scaling view (panel d)."""
    projection = result["model"]["projection"]
    if not projection:
        raise ValueError("model.projection is empty; nothing to plot")
    fractions = sorted({r["suspicious_fraction"] for r in projection})
    chosen = min(fractions, key=lambda fr: abs(fr - fraction))
    rows = sorted(
        (r for r in projection if r["suspicious_fraction"] == chosen),
        key=lambda r: r["total_events"],
    )
    return {
        "fraction": chosen,
        "events": [r["total_events"] for r in rows],
        "wall_ms": {s: [r["wall_ms"][s] for r in rows] for s in STRATEGIES},
    }


def extract_contention(result: dict[str, Any]) -> dict[str, Any]:
    """Per-extend latency (median/p95/p99) and throughput vs concurrent extenders,
    from `run_tpm_cost_experiments.py --experiment contention`."""
    rows = result["contention"]["results"]
    if not rows:
        raise ValueError("contention.results is empty; nothing to plot")
    throughput = [
        statistics.median(r["throughput_per_s"]) if r.get("throughput_per_s") else r.get("throughput_per_s_mean", 0.0)
        for r in rows
    ]
    return {
        "concurrency": [r["concurrency"] for r in rows],
        "median": [r["per_extend_ms"]["median"] for r in rows],
        "p95": [r["per_extend_ms"]["p95"] for r in rows],
        "p99": [r["per_extend_ms"]["p99"] for r in rows],
        "throughput": throughput,
        "base_median": rows[0]["per_extend_ms"]["median"],
        "base_throughput": throughput[0],
    }


def contention_table(data: dict[str, Any]) -> tuple[list[str], list[list[Any]]]:
    header = ["concurrency", "median_ms", "p95_ms", "p99_ms", "throughput_per_s", "latency_vs_K1"]
    rows = []
    for i, k in enumerate(data["concurrency"]):
        rows.append(
            [
                k,
                f"{data['median'][i]:.2f}",
                f"{data['p95'][i]:.2f}",
                f"{data['p99'][i]:.2f}",
                f"{data['throughput'][i]:.0f}",
                f"{data['median'][i] / data['base_median']:.1f}x",
            ]
        )
    return header, rows


def saving_table(curve: dict[str, Any]) -> tuple[list[str], list[list[Any]]]:
    header = ["suspicious_fraction", "final_summary", "policy_triggered", "extend_everything", "saving_extends"]
    rows = [
        [
            f,
            curve["extends"]["final-summary"][i],
            curve["extends"]["policy-triggered"][i],
            curve["extends"]["extend-everything"][i],
            curve["saving_extends"][i],
        ]
        for i, f in enumerate(curve["fractions"])
    ]
    return header, rows


def overhead_table(curve: dict[str, Any]) -> tuple[list[str], list[list[Any]]]:
    """The same projection as `saving_table`, expressed as wall-clock TPM extend
    time (seconds) rather than extend counts — the performance-overhead view."""
    header = [
        "suspicious_fraction",
        "final_summary_s",
        "policy_triggered_s",
        "extend_everything_s",
        "overhead_avoided_s",
    ]
    rows = []
    for i, f in enumerate(curve["fractions"]):
        fs = curve["wall_ms"]["final-summary"][i] / 1000.0
        pt = curve["wall_ms"]["policy-triggered"][i] / 1000.0
        ee = curve["wall_ms"]["extend-everything"][i] / 1000.0
        rows.append([f, f"{fs:.3f}", f"{pt:.3f}", f"{ee:.3f}", f"{ee - pt:.3f}"])
    return header, rows


def overhead_vs_n_table(vs_n: dict[str, Any]) -> tuple[list[str], list[list[Any]]]:
    header = ["events", "final_summary_s", "policy_triggered_s", "extend_everything_s"]
    rows = [
        [
            n,
            f"{vs_n['wall_ms']['final-summary'][i] / 1000.0:.3f}",
            f"{vs_n['wall_ms']['policy-triggered'][i] / 1000.0:.3f}",
            f"{vs_n['wall_ms']['extend-everything'][i] / 1000.0:.3f}",
        ]
        for i, n in enumerate(vs_n["events"])
    ]
    return header, rows


# ---------------------------------------------------------------------- render
def render_extend_cost(data: dict[str, Any], env: dict[str, Any] | None, *, name: str = "f_p4a_extend_cost", figure_dir=None) -> None:
    plt = plotlib.mpl()
    fig, ax = plt.subplots()
    # NB: vertical is the boxplot default; do not pass vert= (deprecated in
    # matplotlib 3.11, removed in 3.13 — the project pins matplotlib>=3.7).
    ax.boxplot([data["raw"]], widths=0.5, showmeans=True)
    point, lo, hi = plotlib.median_ci(data["stats"], data["ci"])
    ax.errorbar([1], [point], yerr=[[lo], [hi]], fmt="o", color=plotlib.PALETTE["scoped"], capsize=4, label="median [95% CI]")
    ax.set_xticks([1])
    ax.set_xticklabels(["tpm2_pcrextend"])
    ax.set_ylabel("per-extend cost (ms)")
    ax.set_title("RQ-P4: cost of one PCR extend")
    ax.legend(loc="upper right")
    plotlib.save(fig, name, figure_dir=figure_dir or plotlib.DEFAULT_FIGURE_DIR)
    plt.close(fig)


def render_saving_curve(curve: dict[str, Any], env: dict[str, Any] | None, *, name: str = "f_p4b_tpm_saving", figure_dir=None) -> None:
    plt = plotlib.mpl()
    fig, ax = plt.subplots()
    f = curve["fractions"]
    for s in STRATEGIES:
        ax.plot(f, curve["extends"][s], marker="o", ms=3, label=s, color=plotlib.PALETTE[s])
    ax.fill_between(
        f,
        curve["extends"]["policy-triggered"],
        curve["extends"]["extend-everything"],
        alpha=0.15,
        color=plotlib.PALETTE["saving"],
        label="policy-triggered saving",
    )
    ax.set_xlabel("suspicious-event fraction (s/N)")
    ax.set_ylabel(f"PCR extends (N={curve['total_events']} events)")
    ax.set_title("RQ-P4: TPM commitment without per-event extension")
    ax.legend(loc="center left")
    plotlib.save(fig, name, figure_dir=figure_dir or plotlib.DEFAULT_FIGURE_DIR)
    plt.close(fig)


def render_overhead_curve(curve: dict[str, Any], env: dict[str, Any] | None, *, name: str = "f_p4c_tpm_overhead_line", figure_dir=None) -> None:
    """The wall-clock cost of the three commitment strategies: cumulative TPM
    extend time (seconds) versus the suspicious-event fraction. This is the
    performance-overhead instantiation of `render_saving_curve`'s extend counts —
    the same projection scaled by the measured per-extend cost. The shaded band is
    the overhead avoided by extending on suspicious events only rather than on
    every event. NB this is the serial sum of every extend at the measured cost
    (cumulative extend latency), not added wall-clock to any single workload run."""
    plt = plotlib.mpl()
    fig, ax = plt.subplots()
    f = curve["fractions"]

    def to_seconds(values: list[float]) -> list[float]:
        return [v / 1000.0 for v in values]

    for s in STRATEGIES:
        ax.plot(f, to_seconds(curve["wall_ms"][s]), marker="o", ms=3, label=LABELS[s], color=plotlib.PALETTE[s])
    ax.fill_between(
        f,
        to_seconds(curve["wall_ms"]["policy-triggered"]),
        to_seconds(curve["wall_ms"]["extend-everything"]),
        alpha=0.15,
        color=plotlib.PALETTE["saving"],
        label="overhead avoided by scoping",
    )
    # Mark the headline operating point (a mostly-benign 5% suspicious workload).
    if 0.05 in f:
        ax.axvline(0.05, color="0.5", ls=":", lw=0.8)
        ax.text(0.05, ax.get_ylim()[1] * 0.6, " 5% suspicious", fontsize=7, color="0.4", va="center")
    ax.set_xlabel("suspicious-event fraction (s/N)")
    ax.set_ylabel(f"cumulative TPM extend time (s), N={curve['total_events']:,} events")
    ax.set_title("RQ-P4: TPM performance overhead by commitment strategy")
    ax.legend(loc="best")
    plotlib.save(fig, name, figure_dir=figure_dir or plotlib.DEFAULT_FIGURE_DIR)
    plt.close(fig)


# Friendly legend labels shared across the multi-panel figure (one per mode).
_PANEL_LEGEND = (
    ("final-summary", "nothing (final-summary)"),
    ("policy-triggered", "suspicious only (policy-triggered)"),
    ("extend-everything", "everything (extend-everything)"),
)


def render_overhead_panels(
    curve: dict[str, Any],
    vs_n: dict[str, Any],
    env: dict[str, Any] | None = None,
    *,
    name: str = "f_p4c_tpm_overhead",
    figure_dir=None,
) -> None:
    """The TPM-overhead result shown four ways on one figure, sharing a colour
    legend: (a) line on a linear axis with the saving band, (b) grouped bars on a
    log axis, (c) the 5%-suspicious operating-point snapshot, and (d) overhead
    scaling with workload size N (log-log). All are the same projection scaled by
    the measured per-extend cost — cumulative extend latency, not single-run
    wall-clock."""
    plt = plotlib.mpl()
    from matplotlib.lines import Line2D
    from matplotlib.patches import Patch

    f = curve["fractions"]

    def to_seconds(values: list[float]) -> list[float]:
        return [v / 1000.0 for v in values]

    secs = {s: to_seconds(curve["wall_ms"][s]) for s in STRATEGIES}

    def nearest(target: float) -> int:
        return min(range(len(f)), key=lambda i: abs(f[i] - target))

    fig, axes = plt.subplots(2, 2, figsize=(7.4, 5.6))
    (ax_a, ax_b), (ax_c, ax_d) = axes

    # (a) line, linear axis -------------------------------------------------
    for s in STRATEGIES:
        ax_a.plot(f, secs[s], marker="o", ms=3, color=plotlib.PALETTE[s])
    ax_a.fill_between(f, secs["policy-triggered"], secs["extend-everything"], alpha=0.15, color=plotlib.PALETTE["saving"])
    if 0.05 in f:
        ax_a.axvline(0.05, color="0.5", ls=":", lw=0.8)
    ax_a.set_title("(a) line, linear axis")
    ax_a.set_xlabel("suspicious fraction (s/N)")
    ax_a.set_ylabel("TPM extend time (s)")

    # (b) grouped bars, log axis -------------------------------------------
    fsel = [fr for fr in (0.01, 0.05, 0.1, 0.25, 0.5, 1.0) if fr <= max(f)]
    idx = [nearest(fr) for fr in fsel]
    xs = list(range(len(fsel)))
    w = 0.27
    ax_b.bar([x - w for x in xs], [secs["final-summary"][i] for i in idx], w, color=plotlib.PALETTE["final-summary"])
    ax_b.bar(xs, [secs["policy-triggered"][i] for i in idx], w, color=plotlib.PALETTE["policy-triggered"])
    ax_b.bar([x + w for x in xs], [secs["extend-everything"][i] for i in idx], w, color=plotlib.PALETTE["extend-everything"])
    ax_b.set_yscale("log")
    ax_b.set_xticks(xs)
    ax_b.set_xticklabels([f"{int(round(fr * 100))}%" for fr in fsel])
    ax_b.set_title("(b) grouped bars (log)")
    ax_b.set_xlabel("suspicious fraction")
    ax_b.set_ylabel("TPM extend time (s)")

    # (c) snapshot at the 5% operating point -------------------------------
    i5 = nearest(0.05)
    vals = [secs[s][i5] for s in STRATEGIES]
    bars = ax_c.bar(["nothing", "suspicious", "everything"], vals, color=[plotlib.PALETTE[s] for s in STRATEGIES])
    ax_c.set_yscale("log")
    ax_c.set_ylim(top=max(vals) * 4)
    for bar, v in zip(bars, vals):
        ax_c.text(bar.get_x() + bar.get_width() / 2, v * 1.3, f"{v:.2f} s" if v >= 0.1 else f"{v:.3f} s", ha="center", fontsize=7)
    ax_c.set_title(f"(c) snapshot at {int(round(f[i5] * 100))}% suspicious")
    ax_c.set_ylabel("TPM extend time (s)")

    # (d) overhead vs workload size, log-log -------------------------------
    n_events = vs_n["events"]
    for s in STRATEGIES:
        ax_d.plot(n_events, to_seconds(vs_n["wall_ms"][s]), marker="o", ms=3, color=plotlib.PALETTE[s])
    ax_d.set_xscale("log")
    ax_d.set_yscale("log")
    ax_d.set_title(f"(d) vs workload size ({int(round(vs_n['fraction'] * 100))}% suspicious)")
    ax_d.set_xlabel("events processed (N)")
    ax_d.set_ylabel("TPM extend time (s)")

    handles = [Line2D([0], [0], color=plotlib.PALETTE[s], marker="o", ms=4, label=lbl) for s, lbl in _PANEL_LEGEND]
    handles.append(Patch(facecolor=plotlib.PALETTE["saving"], alpha=0.15, label="overhead avoided (panel a)"))
    fig.legend(handles=handles, loc="lower center", ncol=2, fontsize=7)
    fig.tight_layout(rect=[0, 0.08, 1, 1])
    plotlib.save(fig, name, figure_dir=figure_dir or plotlib.DEFAULT_FIGURE_DIR)
    plt.close(fig)


def render_contention(data: dict[str, Any], env: dict[str, Any] | None = None, *, name: str = "f_p4d_tpm_contention", figure_dir=None) -> None:
    """Measured TPM behaviour under concurrent extenders: (a) per-extend latency
    (median/p95/p99) climbing with contention, and (b) throughput saturating far
    below the linear scaling the fixed-cost model would predict. Empirical
    counterpoint to the projection's constant-per-extend-cost assumption."""
    plt = plotlib.mpl()
    fig, (ax_lat, ax_thr) = plt.subplots(1, 2, figsize=(7.4, 3.1))
    k = data["concurrency"]

    ax_lat.plot(k, data["median"], marker="o", ms=3, color=plotlib.PALETTE["policy-triggered"], label="median")
    ax_lat.plot(k, data["p95"], marker="s", ms=3, color=plotlib.PALETTE["extend-everything"], label="p95")
    ax_lat.plot(k, data["p99"], marker="^", ms=3, color="0.5", label="p99")
    ax_lat.set_xscale("log", base=2)
    ax_lat.set_yscale("log")
    ax_lat.set_xlabel("concurrent extenders (K)")
    ax_lat.set_ylabel("per-extend latency (ms)")
    ax_lat.set_title("(a) latency vs contention")
    ax_lat.legend(fontsize=7)

    ax_thr.plot(k, data["throughput"], marker="o", ms=3, color=plotlib.PALETTE["policy-triggered"], label="measured")
    ax_thr.plot(k, [data["base_throughput"] * kk for kk in k], ls="--", color="0.6", label="ideal linear (no contention)")
    ax_thr.set_xscale("log", base=2)
    ax_thr.set_xlabel("concurrent extenders (K)")
    ax_thr.set_ylabel("throughput (extends/s)")
    ax_thr.set_title("(b) throughput vs contention")
    ax_thr.legend(fontsize=7)

    fig.suptitle("RQ-P4: TPM under concurrent contention (swtpm) — the fixed-cost model breaks down", fontsize=9)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    plotlib.save(fig, name, figure_dir=figure_dir or plotlib.DEFAULT_FIGURE_DIR)
    plt.close(fig)


def main() -> int:
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", help="tpm_cost_*.json (default: newest under logs/experiments)")
    parser.add_argument("--figure-dir", help="output directory (default: report/figures)")
    args = parser.parse_args()

    path = Path(args.input) if args.input else plotlib.latest("tpm_cost")
    result = json.loads(path.read_text())
    env = result.get("environment")
    figure_dir = Path(args.figure_dir) if args.figure_dir else plotlib.DEFAULT_FIGURE_DIR

    produced: list[str] = []
    if "model" in result:  # --experiment model|both
        curve = extract_saving_curve(result)
        header, rows = saving_table(curve)
        plotlib.write_table("f_p4b_tpm_saving", header, rows, figure_dir=figure_dir)
        render_saving_curve(curve, env, figure_dir=figure_dir)
        produced.append("f_p4b_tpm_saving")

        oheader, orows = overhead_table(curve)
        plotlib.write_table("f_p4c_tpm_overhead", oheader, orows, figure_dir=figure_dir)
        vs_n = extract_overhead_vs_n(result)
        nheader, nrows = overhead_vs_n_table(vs_n)
        plotlib.write_table("f_p4c_tpm_overhead_vs_n", nheader, nrows, figure_dir=figure_dir)
        render_overhead_panels(curve, vs_n, env, figure_dir=figure_dir)
        produced.append("f_p4c_tpm_overhead")

    cost = extract_extend_cost(result)  # --experiment extend-cost|both
    if cost and cost["raw"]:
        render_extend_cost(cost, env, figure_dir=figure_dir)
        produced.append("f_p4a_extend_cost")

    if "contention" in result and result["contention"].get("results"):  # --experiment contention
        cdata = extract_contention(result)
        cheader, crows = contention_table(cdata)
        plotlib.write_table("f_p4d_tpm_contention", cheader, crows, figure_dir=figure_dir)
        render_contention(cdata, env, figure_dir=figure_dir)
        produced.append("f_p4d_tpm_contention")

    if not produced:
        print(f"{path.name} has neither a model projection nor extend_cost samples; nothing to plot")
        return 1
    print(f"wrote {', '.join(produced)} from {path.name} -> {figure_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
