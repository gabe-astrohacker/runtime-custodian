#!/usr/bin/env python3
"""RQ-P4 *measured* end-to-end TPM overhead, from the workload harnesses.

Reads the artefacts produced by `docs/tpm-workload-experiment-runbook.md`:

  F-P4e (a) single-tenant: median binwalk wall-clock per commitment mode (baseline,
            scoped-no-TPM, nothing/final-summary, suspicious/policy-triggered,
            everything/extend-everything) with 95% CIs and the measured per-run
            extend count — showing the modes are within noise (TPM extends run in
            the monitor, off the workload critical path).
        (b) multi-tenant: total wall-clock vs concurrent monitored containers for
            nothing vs everything — the two overlap and nothing drops, so the
            growth is CPU concurrency, not TPM.

`extract_*` is pure (reads loaded JSON); `render_*` draws.
"""
from __future__ import annotations

import argparse
import glob
import sys
from pathlib import Path
from typing import Any

import plotlib

SINGLE_ORDER = [
    ("reference", "baseline", "baseline"),
    ("reference", "scoped", "no TPM"),
    ("final_summary", "scoped", "nothing"),
    ("policy_triggered", "scoped", "suspicious"),
    ("extend_everything", "scoped", "everything"),
]
COLORS = ["#000000", "#999999", plotlib.PALETTE["final-summary"], plotlib.PALETTE["policy-triggered"], plotlib.PALETTE["extend-everything"]]

# F-P4f rate sweep: the FastAPI /echo open-loop contention experiment. Each request
# execs /usr/bin/echo once (acceptable), so the offered request rate IS the offered
# extend rate for extend-everything; policy-triggered/final-summary scope echo out and
# extend zero. (tag, palette key, marker, legend label).
RATE_MODES = [
    ("final_summary", "final-summary", "o", "final-summary"),
    ("policy_triggered", "policy-triggered", "^", "policy-triggered"),
    ("extend_everything", "extend-everything", "s", "extend-everything"),
]
SWTPM_CEILING_RPS = 200  # measured single-tenant swtpm serial extend ceiling (see f_p4d)


def _latest(pattern: str, experiments_dir: Path) -> dict[str, Any] | None:
    import json

    matches = sorted(experiments_dir.glob(pattern))
    return json.loads(matches[-1].read_text()) if matches else None


def _extends_median(trials: list[dict[str, Any]]) -> Any:
    import statistics

    vals = [((t.get("evidence") or {}).get("monitor_summary", {}).get("tpm") or {}).get("event_extend_count") for t in trials]
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None


def extract_single(experiments_dir: Path) -> dict[str, Any]:
    bars: list[dict[str, Any]] = []
    for tag, mode, label in SINGLE_ORDER:
        d = _latest(f"tpm_single_{tag}_*.json", experiments_dir)
        if not d or mode not in d["aggregate"]:
            continue
        agg = d["aggregate"][mode]
        ci = agg.get("median_wall_ms_ci") or {}
        ext = _extends_median(d["trial_results"].get(mode, []))
        bars.append(
            {
                "label": label,
                "median": agg["median_wall_ms"],
                "low": ci.get("low", agg["median_wall_ms"]),
                "high": ci.get("high", agg["median_wall_ms"]),
                "extends": ext,
            }
        )
    return {"bars": bars}


def extract_concurrent(experiments_dir: Path, counts=(1, 2, 4, 8)) -> dict[str, Any]:
    series: dict[str, dict[str, list]] = {}
    for mode in ("final_summary", "extend_everything"):
        ns, wall, thr, drops = [], [], [], []
        for n in counts:
            d = _latest(f"tpm_concurrent_{mode}_n{n}_*.json", experiments_dir)
            if not d:
                continue
            agg = d["aggregate"]["scoped"]
            ns.append(n)
            wall.append(agg["median_total_wall_ms"])
            thr.append(agg["median_completed_runs_per_sec"])
            drops.append(agg["total_dropped_events"])
        series[mode] = {"n": ns, "wall": wall, "throughput": thr, "drops": drops}
    return series


def render(single: dict[str, Any], concurrent: dict[str, Any], *, name: str = "f_p4e_tpm_measured", figure_dir=None) -> None:
    plt = plotlib.mpl()
    fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(7.6, 3.2))

    # (a) single-tenant bars with CI
    bars = single["bars"]
    xs = list(range(len(bars)))
    meds = [b["median"] for b in bars]
    yerr = [[b["median"] - b["low"] for b in bars], [b["high"] - b["median"] for b in bars]]
    ax_a.bar(xs, meds, color=COLORS[: len(bars)], yerr=yerr, capsize=3, error_kw={"elinewidth": 1})
    ax_a.set_xticks(xs)
    ax_a.set_xticklabels([b["label"] for b in bars], fontsize=8)
    ax_a.set_ylabel("binwalk wall-clock (ms)")
    ax_a.set_ylim(bottom=min(meds) * 0.92, top=max(b["high"] for b in bars) * 1.05)
    for x, b in zip(xs, bars):
        if b["extends"] is not None:
            ax_a.text(x, b["high"] * 1.005, f"{int(b['extends'])} ext", ha="center", fontsize=6, color="0.3")
    ax_a.set_title("(a) single-tenant: wall-clock by mode")

    # (b) multi-tenant wall vs containers
    labels = {"final_summary": "nothing (final-summary)", "extend_everything": "everything (extend-everything)"}
    colors = {"final_summary": plotlib.PALETTE["final-summary"], "extend_everything": plotlib.PALETTE["extend-everything"]}
    markers = {"final_summary": "o", "extend_everything": "s"}
    total_drops = 0
    for mode, s in concurrent.items():
        if not s["n"]:
            continue
        ax_b.plot(s["n"], s["wall"], marker=markers[mode], ms=4, color=colors[mode], label=labels[mode])
        total_drops += sum(s["drops"])
    ax_b.set_xscale("log", base=2)
    ax_b.set_xticks(concurrent.get("final_summary", {}).get("n") or [1, 2, 4, 8])
    ax_b.get_xaxis().set_major_formatter(plt.matplotlib.ticker.ScalarFormatter())
    ax_b.set_xlabel("concurrent monitored containers")
    ax_b.set_ylabel("total wall-clock (ms)")
    ax_b.set_title(f"(b) multi-tenant: modes overlap ({total_drops} dropped events)")
    ax_b.legend(fontsize=6.5, loc="upper left")

    fig.suptitle("RQ-P4: measured end-to-end TPM overhead — extends run off the workload critical path", fontsize=8.5)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    plotlib.save(fig, name, figure_dir=figure_dir or plotlib.DEFAULT_FIGURE_DIR)
    plt.close(fig)


def extract_rate_sweep(experiments_dir: Path, rates=(50, 100, 200, 400, 800)) -> dict[str, Any]:
    """Per-mode series across the offered request-rate sweep.

    For each ``(mode, rps)`` reads the newest ``tpmrps_<mode>_r<rps>_*.json`` and pulls,
    across the 3 trials: achieved throughput, dropped exec events per run (mean + observed
    min/max — n=3 is too few for a meaningful bootstrap CI, so the whisker is the full
    range), the fraction of exec events lost (drops / (drops + captured)), and the median
    measured extend count (``None`` at high load, where the stop-race makes the monitor
    fail open before the count is finalised — drops are still recorded)."""
    import statistics

    series: dict[str, dict[str, Any]] = {}
    env: dict[str, Any] | None = None
    for tag, palette, _marker, label in RATE_MODES:
        rps_pts, thru, dmean, dlo, dhi, loss, extends = [], [], [], [], [], [], []
        for r in rates:
            d = _latest(f"tpmrps_{tag}_r{r}_*.json", experiments_dir)
            if not d or "scoped" not in d.get("aggregate", {}):
                continue
            env = env or d.get("environment")
            agg = d["aggregate"]["scoped"]
            trials = d["trial_results"].get("scoped", [])
            drops = [int((t.get("evidence") or {}).get("dropped_events") or 0) for t in trials]
            caps = [int((t.get("evidence") or {}).get("event_count") or 0) for t in trials]
            exts = [((t.get("evidence") or {}).get("monitor_summary", {}).get("tpm") or {}).get("event_extend_count") for t in trials]
            exts = [e for e in exts if e is not None]
            total_d, total_c = sum(drops), sum(caps)
            rps_pts.append(r)
            thru.append(agg.get("median_throughput_rps"))
            dmean.append(statistics.mean(drops) if drops else 0.0)
            dlo.append(float(min(drops)) if drops else 0.0)
            dhi.append(float(max(drops)) if drops else 0.0)
            loss.append(100.0 * total_d / (total_d + total_c) if (total_d + total_c) else 0.0)
            extends.append(statistics.median(exts) if exts else None)
        series[tag] = {
            "label": label,
            "palette": palette,
            "rps": rps_pts,
            "throughput": thru,
            "drops_mean": dmean,
            "drops_lo": dlo,
            "drops_hi": dhi,
            "loss_pct": loss,
            "extends": extends,
        }
    return {"series": series, "environment": env}


def rate_sweep_table(data: dict[str, Any]) -> tuple[list[str], list[list[Any]]]:
    header = ["mode", "offered rps", "achieved rps", "extends/run", "dropped/run", "loss %"]
    rows: list[list[Any]] = []
    for tag, _palette, _marker, _label in RATE_MODES:
        s = data["series"].get(tag)
        if not s:
            continue
        for i, r in enumerate(s["rps"]):
            ext = s["extends"][i]
            thr = s["throughput"][i]
            rows.append([
                tag.replace("_", "-"),
                r,
                f"{thr:.1f}" if thr is not None else "n/a",
                "n/a" if ext is None else int(ext),
                f"{s['drops_mean'][i]:.0f}",
                f"{s['loss_pct'][i]:.0f}",
            ])
    return header, rows


def render_rate_sweep(data: dict[str, Any], *, name: str = "f_p4f_tpm_rate_sweep", figure_dir=None) -> None:
    plt = plotlib.mpl()
    series = data["series"]
    fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(7.6, 3.2))
    all_rps = sorted({r for s in series.values() for r in s["rps"]})

    # (a) throughput vs offered load — every mode sits on the y=x diagonal (indistinguishable)
    if all_rps:
        ax_a.plot(all_rps, all_rps, ls="--", lw=1, color="0.6", label="offered (y=x)", zorder=1)
    for tag, _palette, marker, label in RATE_MODES:
        s = series.get(tag)
        if not s or not s["rps"]:
            continue
        ax_a.plot(s["rps"], s["throughput"], marker=marker, ms=4, lw=1.3,
                  color=plotlib.PALETTE[s["palette"]], label=label, zorder=2)
    ax_a.set_xscale("log", base=2)
    ax_a.set_yscale("log", base=2)
    if all_rps:
        ax_a.set_xticks(all_rps)
        ax_a.set_yticks(all_rps)
        ax_a.get_xaxis().set_major_formatter(plt.matplotlib.ticker.ScalarFormatter())
        ax_a.get_yaxis().set_major_formatter(plt.matplotlib.ticker.ScalarFormatter())
    ax_a.set_xlabel("offered request rate (req/s)")
    ax_a.set_ylabel("achieved throughput (req/s)")
    ax_a.set_title("(a) throughput: all modes track offered load")
    ax_a.legend(fontsize=6, loc="upper left")

    # (b) monitor event loss vs offered load — only extend-everything falls behind
    for tag, _palette, marker, label in RATE_MODES:
        s = series.get(tag)
        if not s or not s["rps"]:
            continue
        yerr = [
            [m - lo for m, lo in zip(s["drops_mean"], s["drops_lo"])],
            [hi - m for m, hi in zip(s["drops_mean"], s["drops_hi"])],
        ]
        ax_b.errorbar(s["rps"], s["drops_mean"], yerr=yerr, marker=marker, ms=4, lw=1.3,
                      capsize=3, color=plotlib.PALETTE[s["palette"]], label=label)
        if tag == "extend_everything":
            for r, m, pct in zip(s["rps"], s["drops_mean"], s["loss_pct"]):
                if m > 0:
                    ax_b.annotate(f"{pct:.0f}% lost", (r, m), textcoords="offset points",
                                  xytext=(0, 7), ha="center", fontsize=6, color="0.3")
    ax_b.set_xscale("log", base=2)
    if all_rps:
        ax_b.set_xticks(all_rps)
        ax_b.get_xaxis().set_major_formatter(plt.matplotlib.ticker.ScalarFormatter())
    ax_b.set_xlabel("offered request rate (req/s)")
    ax_b.set_ylabel("dropped exec events / run")
    ax_b.set_title("(b) monitor event loss: only extend-everything")
    # Headroom so the per-point "% lost" annotations clear the top spine.
    peak = max((max(s["drops_hi"]) for s in series.values() if s["drops_hi"]), default=1.0)
    ax_b.set_ylim(bottom=-0.04 * peak, top=1.18 * peak)
    ax_b.axvline(SWTPM_CEILING_RPS, ls=":", lw=1, color="0.5")
    ax_b.text(SWTPM_CEILING_RPS * 1.04, 0.55 * peak, f"swtpm ~{SWTPM_CEILING_RPS} ext/s",
              rotation=90, va="center", fontsize=6, color="0.4")
    ax_b.legend(fontsize=6, loc="upper left")

    fig.suptitle("RQ-P4: FastAPI /echo rate sweep — attest-everything blinds the monitor "
                 "under load; app throughput is unaffected", fontsize=8)
    foot = plotlib.footnote(data.get("environment"))
    fig.text(0.5, -0.01, foot, ha="center", fontsize=5.5, color="0.45")
    fig.tight_layout(rect=[0, 0.01, 1, 0.93])
    plotlib.save(fig, name, figure_dir=figure_dir or plotlib.DEFAULT_FIGURE_DIR)
    plt.close(fig)


def extract_buffer_tradeoff(experiments_dir: Path, rates=(100, 200, 300, 400, 600, 800)) -> dict[str, Any]:
    """The buffering trade-off for the FastAPI /echo sweep: small-buffer dropped
    events per mode (lossy) vs big-buffer finalisation lag for extend-everything
    (laggy). Small buffer = `tpmrps_<mode>_r<rps>`; big buffer (64 MiB) =
    `tpmrpsbig_extend_everything_r<rps>` (`monitor_drain_secs`)."""
    import statistics

    rates_out: list[int] = []
    drops: dict[str, list[float]] = {tag: [] for tag, *_ in RATE_MODES}
    lag: list[Any] = []
    env: dict[str, Any] | None = None
    for r in rates:
        ee = _latest(f"tpmrps_extend_everything_r{r}_*.json", experiments_dir)
        if not ee or "scoped" not in ee.get("aggregate", {}):
            continue
        rates_out.append(r)
        env = env or ee.get("environment")
        for tag, *_ in RATE_MODES:
            d = _latest(f"tpmrps_{tag}_r{r}_*.json", experiments_dir)
            tr = (d or {}).get("trial_results", {}).get("scoped", [])
            drops[tag].append(
                statistics.mean([int((t.get("evidence") or {}).get("dropped_events") or 0) for t in tr]) if tr else 0.0
            )
        big = _latest(f"tpmrpsbig_extend_everything_r{r}_*.json", experiments_dir)
        btr = (big or {}).get("trial_results", {}).get("scoped", [])
        drains = [t.get("monitor_drain_secs") for t in btr if t.get("monitor_drain_secs") is not None]
        lag.append(statistics.median(drains) if drains else None)
    return {"rates": rates_out, "drops": drops, "lag": lag, "environment": env}


def render_buffer_tradeoff(data: dict[str, Any], *, name: str = "f_p4g_tpm_buffer_tradeoff", figure_dir=None) -> None:
    """Two failure modes of attest-everything under sustained overload: (a) small
    buffer drops events (lossy attestation); (b) big buffer keeps them but the
    monitor finalises late (laggy). Both worsen with load; scoping avoids both."""
    plt = plotlib.mpl()
    rates = data["rates"]
    if not rates:
        return
    fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(7.6, 3.2))

    # (a) small buffer -> dropped events (lossy), per mode
    for tag, palette, marker, label in RATE_MODES:
        ys = data["drops"].get(tag)
        if ys:
            ax_a.plot(rates, ys, marker=marker, ms=4, lw=1.3, color=plotlib.PALETTE[palette], label=label)
    ax_a.set_xscale("log", base=2)
    ax_a.set_xticks(rates)
    ax_a.get_xaxis().set_major_formatter(plt.matplotlib.ticker.ScalarFormatter())
    ax_a.axvline(SWTPM_CEILING_RPS, ls=":", lw=1, color="0.5")
    ax_a.set_xlabel("offered request rate (req/s)")
    ax_a.set_ylabel("dropped exec events / run")
    ax_a.set_title("(a) small buffer (256 KiB): lossy")
    ax_a.legend(fontsize=6, loc="upper left")

    # (b) big buffer -> finalisation lag (laggy), extend-everything; others ~0
    lag = [v if v is not None else float("nan") for v in data["lag"]]
    ax_b.plot(rates, lag, marker="s", ms=4, lw=1.3, color=plotlib.PALETTE["extend-everything"], label="extend-everything")
    ax_b.axhline(0.0, ls="-", lw=1.0, color=plotlib.PALETTE["policy-triggered"], label="nothing / suspicious (≈0)")
    ax_b.set_xscale("log", base=2)
    ax_b.set_xticks(rates)
    ax_b.get_xaxis().set_major_formatter(plt.matplotlib.ticker.ScalarFormatter())
    ax_b.axvline(SWTPM_CEILING_RPS, ls=":", lw=1, color="0.5")
    ax_b.set_xlabel("offered request rate (req/s)")
    ax_b.set_ylabel("attestation finalisation lag (s)")
    ax_b.set_title("(b) big buffer (64 MiB): laggy, 0 dropped")
    ax_b.legend(fontsize=6, loc="upper left")

    fig.suptitle("RQ-P4: you cannot buffer past the ceiling — attest-everything is lossy or laggy; "
                 "scoping is neither", fontsize=8)
    foot = plotlib.footnote(data.get("environment"))
    fig.text(0.5, -0.01, foot, ha="center", fontsize=5.5, color="0.45")
    fig.tight_layout(rect=[0, 0.01, 1, 0.93])
    plotlib.save(fig, name, figure_dir=figure_dir or plotlib.DEFAULT_FIGURE_DIR)
    plt.close(fig)


def extract_binwalk_tradeoff(experiments_dir: Path, counts=(1, 2, 4, 6, 8, 12)) -> dict[str, Any]:
    """The buffering trade-off for the binwalk nested-zip sweep (x = concurrent
    monitored containers): small-buffer dropped events per mode (lossy, from
    `tpmdense_<mode>_n<n>`) vs big-buffer finalisation lag for extend-everything
    (laggy, from `tpmbigbuf_extend_everything_n<n>`)."""
    import statistics

    ns: list[int] = []
    drops: dict[str, list[float]] = {tag: [] for tag, *_ in RATE_MODES}
    lag: list[Any] = []
    env: dict[str, Any] | None = None
    for n in counts:
        ee = _latest(f"tpmdense_extend_everything_n{n}_*.json", experiments_dir)
        if not ee or "scoped" not in ee.get("aggregate", {}):
            continue
        ns.append(n)
        env = env or ee.get("environment")
        for tag, *_ in RATE_MODES:
            d = _latest(f"tpmdense_{tag}_n{n}_*.json", experiments_dir)
            tr = (d or {}).get("trial_results", {}).get("scoped", [])
            drops[tag].append(
                statistics.mean([int((t.get("evidence") or {}).get("dropped_events") or 0) for t in tr]) if tr else 0.0
            )
        big = _latest(f"tpmbigbuf_extend_everything_n{n}_*.json", experiments_dir)
        btr = (big or {}).get("trial_results", {}).get("scoped", [])
        drains = [t.get("monitor_drain_secs") for t in btr if t.get("monitor_drain_secs") is not None]
        lag.append(statistics.median(drains) if drains else None)
    return {"n": ns, "drops": drops, "lag": lag, "environment": env}


def render_binwalk_tradeoff(data: dict[str, Any], *, name: str = "f_p4h_binwalk_buffer_tradeoff", figure_dir=None) -> None:
    """binwalk counterpart of the FastAPI buffer trade-off, x = containers. ~200
    extends/s ceiling is crossed near 4-5 containers (~46 execs/s each)."""
    plt = plotlib.mpl()
    ns = data["n"]
    if not ns:
        return
    ceiling_n = SWTPM_CEILING_RPS / 46.0  # ~46 execs/s/container -> ceiling at ~4.3
    fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(7.6, 3.2))

    for tag, palette, marker, label in RATE_MODES:
        ys = data["drops"].get(tag)
        if ys:
            ax_a.plot(ns, ys, marker=marker, ms=4, lw=1.3, color=plotlib.PALETTE[palette], label=label)
    ax_a.axvline(ceiling_n, ls=":", lw=1, color="0.5")
    ax_a.set_xlabel("concurrent monitored containers")
    ax_a.set_ylabel("dropped exec events / run")
    ax_a.set_title("(a) small buffer (256 KiB): lossy")
    ax_a.legend(fontsize=6, loc="upper left")

    lag = [v if v is not None else float("nan") for v in data["lag"]]
    ax_b.plot(ns, lag, marker="s", ms=4, lw=1.3, color=plotlib.PALETTE["extend-everything"], label="extend-everything")
    ax_b.axhline(0.0, ls="-", lw=1.0, color=plotlib.PALETTE["policy-triggered"], label="nothing / suspicious (≈0)")
    ax_b.axvline(ceiling_n, ls=":", lw=1, color="0.5")
    ax_b.set_xlabel("concurrent monitored containers")
    ax_b.set_ylabel("attestation finalisation lag (s)")
    ax_b.set_title("(b) big buffer (64 MiB): laggy, 0 dropped")
    ax_b.legend(fontsize=6, loc="upper left")

    fig.suptitle("RQ-P4: binwalk nested-zip — same buffering trade-off as FastAPI (lossy or laggy)", fontsize=8)
    foot = plotlib.footnote(data.get("environment"))
    fig.text(0.5, -0.01, foot, ha="center", fontsize=5.5, color="0.45")
    fig.tight_layout(rect=[0, 0.01, 1, 0.93])
    plotlib.save(fig, name, figure_dir=figure_dir or plotlib.DEFAULT_FIGURE_DIR)
    plt.close(fig)


def extract_combined(experiments_dir: Path, fastapi_rates=(100, 200, 300, 400, 600, 800), binwalk_counts=(1, 2, 4, 6, 8, 12)) -> dict[str, Any]:
    """Both workloads' extend-everything on a common x = offered extend rate
    (events/s): FastAPI rate = offered rps (1 exec/req); binwalk rate = offered
    events / wall. y = small-buffer loss % and big-buffer finalisation lag."""
    import statistics

    env: dict[str, Any] | None = None

    def loss_pct(trials: list) -> float:
        dr = sum(int((t.get("evidence") or {}).get("dropped_events") or 0) for t in trials)
        cap = sum(int((t.get("evidence") or {}).get("event_count") or 0) for t in trials)
        return 100.0 * dr / (dr + cap) if (dr + cap) else 0.0

    def lag_secs(d: dict[str, Any] | None) -> Any:
        tr = (d or {}).get("trial_results", {}).get("scoped", [])
        vals = [t.get("monitor_drain_secs") for t in tr if t.get("monitor_drain_secs") is not None]
        return statistics.median(vals) if vals else None

    fa: dict[str, list] = {"rate": [], "loss": [], "lag": []}
    for r in fastapi_rates:
        d = _latest(f"tpmrps_extend_everything_r{r}_*.json", experiments_dir)
        if not d or "scoped" not in d.get("aggregate", {}):
            continue
        env = env or d.get("environment")
        fa["rate"].append(float(r))
        fa["loss"].append(loss_pct(d["trial_results"]["scoped"]))
        fa["lag"].append(lag_secs(_latest(f"tpmrpsbig_extend_everything_r{r}_*.json", experiments_dir)))

    bw: dict[str, list] = {"rate": [], "loss": [], "lag": []}
    for n in binwalk_counts:
        d = _latest(f"tpmdense_extend_everything_n{n}_*.json", experiments_dir)
        if not d or "scoped" not in d.get("aggregate", {}):
            continue
        env = env or d.get("environment")
        tr = d["trial_results"]["scoped"]
        dr = statistics.mean([int((t.get("evidence") or {}).get("dropped_events") or 0) for t in tr])
        cap = statistics.mean([int((t.get("evidence") or {}).get("event_count") or 0) for t in tr])
        wall_s = (d["aggregate"]["scoped"].get("median_total_wall_ms") or 0) / 1000.0
        bw["rate"].append((dr + cap) / wall_s if wall_s else 0.0)
        bw["loss"].append(100.0 * dr / (dr + cap) if (dr + cap) else 0.0)
        bw["lag"].append(lag_secs(_latest(f"tpmbigbuf_extend_everything_n{n}_*.json", experiments_dir)))

    return {"fastapi": fa, "binwalk": bw, "environment": env}


def render_combined(data: dict[str, Any], *, name: str = "f_p4j_combined_contention", figure_dir=None) -> None:
    """Both workloads' extend-everything on one offered-extend-rate axis: they
    collapse onto the same ~200 ext/s ceiling for loss (small buffer) and lag
    (big buffer) — the contention is a property of the TPM, not the workload."""
    plt = plotlib.mpl()
    fa, bw = data["fastapi"], data["binwalk"]
    if not fa["rate"] and not bw["rate"]:
        return
    ee = plotlib.PALETTE["extend-everything"]
    bwc = plotlib.PALETTE["host-wide"]
    fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(7.6, 3.2))

    ax_a.plot(fa["rate"], fa["loss"], marker="o", ms=4, lw=1.3, color=ee, label="FastAPI /echo")
    ax_a.plot(bw["rate"], bw["loss"], marker="s", ms=4, lw=1.3, color=bwc, label="binwalk nested-zip")
    ax_a.axvline(SWTPM_CEILING_RPS, ls=":", lw=1, color="0.5")
    ax_a.text(SWTPM_CEILING_RPS * 1.05, 3, f"~{SWTPM_CEILING_RPS} ext/s", rotation=90, va="bottom", fontsize=6, color="0.4")
    ax_a.set_xscale("log")
    ax_a.set_xlabel("offered extend rate (events/s)")
    ax_a.set_ylabel("exec events lost (%)")
    ax_a.set_title("(a) small buffer: loss")
    ax_a.legend(fontsize=6, loc="upper left")

    def xy(series_x, series_y):
        pts = [(x, y) for x, y in zip(series_x, series_y) if y is not None]
        return [p[0] for p in pts], [p[1] for p in pts]

    fx, fy = xy(fa["rate"], fa["lag"])
    bx, by = xy(bw["rate"], bw["lag"])
    if fx:
        ax_b.plot(fx, fy, marker="o", ms=4, lw=1.3, color=ee, label="FastAPI /echo")
    if bx:
        ax_b.plot(bx, by, marker="s", ms=4, lw=1.3, color=bwc, label="binwalk nested-zip")
    ax_b.axvline(SWTPM_CEILING_RPS, ls=":", lw=1, color="0.5")
    ax_b.set_xscale("log")
    ax_b.set_xlabel("offered extend rate (events/s)")
    ax_b.set_ylabel("finalisation lag (s)")
    ax_b.set_title("(b) big buffer: lag")
    ax_b.legend(fontsize=6, loc="upper left")

    fig.suptitle("RQ-P4: both workloads collapse onto the same ~200 ext/s ceiling (extend-everything)", fontsize=8)
    foot = plotlib.footnote(data.get("environment"))
    fig.text(0.5, -0.01, foot, ha="center", fontsize=5.5, color="0.45")
    fig.tight_layout(rect=[0, 0.01, 1, 0.93])
    plotlib.save(fig, name, figure_dir=figure_dir or plotlib.DEFAULT_FIGURE_DIR)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--experiments-dir", default=str(plotlib.EXPERIMENTS_DIR))
    parser.add_argument("--figure-dir", help="output directory (default: report/figures)")
    args = parser.parse_args()
    exp = Path(args.experiments_dir)
    figure_dir = Path(args.figure_dir) if args.figure_dir else plotlib.DEFAULT_FIGURE_DIR

    rendered: list[str] = []

    single = extract_single(exp)
    concurrent = extract_concurrent(exp)
    if single["bars"]:
        render(single, concurrent, figure_dir=figure_dir)
        rendered.append("f_p4e_tpm_measured")

    # The live sweep uses 100..800 (the pre-fix r50 run is stale); the default
    # stays (50,100,200,400,800) for the unit-test fixture.
    rate = extract_rate_sweep(exp, rates=(100, 200, 300, 400, 600, 800))
    if any(s["rps"] for s in rate["series"].values()):
        render_rate_sweep(rate, figure_dir=figure_dir)
        header, rows = rate_sweep_table(rate)
        plotlib.write_table("f_p4f_tpm_rate_sweep", header, rows, figure_dir=figure_dir)
        rendered.append("f_p4f_tpm_rate_sweep")

    tradeoff = extract_buffer_tradeoff(exp)
    if tradeoff["rates"]:
        render_buffer_tradeoff(tradeoff, figure_dir=figure_dir)
        rendered.append("f_p4g_tpm_buffer_tradeoff")

    binwalk_to = extract_binwalk_tradeoff(exp)
    if binwalk_to["n"]:
        render_binwalk_tradeoff(binwalk_to, figure_dir=figure_dir)
        rendered.append("f_p4h_binwalk_buffer_tradeoff")

    combined = extract_combined(exp)
    if combined["fastapi"]["rate"] or combined["binwalk"]["rate"]:
        render_combined(combined, figure_dir=figure_dir)
        rendered.append("f_p4j_combined_contention")

    if not rendered:
        print("no tpm workload artefacts (tpm_single_*/tpmrps_*) found")
        return 1
    print(f"wrote {', '.join(rendered)} from {exp} -> {figure_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
