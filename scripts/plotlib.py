"""Shared plotting helpers for the evaluation figures.

Design rule: this module does NOT import matplotlib at top level. The pure helpers
(latest-file resolution, the reproducibility footnote, statistics → error-bar
conversion, and the raw-numbers table writer) are stdlib-only so the per-figure
`extract_*` logic and its tests run anywhere — including hosts without matplotlib.
Rendering pulls matplotlib in lazily via `mpl()`.

Conventions enforced here (from the distinguished example reports): every figure
ships its underlying numbers as a sibling CSV + LaTeX table, and is stamped with the
source run's commit / build-mode / governor so it traces back to its data.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPERIMENTS_DIR = REPO_ROOT / "logs" / "experiments"
DEFAULT_FIGURE_DIR = REPO_ROOT / "report" / "figures"

# Okabe–Ito colour-blind-safe palette, keyed by the conditions used across figures.
PALETTE = {
    "baseline": "#000000",
    "scoped": "#0072B2",
    "host-wide": "#D55E00",
    "argv": "#CC79A7",
    "final-summary": "#009E73",
    "policy-triggered": "#0072B2",
    "extend-everything": "#D55E00",
    "saving": "#56B4E9",
}


# --------------------------------------------------------------------------- data
def latest(prefix: str, *, experiments_dir: Path = EXPERIMENTS_DIR) -> Path:
    """Newest ``<experiments_dir>/<prefix>*.json`` (lexicographic = chronological,
    given the UTC timestamp filenames)."""
    matches = sorted(experiments_dir.glob(f"{prefix}*.json"))
    if not matches:
        raise FileNotFoundError(f"no {prefix}*.json under {experiments_dir}")
    return matches[-1]


# ------------------------------------------------------------------ reproducibility
def footnote(env: dict[str, Any] | None) -> str:
    """A one-line provenance stamp for a figure caption."""
    env = env or {}
    commit = (env.get("git_commit") or "?")[:10]
    dirty = "+dirty" if env.get("git_dirty") else ""
    mode = env.get("monitor_build_mode") or env.get("verifier_build_mode") or "?"
    gov = env.get("cpu_governor") or "?"
    when = env.get("captured_utc") or "?"
    return f"commit {commit}{dirty} · {mode} · governor={gov} · {when}"


# --------------------------------------------------------------------- raw tables
def _esc_latex(value: Any) -> str:
    return (
        str(value)
        .replace("\\", r"\textbackslash{}")
        .replace("_", r"\_")
        .replace("%", r"\%")
        .replace("&", r"\&")
        .replace("#", r"\#")
    )


def latex_tabular(header: Sequence[Any], rows: Sequence[Sequence[Any]]) -> str:
    cols = "l" * len(header)
    out = [r"\begin{tabular}{" + cols + "}", r"\toprule",
           " & ".join(_esc_latex(h) for h in header) + r" \\", r"\midrule"]
    out += [" & ".join(_esc_latex(c) for c in row) + r" \\" for row in rows]
    out += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(out) + "\n"


def write_table(
    name: str,
    header: Sequence[Any],
    rows: Sequence[Sequence[Any]],
    *,
    figure_dir: Path = DEFAULT_FIGURE_DIR,
) -> tuple[Path, Path]:
    """Write the figure's source numbers as ``<name>.csv`` + ``<name>.tex`` (a LaTeX
    ``tabular``), so every chart has its raw data preserved beside it."""
    figure_dir.mkdir(parents=True, exist_ok=True)
    csv_path = figure_dir / f"{name}.csv"
    with csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(list(header))
        writer.writerows([list(r) for r in rows])
    tex_path = figure_dir / f"{name}.tex"
    tex_path.write_text(latex_tabular(header, rows))
    return csv_path, tex_path


# ------------------------------------------------------------------ stats → errors
def median_ci(stats: dict[str, Any] | None, ci: dict[str, Any] | None) -> tuple[float, float, float]:
    """``(point, low_err, high_err)`` for a matplotlib asymmetric ``yerr`` from a
    ``summary_stats`` + ``bootstrap_ci`` pair. Falls back to the median with zero
    error when no CI is available."""
    stats = stats or {}
    ci = ci or {}
    point = ci.get("point")
    if point is None:
        point = stats.get("median")
    if point is None:
        return (0.0, 0.0, 0.0)
    point = float(point)
    low, high = ci.get("low"), ci.get("high")
    if low is None or high is None:
        return (point, 0.0, 0.0)
    return (point, max(0.0, point - float(low)), max(0.0, float(high) - point))


# ---------------------------------------------------------------------- rendering
def mpl():
    """Lazily import matplotlib with the headless Agg backend and the report style.

    Raises ImportError if matplotlib is not installed — callers that only need the
    pure helpers never reach here.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "figure.figsize": (5.5, 3.2),
            "font.family": "serif",
            "font.size": 9,
            "axes.grid": True,
            "grid.alpha": 0.3,
            "legend.frameon": False,
            "savefig.bbox": "tight",
            "savefig.dpi": 200,
        }
    )
    return plt


def save(fig, name: str, *, figure_dir: Path = DEFAULT_FIGURE_DIR, formats: Sequence[str] = ("pdf",)) -> list[Path]:
    """Save a figure (vector PDF by default) under ``report/figures/``."""
    figure_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for fmt in formats:
        out = figure_dir / f"{name}.{fmt}"
        fig.savefig(out)
        paths.append(out)
    return paths
