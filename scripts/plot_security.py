#!/usr/bin/env python3
"""RQ-S2 figure from `run_security_experiments.py --experiment tamper` output.

  F-S2  tamper-detection matrix: rows = tamper categories, columns = the verifier's
        16 independent checks; a cell is shaded when that check fired for that
        mutation, and the category's *primary* expected check is outlined. The
        overlap across columns is the defence-in-depth story; the title carries the
        headline detected/precise counts. This is the report's headline security
        figure.

`extract_*` is pure (testable without matplotlib); `render_*` draws.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

import plotlib

# The verifier's VerificationChecks, in a fixed display order (columns).
CHECK_ORDER = [
    "schema_valid",
    "policy_hash_valid",
    "session_valid",
    "sequence_valid",
    "event_hashes_valid",
    "synthetic_hashes_valid",
    "classification_valid",
    "software_chain_valid",
    "counts_valid",
    "lifecycle_valid",
    "workload_identity_valid",
    "drop_policy_valid",
    "tpm_metadata_valid",
    "tpm_summary_valid",
    "tpm_pcr_replay_valid",
    "tpm_quote_valid",
]

# Cell encoding for the matrix.
NOT_FIRED = 0
FIRED = 1
PRIMARY_FIRED = 2


def extract_tamper_matrix(result: dict[str, Any]) -> dict[str, Any]:
    tamper = result["tamper"]
    cases = tamper["cases"]
    matrix: list[list[int]] = []
    for case in cases:
        failed = set(case.get("failed_checks", []))
        primary = case.get("primary_check")
        row = []
        for check in CHECK_ORDER:
            if check in failed:
                row.append(PRIMARY_FIRED if check == primary else FIRED)
            else:
                row.append(NOT_FIRED)
        matrix.append(row)
    return {
        "cases": [c["name"] for c in cases],
        "checks": list(CHECK_ORDER),
        "matrix": matrix,
        "summary": {
            "detected": tamper.get("detected_count"),
            "precise": tamper.get("precise_count"),
            "total": tamper.get("total_count"),
        },
    }


def tamper_table(result: dict[str, Any]) -> tuple[list[str], list[list[Any]]]:
    header = ["case", "guarantee", "decision", "detected", "precise", "primary_check", "failed_checks"]
    rows = []
    for c in result["tamper"]["cases"]:
        rows.append(
            [
                c["name"],
                c.get("guarantee", ""),
                c.get("decision", ""),
                c.get("detected"),
                c.get("precise"),
                c.get("primary_check", ""),
                " ".join(c.get("failed_checks", [])),
            ]
        )
    return header, rows


def render_tamper_matrix(data: dict[str, Any], env: dict[str, Any] | None, *, name: str = "f_s2_tamper_matrix", figure_dir=None) -> None:
    plt = plotlib.mpl()
    from matplotlib.colors import ListedColormap
    from matplotlib.patches import Rectangle

    matrix = data["matrix"]
    cases, checks = data["cases"], data["checks"]
    cmap = ListedColormap(["#f0f0f0", plotlib.PALETTE["scoped"], plotlib.PALETTE["host-wide"]])

    fig, ax = plt.subplots(figsize=(0.30 * len(checks) + 1.9, 0.30 * len(cases) + 1.7))
    ax.imshow(matrix, aspect="equal", cmap=cmap, vmin=0, vmax=2)

    # Draw grid lines at cell *boundaries* (half-integer minor ticks) so each cell is a
    # bounded square. The default grid runs through the integer tick positions (cell
    # centres), which makes the shaded cells look like they sit on the crossings of two
    # lines rather than filling the grid squares themselves.
    ax.grid(False)
    ax.set_xticks([x - 0.5 for x in range(len(checks) + 1)], minor=True)
    ax.set_yticks([y - 0.5 for y in range(len(cases) + 1)], minor=True)
    ax.grid(which="minor", color="#c0c0c0", linewidth=0.8)
    ax.tick_params(which="minor", length=0)

    # Outline the primary-fired cells.
    for i, row in enumerate(matrix):
        for j, val in enumerate(row):
            if val == PRIMARY_FIRED:
                ax.add_patch(Rectangle((j - 0.5, i - 0.5), 1, 1, fill=False, edgecolor="black", lw=1.4))

    ax.set_xticks(range(len(checks)))
    ax.set_xticklabels(checks, rotation=90, fontsize=9)
    ax.set_yticks(range(len(cases)))
    ax.set_yticklabels(cases, fontsize=9)
    s = data["summary"]
    ax.set_title(f"RQ-S2: tamper detection — {s['detected']}/{s['total']} detected, {s['precise']}/{s['total']} by the expected check")
    plotlib.save(fig, name, figure_dir=figure_dir or plotlib.DEFAULT_FIGURE_DIR)
    plt.close(fig)


def main() -> int:
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", help="security_experiment_*.json (default: newest)")
    parser.add_argument("--figure-dir", help="output directory (default: report/figures)")
    args = parser.parse_args()

    path = Path(args.input) if args.input else plotlib.latest("security_experiment")
    result = json.loads(path.read_text())
    if "tamper" not in result or not result["tamper"].get("cases"):
        print(f"{path.name} has no tamper cases (run --experiment tamper)")
        return 1
    env = result.get("environment")
    figure_dir = Path(args.figure_dir) if args.figure_dir else plotlib.DEFAULT_FIGURE_DIR

    data = extract_tamper_matrix(result)
    header, rows = tamper_table(result)
    plotlib.write_table("f_s2_tamper_matrix", header, rows, figure_dir=figure_dir)
    render_tamper_matrix(data, env, figure_dir=figure_dir)
    print(f"wrote f_s2_tamper_matrix from {path.name} -> {figure_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
