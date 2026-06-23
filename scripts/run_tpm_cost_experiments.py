#!/usr/bin/env python3
"""RQ-P4 — TPM cost: policy-triggered vs extend-everything PCR extension.

This substantiates the project's headline novelty — *TPM commitment without
per-event extension* — quantitatively rather than by assertion, following the
microbenchmark-plus-decision-rule pattern of the strong example reports.

Two parts (run both by default):

  extend-cost  Microbenchmark the per-extend cost: time `tpm2_pcrextend` against
               the configured TPM (a software swtpm or real hardware, selected
               via --tcti / $TPM2TOOLS_TCTI). This is the fundamental quantity —
               the cost the monitor's policy-triggered extension *avoids paying
               per acceptable event*. Needs only tpm2-tools + a TPM; no Docker,
               eBPF, or root.

  model        From the measured per-extend cost, project the number of PCR
               extends and the wall-clock for the three commitment strategies
               the monitor supports, across a sweep of event counts and
               suspicious-event fractions, and report the saving plus the
               decision rule. Pure computation; fully reproducible.

Cost model (grounded in tpm.rs `should_extend_classification` + the monitor's
session lifecycle): the monitor performs two fixed extends per TPM session
regardless of mode (session-start digest + final-summary digest), plus one
per-event extend for each event whose classification is in
`attestation.extend_on`. So for N events of which `s` are suspicious/denied:

    final-summary     : 2                 (mode=final-summary; no per-event extends)
    policy-triggered  : s + 2             (extend_on = [suspicious, denied])
    extend-everything : N + 2             (extend_on = [acceptable, suspicious, denied])

Policy-triggered's saving vs extend-everything is exactly the (N - s) avoided
extends — the acceptable events. Its premium over final-summary is `s` extends,
buying *online* per-event PCR binding for the security-relevant events. As the
suspicious fraction s/N -> 1, policy-triggered converges to extend-everything
(the saving vanishes); at low suspicious fractions — the common case for a
benign workload — almost all extends are avoided. That crossover is the result.

Companion: the end-to-end wall-clock validation runs the *real* workload under
the two committed TPM policies
(`policies/runtime-policy-policy-triggered-tpm.json` and
`policies/runtime-policy-extend-everything-tpm.json`) via the existing monitor +
binwalk/latency harnesses; this script provides the per-extend cost and the
projection those live numbers are checked against.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from integration_lib import (
    IntegrationFailure,
    Settings,
    bootstrap_ci,
    environment_metadata,
    fail,
    log,
    safe_filename,
    summary_stats,
)

# Two extends happen in every TPM session independent of extend_on: the
# session-start digest (bind_tpm_session_start) and the final-summary digest
# (finalize_tpm_binding).
FIXED_SESSION_EXTENDS = 2

STRATEGIES = ("final-summary", "policy-triggered", "extend-everything")


def extends_for_strategy(strategy: str, total_events: int, suspicious_events: int) -> int:
    """PCR extends a strategy performs over a run (matches the monitor)."""
    if strategy == "final-summary":
        per_event = 0
    elif strategy == "policy-triggered":
        per_event = suspicious_events
    elif strategy == "extend-everything":
        per_event = total_events
    else:  # pragma: no cover - guarded by argparse/choices
        fail(f"unknown strategy {strategy}")
    return per_event + FIXED_SESSION_EXTENDS


def project_extend_costs(
    extend_cost_ms: float,
    event_counts: list[int],
    suspicious_fractions: list[float],
) -> list[dict[str, Any]]:
    """Projected extends + wall-clock per strategy across the event-mix sweep.

    Pure function (no I/O) so it is unit-testable without a TPM.
    """
    rows: list[dict[str, Any]] = []
    for total in event_counts:
        for frac in suspicious_fractions:
            suspicious = round(total * frac)
            acceptable = total - suspicious
            extends = {s: extends_for_strategy(s, total, suspicious) for s in STRATEGIES}
            wall_ms = {s: extends[s] * extend_cost_ms for s in STRATEGIES}
            # Saving of policy-triggered over extend-everything = avoided extends
            # = the acceptable events; premium over final-summary = suspicious.
            saving_extends = extends["extend-everything"] - extends["policy-triggered"]
            premium_extends = extends["policy-triggered"] - extends["final-summary"]
            rows.append(
                {
                    "total_events": total,
                    "suspicious_fraction": frac,
                    "suspicious_events": suspicious,
                    "acceptable_events": acceptable,
                    "extends": extends,
                    "wall_ms": wall_ms,
                    "policy_triggered_saving_vs_extend_everything": {
                        "extends": saving_extends,
                        "wall_ms": saving_extends * extend_cost_ms,
                        "pct_of_extend_everything": (
                            100.0 * saving_extends / extends["extend-everything"]
                            if extends["extend-everything"]
                            else 0.0
                        ),
                    },
                    "policy_triggered_premium_vs_final_summary": {
                        "extends": premium_extends,
                        "wall_ms": premium_extends * extend_cost_ms,
                    },
                }
            )
    return rows


def decision_rule(extend_cost_ms: float) -> str:
    return (
        f"At the measured ~{extend_cost_ms:.2f} ms per PCR extend, policy-triggered "
        "extension avoids one extend per acceptable event versus extending on every "
        "event, so its saving scales with the acceptable fraction (1 - s/N) and is "
        "largest for benign workloads; it converges to extend-everything only as the "
        "suspicious fraction approaches 1. It costs `s` extends more than a "
        "final-summary-only commitment, which is the price of online per-event PCR "
        "binding for the security-relevant events."
    )


def run_extend_cost(args: argparse.Namespace) -> dict[str, Any]:
    """Time `tpm2_pcrextend` against the configured TPM."""
    tcti = args.tcti or os.environ.get("TPM2TOOLS_TCTI")
    env = dict(os.environ)
    if tcti:
        env["TPM2TOOLS_TCTI"] = tcti

    digest = "ab" * 32  # fixed 32-byte sha256 digest
    extend_arg = f"{args.pcr}:{args.hash_bank}={digest}"

    # Invoke the same hyphenated tpm2-tools binaries the monitor forks
    # (`tpm2_pcrextend`, tpm.rs), not the `tpm2 <subcommand>` dispatcher, so the
    # measured per-extend cost is exactly the fork+exec+TPM round-trip the monitor
    # pays on the per-event path.
    def tpm_tool(program: str, *tool_args: str) -> None:
        result = subprocess.run(
            [program, *tool_args],
            env=env,
            capture_output=True,
            text=True,
            timeout=args.command_timeout_secs,
        )
        if result.returncode != 0:
            fail(
                f"`{program} {' '.join(tool_args)}` failed (rc={result.returncode}); "
                f"is an initialised TPM reachable via TPM2TOOLS_TCTI={tcti!r}? "
                f"(start swtpm + tpm2_startup -c, or point --tcti at a device)"
                f"\n{result.stderr.strip()}"
            )

    # Fail early and clearly if tpm2-tools / a TPM is not available.
    try:
        tpm_tool("tpm2_pcrread", f"{args.hash_bank}:{args.pcr}")
    except FileNotFoundError:
        fail("`tpm2_pcrread` (tpm2-tools) not found on PATH")
    except subprocess.TimeoutExpired:
        fail("`tpm2_pcrread` timed out; no TPM reachable")

    if args.reset_pcr:
        # Best-effort; PCR 23 is resettable, lower PCRs are not.
        subprocess.run(["tpm2_pcrreset", str(args.pcr)], env=env, capture_output=True)

    log(f"warming up {args.warmup} extends on PCR {args.pcr} ({args.hash_bank})")
    for _ in range(args.warmup):
        tpm_tool("tpm2_pcrextend", extend_arg)

    log(f"timing {args.iterations} extends")
    extend_ms: list[float] = []
    for _ in range(args.iterations):
        start = time.perf_counter_ns()
        tpm_tool("tpm2_pcrextend", extend_arg)
        extend_ms.append((time.perf_counter_ns() - start) / 1e6)

    return {
        "pcr": args.pcr,
        "hash_bank": args.hash_bank,
        "tcti": tcti,
        "iterations": args.iterations,
        "warmup": args.warmup,
        "per_extend_ms": summary_stats(extend_ms),
        "per_extend_ms_ci": bootstrap_ci(extend_ms),
        "raw_per_extend_ms": extend_ms,
    }


def run_contention(args: argparse.Namespace) -> dict[str, Any]:
    """Measure how the per-extend cost degrades under *concurrent* extenders.

    The projection model assumes a fixed per-extend cost and a serial sum of
    extends. That holds for a single-tenant monitor on an idle TPM, but a TPM
    processes commands serially, so several agents extending the same TPM
    concurrently queue. This sweeps the number of concurrent extenders K and, at
    each level, has every worker fork `tpm2_pcrextend` in a loop (the same
    fork+exec+TPM round-trip the monitor pays) — measuring per-extend latency
    (median / p95 / p99) and aggregate throughput. If the cost were truly fixed,
    latency would stay flat and throughput would scale linearly with K; queuing
    shows up as a latency tail blow-up and a throughput plateau.
    """
    tcti = args.tcti or os.environ.get("TPM2TOOLS_TCTI")
    env = dict(os.environ)
    if tcti:
        env["TPM2TOOLS_TCTI"] = tcti

    digest = "ab" * 32
    extend_arg = f"{args.pcr}:{args.hash_bank}={digest}"
    extend_cmd = ["tpm2_pcrextend", extend_arg]

    def one_extend() -> float:
        start = time.perf_counter_ns()
        result = subprocess.run(extend_cmd, env=env, capture_output=True, text=True, timeout=args.command_timeout_secs)
        elapsed_ms = (time.perf_counter_ns() - start) / 1e6
        if result.returncode != 0:
            raise IntegrationFailure(f"`tpm2_pcrextend` failed (rc={result.returncode}): {result.stderr.strip()}")
        return elapsed_ms

    # Fail early and clearly if tpm2-tools / a TPM is not reachable.
    try:
        probe = subprocess.run(["tpm2_pcrread", f"{args.hash_bank}:{args.pcr}"], env=env, capture_output=True, text=True, timeout=args.command_timeout_secs)
    except FileNotFoundError:
        fail("`tpm2_pcrread` (tpm2-tools) not found on PATH")
    except subprocess.TimeoutExpired:
        fail("`tpm2_pcrread` timed out; no TPM reachable")
    if probe.returncode != 0:
        fail(f"no TPM reachable via TPM2TOOLS_TCTI={tcti!r}; start swtpm + tpm2_startup -c (rc={probe.returncode})")

    log(f"contention warmup: {args.contention_warmup} extends")
    for _ in range(args.contention_warmup):
        one_extend()

    levels = [int(x) for x in args.concurrency_levels.split(",") if x.strip()]

    def worker(barrier: threading.Barrier) -> list[float]:
        barrier.wait()  # release all K workers together for steady-state concurrency
        return [one_extend() for _ in range(args.per_worker)]

    results: list[dict[str, Any]] = []
    for k in levels:
        latencies: list[float] = []
        throughputs: list[float] = []
        walls: list[float] = []
        for _ in range(args.contention_trials):
            barrier = threading.Barrier(k)
            started = time.perf_counter_ns()
            with ThreadPoolExecutor(max_workers=k) as pool:
                futures = [pool.submit(worker, barrier) for _ in range(k)]
                trial_lat = [ms for future in futures for ms in future.result()]
            wall_ms = (time.perf_counter_ns() - started) / 1e6
            extends = k * args.per_worker
            latencies.extend(trial_lat)
            throughputs.append(extends / (wall_ms / 1000.0) if wall_ms else 0.0)
            walls.append(wall_ms)
        stats = summary_stats(latencies)
        results.append(
            {
                "concurrency": k,
                "per_worker": args.per_worker,
                "trials": args.contention_trials,
                "total_extends": k * args.per_worker * args.contention_trials,
                "per_extend_ms": stats,
                "per_extend_ms_ci": bootstrap_ci(latencies),
                "throughput_per_s_mean": statistics.mean(throughputs),
                "throughput_per_s": throughputs,
                "wall_ms_mean": statistics.mean(walls),
            }
        )
        log(
            f"K={k:>3}: median={stats['median']:.2f} ms  p95={stats['p95']:.2f} ms  "
            f"p99={stats['p99']:.2f} ms  throughput={statistics.mean(throughputs):.1f} ext/s"
        )

    return {
        "tcti": tcti,
        "pcr": args.pcr,
        "hash_bank": args.hash_bank,
        "concurrency_levels": levels,
        "per_worker": args.per_worker,
        "trials": args.contention_trials,
        "warmup": args.contention_warmup,
        "results": results,
    }


def build_model(args: argparse.Namespace, extend_cost_ms: float, source: str) -> dict[str, Any]:
    event_counts = [int(x) for x in args.events.split(",") if x.strip()]
    fractions = [float(x) for x in args.suspicious_fractions.split(",") if x.strip()]
    return {
        "extend_cost_ms": extend_cost_ms,
        "extend_cost_source": source,
        "event_counts": event_counts,
        "suspicious_fractions": fractions,
        "projection": project_extend_costs(extend_cost_ms, event_counts, fractions),
        "decision_rule": decision_rule(extend_cost_ms),
    }


def write_outputs(args: argparse.Namespace, result: dict[str, Any]) -> tuple[Path, Path]:
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = Settings.from_env().root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = safe_filename(f"{args.name}_{stamp}", "tpm_cost")
    json_path = output_dir / f"{base}.json"
    json_path.write_text(json.dumps(result, indent=2) + "\n")

    csv_path = output_dir / f"{base}.csv"
    model = result.get("model")
    if model:
        with csv_path.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "total_events",
                    "suspicious_fraction",
                    "extends_final_summary",
                    "extends_policy_triggered",
                    "extends_extend_everything",
                    "wall_ms_policy_triggered",
                    "wall_ms_extend_everything",
                    "saving_wall_ms",
                    "saving_pct",
                ]
            )
            for row in model["projection"]:
                writer.writerow(
                    [
                        row["total_events"],
                        row["suspicious_fraction"],
                        row["extends"]["final-summary"],
                        row["extends"]["policy-triggered"],
                        row["extends"]["extend-everything"],
                        f"{row['wall_ms']['policy-triggered']:.3f}",
                        f"{row['wall_ms']['extend-everything']:.3f}",
                        f"{row['policy_triggered_saving_vs_extend_everything']['wall_ms']:.3f}",
                        f"{row['policy_triggered_saving_vs_extend_everything']['pct_of_extend_everything']:.1f}",
                    ]
                )
    return json_path, csv_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", default="tpm_cost", help="experiment name prefix")
    parser.add_argument(
        "--experiment",
        choices=("extend-cost", "model", "both", "contention"),
        default="both",
        help="microbenchmark the per-extend cost, project the model, both, or sweep concurrent contention",
    )
    parser.add_argument("--tcti", default=None, help="TPM2TOOLS_TCTI (default: inherit env / device)")
    parser.add_argument("--pcr", type=int, default=23, help="PCR index to extend (23 is resettable)")
    parser.add_argument("--hash-bank", default="sha256")
    parser.add_argument("--iterations", type=int, default=200, help="timed extends in the microbenchmark")
    parser.add_argument("--warmup", type=int, default=20, help="warmup extends before timing")
    parser.add_argument("--reset-pcr", action="store_true", help="tpm2_pcrreset before warmup")
    parser.add_argument("--command-timeout-secs", type=float, default=30.0)
    parser.add_argument(
        "--extend-cost-ms",
        type=float,
        default=None,
        help="per-extend cost for `model` when not running the microbenchmark",
    )
    parser.add_argument(
        "--concurrency-levels",
        default="1,2,4,8,12,16,24",
        help="contention: comma-separated counts of concurrent extenders to sweep",
    )
    parser.add_argument("--per-worker", type=int, default=40, help="contention: timed extends per worker per trial")
    parser.add_argument("--contention-trials", type=int, default=3, help="contention: trials per concurrency level")
    parser.add_argument("--contention-warmup", type=int, default=20, help="contention: warmup extends before the sweep")
    parser.add_argument("--events", default="100,1000,10000", help="comma-separated event counts to sweep")
    parser.add_argument(
        "--suspicious-fractions",
        default="0,0.01,0.05,0.1,0.25,0.5,1.0",
        help="comma-separated suspicious-event fractions to sweep",
    )
    parser.add_argument("--output-dir", default="logs/experiments")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result: dict[str, Any] = {
        "name": args.name,
        "experiment": args.experiment,
        "environment": environment_metadata(Settings.from_env()),
    }

    extend_cost_ms: float | None = args.extend_cost_ms
    source = "supplied --extend-cost-ms"

    if args.experiment == "contention":
        result["contention"] = run_contention(args)
        json_path, _ = write_outputs(args, result)
        log(f"wrote {json_path}")
        return 0

    if args.experiment in ("extend-cost", "both"):
        extend_cost = run_extend_cost(args)
        result["extend_cost"] = extend_cost
        extend_cost_ms = extend_cost["per_extend_ms"]["median"]
        source = "measured microbenchmark median"
        log(
            f"per-extend cost: median={extend_cost_ms:.3f} ms "
            f"[{extend_cost['per_extend_ms_ci']['low']:.3f}, "
            f"{extend_cost['per_extend_ms_ci']['high']:.3f}] (95% CI)"
        )

    if args.experiment in ("model", "both"):
        if extend_cost_ms is None:
            fail("model needs a per-extend cost: run --experiment both, or pass --extend-cost-ms")
        result["model"] = build_model(args, extend_cost_ms, source)
        log(result["model"]["decision_rule"])

    json_path, csv_path = write_outputs(args, result)
    log(f"wrote {json_path}")
    if result.get("model"):
        log(f"wrote {csv_path}")
    return 0


if __name__ == "__main__":
    try:
        _code = main()
    except IntegrationFailure as exc:
        log(f"experiment failed: {exc}")
        _code = 1
    sys.exit(_code)
