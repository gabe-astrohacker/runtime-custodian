#!/usr/bin/env python3
"""Measure runtime-verifier replay cost for existing evidence logs.

Timing is steady-state (warm-cache): each case runs ``--warmup`` discarded
iterations before the recorded ones so the page cache is hot and per-iteration
variance reflects compute, not cold reads. The build mode of the measured
verifier is asserted to be ``release`` (see ``--allow-debug``) and pinned in the
environment manifest alongside SHA-256 digests of the exact bytes replayed.

To observe an O(n) complexity curve, supply a ladder of ``--case`` entries with
monotonically increasing ``runtime_event_count`` (use real evidence logs of
growing size); this script does not synthesise such a ladder.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import signal
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from integration_lib import (
    IntegrationFailure,
    Settings,
    assert_release_binaries,
    bootstrap_ci,
    environment_metadata,
    fail,
    iter_evidence_records,
    iter_runtime_evidence_events,
    log,
    resolve_path,
    safe_filename,
    sha256_file,
    summary_stats,
)


@dataclass(frozen=True)
class VerifierCase:
    name: str
    policy: Path
    evidence: Path
    summary: Path


@dataclass(frozen=True)
class VerifierScalabilityConfig:
    name: str
    cases: tuple[VerifierCase, ...]
    iterations: int
    warmup: int
    cooldown_secs: float
    output_dir: Path
    allow_reject: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Measure runtime-verifier replay cost.")
    parser.add_argument("--name", default="verifier_scalability", help="experiment name prefix")
    parser.add_argument(
        "--case",
        action="append",
        required=True,
        metavar="NAME:POLICY:EVIDENCE:SUMMARY",
        help="case to measure; may be repeated",
    )
    parser.add_argument("--iterations", type=int, default=10, help="recorded verifier runs per case")
    parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="warm-cache iterations run and discarded before the recorded ones",
    )
    parser.add_argument(
        "--cooldown-secs",
        type=float,
        default=0.5,
        help="seconds to sleep between iterations",
    )
    parser.add_argument("--output-dir", default="logs/experiments", help="output directory")
    parser.add_argument(
        "--allow-reject",
        action="store_true",
        help="record non-zero verifier exits instead of failing",
    )
    parser.add_argument(
        "--allow-debug",
        action="store_true",
        help="allow measuring debug binaries; sets ALLOW_DEBUG_BINARIES=1 (development only)",
    )
    return parser.parse_args()


class VerifierScalabilityRunner:
    def __init__(self, settings: Settings, config: VerifierScalabilityConfig) -> None:
        self.settings = settings
        self.config = config

    def run(self) -> int:
        try:
            self.validate()
            self.config.output_dir.mkdir(parents=True, exist_ok=True)
            result = self.run_cases()
            json_path, csv_path = self.write_results(result)
            log(f"Wrote JSON results: {json_path}")
            log(f"Wrote CSV results: {csv_path}")
            for case_name, aggregate in result["aggregate"].items():
                log(
                    f"VERIFIER {case_name}: median={aggregate['median_wall_ms']:.2f}ms "
                    f"events={aggregate['runtime_event_count']} "
                    f"records={aggregate['total_record_count']}"
                )
            return 0
        except KeyboardInterrupt:
            print("Interrupted", file=sys.stderr)
            return 130
        except IntegrationFailure as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1

    def validate(self) -> None:
        if self.config.iterations <= 0:
            fail("--iterations must be > 0")
        if self.config.warmup < 0:
            fail("--warmup must be >= 0")
        if not self.settings.verifier_bin.exists():
            fail(f"missing verifier binary: {self.settings.verifier_bin}")
        # Debug verifier timing is not representative; refuse unless overridden.
        assert_release_binaries(self.settings)
        for case in self.config.cases:
            for label, path in (
                ("policy", case.policy),
                ("evidence", case.evidence),
                ("summary", case.summary),
            ):
                if not path.exists():
                    fail(f"missing {label} for case {case.name}: {path}")

    def run_cases(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "experiment": self.config.name,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "iterations": self.config.iterations,
            "warmup": self.config.warmup,
            "timing_regime": "warm-cache",
            "environment": environment_metadata(self.settings),
            "cases": {},
            "trial_results": {},
            "aggregate": {},
        }

        for case in self.config.cases:
            log(f"== verifier scalability case={case.name} ==")
            result["cases"][case.name] = describe_case(case)
            # Warm-cache regime: run and discard --warmup iterations so the page
            # cache is hot and recorded timings reflect compute, not cold reads.
            for w in range(1, self.config.warmup + 1):
                self.run_one(case, -w)
                if self.config.cooldown_secs > 0:
                    time.sleep(self.config.cooldown_secs)
            trials = []
            for i in range(1, self.config.iterations + 1):
                trials.append(self.run_one(case, i))
                if i < self.config.iterations and self.config.cooldown_secs > 0:
                    time.sleep(self.config.cooldown_secs)
            result["trial_results"][case.name] = trials
            result["aggregate"][case.name] = aggregate_case(result["cases"][case.name], trials)

        return result

    def run_one(self, case: VerifierCase, iteration: int) -> dict[str, Any]:
        report = self.config.output_dir / f"verification_report_{safe_filename(case.name, 'verifier_scalability')}_{iteration}.json"
        args: list[str | Path] = [
            self.settings.verifier_bin,
            "--policy",
            case.policy,
            "--evidence",
            case.evidence,
            "--summary",
            case.summary,
            "--report",
            report,
        ]
        rendered = [str(arg) for arg in args]
        log("$ " + " ".join(shlex.quote(arg) for arg in rendered))
        start_ns = time.perf_counter_ns()
        completed = subprocess.run(
            rendered,
            cwd=self.settings.root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
        if completed.returncode != 0 and not self.config.allow_reject:
            if completed.stdout:
                print(completed.stdout, file=sys.stderr, end="")
            fail(f"verifier failed for case {case.name} iteration {iteration}")

        report_json: dict[str, Any] = {}
        if report.exists():
            try:
                report_json = json.loads(report.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                fail(f"invalid verifier report JSON {report}: {exc}")

        return {
            "iteration": iteration,
            "returncode": completed.returncode,
            "wall_ms": elapsed_ms,
            "report": str(report),
            "decision": report_json.get("decision"),
            "reason": report_json.get("reason"),
            "stdout": completed.stdout,
        }

    def write_results(self, result: dict[str, Any]) -> tuple[Path, Path]:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_name = safe_filename(self.config.name, "verifier_scalability")
        json_path = self.config.output_dir / f"{safe_name}_{stamp}.json"
        csv_path = self.config.output_dir / f"{safe_name}_{stamp}.csv"
        json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_csv(csv_path, result)
        return json_path, csv_path


def describe_case(case: VerifierCase) -> dict[str, Any]:
    total_records = 0
    synthetic_records = 0
    for parsed in iter_evidence_records(case.evidence):
        total_records += 1
        if parsed.data.get("record_kind") == "synthetic":
            synthetic_records += 1

    runtime_events = sum(1 for _ in iter_runtime_evidence_events(case.evidence))
    return {
        "policy": str(case.policy),
        "evidence": str(case.evidence),
        "summary": str(case.summary),
        "evidence_size_bytes": case.evidence.stat().st_size,
        "runtime_event_count": runtime_events,
        "synthetic_record_count": synthetic_records,
        "total_record_count": total_records,
        # Pin the exact bytes replayed so a re-run is verifiably identical.
        "evidence_sha256": sha256_file(case.evidence),
        "policy_sha256": sha256_file(case.policy),
        "summary_sha256": sha256_file(case.summary),
    }


def aggregate_case(case_info: dict[str, Any], trials: list[dict[str, Any]]) -> dict[str, Any]:
    times = [float(trial["wall_ms"]) for trial in trials]
    stats = summary_stats(times)
    return {
        **case_info,
        "mean_wall_ms": stats["mean"],
        "median_wall_ms": stats["median"],
        "min_wall_ms": stats["min"],
        "max_wall_ms": stats["max"],
        "stdev_wall_ms": stats["stdev"],
        "cov_wall": stats["cov"],
        "p95_wall_ms": stats["p95"],
        "p99_wall_ms": stats["p99"],
        "median_wall_ms_ci": bootstrap_ci(times, statistic=statistics.median),
    }


def write_csv(path: Path, result: dict[str, Any]) -> None:
    fieldnames = [
        "case",
        "iteration",
        "returncode",
        "decision",
        "wall_ms",
        "runtime_event_count",
        "synthetic_record_count",
        "total_record_count",
        "evidence_size_bytes",
        "policy",
        "evidence",
        "summary",
        "report",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for case_name, trials in result["trial_results"].items():
            case_info = result["cases"][case_name]
            for trial in trials:
                writer.writerow(
                    {
                        "case": case_name,
                        "iteration": trial["iteration"],
                        "returncode": trial["returncode"],
                        "decision": trial["decision"],
                        "wall_ms": trial["wall_ms"],
                        "runtime_event_count": case_info["runtime_event_count"],
                        "synthetic_record_count": case_info["synthetic_record_count"],
                        "total_record_count": case_info["total_record_count"],
                        "evidence_size_bytes": case_info["evidence_size_bytes"],
                        "policy": case_info["policy"],
                        "evidence": case_info["evidence"],
                        "summary": case_info["summary"],
                        "report": trial["report"],
                    }
                )


def parse_case(root: Path, raw: str) -> VerifierCase:
    parts = raw.split(":")
    if len(parts) != 4:
        fail("--case must use NAME:POLICY:EVIDENCE:SUMMARY")
    name, policy, evidence, summary = parts
    if not name:
        fail("case name must not be empty")
    return VerifierCase(
        name=name,
        policy=resolve_path(root, policy),
        evidence=resolve_path(root, evidence),
        summary=resolve_path(root, summary),
    )


def config_from_args(args: argparse.Namespace, settings: Settings) -> VerifierScalabilityConfig:
    output_dir = resolve_path(settings.root, args.output_dir)
    return VerifierScalabilityConfig(
        name=args.name,
        cases=tuple(parse_case(settings.root, raw) for raw in args.case),
        iterations=args.iterations,
        warmup=args.warmup,
        cooldown_secs=args.cooldown_secs,
        output_dir=output_dir,
        allow_reject=args.allow_reject,
    )


def main() -> int:
    args = parse_args()
    if args.allow_debug:
        os.environ["ALLOW_DEBUG_BINARIES"] = "1"
    settings = Settings.from_env()
    config = config_from_args(args, settings)
    return VerifierScalabilityRunner(settings, config).run()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
