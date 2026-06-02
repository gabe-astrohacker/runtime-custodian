#!/usr/bin/env python3
"""Performance experiments for the runtime evidence prototype.

This script is intentionally separate from run_v1_integration_tests.py because
performance experiments are slower and noisier than correctness smoke tests.

Supported experiments:
- latency: baseline workload latency vs workload latency while the monitor runs.
- event-volume: host-wide vs scoped event volume reduction.
- both: run both experiments in one invocation.

Results are written to JSON and CSV under logs/experiments by default.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import platform
import signal
import statistics
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from integration_lib import IntegrationFailure, RuntimeHarness, Settings, fail, log


@dataclass(frozen=True)
class PerformanceConfig:
    name: str
    experiment: str
    endpoint: str
    requests: int
    warmup_requests: int
    trials: int
    collection_mode: str
    expected_evidence: tuple[str, ...]
    output_dir: Path
    max_overhead_pct: float | None
    verify_evidence: bool
    event_duration_secs: float
    event_requests: int
    top_exec_paths: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run runtime-custodian performance experiments.",
    )

    parser.add_argument("--name", default="runtime_perf", help="experiment name prefix")
    parser.add_argument(
        "--experiment",
        choices=("latency", "event-volume", "both"),
        default="latency",
        help="which experiment to run",
    )
    parser.add_argument("--endpoint", default="/echo", help="HTTP endpoint to benchmark/stimulate")
    parser.add_argument("--requests", type=int, default=100, help="measured requests per latency trial")
    parser.add_argument("--warmup", type=int, default=10, help="warmup requests before each latency phase")
    parser.add_argument("--trials", type=int, default=5, help="number of baseline/monitored latency trials")
    parser.add_argument(
        "--collection-mode",
        choices=("scoped", "host-wide"),
        default="scoped",
        help="collector collection_mode for the monitored latency phase",
    )
    parser.add_argument(
        "--expected-evidence",
        action="append",
        default=None,
        help="substring that must appear in monitored evidence; may be repeated",
    )
    parser.add_argument(
        "--output-dir",
        default="logs/experiments",
        help="directory for JSON/CSV experiment outputs",
    )
    parser.add_argument(
        "--max-overhead-pct",
        type=float,
        default=None,
        help="optional failure threshold for aggregate latency median overhead percentage",
    )
    parser.add_argument(
        "--skip-evidence-check",
        action="store_true",
        help="do not assert that monitored evidence exists/contains expected substrings",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="skip scripts/build_all.sh",
    )

    event_group = parser.add_argument_group("event-volume experiment")
    event_group.add_argument(
        "--event-duration-secs",
        type=float,
        default=10.0,
        help="capture duration for each event-volume mode after monitor readiness",
    )
    event_group.add_argument(
        "--event-requests",
        type=int,
        default=20,
        help="requests sent to --endpoint during each event-volume capture",
    )
    event_group.add_argument(
        "--top-exec-paths",
        type=int,
        default=10,
        help="number of top executable paths to include in event-volume output",
    )

    return parser.parse_args()


class PerformanceExperimentRunner(RuntimeHarness):
    def __init__(self, settings: Settings, config: PerformanceConfig, *, build: bool) -> None:
        super().__init__(settings)
        self.config = config
        self.should_build = build

    def run(self) -> int:
        try:
            self.check_privileges()

            if self.should_build:
                self.build()

            self.config.output_dir.mkdir(parents=True, exist_ok=True)
            self.workload.start()

            result = self.run_selected_experiments()
            json_path, csv_paths = self.write_results(result)

            log(f"Wrote JSON results: {json_path}")
            for csv_path in csv_paths:
                log(f"Wrote CSV results: {csv_path}")

            latency = result.get("latency")
            if latency is not None:
                median_overhead = float(latency["aggregate"]["overhead_pct"]["median_ms"])
                log(f"PERF latency: aggregate median overhead={median_overhead:.2f}%")

                if (
                    self.config.max_overhead_pct is not None
                    and median_overhead > self.config.max_overhead_pct
                ):
                    fail(
                        f"median overhead too high: "
                        f"{median_overhead:.2f}% > {self.config.max_overhead_pct:.2f}%"
                    )

            event_volume = result.get("event_volume")
            if event_volume is not None:
                reduction = event_volume["reduction"]
                log(
                    "PERF event-volume: "
                    f"host-wide={reduction['host_wide_event_count']} "
                    f"scoped={reduction['scoped_event_count']} "
                    f"reduction={reduction['percent_reduction']:.2f}%"
                )

            log("Performance experiments completed")
            return 0
        except KeyboardInterrupt:
            print("Interrupted", file=sys.stderr)
            return 130
        except IntegrationFailure as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            self.monitor.print_log_tail()
            return 1
        finally:
            self.cleanup()

    def run_selected_experiments(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "experiment": self.config.name,
            "requested_experiment": self.config.experiment,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "endpoint": self.config.endpoint,
            "environment": environment_metadata(self.settings),
        }

        if self.config.experiment in ("latency", "both"):
            result["latency"] = self.run_latency_experiment()

        if self.config.experiment in ("event-volume", "both"):
            result["event_volume"] = self.run_event_volume_experiment()

        return result

    def run_latency_experiment(self) -> dict[str, Any]:
        trial_results: list[dict[str, Any]] = []

        for trial in range(1, self.config.trials + 1):
            log(f"== latency trial {trial}/{self.config.trials}: baseline ==")
            baseline = self.measure_http_latency(
                endpoint=self.config.endpoint,
                requests=self.config.requests,
                warmup_requests=self.config.warmup_requests,
            )

            log(f"== latency trial {trial}/{self.config.trials}: monitored ==")
            monitored_paths = self.case_paths(
                f"{self.config.name}_latency_trial_{trial}",
                log_dir=self.config.output_dir,
            )
            self.clean_case(monitored_paths)
            self.write_case_collector_config(
                monitored_paths,
                overrides={"collection_mode": self.config.collection_mode},
            )

            started_at = self.monitor.start(monitored_paths)
            try:
                monitored = self.measure_http_latency(
                    endpoint=self.config.endpoint,
                    requests=self.config.requests,
                    warmup_requests=self.config.warmup_requests,
                )
            finally:
                self.monitor.stop()

            if self.config.verify_evidence:
                self.assert_fresh_evidence(monitored_paths, started_at)
                for expected in self.config.expected_evidence:
                    self.assert_evidence_contains(monitored_paths, expected)

            overhead = overhead_percentages(baseline, monitored)
            summary = read_json_file(monitored_paths.summary)

            log(
                f"trial={trial} median baseline={baseline['median_ms']:.3f}ms "
                f"monitored={monitored['median_ms']:.3f}ms "
                f"overhead={overhead['median_ms']:.2f}%"
            )

            trial_results.append(
                {
                    "trial": trial,
                    "baseline": baseline,
                    "monitored": monitored,
                    "overhead_pct": overhead,
                    "evidence": {
                        "events": str(monitored_paths.evidence),
                        "summary": str(monitored_paths.summary),
                        "monitor_log": str(monitored_paths.monitor_log),
                    },
                    "monitor_summary": summary,
                }
            )

        return {
            "endpoint": self.config.endpoint,
            "requests": self.config.requests,
            "warmup_requests": self.config.warmup_requests,
            "trials": self.config.trials,
            "collection_mode": self.config.collection_mode,
            "expected_evidence": list(self.config.expected_evidence),
            "trial_results": trial_results,
            "aggregate": aggregate_latency_trial_results(trial_results),
        }

    def run_event_volume_experiment(self) -> dict[str, Any]:
        if self.config.event_requests < 0:
            fail("--event-requests must be >= 0")
        if self.config.event_duration_secs < 0:
            fail("--event-duration-secs must be >= 0")

        captures: dict[str, dict[str, Any]] = {}

        for mode in ("host-wide", "scoped"):
            label = mode.replace("-", "_")
            log(f"== event-volume capture: {mode} ==")

            paths = self.case_paths(
                f"{self.config.name}_event_volume_{label}",
                log_dir=self.config.output_dir,
            )
            self.clean_case(paths)
            self.write_case_collector_config(paths, overrides={"collection_mode": mode})

            started_at = self.monitor.start(paths)
            capture_deadline = time.monotonic() + self.config.event_duration_secs
            try:
                for _ in range(self.config.event_requests):
                    self.workload.get(self.config.endpoint)

                remaining = capture_deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(remaining)
            finally:
                self.monitor.stop()

            self.assert_fresh_evidence(paths, started_at)
            captures[mode] = summarise_evidence(paths, top_n=self.config.top_exec_paths)

            log(
                f"event-volume mode={mode} "
                f"events={captures[mode]['event_count']} "
                f"evidence={paths.evidence}"
            )

        reduction = event_volume_reduction(
            int(captures["host-wide"]["event_count"]),
            int(captures["scoped"]["event_count"]),
        )

        return {
            "endpoint": self.config.endpoint,
            "event_requests": self.config.event_requests,
            "event_duration_secs": self.config.event_duration_secs,
            "top_exec_paths": self.config.top_exec_paths,
            "captures": captures,
            "reduction": reduction,
        }

    def measure_http_latency(
        self,
        *,
        endpoint: str,
        requests: int,
        warmup_requests: int,
    ) -> dict[str, float | int]:
        if requests <= 0:
            fail("--requests must be > 0")

        if warmup_requests < 0:
            fail("--warmup must be >= 0")

        for _ in range(warmup_requests):
            self.workload.get(endpoint)

        latencies_ms: list[float] = []

        for _ in range(requests):
            start_ns = time.perf_counter_ns()
            self.workload.get(endpoint)
            elapsed_ns = time.perf_counter_ns() - start_ns
            latencies_ms.append(elapsed_ns / 1_000_000)

        return summarise_latencies(latencies_ms)

    def write_results(self, result: dict[str, Any]) -> tuple[Path, list[Path]]:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_name = safe_filename(self.config.name)

        json_path = self.config.output_dir / f"{safe_name}_{stamp}.json"
        json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        csv_paths: list[Path] = []
        if "latency" in result:
            latency_csv = self.config.output_dir / f"{safe_name}_{stamp}_latency.csv"
            write_latency_csv(latency_csv, result)
            csv_paths.append(latency_csv)

        if "event_volume" in result:
            event_volume_csv = self.config.output_dir / f"{safe_name}_{stamp}_event_volume.csv"
            write_event_volume_csv(event_volume_csv, result)
            csv_paths.append(event_volume_csv)

        return json_path, csv_paths


def summarise_latencies(latencies_ms: list[float]) -> dict[str, float | int]:
    if not latencies_ms:
        fail("cannot summarise empty latency list")

    ordered = sorted(latencies_ms)
    count = len(ordered)
    total = sum(ordered)

    return {
        "requests": count,
        "mean_ms": statistics.fmean(ordered),
        "median_ms": statistics.median(ordered),
        "p95_ms": percentile_nearest_rank(ordered, 95),
        "min_ms": ordered[0],
        "max_ms": ordered[-1],
        "throughput_rps": 1000.0 / (total / count),
    }


def percentile_nearest_rank(ordered_values: list[float], percentile: float) -> float:
    if not ordered_values:
        fail("cannot compute percentile of empty list")

    if len(ordered_values) == 1:
        return ordered_values[0]

    index = int(round((percentile / 100.0) * (len(ordered_values) - 1)))
    index = max(0, min(index, len(ordered_values) - 1))
    return ordered_values[index]


def overhead_percentages(
    baseline: dict[str, float | int],
    monitored: dict[str, float | int],
) -> dict[str, float]:
    metrics = ["mean_ms", "median_ms", "p95_ms", "min_ms", "max_ms"]
    return {metric: overhead_pct(float(baseline[metric]), float(monitored[metric])) for metric in metrics}


def overhead_pct(baseline: float, monitored: float) -> float:
    if baseline == 0:
        return float("inf")
    return ((monitored / baseline) - 1.0) * 100.0


def aggregate_latency_trial_results(trials: list[dict[str, Any]]) -> dict[str, Any]:
    if not trials:
        fail("cannot aggregate zero latency trials")

    metrics = ["mean_ms", "median_ms", "p95_ms", "min_ms", "max_ms", "throughput_rps"]

    def mean_for(phase: str, metric: str) -> float:
        return statistics.fmean(float(trial[phase][metric]) for trial in trials)

    baseline = {metric: mean_for("baseline", metric) for metric in metrics}
    monitored = {metric: mean_for("monitored", metric) for metric in metrics}
    overhead = overhead_percentages(baseline, monitored)

    return {
        "baseline": baseline,
        "monitored": monitored,
        "overhead_pct": overhead,
    }


def summarise_evidence(paths: Any, *, top_n: int) -> dict[str, Any]:
    event_count = 0
    event_type_counts: collections.Counter[str] = collections.Counter()
    workload_counts: collections.Counter[str] = collections.Counter()
    exe_path_counts: collections.Counter[str] = collections.Counter()

    with paths.evidence.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                fail(f"invalid JSON in {paths.evidence} at line {line_number}: {exc}")

            event_count += 1
            event_type_counts[str(event.get("event_type", "<missing>"))] += 1
            workload_counts[str(event.get("workload_id", "<missing>"))] += 1
            exe_path_counts[str(event.get("exe_path") or "<missing>")] += 1

    return {
        "event_count": event_count,
        "event_type_counts": dict(event_type_counts.most_common()),
        "workload_counts": dict(workload_counts.most_common()),
        "top_exec_paths": [
            {"exe_path": exe_path, "count": count}
            for exe_path, count in exe_path_counts.most_common(top_n)
        ],
        "evidence": str(paths.evidence),
        "summary": str(paths.summary),
        "monitor_log": str(paths.monitor_log),
        "monitor_summary": read_json_file(paths.summary),
    }


def event_volume_reduction(host_wide_count: int, scoped_count: int) -> dict[str, float | int]:
    absolute_reduction = host_wide_count - scoped_count
    percent_reduction = 0.0 if host_wide_count == 0 else (absolute_reduction / host_wide_count) * 100.0

    return {
        "host_wide_event_count": host_wide_count,
        "scoped_event_count": scoped_count,
        "absolute_reduction": absolute_reduction,
        "percent_reduction": percent_reduction,
    }


def environment_metadata(settings: Settings) -> dict[str, Any]:
    return {
        "base_url": settings.base_url,
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "root": str(settings.root),
        "monitor_bin": str(settings.monitor_bin),
        "verifier_bin": str(settings.verifier_bin),
    }


def read_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")


def write_latency_csv(path: Path, result: dict[str, Any]) -> None:
    fieldnames = [
        "trial",
        "endpoint",
        "collection_mode",
        "baseline_mean_ms",
        "baseline_median_ms",
        "baseline_p95_ms",
        "baseline_throughput_rps",
        "monitored_mean_ms",
        "monitored_median_ms",
        "monitored_p95_ms",
        "monitored_throughput_rps",
        "overhead_mean_pct",
        "overhead_median_pct",
        "overhead_p95_pct",
    ]

    latency = result["latency"]

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        for trial in latency["trial_results"]:
            writer.writerow(
                {
                    "trial": trial["trial"],
                    "endpoint": latency["endpoint"],
                    "collection_mode": latency["collection_mode"],
                    "baseline_mean_ms": trial["baseline"]["mean_ms"],
                    "baseline_median_ms": trial["baseline"]["median_ms"],
                    "baseline_p95_ms": trial["baseline"]["p95_ms"],
                    "baseline_throughput_rps": trial["baseline"]["throughput_rps"],
                    "monitored_mean_ms": trial["monitored"]["mean_ms"],
                    "monitored_median_ms": trial["monitored"]["median_ms"],
                    "monitored_p95_ms": trial["monitored"]["p95_ms"],
                    "monitored_throughput_rps": trial["monitored"]["throughput_rps"],
                    "overhead_mean_pct": trial["overhead_pct"]["mean_ms"],
                    "overhead_median_pct": trial["overhead_pct"]["median_ms"],
                    "overhead_p95_pct": trial["overhead_pct"]["p95_ms"],
                }
            )


def write_event_volume_csv(path: Path, result: dict[str, Any]) -> None:
    fieldnames = [
        "mode",
        "endpoint",
        "event_requests",
        "event_duration_secs",
        "event_count",
        "top_exec_paths_json",
        "evidence",
        "summary",
        "monitor_log",
    ]

    event_volume = result["event_volume"]

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        for mode, capture in event_volume["captures"].items():
            writer.writerow(
                {
                    "mode": mode,
                    "endpoint": event_volume["endpoint"],
                    "event_requests": event_volume["event_requests"],
                    "event_duration_secs": event_volume["event_duration_secs"],
                    "event_count": capture["event_count"],
                    "top_exec_paths_json": json.dumps(capture["top_exec_paths"], sort_keys=True),
                    "evidence": capture["evidence"],
                    "summary": capture["summary"],
                    "monitor_log": capture["monitor_log"],
                }
            )


def safe_filename(name: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in name)
    return safe or "runtime_perf"


def config_from_args(args: argparse.Namespace, settings: Settings) -> PerformanceConfig:
    endpoint = args.endpoint if args.endpoint.startswith("/") else f"/{args.endpoint}"

    expected = tuple(args.expected_evidence or ("/usr/bin/echo",))
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = settings.root / output_dir

    return PerformanceConfig(
        name=args.name,
        experiment=args.experiment,
        endpoint=endpoint,
        requests=args.requests,
        warmup_requests=args.warmup,
        trials=args.trials,
        collection_mode=args.collection_mode,
        expected_evidence=expected,
        output_dir=output_dir,
        max_overhead_pct=args.max_overhead_pct,
        verify_evidence=not args.skip_evidence_check,
        event_duration_secs=args.event_duration_secs,
        event_requests=args.event_requests,
        top_exec_paths=args.top_exec_paths,
    )


def main() -> int:
    args = parse_args()
    settings = Settings.from_env()
    config = config_from_args(args, settings)
    runner = PerformanceExperimentRunner(settings, config, build=not args.no_build)
    return runner.run()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
