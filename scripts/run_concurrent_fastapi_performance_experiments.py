#!/usr/bin/env python3
"""Concurrent multi-container FastAPI performance experiments.

This script measures runtime-custodian under concurrent traffic across multiple
FastAPI containers. It is intended to complement run_performance_experiments.py:
that script is good for single-container latency and event-volume experiments,
whereas this one stresses the multi-workload collector path and measures true
concurrent request throughput.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import csv
import json
import os
import shlex
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from integration_lib import (
    CasePaths,
    CommandRunner,
    IntegrationFailure,
    MonitorController,
    Settings,
    assert_fresh_evidence,
    assert_release_binaries,
    bootstrap_ci,
    case_paths,
    check_privileges,
    clean_case,
    environment_metadata,
    fail,
    log,
    overhead_pct_inf,
    percentile_nearest_rank,
    resolve_path,
    run_verifier_timed,
    safe_filename,
    summarise_evidence,
    summary_stats,
    write_multi_workload_collector_config,
    write_runtime_policy,
)


@dataclass(frozen=True)
class FastApiTarget:
    index: int
    workload_id: str
    container_name: str
    port: int
    base_url: str


@dataclass(frozen=True)
class ConcurrentFastApiConfig:
    name: str
    endpoint: str
    containers: int
    port_start: int
    listen_address: str
    container_prefix: str
    workload_prefix: str
    image: str
    build_workload_image: bool
    teardown_workloads: bool
    requests_per_container: int
    warmup_per_container: int
    concurrency: int
    trials: int
    modes: tuple[str, ...]
    output_dir: Path
    verifier_policy: Path
    capture_argv: bool
    verify_scoped: bool
    verify_host_wide: bool
    expected_evidence: tuple[str, ...]
    skip_evidence_check: bool
    http_timeout_secs: float
    max_error_rate: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run concurrent multi-container FastAPI performance experiments.",
    )
    parser.add_argument("--name", default="fastapi_concurrent_perf", help="experiment name prefix")
    parser.add_argument("--endpoint", default="/echo", help="HTTP endpoint to benchmark")
    parser.add_argument(
        "--containers",
        type=int,
        default=4,
        help="number of FastAPI containers; set this higher for stress tests, e.g. 50",
    )
    parser.add_argument("--port-start", type=int, default=8100, help="first host port to bind")
    parser.add_argument(
        "--listen-address",
        default="127.0.0.1",
        help="host interface used for container port bindings",
    )
    parser.add_argument(
        "--container-prefix",
        default="fastapi-concurrent",
        help="container-name prefix; containers are suffixed with -1, -2, ...",
    )
    parser.add_argument(
        "--workload-prefix",
        default="fastapi-concurrent",
        help="workload_id prefix; workload IDs are suffixed with -1, -2, ...",
    )
    parser.add_argument(
        "--image",
        default="runtime-custodian-fastapi-concurrent:latest",
        help="Docker image tag used for the FastAPI workload containers",
    )
    parser.add_argument(
        "--skip-workload-build",
        action="store_true",
        help="reuse --image instead of rebuilding workloads/fast-api-workload",
    )
    parser.add_argument(
        "--keep-workloads",
        action="store_true",
        help="leave the generated containers running after the experiment",
    )
    parser.add_argument(
        "--requests-per-container",
        type=int,
        default=100,
        help="measured requests per container per trial",
    )
    parser.add_argument(
        "--warmup-per-container",
        type=int,
        default=10,
        help="warmup requests per container before each measured trial",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=0,
        help="max concurrent HTTP workers; default is the number of containers",
    )
    parser.add_argument("--trials", type=int, default=5, help="number of trials per mode")
    parser.add_argument(
        "--mode",
        action="append",
        choices=("baseline", "scoped", "host-wide"),
        help="mode to run; repeatable. Default: baseline, scoped, host-wide",
    )
    parser.add_argument(
        "--output-dir",
        default="logs/experiments",
        help="directory for JSON/CSV experiment outputs",
    )
    parser.add_argument(
        "--verifier-policy",
        default="policies/fastapi-verifier-policy.json",
        help="runtime verifier policy used for monitored evidence",
    )
    parser.add_argument(
        "--capture-argv",
        action="store_true",
        help="enable argv capture in the collector config",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="skip verifier replay for scoped evidence",
    )
    parser.add_argument(
        "--verify-host-wide",
        action="store_true",
        help="also replay host-wide evidence with the verifier",
    )
    parser.add_argument(
        "--expected-evidence",
        action="append",
        default=None,
        help="substring that must appear in monitored evidence; may be repeated",
    )
    parser.add_argument(
        "--skip-evidence-check",
        action="store_true",
        help="do not assert that monitored evidence contains --expected-evidence substrings",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="skip scripts/build_all.sh",
    )
    parser.add_argument(
        "--http-timeout-secs",
        type=float,
        default=None,
        help="HTTP request timeout; defaults to HTTP_TIMEOUT_SECS from the shared settings",
    )
    parser.add_argument(
        "--allow-debug",
        action="store_true",
        help="permit measuring debug binaries (sets ALLOW_DEBUG_BINARIES=1); development only",
    )
    parser.add_argument(
        "--max-error-rate",
        type=float,
        default=0.5,
        help="abort the experiment if a measured condition exceeds this HTTP error rate",
    )
    return parser.parse_args()


class ConcurrentFastApiExperimentRunner:
    def __init__(
        self,
        settings: Settings,
        config: ConcurrentFastApiConfig,
        *,
        build_monitor: bool,
    ) -> None:
        self.settings = settings
        self.config = config
        self.should_build_monitor = build_monitor
        self.runner = CommandRunner(settings.root)
        self.monitor = MonitorController(settings, self.runner)
        self.targets = build_targets(config)
        self.workloads_started = False

    def run(self) -> int:
        try:
            self.check_privileges()
            self.validate_inputs()

            if self.should_build_monitor:
                self.runner.run([self.settings.root / "scripts/build_all.sh"])

            # Refuse to benchmark debug builds (override via --allow-debug).
            assert_release_binaries(self.settings)

            self.config.output_dir.mkdir(parents=True, exist_ok=True)
            self.start_workloads()

            result = self.run_experiments()
            json_path, csv_path = self.write_results(result)
            log(f"Wrote JSON results: {json_path}")
            log(f"Wrote CSV results: {csv_path}")

            for mode, aggregate in result["aggregate"].items():
                overhead = aggregate.get("overhead_vs_baseline_median_latency_pct")
                overhead_text = "baseline" if overhead is None else f"{overhead:.2f}% vs baseline"
                log(
                    f"FASTAPI-CONCURRENT {mode}: "
                    f"median={aggregate['median_request_latency_ms']:.2f}ms "
                    f"throughput={aggregate['median_throughput_rps']:.2f}rps "
                    f"events={aggregate.get('median_event_count', 'n/a')} "
                    f"dropped={aggregate.get('total_dropped_events', 0)} "
                    f"overhead={overhead_text}"
                )

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

    def check_privileges(self) -> None:
        check_privileges(self.settings, self.runner)

    def validate_inputs(self) -> None:
        if self.config.containers <= 0:
            fail("--containers must be > 0")
        if self.config.port_start <= 0:
            fail("--port-start must be > 0")
        if self.config.port_start + self.config.containers - 1 > 65535:
            fail("--port-start plus --containers exceeds the valid TCP port range")
        if self.config.requests_per_container <= 0:
            fail("--requests-per-container must be > 0")
        if self.config.warmup_per_container < 0:
            fail("--warmup-per-container must be >= 0")
        if self.config.concurrency <= 0:
            fail("--concurrency must be > 0 after defaulting")
        if self.config.trials <= 0:
            fail("--trials must be > 0")
        if self.config.http_timeout_secs <= 0:
            fail("--http-timeout-secs must be > 0")
        if not self.config.verifier_policy.exists() and (
            self.config.verify_scoped or self.config.verify_host_wide
        ):
            fail(f"missing verifier policy: {self.config.verifier_policy}")
        if not self.settings.monitor_bin.exists() and any(
            mode in ("scoped", "host-wide") for mode in self.config.modes
        ):
            fail(f"missing monitor binary: {self.settings.monitor_bin}")

    def start_workloads(self) -> None:
        workload_dir = self.settings.root / "workloads/fast-api-workload"
        if self.config.build_workload_image:
            self.runner.run(["docker", "build", "-t", self.config.image, str(workload_dir)])

        for target in self.targets:
            self.runner.run(["docker", "rm", "-f", target.container_name], check=False)
            self.runner.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    target.container_name,
                    "--label",
                    f"fyp.workload={target.workload_id}",
                    "-p",
                    f"{self.config.listen_address}:{target.port}:8000",
                    "-e",
                    "PYTHONUNBUFFERED=1",
                    self.config.image,
                ]
            )

        self.workloads_started = True
        self.wait_for_workloads()

    def wait_for_workloads(self) -> None:
        deadline = time.monotonic() + self.settings.workload_timeout_secs
        pending = {target.container_name: target for target in self.targets}
        last_error: BaseException | None = None

        while pending and time.monotonic() < deadline:
            for container_name, target in list(pending.items()):
                try:
                    fetch_url(f"{target.base_url}/ping", timeout_secs=self.config.http_timeout_secs)
                    del pending[container_name]
                except IntegrationFailure as exc:
                    last_error = exc
            if pending:
                time.sleep(0.5)

        if pending:
            names = ", ".join(sorted(pending))
            fail(f"workloads did not become ready: {names}; last error: {last_error}")

    def cleanup(self) -> None:
        self.monitor.stop()
        if self.config.teardown_workloads and self.workloads_started:
            for target in self.targets:
                self.runner.run(["docker", "rm", "-f", target.container_name], check=False)

    def run_experiments(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "experiment": self.config.name,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "endpoint": self.config.endpoint,
            "containers": self.config.containers,
            "requests_per_container": self.config.requests_per_container,
            "warmup_per_container": self.config.warmup_per_container,
            "concurrency": self.config.concurrency,
            "trials": self.config.trials,
            "modes": list(self.config.modes),
            "capture_argv": self.config.capture_argv,
            "targets": [target_metadata(target) for target in self.targets],
            "environment": environment_metadata(self.settings),
            "trial_results": {},
            "aggregate": {},
        }

        for mode in self.config.modes:
            mode_trials: list[dict[str, Any]] = []
            for trial in range(1, self.config.trials + 1):
                log(f"== fastapi concurrent mode={mode} trial {trial}/{self.config.trials} ==")
                mode_trials.append(self.run_trial(mode, trial))
            result["trial_results"][mode] = mode_trials

        result["aggregate"] = aggregate_results(result["trial_results"])
        return result

    def run_trial(self, mode: str, trial: int) -> dict[str, Any]:
        if mode == "baseline":
            http_result = self.measure_http()
            return {
                "trial": trial,
                "mode": mode,
                "http": http_result,
            }

        paths = self.case_paths(f"{self.config.name}_{mode.replace('-', '_')}_trial_{trial}")
        self.clean_case(paths)
        policy_path = self.write_runtime_policy(paths)
        self.write_collector_config(paths, collection_mode=mode, runtime_policy=policy_path)

        started_at = self.monitor.start(paths)
        try:
            http_result = self.measure_http()
        finally:
            self.monitor.stop()

        self.assert_fresh_evidence(paths, started_at)
        if not self.config.skip_evidence_check:
            self.assert_evidence_contains(paths, self.config.expected_evidence)

        evidence_summary = summarise_evidence(paths)

        verifier_result: dict[str, Any] | None = None
        should_verify = (mode == "scoped" and self.config.verify_scoped) or (
            mode == "host-wide" and self.config.verify_host_wide
        )
        if should_verify:
            verifier_result = self.run_verifier(paths, policy_path)

        return {
            "trial": trial,
            "mode": mode,
            "http": http_result,
            "evidence": evidence_summary,
            "verifier": verifier_result,
        }

    def measure_http(self) -> dict[str, Any]:
        endpoint = self.config.endpoint
        urls_by_target = [
            (target.container_name, f"{target.base_url}{endpoint}") for target in self.targets
        ]

        warmup_urls = [
            url
            for _ in range(self.config.warmup_per_container)
            for _, url in urls_by_target
        ]
        if warmup_urls:
            self.run_http_batch(warmup_urls, collect_latencies=False)

        measured_urls: list[tuple[str, str]] = [
            (target_name, url)
            for _ in range(self.config.requests_per_container)
            for target_name, url in urls_by_target
        ]

        wall_start_ns = time.perf_counter_ns()
        results = self.run_http_batch(measured_urls, collect_latencies=True)
        total_wall_ms = (time.perf_counter_ns() - wall_start_ns) / 1_000_000

        latencies = [float(item["latency_ms"]) for item in results]
        per_target: dict[str, list[float]] = collections.defaultdict(list)
        for item in results:
            per_target[str(item["target"])].append(float(item["latency_ms"]))

        summary = summarise_latencies(latencies)
        summary.update(
            {
                "total_requests": len(results),
                "requests_per_container": self.config.requests_per_container,
                "container_count": len(self.targets),
                "concurrency": self.config.concurrency,
                "total_wall_ms": total_wall_ms,
                "throughput_rps": 0.0 if total_wall_ms == 0 else len(results) / (total_wall_ms / 1000.0),
                "per_target": {
                    target: summarise_latencies(values) for target, values in sorted(per_target.items())
                },
            }
        )
        return summary

    def run_http_batch(
        self,
        items: list[str] | list[tuple[str, str]],
        *,
        collect_latencies: bool,
    ) -> list[dict[str, Any]]:
        def normalise(item: str | tuple[str, str]) -> tuple[str, str]:
            if isinstance(item, tuple):
                return item
            return ("warmup", item)

        def worker(item: str | tuple[str, str]) -> dict[str, Any]:
            target, url = normalise(item)
            start_ns = time.perf_counter_ns()
            fetch_url(url, timeout_secs=self.config.http_timeout_secs)
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
            return {"target": target, "url": url, "latency_ms": elapsed_ms}

        results: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
            future_to_item = {executor.submit(worker, item): item for item in items}
            for future in concurrent.futures.as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001 - surface target URL in failure message.
                    _, url = normalise(item)
                    fail(f"HTTP request failed for {url}: {exc}")
                if collect_latencies:
                    results.append(result)
        return results

    def run_verifier(self, paths: CasePaths, policy_path: Path) -> dict[str, Any]:
        return run_verifier_timed(
            self.settings,
            paths,
            policy=policy_path,
            fail_message=f"concurrent FastAPI evidence did not verify for {paths.name}",
        )

    def case_paths(self, case_name: str) -> CasePaths:
        return case_paths(self.config.output_dir, case_name)

    def write_runtime_policy(self, paths: CasePaths) -> Path:
        return write_runtime_policy(
            self.config.verifier_policy,
            paths,
            [target.workload_id for target in self.targets],
        )

    def write_collector_config(
        self,
        paths: CasePaths,
        *,
        collection_mode: str,
        runtime_policy: Path,
    ) -> None:
        write_multi_workload_collector_config(
            paths,
            workloads=[
                {"workload_id": target.workload_id, "container_name": target.container_name}
                for target in self.targets
            ],
            collection_mode=collection_mode,
            runtime_policy=runtime_policy,
            capture_argv=self.config.capture_argv,
        )

    def clean_case(self, paths: CasePaths) -> None:
        clean_case(paths)

    def assert_fresh_evidence(self, paths: CasePaths, min_mtime: float) -> None:
        assert_fresh_evidence(paths, min_mtime)

    def assert_evidence_contains(self, paths: CasePaths, expected: tuple[str, ...]) -> None:
        content = paths.evidence.read_text(encoding="utf-8", errors="replace")
        for substring in expected:
            if substring not in content:
                fail(f"evidence does not contain {substring!r}: {paths.evidence}")

    def write_results(self, result: dict[str, Any]) -> tuple[Path, Path]:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_name = safe_filename(self.config.name, "fastapi_concurrent_perf")
        json_path = self.config.output_dir / f"{safe_name}_{stamp}.json"
        csv_path = self.config.output_dir / f"{safe_name}_{stamp}.csv"
        json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_csv(csv_path, result)
        return json_path, csv_path


def fetch_url(url: str, *, timeout_secs: float) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=timeout_secs) as response:
            return response.read()
    except urllib.error.URLError as exc:
        raise IntegrationFailure(str(exc)) from exc


def build_targets(config: ConcurrentFastApiConfig) -> list[FastApiTarget]:
    return [
        FastApiTarget(
            index=index,
            workload_id=f"{config.workload_prefix}-{index}",
            container_name=f"{config.container_prefix}-{index}",
            port=config.port_start + index - 1,
            base_url=f"http://{config.listen_address}:{config.port_start + index - 1}",
        )
        for index in range(1, config.containers + 1)
    ]


def target_metadata(target: FastApiTarget) -> dict[str, Any]:
    return {
        "index": target.index,
        "workload_id": target.workload_id,
        "container_name": target.container_name,
        "port": target.port,
        "base_url": target.base_url,
    }


def summarise_latencies(latencies_ms: list[float]) -> dict[str, float | int]:
    if not latencies_ms:
        fail("cannot summarise empty latency list")

    ordered = sorted(latencies_ms)
    return {
        "requests": len(ordered),
        "mean_ms": statistics.fmean(ordered),
        "median_ms": statistics.median(ordered),
        "p95_ms": percentile_nearest_rank(ordered, 95),
        "p99_ms": percentile_nearest_rank(ordered, 99),
        "min_ms": ordered[0],
        "max_ms": ordered[-1],
    }


def aggregate_results(trial_results: Mapping[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    aggregates: dict[str, dict[str, Any]] = {}
    baseline_latency: float | None = None
    baseline_total_wall: float | None = None
    baseline_throughput: float | None = None

    for mode, trials in trial_results.items():
        median_latencies = [float(trial["http"]["median_ms"]) for trial in trials]
        p95_latencies = [float(trial["http"]["p95_ms"]) for trial in trials]
        p99_latencies = [float(trial["http"]["p99_ms"]) for trial in trials]
        total_wall_times = [float(trial["http"]["total_wall_ms"]) for trial in trials]
        throughputs = [float(trial["http"]["throughput_rps"]) for trial in trials]
        event_counts = [int(trial.get("evidence", {}).get("event_count", 0)) for trial in trials]
        evidence_sizes = [int(trial.get("evidence", {}).get("evidence_size_bytes", 0)) for trial in trials]
        dropped = [int(trial.get("evidence", {}).get("dropped_events", 0)) for trial in trials]
        verifier_times = [
            float(trial["verifier"]["wall_ms"])
            for trial in trials
            if isinstance(trial.get("verifier"), dict)
        ]

        latency = summary_stats(median_latencies)
        throughput = summary_stats(throughputs)
        aggregate: dict[str, Any] = {
            "mean_request_latency_ms": latency["mean"],
            "median_request_latency_ms": latency["median"],
            "stdev_request_latency_ms": latency["stdev"],
            "cov_request_latency": latency["cov"],
            "median_p95_latency_ms": statistics.median(p95_latencies),
            "median_p99_latency_ms": statistics.median(p99_latencies),
            "median_total_wall_ms": statistics.median(total_wall_times),
            "median_throughput_rps": throughput["median"],
            "min_throughput_rps": throughput["min"],
            "max_throughput_rps": throughput["max"],
            "stdev_throughput_rps": throughput["stdev"],
            "cov_throughput": throughput["cov"],
            "median_throughput_rps_ci": bootstrap_ci(throughputs, statistic=statistics.median),
            "median_event_count": statistics.median(event_counts) if event_counts else 0,
            "median_evidence_size_bytes": statistics.median(evidence_sizes) if evidence_sizes else 0,
            # Ring-buffer drops aggregated across trials, to be read against
            # throughput as the concurrency reliability story.
            "total_dropped_events": sum(dropped),
            "max_dropped_events": max(dropped) if dropped else 0,
        }
        if verifier_times:
            aggregate["median_verifier_wall_ms"] = statistics.median(verifier_times)

        if mode == "baseline":
            baseline_latency = float(aggregate["median_request_latency_ms"])
            baseline_total_wall = float(aggregate["median_total_wall_ms"])
            baseline_throughput = float(aggregate["median_throughput_rps"])
            aggregate["overhead_vs_baseline_median_latency_pct"] = None
            aggregate["overhead_vs_baseline_total_wall_pct"] = None
            aggregate["throughput_change_vs_baseline_pct"] = None
        else:
            aggregate["overhead_vs_baseline_median_latency_pct"] = (
                None
                if baseline_latency is None
                else overhead_pct_inf(baseline_latency, float(aggregate["median_request_latency_ms"]))
            )
            aggregate["overhead_vs_baseline_total_wall_pct"] = (
                None
                if baseline_total_wall is None
                else overhead_pct_inf(baseline_total_wall, float(aggregate["median_total_wall_ms"]))
            )
            aggregate["throughput_change_vs_baseline_pct"] = (
                None
                if baseline_throughput is None
                else overhead_pct_inf(baseline_throughput, float(aggregate["median_throughput_rps"]))
            )

        aggregates[mode] = aggregate

    return aggregates


def write_csv(path: Path, result: dict[str, Any]) -> None:
    fieldnames = [
        "mode",
        "trial",
        "containers",
        "concurrency",
        "requests_per_container",
        "total_requests",
        "median_ms",
        "p95_ms",
        "p99_ms",
        "total_wall_ms",
        "throughput_rps",
        "event_count",
        "synthetic_record_count",
        "total_record_count",
        "evidence_size_bytes",
        "dropped_events",
        "verifier_wall_ms",
        "verifier_decision",
        "evidence",
        "summary",
        "monitor_log",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for mode, trials in result["trial_results"].items():
            for trial in trials:
                http = trial["http"]
                evidence = trial.get("evidence") or {}
                verifier = trial.get("verifier") or {}
                writer.writerow(
                    {
                        "mode": mode,
                        "trial": trial["trial"],
                        "containers": result["containers"],
                        "concurrency": result["concurrency"],
                        "requests_per_container": result["requests_per_container"],
                        "total_requests": http["total_requests"],
                        "median_ms": http["median_ms"],
                        "p95_ms": http["p95_ms"],
                        "p99_ms": http["p99_ms"],
                        "total_wall_ms": http["total_wall_ms"],
                        "throughput_rps": http["throughput_rps"],
                        "event_count": evidence.get("event_count"),
                        "synthetic_record_count": evidence.get("synthetic_record_count"),
                        "total_record_count": evidence.get("total_record_count"),
                        "evidence_size_bytes": evidence.get("evidence_size_bytes"),
                        "dropped_events": evidence.get("dropped_events"),
                        "verifier_wall_ms": verifier.get("wall_ms"),
                        "verifier_decision": verifier.get("decision"),
                        "evidence": evidence.get("events"),
                        "summary": evidence.get("summary"),
                        "monitor_log": evidence.get("monitor_log"),
                    }
                )


def config_from_args(args: argparse.Namespace, settings: Settings) -> ConcurrentFastApiConfig:
    endpoint = args.endpoint if args.endpoint.startswith("/") else f"/{args.endpoint}"
    output_dir = resolve_path(settings.root, args.output_dir)
    concurrency = args.concurrency if args.concurrency > 0 else args.containers
    expected = tuple(args.expected_evidence or ("/usr/bin/echo",))

    return ConcurrentFastApiConfig(
        name=args.name,
        endpoint=endpoint,
        containers=args.containers,
        port_start=args.port_start,
        listen_address=args.listen_address,
        container_prefix=args.container_prefix,
        workload_prefix=args.workload_prefix,
        image=args.image,
        build_workload_image=not args.skip_workload_build,
        teardown_workloads=not args.keep_workloads,
        requests_per_container=args.requests_per_container,
        warmup_per_container=args.warmup_per_container,
        concurrency=concurrency,
        trials=args.trials,
        modes=tuple(args.mode or ("baseline", "scoped", "host-wide")),
        output_dir=output_dir,
        verifier_policy=resolve_path(settings.root, args.verifier_policy),
        capture_argv=args.capture_argv,
        verify_scoped=not args.skip_verify,
        verify_host_wide=args.verify_host_wide,
        expected_evidence=expected,
        skip_evidence_check=args.skip_evidence_check,
        http_timeout_secs=(
            settings.http_timeout_secs if args.http_timeout_secs is None else args.http_timeout_secs
        ),
        max_error_rate=args.max_error_rate,
    )


def main() -> int:
    args = parse_args()
    if args.allow_debug:
        os.environ["ALLOW_DEBUG_BINARIES"] = "1"
    settings = Settings.from_env()
    config = config_from_args(args, settings)
    runner = ConcurrentFastApiExperimentRunner(settings, config, build_monitor=not args.no_build)
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
