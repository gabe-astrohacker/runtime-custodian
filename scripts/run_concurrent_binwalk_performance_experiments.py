#!/usr/bin/env python3
"""Concurrent multi-container Binwalk performance experiments.

This stresses runtime-custodian with several process-heavy containers running at
roughly the same time. It complements the single-container Binwalk benchmark by
exercising the collector's multi-workload cgroup map, ring-buffer throughput,
evidence volume, and verifier replay under parallel workload activity.
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
    resolve_path,
    run_verifier_timed,
    safe_filename,
    summarise_evidence,
    summary_stats,
    write_multi_workload_collector_config,
    write_runtime_policy,
)


@dataclass(frozen=True)
class BinwalkTarget:
    index: int
    workload_id: str
    container_name: str
    input_path: Path
    sample_name: str


@dataclass(frozen=True)
class ConcurrentBinwalkConfig:
    name: str
    input_paths: tuple[Path, ...]
    binwalk_args: list[str]
    containers: int
    container_prefix: str
    workload_prefix: str
    image: str
    build_workload_image: bool
    teardown_workloads: bool
    runs_per_container: int
    concurrency: int
    trials: int
    modes: tuple[str, ...]
    output_dir: Path
    verifier_policy: Path
    runtime_policy: Path | None
    tpm_tcti: str | None
    ring_buffer_bytes: int | None
    capture_argv: bool
    verify_scoped: bool
    verify_host_wide: bool
    allow_binwalk_failure: bool
    command_timeout_secs: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run concurrent multi-container Binwalk performance experiments.",
    )
    parser.add_argument("--name", default="binwalk_concurrent_perf", help="experiment name prefix")
    parser.add_argument(
        "--input",
        action="append",
        default=None,
        help=(
            "sample file to mount/run under /samples; relative paths are resolved from the repo root. "
            "May be repeated; samples are assigned round-robin to containers. Default: zip.bin"
        ),
    )
    parser.add_argument(
        "--binwalk-args",
        default="-e --run-as=root",
        help="shell-style argument string passed to binwalk before the sample path",
    )
    parser.add_argument(
        "--containers",
        type=int,
        default=4,
        help="number of Binwalk containers; set this higher for stress tests, e.g. 50",
    )
    parser.add_argument(
        "--container-prefix",
        default="binwalk-concurrent",
        help="container-name prefix; containers are suffixed with -1, -2, ...",
    )
    parser.add_argument(
        "--workload-prefix",
        default="binwalk-concurrent",
        help="workload_id prefix; workload IDs are suffixed with -1, -2, ...",
    )
    parser.add_argument(
        "--image",
        default="runtime-custodian-binwalk-concurrent:latest",
        help="Docker image tag used for the Binwalk workload containers",
    )
    parser.add_argument(
        "--skip-workload-build",
        action="store_true",
        help="reuse --image instead of rebuilding workloads/binwalk-workload",
    )
    parser.add_argument(
        "--keep-workloads",
        action="store_true",
        help="leave the generated containers running after the experiment",
    )
    parser.add_argument(
        "--runs-per-container",
        type=int,
        default=1,
        help="Binwalk commands to execute per container per trial",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=0,
        help="max concurrent docker exec workers; default is the number of containers",
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
        default="policies/binwalk-verifier-policy.json",
        help="runtime verifier policy used for monitored evidence",
    )
    parser.add_argument(
        "--runtime-policy",
        default=None,
        help="override the monitor's runtime policy base (e.g. a TPM-backed policy); "
        "workload_id is rewritten per run. Default: same as --verifier-policy",
    )
    parser.add_argument(
        "--tpm-tcti",
        default=None,
        help="TPM2TOOLS_TCTI injected into the collector config so the monitor's "
        "forked tpm2-tools reach a TPM (e.g. swtpm:host=127.0.0.1,port=2321)",
    )
    parser.add_argument(
        "--ring-bytes",
        type=int,
        default=None,
        help="override the eBPF EVENTS ring-buffer byte size (default 256 KiB); a "
        "large value (e.g. 67108864) trades dropped events for finalisation lag",
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
        "--allow-binwalk-failure",
        action="store_true",
        help="record non-zero binwalk exits instead of failing the experiment",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="skip scripts/build_all.sh",
    )
    parser.add_argument(
        "--allow-debug",
        action="store_true",
        help="allow measuring debug binaries; sets ALLOW_DEBUG_BINARIES=1 (development only)",
    )
    parser.add_argument(
        "--command-timeout-secs",
        type=float,
        default=180.0,
        help="timeout for each docker exec binwalk command",
    )
    return parser.parse_args()


class ConcurrentBinwalkExperimentRunner:
    def __init__(
        self,
        settings: Settings,
        config: ConcurrentBinwalkConfig,
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
                overhead = aggregate.get("overhead_vs_baseline_total_wall_pct")
                overhead_text = "baseline" if overhead is None else f"{overhead:.2f}% vs baseline"
                log(
                    f"BINWALK-CONCURRENT {mode}: "
                    f"batch_wall={aggregate['median_total_wall_ms']:.2f}ms "
                    f"per_run={aggregate['median_per_run_wall_ms']:.2f}ms "
                    f"runs/s={aggregate['median_completed_runs_per_sec']:.3f} "
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
        if self.config.runs_per_container <= 0:
            fail("--runs-per-container must be > 0")
        if self.config.concurrency <= 0:
            fail("--concurrency must be > 0 after defaulting")
        if self.config.trials <= 0:
            fail("--trials must be > 0")
        if self.config.command_timeout_secs <= 0:
            fail("--command-timeout-secs must be > 0")
        for input_path in self.config.input_paths:
            if not input_path.exists():
                fail(f"missing input sample: {input_path}")
        if not self.config.verifier_policy.exists() and (
            self.config.verify_scoped or self.config.verify_host_wide
        ):
            fail(f"missing verifier policy: {self.config.verifier_policy}")
        if not self.settings.monitor_bin.exists() and any(
            mode in ("scoped", "host-wide") for mode in self.config.modes
        ):
            fail(f"missing monitor binary: {self.settings.monitor_bin}")

    def start_workloads(self) -> None:
        workload_dir = self.settings.root / "workloads/binwalk-workload"
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
                    "-v",
                    f"{target.input_path}:/samples/{target.sample_name}:ro",
                    self.config.image,
                    "sleep",
                    "infinity",
                ]
            )

        self.workloads_started = True
        self.wait_for_workloads()

    def wait_for_workloads(self) -> None:
        deadline = time.monotonic() + 30
        pending = {target.container_name: target for target in self.targets}
        while pending and time.monotonic() < deadline:
            for container_name in list(pending):
                result = self.runner.run(
                    ["docker", "exec", container_name, "true"],
                    check=False,
                    capture=True,
                )
                if result.returncode == 0:
                    del pending[container_name]
            if pending:
                time.sleep(0.5)

        if pending:
            fail(f"containers did not become ready: {', '.join(sorted(pending))}")

    def cleanup(self) -> None:
        self.monitor.stop()
        if self.config.teardown_workloads and self.workloads_started:
            for target in self.targets:
                self.runner.run(["docker", "rm", "-f", target.container_name], check=False)

    def run_experiments(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "experiment": self.config.name,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "binwalk_args": self.config.binwalk_args,
            "containers": self.config.containers,
            "runs_per_container": self.config.runs_per_container,
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
                log(f"== binwalk concurrent mode={mode} trial {trial}/{self.config.trials} ==")
                mode_trials.append(self.run_trial(mode, trial))
            result["trial_results"][mode] = mode_trials

        result["aggregate"] = aggregate_results(result["trial_results"])
        return result

    def run_trial(self, mode: str, trial: int) -> dict[str, Any]:
        if mode == "baseline":
            batch_result = self.measure_binwalk_batch(mode, trial)
            return {
                "trial": trial,
                "mode": mode,
                "binwalk": batch_result,
            }

        paths = self.case_paths(f"{self.config.name}_{mode.replace('-', '_')}_trial_{trial}")
        self.clean_case(paths)
        policy_path = self.write_runtime_policy(paths)
        self.write_collector_config(paths, collection_mode=mode, runtime_policy=policy_path)

        started_at = self.monitor.start(paths)
        try:
            batch_result = self.measure_binwalk_batch(mode, trial)
        finally:
            self.monitor.stop()

        self.assert_fresh_evidence(paths, started_at)
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
            "binwalk": batch_result,
            "evidence": evidence_summary,
            "verifier": verifier_result,
            "monitor_drain_secs": self.monitor.last_drain_secs,
        }

    def measure_binwalk_batch(self, mode: str, trial: int) -> dict[str, Any]:
        jobs = [
            (target, run_index)
            for run_index in range(1, self.config.runs_per_container + 1)
            for target in self.targets
        ]

        wall_start_ns = time.perf_counter_ns()
        results: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
            future_to_job = {
                executor.submit(self.run_binwalk_command, target, mode, trial, run_index): (
                    target,
                    run_index,
                )
                for target, run_index in jobs
            }
            for future in concurrent.futures.as_completed(future_to_job):
                target, run_index = future_to_job[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001 - surface target context in failure message.
                    fail(
                        f"binwalk failed for {target.container_name} run={run_index} "
                        f"mode={mode} trial={trial}: {exc}"
                    )

        total_wall_ms = (time.perf_counter_ns() - wall_start_ns) / 1_000_000
        per_run_wall_ms = [float(result["wall_ms"]) for result in results]
        return {
            "total_wall_ms": total_wall_ms,
            "total_runs": len(results),
            "successful_runs": sum(1 for result in results if int(result["returncode"]) == 0),
            "failed_runs": sum(1 for result in results if int(result["returncode"]) != 0),
            "runs_per_container": self.config.runs_per_container,
            "container_count": len(self.targets),
            "concurrency": self.config.concurrency,
            "completed_runs_per_sec": 0.0
            if total_wall_ms == 0
            else len(results) / (total_wall_ms / 1000.0),
            "per_run": sorted(results, key=lambda item: (str(item["container_name"]), int(item["run_index"]))),
            "per_run_wall_ms": summarise_values(per_run_wall_ms),
        }

    def run_binwalk_command(
        self,
        target: BinwalkTarget,
        mode: str,
        trial: int,
        run_index: int,
    ) -> dict[str, Any]:
        out_dir = f"/tmp/binwalk-output/{mode}-{trial}-{run_index}-{target.index}"
        sample = f"/samples/{target.sample_name}"
        args = " ".join(shlex.quote(arg) for arg in self.config.binwalk_args)
        command = (
            f"rm -rf {shlex.quote(out_dir)} && "
            f"mkdir -p {shlex.quote(out_dir)} && "
            f"cd {shlex.quote(out_dir)} && "
            f"binwalk {args} {shlex.quote(sample)}"
        )
        docker_cmd = ["docker", "exec", target.container_name, "sh", "-lc", command]
        rendered = " ".join(shlex.quote(arg) for arg in docker_cmd)
        log("$ " + rendered)

        start_ns = time.perf_counter_ns()
        try:
            completed = subprocess.run(
                docker_cmd,
                cwd=self.settings.root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=self.config.command_timeout_secs,
            )
        except subprocess.TimeoutExpired as exc:
            raise IntegrationFailure(
                f"command timed out after {self.config.command_timeout_secs}s: {exc}"
            ) from exc
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        if completed.returncode != 0 and not self.config.allow_binwalk_failure:
            if completed.stdout:
                print(completed.stdout[-4000:], file=sys.stderr, end="")
            raise IntegrationFailure(f"binwalk command failed with status {completed.returncode}")

        return {
            "container_name": target.container_name,
            "workload_id": target.workload_id,
            "sample_name": target.sample_name,
            "run_index": run_index,
            "returncode": completed.returncode,
            "wall_ms": elapsed_ms,
            "stdout_tail": (completed.stdout or "")[-4000:],
        }

    def run_verifier(self, paths: CasePaths, policy_path: Path) -> dict[str, Any]:
        return run_verifier_timed(
            self.settings,
            paths,
            policy=policy_path,
            fail_message=f"{paths.name} evidence did not verify",
        )

    def case_paths(self, case_name: str) -> CasePaths:
        return case_paths(self.config.output_dir, case_name)

    def write_runtime_policy(self, paths: CasePaths) -> Path:
        return write_runtime_policy(
            self.config.runtime_policy or self.config.verifier_policy,
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
            tpm_tcti=self.config.tpm_tcti,
            ring_buffer_bytes=self.config.ring_buffer_bytes,
        )

    def clean_case(self, paths: CasePaths) -> None:
        clean_case(paths)

    def assert_fresh_evidence(self, paths: CasePaths, min_mtime: float) -> None:
        assert_fresh_evidence(paths, min_mtime)

    def write_results(self, result: dict[str, Any]) -> tuple[Path, Path]:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_name = safe_filename(self.config.name, "binwalk_concurrent_perf")
        json_path = self.config.output_dir / f"{safe_name}_{stamp}.json"
        csv_path = self.config.output_dir / f"{safe_name}_{stamp}.csv"
        json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_csv(csv_path, result)
        return json_path, csv_path


def build_targets(config: ConcurrentBinwalkConfig) -> list[BinwalkTarget]:
    targets: list[BinwalkTarget] = []
    for index in range(1, config.containers + 1):
        input_path = config.input_paths[(index - 1) % len(config.input_paths)]
        targets.append(
            BinwalkTarget(
                index=index,
                workload_id=f"{config.workload_prefix}-{index}",
                container_name=f"{config.container_prefix}-{index}",
                input_path=input_path,
                sample_name=input_path.name,
            )
        )
    return targets


def target_metadata(target: BinwalkTarget) -> dict[str, Any]:
    return {
        "index": target.index,
        "workload_id": target.workload_id,
        "container_name": target.container_name,
        "input": str(target.input_path),
        "sample_name": target.sample_name,
    }


def aggregate_results(trial_results: Mapping[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    aggregates: dict[str, dict[str, Any]] = {}
    baseline_total_wall: float | None = None
    baseline_runs_per_sec: float | None = None

    for mode, trials in trial_results.items():
        total_wall_times = [float(trial["binwalk"]["total_wall_ms"]) for trial in trials]
        per_run_medians = [float(trial["binwalk"]["per_run_wall_ms"]["median_ms"]) for trial in trials]
        throughputs = [float(trial["binwalk"]["completed_runs_per_sec"]) for trial in trials]
        event_counts = [int(trial.get("evidence", {}).get("event_count", 0)) for trial in trials]
        evidence_sizes = [int(trial.get("evidence", {}).get("evidence_size_bytes", 0)) for trial in trials]
        dropped = [int(trial.get("evidence", {}).get("dropped_events", 0)) for trial in trials]
        verifier_times = [
            float(trial["verifier"]["wall_ms"])
            for trial in trials
            if isinstance(trial.get("verifier"), dict)
        ]

        wall = summary_stats(total_wall_times)
        throughput = summary_stats(throughputs)
        aggregate: dict[str, Any] = {
            "mean_total_wall_ms": wall["mean"],
            "median_total_wall_ms": wall["median"],
            "min_total_wall_ms": wall["min"],
            "max_total_wall_ms": wall["max"],
            "stdev_total_wall_ms": wall["stdev"],
            "cov_total_wall": wall["cov"],
            "median_per_run_wall_ms": statistics.median(per_run_medians),
            "median_completed_runs_per_sec": throughput["median"],
            "min_completed_runs_per_sec": throughput["min"],
            "max_completed_runs_per_sec": throughput["max"],
            "stdev_completed_runs_per_sec": throughput["stdev"],
            "cov_completed_runs_per_sec": throughput["cov"],
            "median_completed_runs_per_sec_ci": bootstrap_ci(throughputs, statistic=statistics.median),
            "median_event_count": statistics.median(event_counts) if event_counts else 0,
            "median_evidence_size_bytes": statistics.median(evidence_sizes) if evidence_sizes else 0,
            # Ring-buffer drops aggregated across trials.
            "total_dropped_events": sum(dropped),
            "max_dropped_events": max(dropped) if dropped else 0,
        }
        if verifier_times:
            aggregate["median_verifier_wall_ms"] = statistics.median(verifier_times)

        if mode == "baseline":
            baseline_total_wall = float(aggregate["median_total_wall_ms"])
            baseline_runs_per_sec = float(aggregate["median_completed_runs_per_sec"])
            aggregate["overhead_vs_baseline_total_wall_pct"] = None
            aggregate["completed_runs_per_sec_change_vs_baseline_pct"] = None
        else:
            aggregate["overhead_vs_baseline_total_wall_pct"] = (
                None
                if baseline_total_wall is None
                else overhead_pct_inf(baseline_total_wall, float(aggregate["median_total_wall_ms"]))
            )
            aggregate["completed_runs_per_sec_change_vs_baseline_pct"] = (
                None
                if baseline_runs_per_sec is None
                else overhead_pct_inf(baseline_runs_per_sec, float(aggregate["median_completed_runs_per_sec"]))
            )

        aggregates[mode] = aggregate

    return aggregates


def summarise_values(values: list[float]) -> dict[str, float]:
    if not values:
        return {"count": 0.0, "mean_ms": 0.0, "median_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}
    ordered = sorted(values)
    return {
        "count": float(len(values)),
        "mean_ms": statistics.fmean(values),
        "median_ms": statistics.median(values),
        "p95_ms": percentile(ordered, 0.95),
        "p99_ms": percentile(ordered, 0.99),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def percentile(sorted_values: list[float], fraction: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    index = (len(sorted_values) - 1) * fraction
    lower = int(index)
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = index - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def write_csv(path: Path, result: dict[str, Any]) -> None:
    fieldnames = [
        "mode",
        "trial",
        "containers",
        "concurrency",
        "runs_per_container",
        "total_runs",
        "successful_runs",
        "failed_runs",
        "total_wall_ms",
        "completed_runs_per_sec",
        "median_per_run_wall_ms",
        "p95_per_run_wall_ms",
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
                binwalk = trial["binwalk"]
                evidence = trial.get("evidence") or {}
                verifier = trial.get("verifier") or {}
                per_run = binwalk["per_run_wall_ms"]
                writer.writerow(
                    {
                        "mode": mode,
                        "trial": trial["trial"],
                        "containers": result["containers"],
                        "concurrency": result["concurrency"],
                        "runs_per_container": result["runs_per_container"],
                        "total_runs": binwalk["total_runs"],
                        "successful_runs": binwalk["successful_runs"],
                        "failed_runs": binwalk["failed_runs"],
                        "total_wall_ms": binwalk["total_wall_ms"],
                        "completed_runs_per_sec": binwalk["completed_runs_per_sec"],
                        "median_per_run_wall_ms": per_run["median_ms"],
                        "p95_per_run_wall_ms": per_run["p95_ms"],
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


def config_from_args(args: argparse.Namespace, settings: Settings) -> ConcurrentBinwalkConfig:
    input_values = args.input or ["zip.bin"]
    input_paths = tuple(resolve_path(settings.root, value).resolve() for value in input_values)
    output_dir = resolve_path(settings.root, args.output_dir)
    concurrency = args.concurrency if args.concurrency > 0 else args.containers

    return ConcurrentBinwalkConfig(
        name=args.name,
        input_paths=input_paths,
        binwalk_args=shlex.split(args.binwalk_args),
        containers=args.containers,
        container_prefix=args.container_prefix,
        workload_prefix=args.workload_prefix,
        image=args.image,
        build_workload_image=not args.skip_workload_build,
        teardown_workloads=not args.keep_workloads,
        runs_per_container=args.runs_per_container,
        concurrency=concurrency,
        trials=args.trials,
        modes=tuple(args.mode or ("baseline", "scoped", "host-wide")),
        output_dir=output_dir,
        verifier_policy=resolve_path(settings.root, args.verifier_policy),
        runtime_policy=resolve_path(settings.root, args.runtime_policy) if args.runtime_policy else None,
        tpm_tcti=args.tpm_tcti,
        ring_buffer_bytes=args.ring_bytes,
        capture_argv=args.capture_argv,
        verify_scoped=not args.skip_verify,
        verify_host_wide=args.verify_host_wide,
        allow_binwalk_failure=args.allow_binwalk_failure,
        command_timeout_secs=args.command_timeout_secs,
    )


def main() -> int:
    args = parse_args()
    if args.allow_debug:
        os.environ["ALLOW_DEBUG_BINARIES"] = "1"
    settings = Settings.from_env()
    config = config_from_args(args, settings)
    runner = ConcurrentBinwalkExperimentRunner(settings, config, build_monitor=not args.no_build)
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
