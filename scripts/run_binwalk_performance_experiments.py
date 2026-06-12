#!/usr/bin/env python3
"""Binwalk performance experiments for runtime-custodian.

This script benchmarks a process-heavy real-world command-line workload inside a
stable Docker container. It measures Binwalk wall-clock runtime with no monitor,
scoped collection, and host-wide collection, then writes JSON/CSV artefacts under
logs/experiments.
"""

from __future__ import annotations

import argparse
import collections
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
    overhead_ci,
    overhead_pct,
    resolve_path,
    run_verifier_timed,
    safe_filename,
    sha256_file,
    summarise_evidence,
    summary_stats,
)


@dataclass(frozen=True)
class BinwalkConfig:
    name: str
    input_path: Path
    binwalk_args: list[str]
    trials: int
    modes: tuple[str, ...]
    output_dir: Path
    workload_id: str
    container_name: str
    compose_file: Path
    project_dir: Path
    verifier_policy: Path
    capture_argv: bool
    verify_scoped: bool
    allow_binwalk_failure: bool
    teardown_workload: bool
    command_timeout_secs: float
    seed: int
    cooldown_secs: float
    warmup: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Binwalk performance experiments.")
    parser.add_argument("--name", default="binwalk_perf", help="experiment name prefix")
    parser.add_argument(
        "--input",
        default="zip.bin",
        help="sample file to mount/run under /samples; relative paths are resolved from repo root",
    )
    parser.add_argument(
        "--binwalk-args",
        default="-e --run-as=root",
        help="shell-style argument string passed to binwalk before the sample path",
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
    parser.add_argument("--workload-id", default="binwalk", help="workload_id for scoped evidence")
    parser.add_argument(
        "--container-name",
        default="binwalk-workload",
        help="Docker container name used by the collector for cgroup binding",
    )
    parser.add_argument(
        "--compose-file",
        default="workloads/binwalk-workload/compose.yml",
        help="Docker Compose file for the Binwalk workload container",
    )
    parser.add_argument(
        "--project-dir",
        default="workloads/binwalk-workload",
        help="Docker Compose project directory for the Binwalk workload container",
    )
    parser.add_argument(
        "--verifier-policy",
        default="policies/binwalk-verifier-policy.json",
        help="runtime verifier policy used for scoped Binwalk evidence",
    )
    parser.add_argument(
        "--capture-argv",
        action="store_true",
        help="enable argv capture in the collector config",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="skip verifier replay for scoped runs",
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
        "--keep-workload",
        action="store_true",
        help="leave the Binwalk container running after the experiment",
    )
    parser.add_argument(
        "--command-timeout-secs",
        type=float,
        default=120.0,
        help="timeout for each docker exec binwalk command",
    )
    parser.add_argument(
        "--allow-debug",
        action="store_true",
        help="permit measuring debug (non-release) binaries; sets ALLOW_DEBUG_BINARIES=1",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1234,
        help="seed for the per-trial mode-order shuffle (reproducible interleaving)",
    )
    parser.add_argument(
        "--cooldown-secs",
        type=float,
        default=2.0,
        help="seconds to sleep after each timed trial to let the system settle",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="discarded warmup trials per mode run before timed trials",
    )
    return parser.parse_args()


class BinwalkExperimentRunner:
    def __init__(self, settings: Settings, config: BinwalkConfig, *, build: bool) -> None:
        self.settings = settings
        self.config = config
        self.should_build = build
        self.runner = CommandRunner(settings.root)
        self.monitor = MonitorController(settings, self.runner)
        self.workload_started = False

    def run(self) -> int:
        try:
            self.check_privileges()
            self.validate_inputs()

            if self.should_build:
                self.runner.run([self.settings.root / "scripts/build_all.sh"])

            # Refuse to benchmark debug builds (override via --allow-debug);
            # the build mode is recorded in result["environment"] regardless.
            assert_release_binaries(self.settings)

            self.config.output_dir.mkdir(parents=True, exist_ok=True)
            self.start_workload()

            result = self.run_experiments()
            json_path, csv_path = self.write_results(result)
            log(f"Wrote JSON results: {json_path}")
            log(f"Wrote CSV results: {csv_path}")

            for mode, aggregate in result["aggregate"].items():
                if "median_wall_ms" not in aggregate:
                    log(f"BINWALK {mode}: no usable trials (n_failed={aggregate.get('n_failed')})")
                    continue
                overhead = aggregate.get("overhead_vs_baseline_pct")
                overhead_text = "baseline" if overhead is None else f"{overhead:.2f}% vs baseline"
                log(
                    f"BINWALK {mode}: median={aggregate['median_wall_ms']:.2f}ms "
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
        if self.config.trials <= 0:
            fail("--trials must be > 0")
        if self.config.command_timeout_secs <= 0:
            fail("--command-timeout-secs must be > 0")
        if not self.config.input_path.exists():
            fail(f"missing input sample: {self.config.input_path}")
        if not self.config.compose_file.exists():
            fail(f"missing compose file: {self.config.compose_file}")
        if not self.config.verifier_policy.exists() and self.config.verify_scoped:
            fail(f"missing verifier policy: {self.config.verifier_policy}")
        if not self.settings.monitor_bin.exists() and any(
            mode in ("scoped", "host-wide") for mode in self.config.modes
        ):
            fail(f"missing monitor binary: {self.settings.monitor_bin}")

    def start_workload(self) -> None:
        self.runner.run(
            [
                "docker",
                "compose",
                "-f",
                self.config.compose_file,
                "--project-directory",
                self.config.project_dir,
                "up",
                "-d",
                "--build",
            ]
        )
        self.workload_started = True
        self.wait_for_container()

    def wait_for_container(self) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = self.runner.run(
                ["docker", "exec", self.config.container_name, "true"],
                check=False,
                capture=True,
            )
            if result.returncode == 0:
                return
            time.sleep(0.5)
        fail(f"container did not become ready: {self.config.container_name}")

    def cleanup(self) -> None:
        self.monitor.stop()
        if self.config.teardown_workload and self.workload_started:
            self.runner.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    self.config.compose_file,
                    "--project-directory",
                    self.config.project_dir,
                    "down",
                    "-v",
                ],
                check=False,
            )

    def run_experiments(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "experiment": self.config.name,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "input": str(self.config.input_path),
            "sample_name": self.config.input_path.name,
            "input_sha256": sha256_file(self.config.input_path),
            "input_size_bytes": self.config.input_path.stat().st_size
            if self.config.input_path.exists()
            else None,
            "binwalk_args": self.config.binwalk_args,
            "trials": self.config.trials,
            "modes": list(self.config.modes),
            "capture_argv": self.config.capture_argv,
            "environment": environment_metadata(self.settings),
            "trial_results": {},
            "aggregate": {},
        }

        for mode in self.config.modes:
            mode_trials: list[dict[str, Any]] = []
            for trial in range(1, self.config.trials + 1):
                log(f"== binwalk mode={mode} trial {trial}/{self.config.trials} ==")
                mode_trials.append(self.run_trial(mode, trial))
            result["trial_results"][mode] = mode_trials

        result["aggregate"] = aggregate_results(result["trial_results"])
        return result

    def run_trial(self, mode: str, trial: int) -> dict[str, Any]:
        if mode == "baseline":
            command_result = self.run_binwalk_command(mode, trial)
            return {
                "trial": trial,
                "mode": mode,
                "binwalk": command_result,
            }

        paths = self.case_paths(f"{self.config.name}_{mode.replace('-', '_')}_trial_{trial}")
        self.clean_case(paths)
        self.write_collector_config(paths, collection_mode=mode)

        started_at = self.monitor.start(paths)
        try:
            command_result = self.run_binwalk_command(mode, trial)
        finally:
            self.monitor.stop()

        self.assert_fresh_evidence(paths, started_at)
        evidence_summary = summarise_evidence(paths)

        verifier_result: dict[str, Any] | None = None
        if mode == "scoped" and self.config.verify_scoped:
            verifier_result = self.run_verifier(paths)

        return {
            "trial": trial,
            "mode": mode,
            "binwalk": command_result,
            "evidence": evidence_summary,
            "verifier": verifier_result,
        }

    def run_binwalk_command(self, mode: str, trial: int) -> dict[str, Any]:
        out_dir = f"/tmp/binwalk-output/{mode}-{trial}"
        sample = f"/samples/{self.config.input_path.name}"
        args = " ".join(shlex.quote(arg) for arg in self.config.binwalk_args)
        command = (
            f"rm -rf {shlex.quote(out_dir)} && "
            f"mkdir -p {shlex.quote(out_dir)} && "
            f"cd {shlex.quote(out_dir)} && "
            f"binwalk {args} {shlex.quote(sample)}"
        )
        docker_cmd = ["docker", "exec", self.config.container_name, "sh", "-lc", command]
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
            fail(f"binwalk command timed out after {self.config.command_timeout_secs}s: {exc}")
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        if completed.returncode != 0 and not self.config.allow_binwalk_failure:
            if completed.stdout:
                print(completed.stdout[-4000:], file=sys.stderr, end="")
            fail(f"binwalk command failed with status {completed.returncode}")

        return {
            "returncode": completed.returncode,
            "wall_ms": elapsed_ms,
            "stdout_tail": (completed.stdout or "")[-4000:],
        }

    def run_verifier(self, paths: CasePaths) -> dict[str, Any]:
        return run_verifier_timed(
            self.settings,
            paths,
            policy=self.config.verifier_policy,
            fail_message="scoped Binwalk evidence did not verify",
        )

    def case_paths(self, case_name: str) -> CasePaths:
        return case_paths(self.config.output_dir, case_name)

    def write_collector_config(self, paths: CasePaths, *, collection_mode: str) -> None:
        config = {
            "workload_id": self.config.workload_id,
            "container_name": self.config.container_name,
            "collection_mode": collection_mode,
            "evidence_out": str(paths.evidence),
            "summary_out": str(paths.summary),
            "runtime_policy": str(self.config.verifier_policy),
            "capture_argv": self.config.capture_argv,
        }
        paths.collector_config.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")

    def clean_case(self, paths: CasePaths) -> None:
        clean_case(paths)

    def assert_fresh_evidence(self, paths: CasePaths, min_mtime: float) -> None:
        assert_fresh_evidence(paths, min_mtime)

    def write_results(self, result: dict[str, Any]) -> tuple[Path, Path]:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_name = safe_filename(self.config.name, "binwalk_perf")
        json_path = self.config.output_dir / f"{safe_name}_{stamp}.json"
        csv_path = self.config.output_dir / f"{safe_name}_{stamp}.csv"
        json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_csv(csv_path, result)
        return json_path, csv_path


def _trial_ok(trial: Mapping[str, Any]) -> bool:
    """A trial counts only if its binwalk run exited cleanly."""
    return int(trial.get("binwalk", {}).get("returncode", 0)) == 0


def aggregate_results(trial_results: Mapping[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    aggregates: dict[str, dict[str, Any]] = {}
    baseline_median: float | None = None
    baseline_wall_times: list[float] = []

    for mode, trials in trial_results.items():
        # Exclude failed binwalk runs from timing/event aggregates so a partial
        # run (artificially short wall time) does not bias the result.
        used = [trial for trial in trials if _trial_ok(trial)]
        n_failed = len(trials) - len(used)
        if not used:
            aggregates[mode] = {"n_used": 0, "n_failed": n_failed}
            continue

        wall_times = [float(trial["binwalk"]["wall_ms"]) for trial in used]
        event_counts = [int(trial.get("evidence", {}).get("event_count", 0)) for trial in used]
        evidence_sizes = [int(trial.get("evidence", {}).get("evidence_size_bytes", 0)) for trial in used]
        dropped = [int(trial.get("evidence", {}).get("dropped_events", 0)) for trial in used]
        verifier_times = [
            float(trial["verifier"]["wall_ms"])
            for trial in used
            if isinstance(trial.get("verifier"), dict)
        ]

        wall = summary_stats(wall_times)
        events = summary_stats([float(x) for x in event_counts])
        sizes = summary_stats([float(x) for x in evidence_sizes])
        aggregate: dict[str, Any] = {
            "n_used": len(used),
            "n_failed": n_failed,
            "mean_wall_ms": wall["mean"],
            "median_wall_ms": wall["median"],
            "min_wall_ms": wall["min"],
            "max_wall_ms": wall["max"],
            "stdev_wall_ms": wall["stdev"],
            "cov_wall": wall["cov"],
            "p95_wall_ms": wall["p95"],
            "p99_wall_ms": wall["p99"],
            "median_wall_ms_ci": bootstrap_ci(wall_times, statistic=statistics.median),
            "median_event_count": events["median"],
            "stdev_event_count": events["stdev"],
            "median_evidence_size_bytes": sizes["median"],
            "stdev_evidence_size_bytes": sizes["stdev"],
            # Ring-buffer drops aggregated across trials (headline reliability).
            "total_dropped_events": sum(dropped),
            "max_dropped_events": max(dropped) if dropped else 0,
        }
        if verifier_times:
            vstats = summary_stats(verifier_times)
            aggregate["median_verifier_wall_ms"] = vstats["median"]
            aggregate["stdev_verifier_wall_ms"] = vstats["stdev"]

        if mode == "baseline":
            baseline_median = float(aggregate["median_wall_ms"])
            baseline_wall_times = wall_times
            aggregate["overhead_vs_baseline_pct"] = None
            aggregate["overhead_vs_baseline_pct_ci"] = None
        elif baseline_median is not None:
            aggregate["overhead_vs_baseline_pct"] = overhead_pct(
                baseline_median,
                float(aggregate["median_wall_ms"]),
            )
            # Bootstrap CI for the overhead rather than a bare point estimate.
            aggregate["overhead_vs_baseline_pct_ci"] = overhead_ci(
                baseline_wall_times, wall_times, statistic=statistics.median
            )
        else:
            aggregate["overhead_vs_baseline_pct"] = None
            aggregate["overhead_vs_baseline_pct_ci"] = None

        aggregates[mode] = aggregate

    return aggregates


def write_csv(path: Path, result: dict[str, Any]) -> None:
    fieldnames = [
        "mode",
        "trial",
        "returncode",
        "wall_ms",
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
                evidence = trial.get("evidence") or {}
                verifier = trial.get("verifier") or {}
                writer.writerow(
                    {
                        "mode": mode,
                        "trial": trial["trial"],
                        "returncode": trial["binwalk"]["returncode"],
                        "wall_ms": trial["binwalk"]["wall_ms"],
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


def config_from_args(args: argparse.Namespace, settings: Settings) -> BinwalkConfig:
    output_dir = resolve_path(settings.root, args.output_dir)
    modes = tuple(args.mode or ("baseline", "scoped", "host-wide"))
    return BinwalkConfig(
        name=args.name,
        input_path=resolve_path(settings.root, args.input),
        binwalk_args=shlex.split(args.binwalk_args),
        trials=args.trials,
        modes=modes,
        output_dir=output_dir,
        workload_id=args.workload_id,
        container_name=args.container_name,
        compose_file=resolve_path(settings.root, args.compose_file),
        project_dir=resolve_path(settings.root, args.project_dir),
        verifier_policy=resolve_path(settings.root, args.verifier_policy),
        capture_argv=args.capture_argv,
        verify_scoped=not args.skip_verify,
        allow_binwalk_failure=args.allow_binwalk_failure,
        teardown_workload=not args.keep_workload,
        command_timeout_secs=args.command_timeout_secs,
        seed=args.seed,
        cooldown_secs=args.cooldown_secs,
        warmup=args.warmup,
    )


def main() -> int:
    args = parse_args()
    if args.allow_debug:
        os.environ["ALLOW_DEBUG_BINARIES"] = "1"
    settings = Settings.from_env()
    config = config_from_args(args, settings)
    runner = BinwalkExperimentRunner(settings, config, build=not args.no_build)
    return runner.run()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
