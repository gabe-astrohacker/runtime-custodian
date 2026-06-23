#!/usr/bin/env python3
"""Shared helpers for runtime-custodian integration and experiment scripts.

This module intentionally has no project-specific test cases. It only owns
configuration, command execution, workload lifecycle, monitor lifecycle, and
evidence/verifier helpers.
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import os
import platform
import random
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
from typing import Any, Callable, Iterator, Mapping, Sequence, TextIO


class IntegrationFailure(RuntimeError):
    """Raised for expected integration/experiment failures."""


def log(message: str) -> None:
    print(message, flush=True)


def fail(message: str) -> None:
    raise IntegrationFailure(message)


def resolve_path(root: Path, path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return root / candidate


def determine_privilege_prefix() -> list[str]:
    sudo = os.environ.get("SUDO")
    if sudo is not None:
        return shlex.split(sudo)

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []

    return ["sudo", "-n"]


# ---------------------------------------------------------------------------
# Reproducibility: build mode and environment capture
# ---------------------------------------------------------------------------


def build_mode(bin_path: Path) -> str:
    """Infer the cargo build profile from a binary path under target/."""
    parts = bin_path.parts
    if "release" in parts:
        return "release"
    if "debug" in parts:
        return "debug"
    return "unknown"


def assert_release_binaries(settings: "Settings") -> None:
    """Fail fast if performance/security experiments would measure debug builds.

    Debug Rust binaries are typically several-fold slower than release, so any
    timing measured against them is not representative. Set
    ``ALLOW_DEBUG_BINARIES=1`` to override (development only); the chosen build
    mode is always recorded in ``environment_metadata`` regardless.
    """
    if os.environ.get("ALLOW_DEBUG_BINARIES", "0") == "1":
        return

    offenders = [
        str(path)
        for path in (settings.monitor_bin, settings.verifier_bin)
        if build_mode(path) != "release"
    ]
    if offenders:
        fail(
            "refusing to run experiments against non-release binaries: "
            + ", ".join(offenders)
            + " — build with `cargo build --release` (scripts/build_all.sh now "
            "does this) or set ALLOW_DEBUG_BINARIES=1 to override for development"
        )


def _tool_version(args: list[str]) -> str | None:
    """Best-effort capture of an external tool version; never raises."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (result.stdout or result.stderr or "").strip()
    return output.splitlines()[0] if output else None


def _cpu_model() -> str | None:
    model = platform.processor()
    if model:
        return model
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def _cpu_governor() -> str | None:
    try:
        return (
            Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
            .read_text(encoding="utf-8")
            .strip()
        )
    except OSError:
        return None


def sha256_file(path: Path) -> str | None:
    """SHA-256 of a file's contents, or None if it cannot be read."""
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def environment_metadata(settings: "Settings") -> dict[str, Any]:
    """Capture a reproducibility manifest shared by every experiment runner.

    Every probe is best-effort so capture never aborts an experiment. The
    binary build mode is derived from the resolved path so the debug-vs-release
    question is answered inside the artefact itself.
    """
    head = _tool_version(["git", "-C", str(settings.root), "rev-parse", "HEAD"])
    dirty = _tool_version(["git", "-C", str(settings.root), "status", "--porcelain"])
    return {
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        # Host / OS
        "platform": platform.platform(),
        "kernel": _tool_version(["uname", "-r"]),
        "cpu_model": _cpu_model(),
        "cpu_cores": os.cpu_count(),
        "cpu_governor": _cpu_governor(),
        # Toolchain
        "python": sys.version.split()[0],
        "rustc": _tool_version(["rustc", "--version"]),
        "cargo": _tool_version(["cargo", "--version"]),
        # Security / runtime dependencies
        "tpm2_tools": _tool_version(["tpm2", "--version"]),
        "swtpm": _tool_version(["swtpm", "--version"]),
        "docker": _tool_version(["docker", "--version"]),
        # Repository state
        "git_commit": head,
        "git_dirty": bool(dirty),
        # Binaries actually measured (answers debug-vs-release in the artefact)
        "monitor_bin": str(settings.monitor_bin),
        "verifier_bin": str(settings.verifier_bin),
        "monitor_build_mode": build_mode(settings.monitor_bin),
        "verifier_build_mode": build_mode(settings.verifier_bin),
        "monitor_sha256": sha256_file(settings.monitor_bin),
        "verifier_sha256": sha256_file(settings.verifier_bin),
    }


# ---------------------------------------------------------------------------
# Statistics: dispersion, percentiles, and bootstrap confidence intervals
# ---------------------------------------------------------------------------


def percentile(values: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile (q in [0, 100]); robust for small n."""
    if not values:
        fail("percentile of empty sequence")
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (q / 100.0) * (len(ordered) - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return float(ordered[low])
    weight = rank - low
    return float(ordered[low] * (1.0 - weight) + ordered[high] * weight)


def summary_stats(values: Sequence[float]) -> dict[str, Any]:
    """min/max/mean/median/stdev/CoV/p95/p99 for a sample, with n.

    Dispersion (stdev, CoV) is reported alongside every central-tendency number
    so no point estimate is presented without its spread.
    """
    sample = [float(v) for v in values]
    if not sample:
        return {
            "n": 0,
            "min": None,
            "max": None,
            "mean": None,
            "median": None,
            "stdev": None,
            "cov": None,
            "p95": None,
            "p99": None,
        }
    mean = statistics.fmean(sample)
    stdev = statistics.stdev(sample) if len(sample) > 1 else 0.0
    return {
        "n": len(sample),
        "min": min(sample),
        "max": max(sample),
        "mean": mean,
        "median": statistics.median(sample),
        "stdev": stdev,
        "cov": (stdev / mean) if mean else None,
        "p95": percentile(sample, 95.0),
        "p99": percentile(sample, 99.0),
    }


def _resample(values: Sequence[float], rng: random.Random) -> list[float]:
    return [values[rng.randrange(len(values))] for _ in range(len(values))]


def bootstrap_ci(
    values: Sequence[float],
    statistic: Callable[[Sequence[float]], float] = statistics.median,
    *,
    confidence: float = 0.95,
    iterations: int = 2000,
    seed: int = 1234,
) -> dict[str, Any]:
    """Percentile bootstrap CI for an arbitrary statistic (median by default).

    Pure-Python (no numpy/scipy). The seed is fixed for reproducibility — two
    runs over the same sample yield the same interval.
    """
    sample = [float(v) for v in values]
    if not sample:
        return {"point": None, "low": None, "high": None, "confidence": confidence}
    point = float(statistic(sample))
    if len(sample) == 1:
        return {"point": point, "low": point, "high": point, "confidence": confidence}
    rng = random.Random(seed)
    estimates = sorted(float(statistic(_resample(sample, rng))) for _ in range(iterations))
    alpha = (1.0 - confidence) / 2.0
    return {
        "point": point,
        "low": percentile(estimates, alpha * 100.0),
        "high": percentile(estimates, (1.0 - alpha) * 100.0),
        "confidence": confidence,
    }


def overhead_pct(baseline: float, measured: float) -> float:
    """Percentage overhead of measured relative to baseline."""
    if baseline == 0:
        fail("cannot compute overhead against a zero baseline")
    return (measured / baseline - 1.0) * 100.0


def overhead_pct_inf(baseline: float, measured: float) -> float:
    """Percentage overhead of measured relative to baseline.

    Unlike :func:`overhead_pct`, a zero baseline yields ``inf`` rather than
    raising. Experiment runners that compare wall/throughput aggregates use this
    convention so a degenerate zero baseline does not abort the whole run.
    """
    if baseline == 0:
        return float("inf")
    return ((measured / baseline) - 1.0) * 100.0


def percentile_nearest_rank(ordered_values: list[float], percentile: float) -> float:
    if not ordered_values:
        fail("cannot compute percentile of empty list")

    if len(ordered_values) == 1:
        return ordered_values[0]

    index = int(round((percentile / 100.0) * (len(ordered_values) - 1)))
    index = max(0, min(index, len(ordered_values) - 1))
    return ordered_values[index]


def overhead_ci(
    baseline: Sequence[float],
    measured: Sequence[float],
    *,
    statistic: Callable[[Sequence[float]], float] = statistics.median,
    confidence: float = 0.95,
    iterations: int = 2000,
    seed: int = 1234,
) -> dict[str, Any]:
    """Bootstrap CI for the overhead percentage between two samples.

    Resamples both samples independently and recomputes the overhead of the
    chosen statistic (median by default), so the headline overhead number is
    reported with an uncertainty interval rather than as a bare point estimate.
    """
    base = [float(v) for v in baseline]
    meas = [float(v) for v in measured]
    if not base or not meas:
        return {"point": None, "low": None, "high": None, "confidence": confidence}
    point = overhead_pct(float(statistic(base)), float(statistic(meas)))
    rng = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        b = statistic(_resample(base, rng))
        m = statistic(_resample(meas, rng))
        if b:
            estimates.append((m / b - 1.0) * 100.0)
    if not estimates:
        return {"point": point, "low": None, "high": None, "confidence": confidence}
    estimates.sort()
    alpha = (1.0 - confidence) / 2.0
    return {
        "point": point,
        "low": percentile(estimates, alpha * 100.0),
        "high": percentile(estimates, (1.0 - alpha) * 100.0),
        "confidence": confidence,
    }


@dataclass(frozen=True)
class Settings:
    root: Path
    base_url: str
    base_collector_config: Path
    verifier_policy: Path
    log_dir: Path
    monitor_bin: Path
    verifier_bin: Path
    monitor_startup_secs: float
    monitor_startup_timeout_secs: float
    monitor_ready_pattern: str
    http_timeout_secs: float
    workload_timeout_secs: float
    teardown_workload: bool
    privilege_prefix: list[str]

    @classmethod
    def from_env(cls) -> "Settings":
        root = Path(__file__).resolve().parent.parent

        collector_config = os.environ.get("COLLECTOR_CONFIG", "config/collector_config.json")
        verifier_policy = os.environ.get("VERIFIER_POLICY", "config/verifier_policy.json")

        collector_config_path = resolve_path(root, collector_config)
        verifier_policy_path = resolve_path(root, verifier_policy)

        # Preserve the existing repo fallback behaviour.
        if collector_config == "config/collector_config.json" and not collector_config_path.exists():
            collector_config_path = root / "policies/fastapi-monitor-policy.json"

        if verifier_policy == "config/verifier_policy.json" and not verifier_policy_path.exists():
            verifier_policy_path = root / "policies/fastapi-verifier-policy.json"

        teardown_workload = (
            os.environ.get("TEARDOWN_WORKLOAD", "1") == "1"
            and os.environ.get("KEEP_WORKLOAD", "0") != "1"
        )

        return cls(
            root=root,
            base_url=os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/"),
            base_collector_config=collector_config_path,
            verifier_policy=verifier_policy_path,
            log_dir=resolve_path(root, os.environ.get("LOG_DIR", "logs/integration")),
            monitor_bin=resolve_path(root, os.environ.get("MONITOR_BIN", "target/release/runtime-monitor")),
            verifier_bin=resolve_path(root, os.environ.get("VERIFIER_BIN", "target/release/runtime-verifier")),
            monitor_startup_secs=float(os.environ.get("MONITOR_STARTUP_SECS", "2")),
            monitor_startup_timeout_secs=float(os.environ.get("MONITOR_STARTUP_TIMEOUT_SECS", "10")),
            monitor_ready_pattern=os.environ.get("MONITOR_READY_PATTERN", ""),
            http_timeout_secs=float(os.environ.get("HTTP_TIMEOUT_SECS", "5")),
            workload_timeout_secs=float(os.environ.get("WORKLOAD_TIMEOUT_SECS", "30")),
            teardown_workload=teardown_workload,
            privilege_prefix=determine_privilege_prefix(),
        )


@dataclass(frozen=True)
class CasePaths:
    name: str
    collector_config: Path
    evidence: Path
    summary: Path
    monitor_log: Path


@dataclass(frozen=True)
class EvidenceJsonRecord:
    line_number: int
    data: Mapping[str, Any]
    raw_line: str = ""


@dataclass(frozen=True)
class RuntimeEvidenceEvent:
    line_number: int
    record: Mapping[str, Any]
    event: Mapping[str, Any]
    legacy: bool


LEGACY_RUNTIME_EVENT_DETAIL_FIELDS = frozenset(("exe_path", "comm", "workload_id", "cgroup_id"))


def is_legacy_runtime_event(data: Mapping[str, Any]) -> bool:
    return "event_type" in data and bool(LEGACY_RUNTIME_EVENT_DETAIL_FIELDS.intersection(data))


def iter_evidence_records(path: Path) -> Iterator[EvidenceJsonRecord]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                fail(f"invalid JSON in {path} at line {line_number}: {exc}")

            if not isinstance(data, dict):
                fail(f"invalid evidence record in {path} at line {line_number}: expected JSON object")

            yield EvidenceJsonRecord(
                line_number=line_number,
                data=data,
                raw_line=line.rstrip("\n"),
            )


def iter_runtime_evidence_events(path: Path) -> Iterator[RuntimeEvidenceEvent]:
    for parsed in iter_evidence_records(path):
        data = parsed.data
        record_kind = data.get("record_kind")

        # Synthetic records are valid evidence records, but runtime event
        # summaries intentionally exclude monitor lifecycle/policy metadata.
        if record_kind == "synthetic":
            continue

        if record_kind == "runtime-event":
            record = data.get("record")
            if not isinstance(record, dict):
                fail(
                    f"invalid runtime evidence record in {path} at line {parsed.line_number}: "
                    "missing object field 'record'"
                )

            event = record.get("event")
            if not isinstance(event, dict):
                fail(
                    f"invalid runtime evidence record in {path} at line {parsed.line_number}: "
                    "missing object field 'record.event'"
                )

            yield RuntimeEvidenceEvent(
                line_number=parsed.line_number,
                record=record,
                event=event,
                legacy=False,
            )
            continue

        if record_kind is not None:
            fail(f"unsupported evidence record_kind in {path} at line {parsed.line_number}: {record_kind}")

        if is_legacy_runtime_event(data):
            yield RuntimeEvidenceEvent(
                line_number=parsed.line_number,
                record=data,
                event=data,
                legacy=True,
            )
            continue

        fail(
            f"unsupported evidence record in {path} at line {parsed.line_number}: "
            "missing record_kind and not a legacy runtime event"
        )


# ---------------------------------------------------------------------------
# Tamper support: read, mutate, and re-serialise evidence records
# ---------------------------------------------------------------------------


def read_evidence_lines(path: Path) -> list[EvidenceJsonRecord]:
    """Load every evidence record, preserving the exact source line text.

    Returns a list (not a generator) so a tamper harness can index, reorder,
    delete, and duplicate records before writing them back.
    """
    return list(iter_evidence_records(path))


def serialise_record(record: EvidenceJsonRecord) -> str:
    """Return the JSONL text for a record.

    Untouched records keep their original bytes via ``raw_line`` so the
    software-chain over them is unaffected; mutated records (built by
    :func:`mutated_record`) carry a re-serialised ``raw_line``.
    """
    if record.raw_line:
        return record.raw_line
    return json.dumps(record.data, sort_keys=True)


def mutated_record(record: EvidenceJsonRecord, new_data: Mapping[str, Any]) -> EvidenceJsonRecord:
    """Build a record with replaced data and a matching re-serialised line."""
    return EvidenceJsonRecord(
        line_number=record.line_number,
        data=new_data,
        raw_line=json.dumps(new_data, sort_keys=True),
    )


def write_evidence_lines(path: Path, records: Sequence[EvidenceJsonRecord]) -> None:
    """Write evidence records back to a JSONL file, one per line."""
    path.write_text(
        "".join(serialise_record(record) + "\n" for record in records),
        encoding="utf-8",
    )


def deep_set(data: Mapping[str, Any], dotted_path: str, value: Any) -> dict[str, Any]:
    """Return a deep copy of ``data`` with ``dotted_path`` set to ``value``.

    Example: ``deep_set(rec.data, "record.event.exe_path", "/usr/bin/evil")``.
    Fails if any intermediate key is missing, so a tamper operator cannot
    silently no-op against an unexpected schema.
    """
    clone = json.loads(json.dumps(data))
    keys = dotted_path.split(".")
    cursor: Any = clone
    for key in keys[:-1]:
        if not isinstance(cursor, dict) or key not in cursor:
            fail(f"deep_set: missing intermediate key {key!r} in path {dotted_path!r}")
        cursor = cursor[key]
    leaf = keys[-1]
    if not isinstance(cursor, dict) or leaf not in cursor:
        fail(f"deep_set: missing leaf key {leaf!r} in path {dotted_path!r}")
    cursor[leaf] = value
    return clone


# ---------------------------------------------------------------------------
# Verifier invocation that returns the structured report
# ---------------------------------------------------------------------------


def run_verifier_cli(
    settings: "Settings",
    runner: "CommandRunner",
    *,
    evidence: Path,
    policy: Path | None = None,
    summary: Path | None = None,
    report: Path | None = None,
    require_tpm_quote: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run the verifier over explicit paths (no CasePaths required).

    Used by the security/tamper harness, which verifies arbitrary mutated
    evidence/summary/policy triples rather than a single live case.
    """
    if not settings.verifier_bin.exists():
        fail(f"missing verifier binary: {settings.verifier_bin}")

    chosen_policy = policy or settings.verifier_policy
    if not chosen_policy.exists():
        fail(f"missing verifier policy: {chosen_policy}")

    args: list[str | Path] = [
        settings.verifier_bin,
        "--policy",
        chosen_policy,
        "--evidence",
        evidence,
    ]
    if summary is not None:
        args.extend(["--summary", summary])
    if report is not None:
        args.extend(["--report", report])
    if require_tpm_quote:
        args.append("--require-tpm-quote")

    return runner.run(args, check=False, capture=True)


def read_report(path: Path) -> dict[str, Any]:
    """Parse a verifier report JSON file (empty dict if absent/invalid)."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid verifier report JSON {path}: {exc}")
    return data if isinstance(data, dict) else {}


def failed_checks(report: Mapping[str, Any]) -> list[str]:
    """Names of verifier checks that did not pass (value is not True)."""
    checks = report.get("checks")
    if not isinstance(checks, dict):
        return []
    return sorted(name for name, ok in checks.items() if ok is not True)


# ---------------------------------------------------------------------------
# Shared experiment-runner helpers (extracted verbatim from the experiment
# scripts so the standalone runners can drop their copy-pasted equivalents).
# ---------------------------------------------------------------------------


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")


def safe_filename(name: str, default: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in name)
    return safe or default


def case_paths(output_dir: Path, case_name: str) -> CasePaths:
    output_dir.mkdir(parents=True, exist_ok=True)
    return CasePaths(
        name=case_name,
        collector_config=output_dir / f"collector_config_{case_name}.json",
        evidence=output_dir / f"runtime_events_{case_name}.jsonl",
        summary=output_dir / f"runtime_events_{case_name}.summary.json",
        monitor_log=output_dir / f"integration_monitor_{case_name}.log",
    )


def clean_case(paths: CasePaths) -> None:
    for path in [paths.collector_config, paths.evidence, paths.summary, paths.monitor_log]:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def assert_fresh_evidence(paths: CasePaths, min_mtime: float) -> None:
    if not paths.evidence.exists():
        fail(f"missing evidence file {paths.evidence}")
    if paths.evidence.stat().st_size == 0:
        fail(f"evidence file is empty: {paths.evidence}")
    if paths.evidence.stat().st_mtime < min_mtime:
        fail(f"evidence file is stale: {paths.evidence}")


def check_privileges(settings: "Settings", runner: "CommandRunner") -> None:
    if not settings.privilege_prefix:
        return

    result = runner.run([*settings.privilege_prefix, "true"], check=False, capture=True)
    if result.returncode == 0:
        return
    if result.stdout:
        print(result.stdout, file=sys.stderr, end="")
    fail("passwordless privilege escalation is required; run `sudo -v` first or run as root")


def summarise_evidence(paths: CasePaths) -> dict[str, Any]:
    total_record_count = 0
    synthetic_record_count = 0
    for parsed in iter_evidence_records(paths.evidence):
        total_record_count += 1
        if parsed.data.get("record_kind") == "synthetic":
            synthetic_record_count += 1

    event_count = 0
    event_type_counts: collections.Counter[str] = collections.Counter()
    workload_counts: collections.Counter[str] = collections.Counter()
    exe_path_counts: collections.Counter[str] = collections.Counter()
    classification_counts: collections.Counter[str] = collections.Counter()

    for runtime_event in iter_runtime_evidence_events(paths.evidence):
        event = runtime_event.event
        record = runtime_event.record
        event_count += 1
        event_type_counts[str(event.get("event_type", "<missing>"))] += 1
        workload_counts[str(event.get("workload_id", "<missing>"))] += 1
        exe_path_counts[str(event.get("exe_path") or "<missing>")] += 1
        classification = record.get("classification")
        if classification is not None:
            classification_counts[str(classification)] += 1

    monitor_summary = read_json(paths.summary)
    return {
        "event_count": event_count,
        "synthetic_record_count": synthetic_record_count,
        "total_record_count": total_record_count,
        "evidence_size_bytes": paths.evidence.stat().st_size if paths.evidence.exists() else 0,
        # Ring-buffer drops self-reported by the monitor; surfaced so they can
        # be tracked per mode rather than silently discarded.
        "dropped_events": int(monitor_summary.get("dropped_events", 0)),
        "event_type_counts": dict(event_type_counts.most_common()),
        "workload_counts": dict(workload_counts.most_common()),
        "classification_counts": dict(classification_counts.most_common()),
        "top_exec_paths": [
            {"exe_path": exe_path, "count": count} for exe_path, count in exe_path_counts.most_common(20)
        ],
        "events": str(paths.evidence),
        "summary": str(paths.summary),
        "monitor_log": str(paths.monitor_log),
        "monitor_summary": monitor_summary,
    }


def run_verifier_timed(
    settings: "Settings",
    paths: CasePaths,
    *,
    policy: Path,
    fail_message: str,
) -> dict[str, Any]:
    report_path = paths.summary.with_name(f"verification_report_{paths.name}.json")
    args: list[str | Path] = [
        settings.verifier_bin,
        "--policy",
        policy,
        "--evidence",
        paths.evidence,
        "--summary",
        paths.summary,
        "--report",
        report_path,
    ]
    rendered = [str(arg) for arg in args]
    log("$ " + " ".join(shlex.quote(arg) for arg in rendered))
    start_ns = time.perf_counter_ns()
    completed = subprocess.run(
        rendered,
        cwd=settings.root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

    report: Mapping[str, Any] = {}
    if report_path.exists():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"invalid verifier report JSON {report_path}: {exc}")

    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, file=sys.stderr, end="")
        fail(fail_message)

    return {
        "returncode": completed.returncode,
        "wall_ms": elapsed_ms,
        "stdout": completed.stdout,
        "report": str(report_path),
        "decision": report.get("decision"),
        "reason": report.get("reason"),
        "counts": report.get("counts"),
    }


def write_runtime_policy(verifier_policy: Path, paths: CasePaths, workload_ids: Sequence[str]) -> Path:
    policy = json.loads(verifier_policy.read_text(encoding="utf-8"))
    policy["workload_id"] = ",".join(workload_ids)
    policy_path = paths.summary.with_name(f"runtime_policy_{paths.name}.json")
    policy_path.write_text(
        json.dumps(policy, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return policy_path


def write_multi_workload_collector_config(
    paths: CasePaths,
    *,
    workloads: Sequence[Mapping[str, str]],
    collection_mode: str,
    runtime_policy: Path,
    capture_argv: bool,
    tpm_tcti: str | None = None,
    ring_buffer_bytes: int | None = None,
) -> None:
    config = {
        "workloads": [
            {"workload_id": workload["workload_id"], "container_name": workload["container_name"]}
            for workload in workloads
        ],
        "collection_mode": collection_mode,
        "evidence_out": str(paths.evidence),
        "summary_out": str(paths.summary),
        "runtime_policy": str(runtime_policy),
        "capture_argv": capture_argv,
    }
    if tpm_tcti:
        # The monitor forks tpm2-tools and reads the TCTI from this field
        # (main.rs -> TpmConfig.tcti), so swtpm is reachable without sudo -E.
        config["tpm_tcti"] = tpm_tcti
    if ring_buffer_bytes:
        # Override the eBPF EVENTS ring-buffer size (default 256 KiB). A larger
        # buffer absorbs bursts that would otherwise drop, at the cost of monitor
        # finalisation lag (the buffering experiment). Survives sudo via config.
        config["ring_buffer_bytes"] = ring_buffer_bytes
    paths.collector_config.write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class CommandRunner:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run(
        self,
        args: list[str | Path],
        *,
        check: bool = True,
        capture: bool = False,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        rendered = [str(arg) for arg in args]
        log("$ " + " ".join(shlex.quote(arg) for arg in rendered))

        command_env = None
        if env is not None:
            command_env = os.environ.copy()
            command_env.update(env)

        result = subprocess.run(
            rendered,
            cwd=cwd or self.root,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            check=False,
            env=command_env,
        )

        if check and result.returncode != 0:
            if capture and result.stdout:
                print(result.stdout, file=sys.stderr, end="")
            fail(f"command failed with status {result.returncode}: {' '.join(rendered)}")

        return result


class WorkloadController:
    def __init__(self, settings: Settings, runner: CommandRunner) -> None:
        self.settings = settings
        self.runner = runner
        self.started = False

    def start(self) -> None:
        self.runner.run([self.settings.root / "scripts/run_workload.sh"])
        self.started = True
        self.wait_until_ready()

    def stop_if_requested(self) -> None:
        if not self.settings.teardown_workload or not self.started:
            return

        stop_script = self.settings.root / "scripts/stop_workload.sh"
        if stop_script.exists():
            self.runner.run([stop_script], check=False)
            return

        # Fallback for repos without a dedicated stop script.
        self.runner.run(["docker", "compose", "down"], check=False, cwd=self.settings.root)

        workload_dir = self.settings.root / "workload"
        if workload_dir.exists():
            self.runner.run(["docker", "compose", "down"], check=False, cwd=workload_dir)

    def get(self, path: str) -> bytes:
        if not path.startswith("/"):
            path = f"/{path}"

        url = f"{self.settings.base_url}{path}"
        try:
            with urllib.request.urlopen(url, timeout=self.settings.http_timeout_secs) as response:
                return response.read()
        except urllib.error.URLError as exc:
            fail(f"HTTP request failed for {url}: {exc}")

    def wait_until_ready(self) -> None:
        deadline = time.monotonic() + self.settings.workload_timeout_secs
        last_error: BaseException | None = None

        while time.monotonic() < deadline:
            try:
                self.get("/ping")
                return
            except IntegrationFailure as exc:
                last_error = exc
                time.sleep(0.5)

        fail(f"workload did not become ready at {self.settings.base_url}/ping: {last_error}")


class MonitorController:
    def __init__(self, settings: Settings, runner: CommandRunner) -> None:
        self.settings = settings
        self.runner = runner
        self.proc: subprocess.Popen[str] | None = None
        self.log_handle: TextIO | None = None
        self.log_path: Path | None = None
        # Seconds from stop-signal to monitor exit = the shutdown drain time
        # (how long the monitor took to process its remaining buffered events and
        # finalise). The buffering experiment reads this as the attestation lag.
        self.last_drain_secs: float | None = None

    def start(self, paths: CasePaths) -> float:
        if self.proc is not None:
            fail("monitor is already running")

        if not self.settings.monitor_bin.exists():
            fail(f"missing monitor binary: {self.settings.monitor_bin}")

        self.log_path = paths.monitor_log
        self.log_handle = self.log_path.open("w", encoding="utf-8")

        cmd = [
            *self.settings.privilege_prefix,
            str(self.settings.monitor_bin),
            "--collector-config",
            str(paths.collector_config),
        ]

        log("$ " + " ".join(shlex.quote(arg) for arg in cmd))
        started_at = time.time()

        popen_kwargs: dict[str, Any] = {
            "cwd": self.settings.root,
            "text": True,
            "stdout": self.log_handle,
            "stderr": subprocess.STDOUT,
        }

        if sys.version_info >= (3, 11):
            # New process group, same session. This preserves sudo's tty
            # timestamp while still letting us signal the whole monitor group.
            popen_kwargs["process_group"] = 0
        else:
            # Fallback for older Python.
            popen_kwargs["preexec_fn"] = os.setpgrp

        self.proc = subprocess.Popen(cmd, **popen_kwargs)
        self.wait_until_ready()

        return started_at

    def stop(self) -> None:
        proc = self.proc
        if proc is None:
            return

        self.proc = None

        if proc.poll() is None:
            # SIGINT triggers graceful shutdown: the monitor drains its remaining
            # buffered events (extends and all) before finalising. A large ring
            # buffer can make that drain long, so the wait is configurable via
            # MONITOR_STOP_TIMEOUT_SECS (default 30s) before escalating.
            wait_secs = float(os.environ.get("MONITOR_STOP_TIMEOUT_SECS", "30"))
            started = time.perf_counter()
            self.kill_process_group(proc.pid, "INT")
            try:
                proc.wait(timeout=wait_secs)
            except subprocess.TimeoutExpired:
                self.kill_process_group(proc.pid, "TERM")
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.kill_process_group(proc.pid, "KILL")
                    proc.wait(timeout=5)
            self.last_drain_secs = time.perf_counter() - started

        if self.log_handle is not None:
            self.log_handle.close()
            self.log_handle = None

    def kill_process_group(self, pid: int, sig: str) -> None:
        self.runner.run(
            [*self.settings.privilege_prefix, "kill", f"-{sig}", "--", f"-{pid}"],
            check=False,
        )

    def wait_until_ready(self) -> None:
        deadline = time.monotonic() + self.settings.monitor_startup_timeout_secs
        minimum_wait_until = time.monotonic() + self.settings.monitor_startup_secs

        while time.monotonic() < deadline:
            if self.proc is None:
                fail("monitor was not started")

            if self.proc.poll() is not None:
                self.print_log_tail()
                fail("monitor exited before test traffic")

            if self.settings.monitor_ready_pattern:
                if self.settings.monitor_ready_pattern in self.read_log():
                    return
            elif time.monotonic() >= minimum_wait_until:
                # The current monitor does not expose a formal readiness signal.
                # Keep the legacy delay but poll the process during the wait.
                return

            time.sleep(0.1)

        if self.settings.monitor_ready_pattern:
            self.print_log_tail()
            fail(f"monitor did not print readiness pattern: {self.settings.monitor_ready_pattern!r}")

        fail("monitor did not become ready before timeout")

    def read_log(self) -> str:
        if self.log_handle is not None:
            self.log_handle.flush()

        if self.log_path is None or not self.log_path.exists():
            return ""

        return self.log_path.read_text(encoding="utf-8", errors="replace")

    def print_log_tail(self) -> None:
        if self.log_path is None or not self.log_path.exists():
            return

        print(f"--- monitor log tail: {self.log_path} ---", file=sys.stderr)
        try:
            lines = self.read_log().splitlines()
            for line in lines[-80:]:
                print(line, file=sys.stderr)
        except OSError as exc:
            print(f"failed to read monitor log: {exc}", file=sys.stderr)
        print("--- end monitor log tail ---", file=sys.stderr)


class RuntimeHarness:
    """Shared harness for correctness tests and performance experiments."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.runner = CommandRunner(settings.root)
        self.workload = WorkloadController(settings, self.runner)
        self.monitor = MonitorController(settings, self.runner)

    def check_privileges(self) -> None:
        if not self.settings.privilege_prefix:
            return

        result = self.runner.run(
            [*self.settings.privilege_prefix, "true"],
            check=False,
            capture=True,
        )

        if result.returncode == 0:
            return

        if result.stdout:
            print(result.stdout, file=sys.stderr, end="")

        fail(
            "passwordless privilege escalation is required; "
            "run `sudo -v` first, run as root, or set SUDO to a non-interactive command "
            "such as 'sudo -n'"
        )

    def build(self) -> None:
        self.runner.run([self.settings.root / "scripts/build_all.sh"])

    def cleanup(self) -> None:
        self.monitor.stop()
        self.workload.stop_if_requested()

    def case_paths(self, case_name: str, *, log_dir: Path | None = None) -> CasePaths:
        target_dir = log_dir or self.settings.log_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        return CasePaths(
            name=case_name,
            collector_config=target_dir / f"collector_config_{case_name}.json",
            evidence=target_dir / f"runtime_events_{case_name}.jsonl",
            summary=target_dir / f"runtime_events_{case_name}.summary.json",
            monitor_log=target_dir / f"integration_monitor_{case_name}.log",
        )

    def clean_case(self, paths: CasePaths) -> None:
        for path in [paths.collector_config, paths.evidence, paths.summary, paths.monitor_log]:
            self.remove_if_exists(path)

    def clean_logs(self, directory: Path, patterns: list[str]) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        for pattern in patterns:
            for path in directory.glob(pattern):
                self.remove_if_exists(path)

    def clean_integration_logs(self) -> None:
        self.clean_logs(
            self.settings.log_dir,
            [
                "runtime_events_*.jsonl",
                "runtime_events_*.summary.json",
                "collector_config_*.json",
                "integration_monitor_*.log",
            ],
        )

    def write_case_collector_config(
        self,
        paths: CasePaths,
        *,
        overrides: Mapping[str, object] | None = None,
    ) -> None:
        if not self.settings.base_collector_config.exists():
            fail(f"missing collector config: {self.settings.base_collector_config}")

        try:
            config = json.loads(self.settings.base_collector_config.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"collector config is not valid JSON: {self.settings.base_collector_config}: {exc}")

        config.setdefault("collection_mode", "scoped")

        if overrides:
            config.update(overrides)

        # Force test-specific outputs so stale/default evidence or summary
        # files cannot satisfy assertions accidentally.
        config["evidence_out"] = str(paths.evidence)
        config["summary_out"] = str(paths.summary)

        paths.collector_config.write_text(
            json.dumps(config, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def run_verifier(self, paths: CasePaths) -> subprocess.CompletedProcess[str]:
        if not self.settings.verifier_bin.exists():
            fail(f"missing verifier binary: {self.settings.verifier_bin}")

        if not self.settings.verifier_policy.exists():
            fail(f"missing verifier policy: {self.settings.verifier_policy}")

        args: list[str | Path] = [
            self.settings.verifier_bin,
            "--policy",
            self.settings.verifier_policy,
            "--evidence",
            paths.evidence,
        ]

        if paths.summary.exists():
            args.extend(["--summary", paths.summary])

        return self.runner.run(args, check=False, capture=True)

    def expect_verifier(self, paths: CasePaths, *, expect_accept: bool) -> None:
        result = self.run_verifier(paths)

        if result.stdout:
            print(result.stdout, end="")

        expected_prefix = "ACCEPT:" if expect_accept else "REJECT:"

        if expect_accept and result.returncode != 0:
            fail("expected ACCEPT")

        if not expect_accept and result.returncode == 0:
            fail("expected REJECT, got ACCEPT")

        if not result.stdout.startswith(expected_prefix):
            fail(f"verifier did not print {expected_prefix}")

    def assert_fresh_evidence(self, paths: CasePaths, min_mtime: float) -> None:
        if not paths.evidence.exists():
            fail(f"missing evidence file {paths.evidence}")

        if paths.evidence.stat().st_size == 0:
            fail(f"evidence file is empty: {paths.evidence}")

        if paths.evidence.stat().st_mtime < min_mtime:
            fail(f"evidence file is stale: {paths.evidence}")

    def assert_evidence_contains(self, paths: CasePaths, expected: str) -> None:
        content = paths.evidence.read_text(encoding="utf-8", errors="replace")
        if expected not in content:
            fail(f"evidence does not contain {expected}")

    @staticmethod
    def remove_if_exists(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            return
