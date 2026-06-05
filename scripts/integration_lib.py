#!/usr/bin/env python3
"""Shared helpers for runtime-custodian integration and experiment scripts.

This module intentionally has no project-specific test cases. It only owns
configuration, command execution, workload lifecycle, monitor lifecycle, and
evidence/verifier helpers.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, TextIO


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
            monitor_bin=resolve_path(root, os.environ.get("MONITOR_BIN", "target/debug/runtime-monitor")),
            verifier_bin=resolve_path(root, os.environ.get("VERIFIER_BIN", "target/debug/runtime-verifier")),
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

            yield EvidenceJsonRecord(line_number=line_number, data=data)


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
            self.kill_process_group(proc.pid, "INT")
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.kill_process_group(proc.pid, "TERM")
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.kill_process_group(proc.pid, "KILL")
                    proc.wait(timeout=5)

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
