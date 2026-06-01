#!/usr/bin/env python3
"""V1 integration tests for the runtime evidence prototype.

This is a Docker + sudo + eBPF integration smoke test, so it intentionally
stays outside `cargo test`.

Expected behaviour:
- /echo produces /usr/bin/echo evidence and verifier ACCEPTs.
- /bad produces /usr/bin/id evidence and verifier REJECTs.

The runner creates per-case collector configs and evidence files under
LOG_DIR so stale logs from previous runs are not mistaken for fresh evidence.
By default it also tears the workload down after the run; set KEEP_WORKLOAD=1
or TEARDOWN_WORKLOAD=0 to keep containers running for development.
"""

import json
import os
import shlex
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO


ROOT = Path(__file__).resolve().parent.parent

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
COLLECTOR_CONFIG = os.environ.get("COLLECTOR_CONFIG", "config/collector_config.json")
VERIFIER_POLICY = os.environ.get("VERIFIER_POLICY", "config/verifier_policy.json")
LOG_DIR = os.environ.get("LOG_DIR", "logs/integration")
MONITOR_BIN = os.environ.get("MONITOR_BIN", "target/debug/runtime-monitor")
VERIFIER_BIN = os.environ.get("VERIFIER_BIN", "target/debug/runtime-verifier")
MONITOR_STARTUP_SECS = float(os.environ.get("MONITOR_STARTUP_SECS", "2"))
MONITOR_STARTUP_TIMEOUT_SECS = float(os.environ.get("MONITOR_STARTUP_TIMEOUT_SECS", "10"))
MONITOR_READY_PATTERN = os.environ.get("MONITOR_READY_PATTERN", "")
HTTP_TIMEOUT_SECS = float(os.environ.get("HTTP_TIMEOUT_SECS", "5"))
WORKLOAD_TIMEOUT_SECS = float(os.environ.get("WORKLOAD_TIMEOUT_SECS", "30"))
TEARDOWN_WORKLOAD = (
    os.environ.get("TEARDOWN_WORKLOAD", "1") == "1"
    and os.environ.get("KEEP_WORKLOAD", "0") != "1"
)

SUDO = os.environ.get("SUDO")
if SUDO is not None:
    PRIVILEGE_PREFIX = shlex.split(SUDO)
elif hasattr(os, "geteuid") and os.geteuid() == 0:
    PRIVILEGE_PREFIX = []
else:
    PRIVILEGE_PREFIX = ["sudo", "-n"]

monitor_proc: subprocess.Popen[str] | None = None
monitor_log_handle: TextIO | None = None
monitor_log_path: Path | None = None
workload_started = False


class IntegrationFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class CasePaths:
    name: str
    collector_config: Path
    evidence: Path
    summary: Path
    monitor_log: Path


def log(message: str) -> None:
    print(message, flush=True)


def fail(message: str) -> None:
    raise IntegrationFailure(message)


def resolve_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return ROOT / candidate


BASE_COLLECTOR_CONFIG_PATH = resolve_path(COLLECTOR_CONFIG)
VERIFIER_POLICY_PATH = resolve_path(VERIFIER_POLICY)
LOG_DIR_PATH = resolve_path(LOG_DIR)
MONITOR_BIN_PATH = resolve_path(MONITOR_BIN)
VERIFIER_BIN_PATH = resolve_path(VERIFIER_BIN)

if COLLECTOR_CONFIG == "config/collector_config.json" and not BASE_COLLECTOR_CONFIG_PATH.exists():
    BASE_COLLECTOR_CONFIG_PATH = ROOT / "policies/fastapi-monitor-policy.json"

if VERIFIER_POLICY == "config/verifier_policy.json" and not VERIFIER_POLICY_PATH.exists():
    VERIFIER_POLICY_PATH = ROOT / "policies/fastapi-verifier-policy.json"


def run_command(
    args: list[str | Path],
    *,
    check: bool = True,
    capture: bool = False,
    env: dict[str, str] | None = None,
    cwd: Path = ROOT,
) -> subprocess.CompletedProcess[str]:
    rendered = [str(arg) for arg in args]
    log("$ " + " ".join(rendered))

    result = subprocess.run(
        rendered,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        check=False,
        env=env,
    )

    if check and result.returncode != 0:
        if capture and result.stdout:
            print(result.stdout, file=sys.stderr, end="")
        fail(f"command failed with status {result.returncode}: {' '.join(rendered)}")

    return result


def http_get(path: str) -> None:
    url = f"{BASE_URL}{path}"
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT_SECS) as response:
            response.read()
    except urllib.error.URLError as exc:
        fail(f"HTTP request failed for {url}: {exc}")


def wait_for_ping() -> None:
    deadline = time.monotonic() + WORKLOAD_TIMEOUT_SECS
    last_error: BaseException | None = None

    while time.monotonic() < deadline:
        try:
            http_get("/ping")
            return
        except IntegrationFailure as exc:
            last_error = exc
            time.sleep(0.5)

    fail(f"workload did not become ready at {BASE_URL}/ping: {last_error}")


def read_monitor_log() -> str:
    if monitor_log_handle is not None:
        monitor_log_handle.flush()
    if monitor_log_path is None or not monitor_log_path.exists():
        return ""
    return monitor_log_path.read_text(encoding="utf-8", errors="replace")


def print_monitor_log_tail() -> None:
    if monitor_log_path is None or not monitor_log_path.exists():
        return

    print(f"--- monitor log tail: {monitor_log_path} ---", file=sys.stderr)
    try:
        lines = read_monitor_log().splitlines()
        for line in lines[-80:]:
            print(line, file=sys.stderr)
    except OSError as exc:
        print(f"failed to read monitor log: {exc}", file=sys.stderr)
    print("--- end monitor log tail ---", file=sys.stderr)


def kill_process_group(pid: int, sig: str) -> None:
    # The monitor is started through sudo in a new process group. Signalling the
    # group is more reliable than signalling only the sudo wrapper process.
    run_command([*PRIVILEGE_PREFIX, "kill", f"-{sig}", "--", f"-{pid}"], check=False)


def stop_monitor() -> None:
    global monitor_proc, monitor_log_handle, monitor_log_path

    proc = monitor_proc
    if proc is None:
        return

    monitor_proc = None

    if proc.poll() is None:
        kill_process_group(proc.pid, "INT")
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            kill_process_group(proc.pid, "TERM")
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                kill_process_group(proc.pid, "KILL")
                proc.wait(timeout=5)

    if monitor_log_handle is not None:
        monitor_log_handle.close()
        monitor_log_handle = None


def teardown_workload_if_requested() -> None:
    if not TEARDOWN_WORKLOAD or not workload_started:
        return

    stop_script = ROOT / "scripts/stop_workload.sh"
    if stop_script.exists():
        run_command([stop_script], check=False)
        return

    # Fallback for repos without a dedicated stop script.
    run_command(["docker", "compose", "down"], check=False, cwd=ROOT)
    workload_dir = ROOT / "workload"
    if workload_dir.exists():
        run_command(["docker", "compose", "down"], check=False, cwd=workload_dir)


def cleanup() -> None:
    stop_monitor()
    teardown_workload_if_requested()


def remove_if_exists(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return


def case_paths(case_name: str) -> CasePaths:
    LOG_DIR_PATH.mkdir(parents=True, exist_ok=True)
    return CasePaths(
        name=case_name,
        collector_config=LOG_DIR_PATH / f"collector_config_{case_name}.json",
        evidence=LOG_DIR_PATH / f"runtime_events_{case_name}.jsonl",
        summary=LOG_DIR_PATH / f"runtime_events_{case_name}.summary.json",
        monitor_log=LOG_DIR_PATH / f"integration_monitor_{case_name}.log",
    )


def clean_case(paths: CasePaths) -> None:
    for path in [paths.collector_config, paths.evidence, paths.summary, paths.monitor_log]:
        remove_if_exists(path)


def clean_integration_logs() -> None:
    LOG_DIR_PATH.mkdir(parents=True, exist_ok=True)
    for path in LOG_DIR_PATH.glob("runtime_events_*.jsonl"):
        path.unlink()
    for path in LOG_DIR_PATH.glob("runtime_events_*.summary.json"):
        path.unlink()
    for path in LOG_DIR_PATH.glob("collector_config_*.json"):
        path.unlink()
    for path in LOG_DIR_PATH.glob("integration_monitor_*.log"):
        path.unlink()


def write_case_collector_config(paths: CasePaths) -> None:
    if not BASE_COLLECTOR_CONFIG_PATH.exists():
        fail(f"missing collector config: {BASE_COLLECTOR_CONFIG_PATH}")

    try:
        config = json.loads(BASE_COLLECTOR_CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"collector config is not valid JSON: {BASE_COLLECTOR_CONFIG_PATH}: {exc}")

    # Force test-specific evidence output so stale/default logs cannot satisfy
    # assertions accidentally. Preserve all other collector config fields.
    config["evidence_out"] = str(paths.evidence)
    config.setdefault("collection_mode", "scoped")

    paths.collector_config.write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def wait_for_monitor_ready() -> None:
    deadline = time.monotonic() + MONITOR_STARTUP_TIMEOUT_SECS
    minimum_wait_until = time.monotonic() + MONITOR_STARTUP_SECS

    while time.monotonic() < deadline:
        if monitor_proc is None:
            fail("monitor was not started")
        if monitor_proc.poll() is not None:
            print_monitor_log_tail()
            fail("monitor exited before test traffic")

        if MONITOR_READY_PATTERN:
            if MONITOR_READY_PATTERN in read_monitor_log():
                return
        elif time.monotonic() >= minimum_wait_until:
            # The current monitor does not expose a formal readiness signal.
            # Keep the legacy delay but poll the process during the wait.
            return

        time.sleep(0.1)

    if MONITOR_READY_PATTERN:
        print_monitor_log_tail()
        fail(f"monitor did not print readiness pattern: {MONITOR_READY_PATTERN!r}")
    fail("monitor did not become ready before timeout")


def start_monitor(paths: CasePaths) -> float:
    global monitor_proc, monitor_log_handle, monitor_log_path

    if not MONITOR_BIN_PATH.exists():
        fail(f"missing monitor binary: {MONITOR_BIN_PATH}")

    write_case_collector_config(paths)
    monitor_log_path = paths.monitor_log
    monitor_log_handle = monitor_log_path.open("w", encoding="utf-8")

    cmd = [*PRIVILEGE_PREFIX, str(MONITOR_BIN_PATH), "--collector-config", str(paths.collector_config)]
    log("$ " + " ".join(cmd))
    started_at = time.time()
    monitor_proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        text=True,
        stdout=monitor_log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    wait_for_monitor_ready()
    return started_at


def assert_fresh_evidence(paths: CasePaths, min_mtime: float) -> None:
    if not paths.evidence.exists():
        fail(f"missing evidence file {paths.evidence}")
    if paths.evidence.stat().st_size == 0:
        fail(f"evidence file is empty: {paths.evidence}")
    if paths.evidence.stat().st_mtime < min_mtime:
        fail(f"evidence file is stale: {paths.evidence}")


def run_verifier(paths: CasePaths) -> subprocess.CompletedProcess[str]:
    if not VERIFIER_BIN_PATH.exists():
        fail(f"missing verifier binary: {VERIFIER_BIN_PATH}")
    if not VERIFIER_POLICY_PATH.exists():
        fail(f"missing verifier policy: {VERIFIER_POLICY_PATH}")

    args: list[str | Path] = [
        VERIFIER_BIN_PATH,
        "--policy",
        VERIFIER_POLICY_PATH,
        "--evidence",
        paths.evidence,
    ]
    if paths.summary.exists():
        args.extend(["--summary", paths.summary])

    return run_command(args, check=False, capture=True)


def expect_accept(paths: CasePaths) -> None:
    result = run_verifier(paths)
    print(result.stdout, end="")

    if result.returncode != 0:
        fail("expected ACCEPT")
    if not result.stdout.startswith("ACCEPT:"):
        fail("verifier did not print ACCEPT")


def expect_reject(paths: CasePaths) -> None:
    result = run_verifier(paths)
    print(result.stdout, end="")

    if result.returncode == 0:
        fail("expected REJECT, got ACCEPT")
    if not result.stdout.startswith("REJECT:"):
        fail("verifier did not print REJECT")


def assert_evidence_contains(paths: CasePaths, expected: str) -> None:
    content = paths.evidence.read_text(encoding="utf-8", errors="replace")
    if expected not in content:
        fail(f"evidence does not contain {expected}")


def run_echo_case() -> None:
    log("== scoped /echo case ==")
    paths = case_paths("echo")
    clean_case(paths)
    started_at = start_monitor(paths)
    http_get("/ping")
    http_get("/echo")
    stop_monitor()
    assert_fresh_evidence(paths, started_at)
    assert_evidence_contains(paths, "/usr/bin/echo")
    expect_accept(paths)
    log("PASS: scoped /echo case")


def run_bad_case() -> None:
    log("== scoped /bad case ==")
    paths = case_paths("bad")
    clean_case(paths)
    started_at = start_monitor(paths)
    http_get("/bad")
    stop_monitor()
    assert_fresh_evidence(paths, started_at)
    assert_evidence_contains(paths, "/usr/bin/id")
    expect_reject(paths)
    log("PASS: scoped /bad case")


def main() -> int:
    global workload_started

    try:
        if PRIVILEGE_PREFIX:
            privilege_check = run_command([*PRIVILEGE_PREFIX, "true"], check=False, capture=True)
            if privilege_check.returncode != 0:
                if privilege_check.stdout:
                    print(privilege_check.stdout, file=sys.stderr, end="")
                fail(
                    "passwordless privilege escalation is required; "
                    "run as root or set SUDO to a non-interactive command such as 'sudo -n'"
                )
        run_command([ROOT / "scripts/build_all.sh"])
        clean_integration_logs()
        run_command([ROOT / "scripts/run_workload.sh"])
        workload_started = True
        wait_for_ping()

        run_echo_case()
        run_bad_case()

        log("V1 integration tests passed")
        return 0
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except IntegrationFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        print_monitor_log_tail()
        return 1
    finally:
        cleanup()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
