#!/usr/bin/env python3
"""Stage 9E argv-sensitive policy smoke test.

This is an opt-in integration smoke test. It loads eBPF via the runtime monitor,
so it requires the same sudo/Docker prerequisites as the other integration
scripts. The test prefers scoped capture by running a controlled Python command
inside the configured Docker workload with `docker exec`; if that is not
available, it falls back to host-wide capture of a local Python command.

The important assertions are made on the marker-bearing exec-attempt evidence
records themselves. Overall verifier ACCEPT-WITH-WARNINGS is allowed because
Stage 9D does not correlate exec-attempt records with later successful
sched_process_exec records, and successful exec records usually have empty argv.
"""

from __future__ import annotations

import json
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from integration_lib import IntegrationFailure, RuntimeHarness, Settings, log


CONTAINER_NAME = "fastapi-echo"
WORKLOAD_ID = "fastapi-echo"


@dataclass(frozen=True)
class CaptureTarget:
    collection_mode: str
    workload_id: str
    command_prefix: tuple[str, ...]
    interpreter: str


class ArgvSensitiveSmoke(RuntimeHarness):
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.trainer_bin = settings.root / "target/debug/runtime-policy-trainer"

    def run(self) -> int:
        try:
            self.check_privileges()
            self.build()
            self.clean_logs(
                self.settings.log_dir,
                [
                    "argv_sensitive_*",
                    "runtime_events_argv-sensitive-*.jsonl",
                    "runtime_events_argv-sensitive-*.summary.json",
                    "collector_config_argv-sensitive-*.json",
                    "integration_monitor_argv-sensitive-*.log",
                ],
            )

            self.workload.start()
            target = self.choose_capture_target()
            log(
                "argv-sensitive smoke capture mode: "
                f"{target.collection_mode} workload_id={target.workload_id}"
            )

            run_id = f"{int(time.time())}-{id(self)}"
            allowed_marker = f"stage9e_allowed_{run_id}"
            mismatch_marker = f"stage9e_mismatch_{run_id}"

            baseline_paths = self.capture_python_invocation(
                "argv-sensitive-baseline",
                target,
                allowed_marker,
                runtime_policy=None,
            )
            allowed_record = find_marker_exec_attempt(baseline_paths.evidence, allowed_marker)
            assert_record_has_argv(allowed_record, allowed_marker)

            metadata_path = self.settings.log_dir / "argv_sensitive_training.json"
            trained_policy_path = self.settings.log_dir / "argv_sensitive_trained_policy.json"
            self.run_trainer(target, baseline_paths, trained_policy_path, metadata_path)
            self.assert_training_metadata(metadata_path, allowed_marker)

            argv_policy_path = self.settings.log_dir / "argv_sensitive_policy.json"
            write_argv_sensitive_policy(
                argv_policy_path,
                target.workload_id,
                allowed_record["event"]["exe_path"],
                allowed_record["event"]["argv"],
            )

            allowed_paths = self.capture_python_invocation(
                "argv-sensitive-allowed",
                target,
                allowed_marker,
                runtime_policy=argv_policy_path,
            )
            allowed_report_path = self.settings.log_dir / "argv_sensitive_allowed_report.json"
            allowed_verifier = self.run_verifier_with_policy(
                allowed_paths,
                argv_policy_path,
                allowed_report_path,
            )
            allowed_event = find_marker_exec_attempt(allowed_paths.evidence, allowed_marker)
            assert_marker_classification(
                allowed_event,
                classification="acceptable",
                rule_id="acceptable-argv-invocation",
            )
            assert_accept_or_warning(allowed_verifier, allowed_report_path)

            mismatch_paths = self.capture_python_invocation(
                "argv-sensitive-mismatch",
                target,
                mismatch_marker,
                runtime_policy=argv_policy_path,
            )
            mismatch_report_path = self.settings.log_dir / "argv_sensitive_mismatch_report.json"
            mismatch_verifier = self.run_verifier_with_policy(
                mismatch_paths,
                argv_policy_path,
                mismatch_report_path,
            )
            mismatch_event = find_marker_exec_attempt(
                mismatch_paths.evidence,
                mismatch_marker,
            )
            assert_marker_classification(
                mismatch_event,
                classification="suspicious",
                rule_id="argv-sensitive-mismatch",
            )
            assert_mismatch_report(mismatch_verifier, mismatch_report_path)

            log("Stage 9E argv-sensitive policy smoke passed")
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

    def choose_capture_target(self) -> CaptureTarget:
        probe_marker = f"stage9e_probe_{int(time.time())}"
        last_probe_output = ""
        for interpreter in ("python", "python3"):
            probe = self.runner.run(
                [
                    "docker",
                    "exec",
                    CONTAINER_NAME,
                    interpreter,
                    "-c",
                    f"print('{probe_marker}')",
                ],
                check=False,
                capture=True,
            )
            if probe.returncode == 0:
                return CaptureTarget(
                    collection_mode="scoped",
                    workload_id=WORKLOAD_ID,
                    command_prefix=("docker", "exec", CONTAINER_NAME),
                    interpreter=interpreter,
                )
            last_probe_output = probe.stdout or last_probe_output

        if last_probe_output:
            print(last_probe_output, file=sys.stderr, end="")
        log("docker exec was not available for the workload; falling back to host-wide capture")
        return CaptureTarget(
            collection_mode="host-wide",
            workload_id="host-wide",
            command_prefix=(),
            interpreter=sys.executable,
        )

    def capture_python_invocation(
        self,
        case_name: str,
        target: CaptureTarget,
        marker: str,
        *,
        runtime_policy: Path | None,
    ):
        paths = self.case_paths(case_name)
        self.clean_case(paths)
        overrides: dict[str, object] = {
            "capture_argv": True,
            "collection_mode": target.collection_mode,
            "summary_out": str(paths.summary),
        }
        if runtime_policy is not None:
            overrides["runtime_policy"] = str(runtime_policy)
        self.write_case_collector_config(paths, overrides=overrides)

        started_at = self.monitor.start(paths)
        try:
            self.run_python_marker(target, marker)
        finally:
            self.monitor.stop()

        self.assert_fresh_evidence(paths, started_at)
        find_marker_exec_attempt(paths.evidence, marker)
        return paths

    def run_python_marker(self, target: CaptureTarget, marker: str) -> None:
        script = f"print('{marker}')"
        if target.command_prefix:
            command = [*target.command_prefix, target.interpreter, "-c", script]
        else:
            command = [target.interpreter, "-c", script]
        self.runner.run(command)

    def run_trainer(
        self,
        target: CaptureTarget,
        paths,
        policy_out: Path,
        metadata_out: Path,
    ) -> None:
        if not self.trainer_bin.exists():
            raise IntegrationFailure(f"missing policy trainer binary: {self.trainer_bin}")

        args: list[str | Path] = [
            self.trainer_bin,
            "--evidence",
            paths.evidence,
            "--summary",
            paths.summary,
        ]
        if target.collection_mode == "scoped":
            args.extend(["--workload-id", target.workload_id])
        args.extend(["--out", policy_out, "--metadata-out", metadata_out])

        result = self.runner.run(args, check=False, capture=True)
        if result.returncode == 0:
            return

        if result.stdout:
            print(result.stdout, file=sys.stderr, end="")
        if target.collection_mode == "host-wide":
            raise IntegrationFailure(
                "runtime-policy-trainer failed for host-wide fallback evidence. "
                "If the capture contains multiple workload IDs, rerun with scoped "
                "container capture or train manually with --workload-id."
            )
        raise IntegrationFailure("runtime-policy-trainer failed for scoped argv smoke evidence")

    def assert_training_metadata(self, metadata_path: Path, marker: str) -> None:
        metadata = read_json(metadata_path)
        assert_metadata_has_marker(
            metadata,
            "observed_exec_attempt_invocations",
            marker,
        )
        assert_metadata_has_marker(
            metadata,
            "observed_interpreter_invocations",
            marker,
        )

    def run_verifier_with_policy(self, paths, policy_path: Path, report_path: Path):
        if not self.settings.verifier_bin.exists():
            raise IntegrationFailure(f"missing verifier binary: {self.settings.verifier_bin}")

        result = self.runner.run(
            [
                self.settings.verifier_bin,
                "--policy",
                policy_path,
                "--evidence",
                paths.evidence,
                "--summary",
                paths.summary,
                "--report",
                report_path,
            ],
            check=False,
            capture=True,
        )
        if result.stdout:
            print(result.stdout, end="")
        return result


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise IntegrationFailure(f"failed to read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise IntegrationFailure(f"failed to parse JSON {path}: {exc}") from exc


def read_evidence(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise IntegrationFailure(
                        f"failed to parse evidence {path} line {line_no}: {exc}"
                    ) from exc
    except OSError as exc:
        raise IntegrationFailure(f"failed to read evidence {path}: {exc}") from exc
    return records


def runtime_event_records(path: Path) -> list[dict[str, Any]]:
    events = []
    for record in read_evidence(path):
        if record.get("record_kind") == "runtime-event":
            events.append(record["record"])
    return events


def find_marker_exec_attempt(path: Path, marker: str) -> dict[str, Any]:
    matches = []
    for record in runtime_event_records(path):
        event = record.get("event", {})
        argv = event.get("argv", [])
        if event.get("event_type") == "exec-attempt" and any(marker in arg for arg in argv):
            matches.append(record)

    if not matches:
        raise IntegrationFailure(
            f"missing marker-bearing exec-attempt record for marker {marker}"
        )
    if len(matches) > 1:
        raise IntegrationFailure(
            f"expected one marker-bearing exec-attempt for {marker}, got {len(matches)}"
        )
    return matches[0]


def assert_record_has_argv(record: dict[str, Any], marker: str) -> None:
    argv = record.get("event", {}).get("argv", [])
    if not argv:
        raise IntegrationFailure(f"marker record for {marker} has empty argv")


def assert_marker_classification(
    record: dict[str, Any],
    *,
    classification: str,
    rule_id: str,
) -> None:
    actual_classification = record.get("classification")
    actual_rule_id = record.get("rule_id")
    if actual_classification != classification or actual_rule_id != rule_id:
        raise IntegrationFailure(
            "marker exec-attempt classification mismatch: "
            f"expected {classification}/{rule_id}, "
            f"got {actual_classification}/{actual_rule_id}"
        )


def assert_metadata_has_marker(metadata: dict[str, Any], field: str, marker: str) -> None:
    invocations = metadata.get(field)
    if not isinstance(invocations, list):
        raise IntegrationFailure(f"training metadata field {field} is missing or not a list")

    for invocation in invocations:
        argv = invocation.get("argv", [])
        if any(marker in arg for arg in argv):
            return

    raise IntegrationFailure(f"training metadata field {field} does not contain marker {marker}")


def write_argv_sensitive_policy(
    path: Path,
    workload_id: str,
    exe_path: str,
    argv: list[str],
) -> None:
    policy = {
        "workload_id": workload_id,
        "profile_mode": "minimal-behaviour",
        "acceptable": {
            "exec_paths": [],
            "event_types": ["fork"],
            "argv_sensitive_exec_paths": [exe_path],
            "allowed_invocations": [
                {
                    "exe_path": exe_path,
                    "argv": argv,
                    "match_type": "exact",
                }
            ],
        },
        "suspicious": {
            "unknown_exec_path": True,
        },
        "denied": {
            "exec_paths": [],
            "comm_names": [],
        },
        "attestation": {
            "backend": "none",
            "mode": "software-chain",
            "fail_on_suspicious": False,
            "fail_on_denied": True,
            "fail_on_drops": True,
        },
    }
    path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log(f"wrote argv-sensitive verifier policy: {path}")


def report_decision(report_path: Path) -> str:
    report = read_json(report_path)
    decision = report.get("decision")
    if not isinstance(decision, str):
        raise IntegrationFailure(f"verifier report {report_path} is missing string decision")
    return decision


def assert_accept_or_warning(result, report_path: Path) -> None:
    decision = report_decision(report_path)
    if decision not in {"accept", "accept-with-warnings"}:
        raise IntegrationFailure(
            "expected verifier report decision accept or accept-with-warnings, "
            f"got {decision}"
        )
    if result.returncode != 0:
        raise IntegrationFailure(
            f"verifier report decision was {decision}, but process exited "
            f"with status {result.returncode}"
        )


def assert_mismatch_report(result, report_path: Path) -> None:
    decision = report_decision(report_path)
    if decision in {"reject", "invalid-evidence"}:
        raise IntegrationFailure(
            f"expected mismatched argv to be suspicious/warning, got {decision}"
        )
    if decision != "accept-with-warnings":
        raise IntegrationFailure(
            "expected mismatched argv verifier decision accept-with-warnings, "
            f"got {decision}"
        )
    if result.returncode != 0:
        raise IntegrationFailure(
            f"mismatched argv report decision was {decision}, but process "
            f"exited with status {result.returncode}"
        )


def main() -> int:
    settings = Settings.from_env()
    return ArgvSensitiveSmoke(settings).run()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
