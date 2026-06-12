#!/usr/bin/env python3
"""Security experiments for the runtime evidence prototype.

This is the security counterpart to the performance experiment scripts. It
evaluates the two security properties the system claims, and unlike the
correctness smoke tests it produces a structured, reproducible results matrix.

Experiments:
- tamper:    a systematic tamper-evidence matrix. A single valid evidence
             baseline (evidence + summary + policy) is mutated one way at a
             time, the verifier is replayed over each mutation, and we record
             which verifier check fired and whether the tamper was detected.
             This is offline and deterministic: it only re-runs the verifier,
             so it needs neither sudo, Docker, nor eBPF.
- detection: behavioural detection (live). Runs a benign and a denied workload
             case through the real monitor and records the verifier decision
             and the rule that fired. Requires the same sudo/Docker/eBPF
             prerequisites as the other integration scripts.

The headline experiment is `tamper`: it drives the verifier's independent
re-derivation (sequence, per-event hash, software chain, counts, lifecycle,
session, policy binding) and demonstrates that post-collection evidence
manipulation is caught. The pass criterion is the security property itself --
every tamper must be detected (decision is not accept/accept-with-warnings) --
while the *which check fired* mapping is reported as measured data rather than
assumed.

Results are written to JSON and CSV under logs/experiments by default.
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from integration_lib import (
    CommandRunner,
    EvidenceJsonRecord,
    IntegrationFailure,
    RuntimeHarness,
    Settings,
    assert_release_binaries,
    deep_set,
    environment_metadata,
    fail,
    failed_checks,
    log,
    mutated_record,
    read_evidence_lines,
    read_report,
    resolve_path,
    run_verifier_cli,
    write_evidence_lines,
)

# Decisions that mean "the verifier accepted this evidence as authentic".
# A tamper is only "detected" if the decision is NOT one of these.
ACCEPTING_DECISIONS = frozenset({"accept", "accept-with-warnings"})


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Baseline:
    """A valid evidence triple to be tampered with."""

    records: list[EvidenceJsonRecord]
    summary: dict[str, Any]
    policy: dict[str, Any]
    evidence_path: Path
    summary_path: Path
    policy_path: Path

    def runtime_event_indices(self) -> list[int]:
        return [
            i
            for i, r in enumerate(self.records)
            if r.data.get("record_kind") == "runtime-event"
        ]

    def synthetic_indices(self) -> list[int]:
        return [
            i
            for i, r in enumerate(self.records)
            if r.data.get("record_kind") == "synthetic"
        ]


def load_baseline(evidence: Path, summary: Path, policy: Path) -> Baseline:
    for path in (evidence, summary, policy):
        if not path.exists():
            fail(f"missing baseline file: {path}")
    return Baseline(
        records=read_evidence_lines(evidence),
        summary=json.loads(summary.read_text(encoding="utf-8")),
        policy=json.loads(policy.read_text(encoding="utf-8")),
        evidence_path=evidence,
        summary_path=summary,
        policy_path=policy,
    )


# ---------------------------------------------------------------------------
# Tamper operators
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MutatedTriple:
    evidence: Path
    summary: Path
    policy: Path


@dataclass(frozen=True)
class TamperCase:
    name: str
    description: str
    # The verifier guarantee this attacks, for the results table.
    guarantee: str
    # The check we expect to catch it (reported as "precise" if it does).
    primary_check: str
    # apply(baseline, out_dir) -> the mutated triple to verify.
    apply: Callable[[Baseline, Path], MutatedTriple]


def _write_records(out_dir: Path, records: list[EvidenceJsonRecord]) -> Path:
    path = out_dir / "evidence.jsonl"
    write_evidence_lines(path, records)
    return path


def _write_summary(out_dir: Path, summary: dict[str, Any]) -> Path:
    path = out_dir / "summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_policy(out_dir: Path, policy: dict[str, Any]) -> Path:
    path = out_dir / "policy.json"
    path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _evidence_mutation(base: Baseline, out_dir: Path, records: list[EvidenceJsonRecord]) -> MutatedTriple:
    """Evidence was mutated; summary and policy are the untouched originals."""
    return MutatedTriple(
        evidence=_write_records(out_dir, records),
        summary=base.summary_path,
        policy=base.policy_path,
    )


def tamper_edit_exe_path(base: Baseline, out_dir: Path) -> MutatedTriple:
    records = list(base.records)
    idx = base.runtime_event_indices()[0]
    new_data = deep_set(records[idx].data, "record.event.exe_path", "/usr/bin/this-was-tampered")
    records[idx] = mutated_record(records[idx], new_data)
    return _evidence_mutation(base, out_dir, records)


def tamper_flip_classification(base: Baseline, out_dir: Path) -> MutatedTriple:
    records = list(base.records)
    idx = base.runtime_event_indices()[0]
    current = records[idx].data.get("record", {}).get("classification")
    replacement = "acceptable" if current != "acceptable" else "denied"
    new_data = deep_set(records[idx].data, "record.classification", replacement)
    records[idx] = mutated_record(records[idx], new_data)
    return _evidence_mutation(base, out_dir, records)


def tamper_forge_event_hash(base: Baseline, out_dir: Path) -> MutatedTriple:
    records = list(base.records)
    idx = base.runtime_event_indices()[0]
    forged = "0" * 64
    original = records[idx].data.get("record", {}).get("event_hash")
    if original == forged:
        forged = "1" * 64
    new_data = deep_set(records[idx].data, "record.event_hash", forged)
    records[idx] = mutated_record(records[idx], new_data)
    return _evidence_mutation(base, out_dir, records)


def tamper_corrupt_chain_head(base: Baseline, out_dir: Path) -> MutatedTriple:
    records = list(base.records)
    idx = base.runtime_event_indices()[len(base.runtime_event_indices()) // 2]
    forged = "f" * 64
    original = records[idx].data.get("record", {}).get("software_chain_head")
    if original == forged:
        forged = "e" * 64
    new_data = deep_set(records[idx].data, "record.software_chain_head", forged)
    records[idx] = mutated_record(records[idx], new_data)
    return _evidence_mutation(base, out_dir, records)


def tamper_edit_session_id(base: Baseline, out_dir: Path) -> MutatedTriple:
    records = list(base.records)
    idx = base.runtime_event_indices()[0]
    original = records[idx].data.get("record", {}).get("session_id", "")
    forged = ("a" * 64) if original != ("a" * 64) else ("b" * 64)
    new_data = deep_set(records[idx].data, "record.session_id", forged)
    records[idx] = mutated_record(records[idx], new_data)
    return _evidence_mutation(base, out_dir, records)


def tamper_delete_record(base: Baseline, out_dir: Path) -> MutatedTriple:
    indices = base.runtime_event_indices()
    drop = indices[len(indices) // 2]
    records = [r for i, r in enumerate(base.records) if i != drop]
    return _evidence_mutation(base, out_dir, records)


def tamper_duplicate_record(base: Baseline, out_dir: Path) -> MutatedTriple:
    indices = base.runtime_event_indices()
    dup = indices[len(indices) // 2]
    records = list(base.records)
    records.insert(dup + 1, records[dup])
    return _evidence_mutation(base, out_dir, records)


def tamper_reorder_records(base: Baseline, out_dir: Path) -> MutatedTriple:
    indices = base.runtime_event_indices()
    a, b = indices[len(indices) // 2], indices[len(indices) // 2 + 1]
    records = list(base.records)
    records[a], records[b] = records[b], records[a]
    return _evidence_mutation(base, out_dir, records)


def tamper_truncate_tail(base: Baseline, out_dir: Path) -> MutatedTriple:
    # Drop the final five records, which include the monitor-stop lifecycle
    # record, so the evidence log ends abruptly.
    records = base.records[:-5]
    return _evidence_mutation(base, out_dir, records)


def tamper_edit_synthetic(base: Baseline, out_dir: Path) -> MutatedTriple:
    records = list(base.records)
    idx = base.synthetic_indices()[0]
    new_data = deep_set(records[idx].data, "record.reason", "tampered synthetic reason")
    records[idx] = mutated_record(records[idx], new_data)
    return _evidence_mutation(base, out_dir, records)


def tamper_policy_hash_mismatch(base: Baseline, out_dir: Path) -> MutatedTriple:
    # Verify with a policy that differs from the one bound into the evidence.
    policy = copy.deepcopy(base.policy)
    acceptable = policy.setdefault("acceptable", {})
    exec_paths = acceptable.setdefault("exec_paths", [])
    if isinstance(exec_paths, list):
        exec_paths.append("/usr/bin/this-path-was-added-after-collection")
    else:  # schema drift guard
        fail("baseline policy has unexpected acceptable.exec_paths shape")
    return MutatedTriple(
        evidence=base.evidence_path,
        summary=base.summary_path,
        policy=_write_policy(out_dir, policy),
    )


def tamper_summary_count_mismatch(base: Baseline, out_dir: Path) -> MutatedTriple:
    summary = copy.deepcopy(base.summary)
    # Inflate a classification count so it no longer reconciles with the log.
    for key in ("suspicious_count", "acceptable_count", "event_count"):
        if key in summary and isinstance(summary[key], int):
            summary[key] = summary[key] + 1
            break
    else:
        fail("baseline summary has no integer count field to perturb")
    return MutatedTriple(
        evidence=base.evidence_path,
        summary=_write_summary(out_dir, summary),
        policy=base.policy_path,
    )


def tamper_summary_chain_mismatch(base: Baseline, out_dir: Path) -> MutatedTriple:
    summary = copy.deepcopy(base.summary)
    if "software_chain_head" not in summary:
        fail("baseline summary has no software_chain_head to perturb")
    forged = "c" * 64
    if summary["software_chain_head"] == forged:
        forged = "d" * 64
    summary["software_chain_head"] = forged
    return MutatedTriple(
        evidence=base.evidence_path,
        summary=_write_summary(out_dir, summary),
        policy=base.policy_path,
    )


TAMPER_CASES: tuple[TamperCase, ...] = (
    TamperCase(
        "edit-exe-path",
        "Rewrite a runtime event's executable path",
        "per-event integrity (canonical event hash)",
        "event_hashes_valid",
        tamper_edit_exe_path,
    ),
    TamperCase(
        "forge-event-hash",
        "Replace a recorded per-event hash with a forged value",
        "per-event integrity (canonical event hash)",
        "event_hashes_valid",
        tamper_forge_event_hash,
    ),
    TamperCase(
        "flip-classification",
        "Relabel a suspicious event as acceptable",
        "independent re-classification",
        "classification_valid",
        tamper_flip_classification,
    ),
    TamperCase(
        "edit-session-id",
        "Change one record's session identifier",
        "session binding",
        "session_valid",
        tamper_edit_session_id,
    ),
    TamperCase(
        "corrupt-chain-head",
        "Corrupt a record's rolling software-chain head",
        "tamper-evident hash chain",
        "software_chain_valid",
        tamper_corrupt_chain_head,
    ),
    TamperCase(
        "delete-record",
        "Delete a runtime event from the middle of the log",
        "sequence contiguity",
        "sequence_valid",
        tamper_delete_record,
    ),
    TamperCase(
        "duplicate-record",
        "Duplicate a runtime event (replayed sequence number)",
        "sequence contiguity",
        "sequence_valid",
        tamper_duplicate_record,
    ),
    TamperCase(
        "reorder-records",
        "Swap two adjacent runtime events",
        "sequence / hash chain ordering",
        "software_chain_valid",
        tamper_reorder_records,
    ),
    TamperCase(
        "truncate-tail",
        "Drop the tail of the log, removing monitor-stop",
        "lifecycle completeness",
        "lifecycle_valid",
        tamper_truncate_tail,
    ),
    TamperCase(
        "edit-synthetic",
        "Edit a synthetic lifecycle record's contents",
        "synthetic record integrity",
        "synthetic_hashes_valid",
        tamper_edit_synthetic,
    ),
    TamperCase(
        "policy-hash-mismatch",
        "Verify against a policy altered after collection",
        "policy binding (policy_hash)",
        "policy_hash_valid",
        tamper_policy_hash_mismatch,
    ),
    TamperCase(
        "summary-count-mismatch",
        "Inflate a classification count in the summary",
        "count reconciliation",
        "counts_valid",
        tamper_summary_count_mismatch,
    ),
    TamperCase(
        "summary-chain-mismatch",
        "Corrupt the final software-chain head in the summary",
        "final chain commitment",
        "software_chain_valid",
        tamper_summary_chain_mismatch,
    ),
)


# ---------------------------------------------------------------------------
# Tamper experiment driver
# ---------------------------------------------------------------------------


@dataclass
class TamperResult:
    name: str
    description: str
    guarantee: str
    primary_check: str
    decision: str | None
    detected: bool
    precise: bool
    failed_checks: list[str]
    returncode: int


def run_tamper_experiment(
    settings: Settings,
    runner: CommandRunner,
    base: Baseline,
    work_dir: Path,
) -> dict[str, Any]:
    log(f"== tamper matrix over baseline {base.evidence_path.name} "
        f"({len(base.records)} records) ==")

    # Sanity-check the baseline itself verifies before we start mutating it.
    baseline_report = work_dir / "baseline_report.json"
    baseline_proc = run_verifier_cli(
        settings,
        runner,
        evidence=base.evidence_path,
        summary=base.summary_path,
        policy=base.policy_path,
        report=baseline_report,
    )
    baseline_json = read_report(baseline_report)
    baseline_decision = baseline_json.get("decision")
    baseline_failed = failed_checks(baseline_json)
    if baseline_failed:
        fail(
            f"baseline is not clean (failed checks {baseline_failed}); "
            "tamper results would be meaningless"
        )
    log(f"baseline decision={baseline_decision} (clean, all checks pass)")

    results: list[TamperResult] = []
    for case in TAMPER_CASES:
        case_dir = work_dir / case.name
        case_dir.mkdir(parents=True, exist_ok=True)
        try:
            triple = case.apply(base, case_dir)
        except IntegrationFailure as exc:
            fail(f"tamper case {case.name} could not be applied: {exc}")

        report_path = case_dir / "report.json"
        proc = run_verifier_cli(
            settings,
            runner,
            evidence=triple.evidence,
            summary=triple.summary,
            policy=triple.policy,
            report=report_path,
        )
        report = read_report(report_path)
        decision = report.get("decision")
        failed = failed_checks(report)
        detected = decision not in ACCEPTING_DECISIONS
        precise = case.primary_check in failed
        results.append(
            TamperResult(
                name=case.name,
                description=case.description,
                guarantee=case.guarantee,
                primary_check=case.primary_check,
                decision=decision,
                detected=detected,
                precise=precise,
                failed_checks=failed,
                returncode=proc.returncode,
            )
        )
        status = "DETECTED" if detected else "MISSED"
        precise_note = "" if precise else f" (caught by {failed or 'n/a'}, not {case.primary_check})"
        log(f"  {case.name:<24} decision={decision:<20} {status}{precise_note}")

    detected_count = sum(1 for r in results if r.detected)
    precise_count = sum(1 for r in results if r.precise)
    log(f"tamper matrix: {detected_count}/{len(results)} detected, "
        f"{precise_count}/{len(results)} caught by the expected check")

    return {
        "baseline": {
            "evidence": str(base.evidence_path),
            "summary": str(base.summary_path),
            "policy": str(base.policy_path),
            "record_count": len(base.records),
            "decision": baseline_decision,
        },
        "cases": [vars(r) for r in results],
        "detected_count": detected_count,
        "total_count": len(results),
        "precise_count": precise_count,
    }


# ---------------------------------------------------------------------------
# Behavioural detection experiment (live)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionCase:
    name: str
    http_paths: tuple[str, ...]
    expect_accept: bool
    note: str


DETECTION_CASES: tuple[DetectionCase, ...] = (
    DetectionCase("benign", ("/ping", "/echo"), True, "expected exec paths only"),
    DetectionCase("denied", ("/bad",), False, "invokes a denied executable (/usr/bin/id)"),
)


def run_detection_experiment(settings: Settings, work_dir: Path) -> dict[str, Any]:
    harness = RuntimeHarness(settings)
    harness.check_privileges()
    harness.build()
    results: list[dict[str, Any]] = []
    try:
        harness.workload.start()
        for case in DETECTION_CASES:
            log(f"== detection case {case.name}: {case.note} ==")
            paths = harness.case_paths(f"security_detection_{case.name}", log_dir=work_dir)
            harness.clean_case(paths)
            harness.write_case_collector_config(paths, overrides={"collection_mode": "scoped"})
            harness.monitor.start(paths)
            try:
                for path in case.http_paths:
                    harness.workload.get(path)
            finally:
                harness.monitor.stop()

            report_path = work_dir / f"detection_report_{case.name}.json"
            proc = run_verifier_cli(
                settings,
                harness.runner,
                evidence=paths.evidence,
                summary=paths.summary,
                report=report_path,
            )
            report = read_report(report_path)
            decision = report.get("decision")
            accepted = decision in ACCEPTING_DECISIONS
            correct = accepted == case.expect_accept
            results.append({
                "name": case.name,
                "expected": "accept" if case.expect_accept else "reject",
                "decision": decision,
                "correct": correct,
                "first_denied_event": report.get("first_denied_event"),
                "first_suspicious_event": report.get("first_suspicious_event"),
                "returncode": proc.returncode,
            })
            log(f"  {case.name}: decision={decision} "
                f"({'correct' if correct else 'INCORRECT'})")
    finally:
        harness.cleanup()

    return {
        "cases": results,
        "correct_count": sum(1 for r in results if r["correct"]),
        "total_count": len(results),
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def write_tamper_csv(path: Path, tamper: dict[str, Any]) -> None:
    fieldnames = [
        "name", "guarantee", "primary_check", "decision",
        "detected", "precise", "failed_checks", "returncode", "description",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for case in tamper["cases"]:
            row = dict(case)
            row["failed_checks"] = ";".join(case["failed_checks"])
            writer.writerow({k: row.get(k) for k in fieldnames})


def write_results(output_dir: Path, name: str, result: dict[str, Any]) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    paths: list[Path] = []
    json_path = output_dir / f"{name}_{stamp}.json"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths.append(json_path)
    if "tamper" in result:
        csv_path = output_dir / f"{name}_{stamp}_tamper.csv"
        write_tamper_csv(csv_path, result["tamper"])
        paths.append(csv_path)
    return paths


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Security experiments for runtime-custodian.")
    parser.add_argument(
        "--experiment",
        choices=("tamper", "detection", "both"),
        default="tamper",
        help="which security experiment to run (default: tamper, offline)",
    )
    parser.add_argument("--name", default="security_experiment", help="output artefact base name")
    parser.add_argument("--output-dir", default="logs/experiments", help="output directory")
    parser.add_argument(
        "--work-dir",
        default="logs/experiments/security_work",
        help="scratch directory for mutated evidence",
    )
    parser.add_argument("--baseline-evidence", help="baseline evidence JSONL for the tamper matrix")
    parser.add_argument("--baseline-summary", help="baseline summary JSON for the tamper matrix")
    parser.add_argument("--baseline-policy", help="baseline policy JSON for the tamper matrix")
    parser.add_argument(
        "--allow-debug",
        action="store_true",
        help="permit non-release binaries (sets ALLOW_DEBUG_BINARIES for this run)",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    settings = Settings.from_env()

    if args.allow_debug:
        import os
        os.environ["ALLOW_DEBUG_BINARIES"] = "1"
    assert_release_binaries(settings)

    output_dir = resolve_path(settings.root, args.output_dir)
    work_dir = resolve_path(settings.root, args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    runner = CommandRunner(settings.root)

    result: dict[str, Any] = {
        "experiment": args.experiment,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "environment": environment_metadata(settings),
    }

    overall_ok = True

    if args.experiment in ("tamper", "both"):
        if not (args.baseline_evidence and args.baseline_summary and args.baseline_policy):
            fail(
                "the tamper experiment needs a baseline triple: pass "
                "--baseline-evidence, --baseline-summary and --baseline-policy "
                "(any valid scoped run's evidence/summary/policy works)"
            )
        base = load_baseline(
            resolve_path(settings.root, args.baseline_evidence),
            resolve_path(settings.root, args.baseline_summary),
            resolve_path(settings.root, args.baseline_policy),
        )
        tamper = run_tamper_experiment(settings, runner, base, work_dir)
        result["tamper"] = tamper
        if tamper["detected_count"] != tamper["total_count"]:
            overall_ok = False

    if args.experiment in ("detection", "both"):
        detection = run_detection_experiment(settings, work_dir)
        result["detection"] = detection
        if detection["correct_count"] != detection["total_count"]:
            overall_ok = False

    written = write_results(output_dir, args.name, result)
    for path in written:
        log(f"wrote {path}")

    return 0 if overall_ok else 1


def _install_sigint() -> None:
    def handler(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handler)


if __name__ == "__main__":
    _install_sigint()
    try:
        sys.exit(main(sys.argv[1:]))
    except IntegrationFailure as exc:
        print(f"security experiment failed: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        sys.exit(130)
