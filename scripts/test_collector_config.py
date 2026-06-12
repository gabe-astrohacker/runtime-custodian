#!/usr/bin/env python3
"""Lightweight checks for integration collector config rewriting."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from integration_lib import CasePaths, RuntimeHarness, Settings


def make_settings(tmpdir: Path, base_config: Path) -> Settings:
    return Settings(
        root=tmpdir,
        base_url="http://127.0.0.1:8000",
        base_collector_config=base_config,
        verifier_policy=tmpdir / "verifier-policy.json",
        log_dir=tmpdir / "logs",
        monitor_bin=tmpdir / "runtime-monitor",
        verifier_bin=tmpdir / "runtime-verifier",
        monitor_startup_secs=0.0,
        monitor_startup_timeout_secs=0.0,
        monitor_ready_pattern="",
        http_timeout_secs=0.0,
        workload_timeout_secs=0.0,
        teardown_workload=False,
        privilege_prefix=[],
    )


def make_paths(tmpdir: Path, name: str) -> CasePaths:
    return CasePaths(
        name=name,
        collector_config=tmpdir / f"collector_config_{name}.json",
        evidence=tmpdir / f"runtime_events_{name}.jsonl",
        summary=tmpdir / f"runtime_events_{name}.summary.json",
        monitor_log=tmpdir / f"integration_monitor_{name}.log",
    )


class CollectorConfigTests(unittest.TestCase):
    def assert_rewritten_outputs(self, base_config_data: dict[str, object]) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            base_config = tmpdir / "base_collector_config.json"
            base_config.write_text(json.dumps(base_config_data) + "\n", encoding="utf-8")

            paths = make_paths(tmpdir, "case")
            harness = RuntimeHarness(make_settings(tmpdir, base_config))
            harness.write_case_collector_config(
                paths,
                overrides={
                    "collection_mode": "host-wide",
                    "summary_out": str(tmpdir / "stale-summary.json"),
                },
            )

            written = json.loads(paths.collector_config.read_text(encoding="utf-8"))

            self.assertEqual(written["evidence_out"], str(paths.evidence))
            self.assertEqual(written["summary_out"], str(paths.summary))
            self.assertEqual(written["collection_mode"], "host-wide")

    def test_single_workload_config_sets_case_evidence_and_summary_paths(self) -> None:
        self.assert_rewritten_outputs(
            {
                "workload_id": "fastapi-echo",
                "container_name": "fastapi-echo",
                "evidence_out": "logs/runtime_events.jsonl",
            }
        )

    def test_multi_workload_config_sets_case_evidence_and_summary_paths(self) -> None:
        self.assert_rewritten_outputs(
            {
                "workloads": [
                    {
                        "workload_id": "fastapi-echo",
                        "container_name": "fastapi-echo",
                    },
                    {
                        "workload_id": "fastapi-worker",
                        "container_name": "fastapi-worker",
                    },
                ],
                "evidence_out": "logs/runtime_events.jsonl",
            }
        )


if __name__ == "__main__":
    unittest.main()
