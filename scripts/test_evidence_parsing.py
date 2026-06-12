#!/usr/bin/env python3
"""Lightweight checks for evidence JSONL parsing helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from integration_lib import IntegrationFailure, iter_runtime_evidence_events


def write_jsonl(path: Path, records: list[object]) -> None:
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )


class EvidenceParsingTests(unittest.TestCase):
    def test_tagged_runtime_events_skip_synthetic_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            evidence = Path(tmpdir) / "evidence.jsonl"
            write_jsonl(
                evidence,
                [
                    {
                        "record_kind": "synthetic",
                        "record": {
                            "record_type": "monitor-start",
                            "session_id": "session-1",
                            "seq_no": 0,
                        },
                    },
                    {
                        "record_kind": "runtime-event",
                        "record": {
                            "session_id": "session-1",
                            "seq_no": 1,
                            "event": {
                                "event_type": "exec",
                                "workload_id": "fastapi-echo",
                                "comm": "python3",
                                "exe_path": "/usr/bin/python3",
                                "cgroup_id": 42,
                            },
                            "classification": "acceptable",
                        },
                    },
                ],
            )

            events = list(iter_runtime_evidence_events(evidence))

            self.assertEqual(len(events), 1)
            self.assertFalse(events[0].legacy)
            self.assertEqual(events[0].event["exe_path"], "/usr/bin/python3")
            self.assertEqual(events[0].record["classification"], "acceptable")

    def test_legacy_flat_runtime_event_is_counted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            evidence = Path(tmpdir) / "legacy.jsonl"
            write_jsonl(
                evidence,
                [
                    {
                        "event_type": "exec",
                        "workload_id": "legacy-workload",
                        "comm": "bash",
                        "exe_path": "/usr/bin/bash",
                        "cgroup_id": 7,
                    }
                ],
            )

            events = list(iter_runtime_evidence_events(evidence))

            self.assertEqual(len(events), 1)
            self.assertTrue(events[0].legacy)
            self.assertEqual(events[0].event["workload_id"], "legacy-workload")

    def test_invalid_json_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            evidence = Path(tmpdir) / "bad.jsonl"
            evidence.write_text('{"event_type": "exec"\n', encoding="utf-8")

            with self.assertRaisesRegex(IntegrationFailure, "invalid JSON"):
                list(iter_runtime_evidence_events(evidence))

    def test_unknown_json_object_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            evidence = Path(tmpdir) / "unknown.jsonl"
            write_jsonl(evidence, [{"session_id": "session-1", "seq_no": 1}])

            with self.assertRaisesRegex(IntegrationFailure, "missing record_kind and not a legacy runtime event"):
                list(iter_runtime_evidence_events(evidence))

    def test_event_type_only_is_not_legacy_runtime_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            evidence = Path(tmpdir) / "event-type-only.jsonl"
            write_jsonl(evidence, [{"event_type": "exec"}])

            with self.assertRaisesRegex(IntegrationFailure, "not a legacy runtime event"):
                list(iter_runtime_evidence_events(evidence))

    def test_tagged_runtime_event_missing_event_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            evidence = Path(tmpdir) / "missing-event.jsonl"
            write_jsonl(
                evidence,
                [
                    {
                        "record_kind": "runtime-event",
                        "record": {
                            "session_id": "session-1",
                            "seq_no": 1,
                            "classification": "acceptable",
                        },
                    }
                ],
            )

            with self.assertRaisesRegex(IntegrationFailure, "record.event"):
                list(iter_runtime_evidence_events(evidence))


if __name__ == "__main__":
    unittest.main()
