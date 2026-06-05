#!/usr/bin/env python3
import argparse
import collections
from pathlib import Path

from integration_lib import IntegrationFailure, iter_runtime_evidence_events


def key(value):
    return "<missing>" if value is None else str(value)


def main():
    parser = argparse.ArgumentParser(description="Summarise runtime evidence JSONL")
    parser.add_argument(
        "evidence",
        help="Path to runtime evidence JSONL, e.g. logs/integration/runtime_events_echo.jsonl",
    )

    args = parser.parse_args()

    evidence = Path(args.evidence)
    counts = collections.Counter()
    total = 0

    try:
        for runtime_event in iter_runtime_evidence_events(evidence):
            event = runtime_event.event
            record = runtime_event.record
            total += 1
            counts[
                (
                    key(event.get("event_type")),
                    key(event.get("exe_path")),
                    key(event.get("comm")),
                    key(event.get("cgroup_id")),
                    key(event.get("workload_id")),
                    key(record.get("classification")),
                )
            ] += 1
    except IntegrationFailure as exc:
        raise SystemExit(str(exc)) from exc

    print(f"events={total}")
    print("count\tevent_type\texe_path\tcomm\tcgroup_id\tworkload_id\tclassification")
    for (event_type, exe_path, comm, cgroup_id, workload_id, classification), count in counts.most_common():
        print(f"{count}\t{event_type}\t{exe_path}\t{comm}\t{cgroup_id}\t{workload_id}\t{classification}")


if __name__ == "__main__":
    main()
