#!/usr/bin/env python3
import argparse
import collections
import json
from pathlib import Path


def key(value):
    return "<missing>" if value is None else str(value)


def main():
    parser = argparse.ArgumentParser(description="Summarise runtime evidence JSONL")
    parser.add_argument(
        "evidence",
        nargs="?",
        default="logs/runtime_events.jsonl",
        help="Path to runtime_events.jsonl",
    )
    args = parser.parse_args()

    evidence = Path(args.evidence)
    counts = collections.Counter()
    total = 0

    with evidence.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            event = json.loads(line)
            total += 1
            counts[
                (
                    key(event.get("exe_path")),
                    key(event.get("comm")),
                    key(event.get("cgroup_id")),
                    key(event.get("workload_id")),
                )
            ] += 1

    print(f"events={total}")
    print("count\texe_path\tcomm\tcgroup_id\tworkload_id")
    for (exe_path, comm, cgroup_id, workload_id), count in counts.most_common():
        print(f"{count}\t{exe_path}\t{comm}\t{cgroup_id}\t{workload_id}")


if __name__ == "__main__":
    main()
