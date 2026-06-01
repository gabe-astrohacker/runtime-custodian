#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


METRICS = ("mean_ms", "median_ms", "p95_ms", "min_ms", "max_ms")


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def overhead(baseline, monitored):
    absolute = monitored - baseline
    percent = 0.0 if baseline == 0 else (absolute / baseline) * 100.0
    return absolute, percent


def main():
    parser = argparse.ArgumentParser(description="Summarise monitored latency overhead")
    parser.add_argument("--baseline", required=True, help="Baseline latency JSON")
    parser.add_argument("--monitored", required=True, help="Monitored latency JSON")
    args = parser.parse_args()

    baseline = load(args.baseline)
    monitored = load(args.monitored)

    print("Latency overhead summary")
    print(f"baseline_count={baseline.get('count', 0)} monitored_count={monitored.get('count', 0)}")
    print("metric\tbaseline_ms\tmonitored_ms\toverhead_ms\toverhead_percent")

    for metric in METRICS:
        base_value = float(baseline.get(metric, 0.0))
        monitored_value = float(monitored.get(metric, 0.0))
        absolute, percent = overhead(base_value, monitored_value)
        print(
            f"{metric}\t{base_value:.3f}\t{monitored_value:.3f}\t"
            f"{absolute:.3f}\t{percent:.2f}%"
        )


if __name__ == "__main__":
    main()
