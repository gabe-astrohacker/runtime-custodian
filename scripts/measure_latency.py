#!/usr/bin/env python3
import argparse
import json
import statistics
import time
import urllib.request
from pathlib import Path


def percentile(values, percentile):
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def request_latency_ms(url):
    start = time.perf_counter()
    with urllib.request.urlopen(url, timeout=30) as response:
        response.read()
    end = time.perf_counter()
    return (end - start) * 1000.0


def summarise(latencies):
    return {
        "count": len(latencies),
        "mean_ms": statistics.fmean(latencies) if latencies else 0.0,
        "median_ms": statistics.median(latencies) if latencies else 0.0,
        "p95_ms": percentile(latencies, 0.95),
        "min_ms": min(latencies) if latencies else 0.0,
        "max_ms": max(latencies) if latencies else 0.0,
        "raw_latencies_ms": latencies,
    }


def main():
    parser = argparse.ArgumentParser(description="Measure HTTP request latency")
    parser.add_argument("--url", required=True, help="Endpoint URL to request")
    parser.add_argument("--requests", required=True, type=int, help="Number of requests to send")
    parser.add_argument("--out", required=True, help="Output JSON path")
    args = parser.parse_args()

    if args.requests < 1:
        raise SystemExit("--requests must be at least 1")

    latencies = [request_latency_ms(args.url) for _ in range(args.requests)]
    result = summarise(latencies)

    out = Path(args.out)
    if out.parent != Path("."):
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(
        "count={count} mean_ms={mean_ms:.3f} median_ms={median_ms:.3f} "
        "p95_ms={p95_ms:.3f} min_ms={min_ms:.3f} max_ms={max_ms:.3f}".format(**result)
    )


if __name__ == "__main__":
    main()
