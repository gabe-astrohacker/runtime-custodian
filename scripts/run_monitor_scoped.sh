#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MONITOR_BIN="${MONITOR_BIN:-$ROOT/target/debug/runtime-monitor}"
COLLECTOR_CONFIG="${COLLECTOR_CONFIG:-$ROOT/policies/fastapi-monitor-policy.json}"

sudo "$MONITOR_BIN" --collector-config "$COLLECTOR_CONFIG"
