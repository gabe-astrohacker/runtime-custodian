#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_ROOT="${LOG_ROOT:-$ROOT/logs}"

rm -f "$LOG_ROOT"/integration/runtime_events_*.jsonl
rm -f "$LOG_ROOT"/integration/runtime_events_*.summary.json
rm -f "$LOG_ROOT"/integration/collector_config_*.json
rm -f "$LOG_ROOT"/integration/integration_monitor_*.log

rm -f "$LOG_ROOT"/experiments/*.json
rm -f "$LOG_ROOT"/experiments/*.csv
rm -f "$LOG_ROOT"/experiments/runtime_events_*.jsonl
rm -f "$LOG_ROOT"/experiments/runtime_events_*.summary.json
rm -f "$LOG_ROOT"/experiments/collector_config_*.json
rm -f "$LOG_ROOT"/experiments/integration_monitor_*.log

echo "Cleaned integration and experiment logs under $LOG_ROOT"