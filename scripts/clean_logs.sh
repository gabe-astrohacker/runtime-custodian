#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${LOG_DIR:-$ROOT/logs}"

rm -f "$LOG_DIR"/*.jsonl "$LOG_DIR"/*summary*.json
