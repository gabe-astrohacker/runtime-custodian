#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="$ROOT/runtime-monitors/runtime-monitor"

sudo "$WORKSPACE/target/debug/runtime-monitor" --collector-config "$ROOT/policies/fastapi-monitor-policy.json"
