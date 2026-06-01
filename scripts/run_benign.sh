#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="$ROOT/runtime-monitors/runtime-monitor"
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"

curl -fsS "$BASE_URL/ping"
echo
curl -fsS "$BASE_URL/echo"
echo

"$WORKSPACE/target/debug/runtime-verifier" \
  --policy "$ROOT/policies/fastapi-verifier-policy.json" \
  --evidence "$ROOT/logs/runtime_events.jsonl"

echo "Expected result: ACCEPT"
