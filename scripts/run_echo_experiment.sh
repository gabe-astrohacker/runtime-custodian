#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
VERIFIER_BIN="${VERIFIER_BIN:-$ROOT/target/debug/runtime-verifier}"
POLICY="${POLICY:-$ROOT/policies/fastapi-verifier-policy.json}"
EVIDENCE="${EVIDENCE:-$ROOT/logs/runtime_events.jsonl}"
SUMMARY="${SUMMARY:-$ROOT/logs/runtime_events.summary.json}"

"$ROOT/scripts/clean_logs.sh"

curl -fsS "$BASE_URL/ping"
echo
curl -fsS "$BASE_URL/echo"
echo

args=(--policy "$POLICY" --evidence "$EVIDENCE")
if [[ -f "$SUMMARY" ]]; then
  args+=(--summary "$SUMMARY")
fi

"$VERIFIER_BIN" "${args[@]}"

echo "Expected result: ACCEPT"
