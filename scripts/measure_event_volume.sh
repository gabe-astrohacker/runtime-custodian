#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
DURATION_SECS="${DURATION_SECS:-10}"
ECHO_REQUESTS="${ECHO_REQUESTS:-20}"
LOG_DIR="${LOG_DIR:-$ROOT/logs}"
MONITOR_BIN="${MONITOR_BIN:-$ROOT/target/debug/runtime-monitor}"
HOST_WIDE_EVIDENCE="${HOST_WIDE_EVIDENCE:-$LOG_DIR/host_wide_events.jsonl}"
SCOPED_EVIDENCE="${SCOPED_EVIDENCE:-$LOG_DIR/scoped_events.jsonl}"
WORKLOAD_ID="${WORKLOAD_ID:-fastapi-echo}"
CONTAINER_NAME="${CONTAINER_NAME:-fastapi-echo}"

mkdir -p "$LOG_DIR"
"$ROOT/scripts/run_workload.sh"
rm -f "$HOST_WIDE_EVIDENCE" "$SCOPED_EVIDENCE" "$LOG_DIR"/*summary*.json

make_config() {
  local mode="$1"
  local evidence="$2"
  local config="$3"

  cat >"$config" <<EOF
{
  "workload_id": "$WORKLOAD_ID",
  "container_name": "$CONTAINER_NAME",
  "collection_mode": "$mode",
  "evidence_out": "$evidence"
}
EOF
}

hit_echo() {
  for _ in $(seq 1 "$ECHO_REQUESTS"); do
    curl -fsS "$BASE_URL/echo" >/dev/null
  done
}

run_capture() {
  local label="$1"
  local mode="$2"
  local evidence="$3"
  local config="$LOG_DIR/${label}_collector_config.json"

  make_config "$mode" "$evidence" "$config"

  echo "Starting $label monitor for ${DURATION_SECS}s..."
  sudo "$MONITOR_BIN" --collector-config "$config" &
  local monitor_pid=$!

  sleep 1
  hit_echo

  local deadline=$((SECONDS + DURATION_SECS))
  while (( SECONDS < deadline )); do
    sleep 1
  done

  kill -INT "$monitor_pid" 2>/dev/null || true
  wait "$monitor_pid" || true
}

event_count() {
  python3 - "$1" <<'PY'
import json
import sys

count = 0
with open(sys.argv[1], encoding="utf-8") as handle:
    for line in handle:
        if line.strip():
            json.loads(line)
            count += 1
print(count)
PY
}

top_exec_paths() {
  python3 - "$1" <<'PY'
import collections
import json
import sys

counts = collections.Counter()
with open(sys.argv[1], encoding="utf-8") as handle:
    for line in handle:
        if line.strip():
            event = json.loads(line)
            counts[event.get("exe_path") or "<missing>"] += 1

for exe_path, count in counts.most_common(10):
    print(f"{count}\t{exe_path}")
PY
}

run_capture "host_wide" "host-wide" "$HOST_WIDE_EVIDENCE"
run_capture "scoped" "scoped" "$SCOPED_EVIDENCE"

echo
echo "Host-wide event summary"
"$ROOT/scripts/count_events.py" "$HOST_WIDE_EVIDENCE"

echo
echo "Scoped event summary"
"$ROOT/scripts/count_events.py" "$SCOPED_EVIDENCE"

host_wide_count="$(event_count "$HOST_WIDE_EVIDENCE")"
scoped_count="$(event_count "$SCOPED_EVIDENCE")"
absolute_reduction=$((host_wide_count - scoped_count))
percent_reduction="$(python3 - "$host_wide_count" "$scoped_count" <<'PY'
import sys

host = int(sys.argv[1])
scoped = int(sys.argv[2])
if host == 0:
    print("0.00")
else:
    print(f"{((host - scoped) / host) * 100.0:.2f}")
PY
)"

echo
echo "Event volume reduction"
echo "host_wide_event_count=$host_wide_count"
echo "scoped_event_count=$scoped_count"
echo "absolute_reduction=$absolute_reduction"
echo "percent_reduction=${percent_reduction}%"

echo
echo "Top host-wide exec paths"
top_exec_paths "$HOST_WIDE_EVIDENCE"

echo
echo "Top scoped exec paths"
top_exec_paths "$SCOPED_EVIDENCE"
