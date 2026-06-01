#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT/workloads/fast-api-workload/compose.yml}"
PROJECT_DIR="${PROJECT_DIR:-$ROOT/workloads/fast-api-workload}"
PING_TIMEOUT_SECS="${PING_TIMEOUT_SECS:-60}"

docker compose \
  -f "$COMPOSE_FILE" \
  --project-directory "$PROJECT_DIR" \
  up -d --build

deadline=$((SECONDS + PING_TIMEOUT_SECS))
until curl -fsS "$BASE_URL/ping" >/dev/null; do
  if (( SECONDS >= deadline )); then
    echo "Timed out waiting for $BASE_URL/ping" >&2
    exit 1
  fi
  sleep 1
done

echo "Workload is ready at $BASE_URL"
