#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT/workloads/fast-api-workload/compose.yml}"
PROJECT_DIR="${PROJECT_DIR:-$ROOT/workloads/fast-api-workload}"

docker compose \
  -f "$COMPOSE_FILE" \
  --project-directory "$PROJECT_DIR" \
  down
