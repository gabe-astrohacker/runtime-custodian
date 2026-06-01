#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
COLLECTOR_CONFIG="${COLLECTOR_CONFIG:-config/collector_config.json}"
VERIFIER_POLICY="${VERIFIER_POLICY:-config/verifier_policy.json}"
EVIDENCE="${EVIDENCE:-logs/runtime_events.jsonl}"
SUMMARY="${SUMMARY:-logs/runtime_events.summary.json}"
MONITOR_BIN="${MONITOR_BIN:-target/debug/runtime-monitor}"
VERIFIER_BIN="${VERIFIER_BIN:-target/debug/runtime-verifier}"
MONITOR_STARTUP_SECS="${MONITOR_STARTUP_SECS:-2}"

MONITOR_PID=""

resolve_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$ROOT" "$1" ;;
  esac
}

COLLECTOR_CONFIG_PATH="$(resolve_path "$COLLECTOR_CONFIG")"
VERIFIER_POLICY_PATH="$(resolve_path "$VERIFIER_POLICY")"
EVIDENCE_PATH="$(resolve_path "$EVIDENCE")"
SUMMARY_PATH="$(resolve_path "$SUMMARY")"
MONITOR_BIN_PATH="$(resolve_path "$MONITOR_BIN")"
VERIFIER_BIN_PATH="$(resolve_path "$VERIFIER_BIN")"

if [[ "$COLLECTOR_CONFIG" == "config/collector_config.json" && ! -f "$COLLECTOR_CONFIG_PATH" ]]; then
  COLLECTOR_CONFIG_PATH="$ROOT/policies/fastapi-monitor-policy.json"
fi

if [[ "$VERIFIER_POLICY" == "config/verifier_policy.json" && ! -f "$VERIFIER_POLICY_PATH" ]]; then
  VERIFIER_POLICY_PATH="$ROOT/policies/fastapi-verifier-policy.json"
fi

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

stop_monitor() {
  if [[ -z "${MONITOR_PID:-}" ]]; then
    return
  fi

  sudo -n kill -INT "$MONITOR_PID" >/dev/null 2>&1 || true
  wait "$MONITOR_PID" >/dev/null 2>&1 || true
  MONITOR_PID=""
}

cleanup() {
  stop_monitor
  if [[ -f "$ROOT/scripts/stop_workload.sh" ]]; then
    "$ROOT/scripts/stop_workload.sh" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

clean_logs() {
  mkdir -p "$(dirname "$EVIDENCE_PATH")"
  LOG_DIR="$(dirname "$EVIDENCE_PATH")" "$ROOT/scripts/clean_logs.sh"
  rm -f "$SUMMARY_PATH"
}

start_monitor() {
  sudo -n "$MONITOR_BIN_PATH" --collector-config "$COLLECTOR_CONFIG_PATH" &
  MONITOR_PID=$!
  sleep "$MONITOR_STARTUP_SECS"
  sudo -n kill -0 "$MONITOR_PID" >/dev/null 2>&1 || fail "monitor exited before test traffic"
}

run_verifier() {
  local args=(--policy "$VERIFIER_POLICY_PATH" --evidence "$EVIDENCE_PATH")
  if [[ -f "$SUMMARY_PATH" ]]; then
    args+=(--summary "$SUMMARY_PATH")
  fi

  "$VERIFIER_BIN_PATH" "${args[@]}"
}

expect_accept() {
  local output
  if ! output="$(run_verifier 2>&1)"; then
    echo "$output" >&2
    fail "expected ACCEPT"
  fi

  echo "$output"
  grep -q '^ACCEPT:' <<<"$output" || fail "verifier did not print ACCEPT"
}

expect_reject() {
  local output
  local status

  set +e
  output="$(run_verifier 2>&1)"
  status=$?
  set -e

  echo "$output"
  if [[ "$status" -eq 0 ]]; then
    fail "expected REJECT, got ACCEPT"
  fi
  grep -q '^REJECT:' <<<"$output" || fail "verifier did not print REJECT"
}

assert_evidence_contains() {
  local expected="$1"

  [[ -f "$EVIDENCE_PATH" ]] || fail "missing evidence file $EVIDENCE_PATH"
  grep -Fq "$expected" "$EVIDENCE_PATH" || fail "evidence does not contain $expected"
}

run_echo_case() {
  echo "== scoped /echo case =="
  clean_logs
  start_monitor
  curl -fsS "$BASE_URL/ping" >/dev/null
  curl -fsS "$BASE_URL/echo" >/dev/null
  stop_monitor
  expect_accept
  assert_evidence_contains "/usr/bin/echo"
}

run_bad_case() {
  echo "== scoped /bad case =="
  clean_logs
  start_monitor
  curl -fsS "$BASE_URL/bad" >/dev/null
  stop_monitor
  expect_reject
  assert_evidence_contains "/usr/bin/id"
}

sudo -n true || fail "passwordless sudo is required; run as root or configure sudo -n"
"$ROOT/scripts/build_all.sh"
"$ROOT/scripts/run_workload.sh"

run_echo_case
run_bad_case

echo "V1 integration tests passed"
