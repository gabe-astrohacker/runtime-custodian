#!/usr/bin/env bash
set -euo pipefail

# Prototype composition wrapper only.
# This does not integrate with or modify Keylime internals; it combines an
# external Keylime pass/fail result with this prototype's runtime verifier.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_VERIFIER="${RUNTIME_VERIFIER:-$ROOT/target/debug/runtime-verifier}"

runtime_policy=""
runtime_evidence=""
keylime_result_file=""
keylime_command=""

usage() {
  cat <<'EOF'
usage:
  combined_attestation.sh --runtime-policy <path> --runtime-evidence <path> \
    (--keylime-result-file <json> | --keylime-command "<cmd>")

file mode expects simple JSON, for example: {"keylime_passed": true}
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-policy)
      runtime_policy="${2:-}"
      shift 2
      ;;
    --runtime-evidence)
      runtime_evidence="${2:-}"
      shift 2
      ;;
    --keylime-result-file)
      keylime_result_file="${2:-}"
      shift 2
      ;;
    --keylime-command)
      keylime_command="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$runtime_policy" || -z "$runtime_evidence" ]]; then
  usage >&2
  exit 2
fi

if [[ -n "$keylime_result_file" && -n "$keylime_command" ]]; then
  echo "provide only one of --keylime-result-file or --keylime-command" >&2
  exit 2
fi

if [[ -z "$keylime_result_file" && -z "$keylime_command" ]]; then
  echo "provide --keylime-result-file or --keylime-command" >&2
  exit 2
fi

keylime_passed=false
if [[ -n "$keylime_result_file" ]]; then
  keylime_passed="$(
    python3 - "$keylime_result_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)

print("true" if data.get("keylime_passed") is True else "false")
PY
  )"
else
  if bash -c "$keylime_command"; then
    keylime_passed=true
  fi
fi

runtime_passed=false
if "$RUNTIME_VERIFIER" --policy "$runtime_policy" --evidence "$runtime_evidence"; then
  runtime_passed=true
fi

if [[ "$keylime_passed" == "true" ]]; then
  echo "keylime_result=PASS"
else
  echo "keylime_result=FAIL"
fi

if [[ "$runtime_passed" == "true" ]]; then
  echo "runtime_result=PASS"
else
  echo "runtime_result=FAIL"
fi

if [[ "$keylime_passed" == "true" && "$runtime_passed" == "true" ]]; then
  echo "final_result=ACCEPT"
else
  echo "final_result=REJECT"
  exit 1
fi
