#!/usr/bin/env bash
set -euo pipefail

# Manual non-privileged smoke test for Stage 8 TPM quote support.
#
# This verifies:
#   tpm2-tools -> TPM2TOOLS_TCTI=swtpm:... -> swtpm
#   AK creation -> tpm2_quote -> tpm2_checkquote
#
# It does not run the runtime monitor, does not use a real hardware TPM, does
# not use sudo, and does not prove AK/EK certificate trust, Keylime identity,
# platform identity, or recorder protection.

PCR="${PCR:-23}"
HASH_BANK="${HASH_BANK:-sha256}"
DIGEST_HEX="${DIGEST_HEX:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
TPM2_TIMEOUT_SECS="${TPM2_TIMEOUT_SECS:-10}"
KEEP_SWTPM="${KEEP_SWTPM:-0}"

require_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "missing required command: $command_name" >&2
        exit 127
    fi
}

require_command swtpm
require_command tpm2_startup
require_command tpm2_pcrread
require_command tpm2_pcrreset
require_command tpm2_pcrextend
require_command tpm2_createek
require_command tpm2_createak
require_command tpm2_quote
require_command tpm2_checkquote
require_command tpm2_flushcontext
require_command python3
require_command awk
require_command timeout

if [[ "$HASH_BANK" != "sha256" ]]; then
    echo "unsupported HASH_BANK=$HASH_BANK; runtime-monitor currently supports sha256 only" >&2
    exit 2
fi

if ! [[ "$PCR" =~ ^[0-9]+$ ]] || (( PCR < 0 || PCR > 23 )); then
    echo "PCR must be an integer in range 0..=23; got $PCR" >&2
    exit 2
fi

if ! [[ "$DIGEST_HEX" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "DIGEST_HEX must be a 64-character SHA-256 hex digest" >&2
    exit 2
fi

DIGEST_HEX="$(printf '%s' "$DIGEST_HEX" | tr 'A-F' 'a-f')"

if [[ -n "${NONCE_HEX:-}" ]]; then
    if ! [[ "$NONCE_HEX" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "NONCE_HEX must be a 64-character SHA-256 hex nonce" >&2
        exit 2
    fi
    NONCE_HEX="$(printf '%s' "$NONCE_HEX" | tr 'A-F' 'a-f')"
else
    NONCE_HEX="$(
        python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
    )"
fi

TMP_DIR="$(mktemp -d)"
STATE_DIR="$TMP_DIR/tpm-state"
PID_FILE="$TMP_DIR/swtpm.pid"
SWTPM_LOG="$TMP_DIR/swtpm.log"
SWTPM_STDOUT="$TMP_DIR/swtpm.stdout"
SWTPM_STDERR="$TMP_DIR/swtpm.stderr"
ARTIFACT_DIR="$TMP_DIR/artifacts"

mkdir -p "$STATE_DIR" "$ARTIFACT_DIR"

cleanup() {
    if [[ "$KEEP_SWTPM" == "1" ]]; then
        echo "KEEP_SWTPM=1 set; leaving swtpm running/state in $TMP_DIR" >&2
        return
    fi

    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid="$(cat "$PID_FILE")"

        if [[ -n "$pid" ]]; then
            kill "$pid" >/dev/null 2>&1 || true

            for _ in {1..20}; do
                if ! kill -0 "$pid" >/dev/null 2>&1; then
                    break
                fi
                sleep 0.05
            done

            kill -9 "$pid" >/dev/null 2>&1 || true
            wait "$pid" >/dev/null 2>&1 || true
        fi
    fi

    rm -rf "$TMP_DIR"
}

trap cleanup EXIT

read -r SERVER_PORT CTRL_PORT < <(
    python3 - <<'PY'
import socket

for candidate in range(2321, 65534):
    server = socket.socket()
    ctrl = socket.socket()

    try:
        server.bind(("127.0.0.1", candidate))
        ctrl.bind(("127.0.0.1", candidate + 1))
    except OSError:
        server.close()
        ctrl.close()
        continue

    print(candidate, candidate + 1)
    server.close()
    ctrl.close()
    break
else:
    raise SystemExit("could not find a free adjacent TCP port pair")
PY
)

if [[ -z "${SERVER_PORT:-}" || -z "${CTRL_PORT:-}" ]]; then
    echo "failed to select swtpm TCP ports" >&2
    exit 1
fi

echo "Starting swtpm on 127.0.0.1:$SERVER_PORT control port $CTRL_PORT"
echo "Temporary state: $STATE_DIR"
echo "Artifacts: $ARTIFACT_DIR"

swtpm socket \
    --tpm2 \
    --tpmstate "dir=$STATE_DIR" \
    --ctrl "type=tcp,port=$CTRL_PORT,bindaddr=127.0.0.1" \
    --server "type=tcp,port=$SERVER_PORT,bindaddr=127.0.0.1" \
    --flags not-need-init \
    --log "file=$SWTPM_LOG,level=20" \
    >"$SWTPM_STDOUT" 2>"$SWTPM_STDERR" &

echo "$!" > "$PID_FILE"

TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$SERVER_PORT"
export TPM2TOOLS_TCTI

echo "Started swtpm pid=$(cat "$PID_FILE")"
echo "Using TPM2TOOLS_TCTI=$TPM2TOOLS_TCTI"

print_swtpm_debug() {
    echo "swtpm debug information:" >&2

    echo "--- swtpm log: $SWTPM_LOG ---" >&2
    cat "$SWTPM_LOG" >&2 2>/dev/null || true

    echo "--- swtpm stdout: $SWTPM_STDOUT ---" >&2
    cat "$SWTPM_STDOUT" >&2 2>/dev/null || true

    echo "--- swtpm stderr: $SWTPM_STDERR ---" >&2
    cat "$SWTPM_STDERR" >&2 2>/dev/null || true
}

wait_for_swtpm() {
    local pid
    pid="$(cat "$PID_FILE")"

    for _ in {1..50}; do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            echo "swtpm exited before becoming ready" >&2
            print_swtpm_debug
            exit 1
        fi

        if timeout 1 bash -c ":</dev/tcp/127.0.0.1/$SERVER_PORT" >/dev/null 2>&1; then
            return 0
        fi

        sleep 0.1
    done

    echo "swtpm did not become ready on 127.0.0.1:$SERVER_PORT" >&2
    print_swtpm_debug
    exit 1
}

run_tpm2() {
    local description="$1"
    shift

    local output
    local status

    set +e
    output="$(timeout "${TPM2_TIMEOUT_SECS}s" "$@" 2>&1)"
    status=$?
    set -e

    if (( status != 0 )); then
        echo "TPM command failed or timed out while trying to: $description" >&2
        echo "command: $*" >&2
        echo "exit status: $status" >&2
        echo "TPM2TOOLS_TCTI=$TPM2TOOLS_TCTI" >&2

        if [[ -n "$output" ]]; then
            echo "--- command output ---" >&2
            echo "$output" >&2
        fi

        print_swtpm_debug
        exit "$status"
    fi

    printf '%s\n' "$output"
}

pcr_read() {
    run_tpm2 "read PCR $PCR" tpm2_pcrread "$HASH_BANK:$PCR" |
        awk -v pcr="$PCR" '
            $1 == pcr ":" || $1 == pcr":" {
                digest = tolower($2)
                sub(/^0x/, "", digest)
                print digest
                found = 1
                exit
            }
            END {
                if (!found) {
                    exit 1
                }
            }
        '
}

expected_extend() {
    python3 - "$1" "$2" <<'PY'
import hashlib
import sys

old_pcr = bytes.fromhex(sys.argv[1])
digest = bytes.fromhex(sys.argv[2])
print(hashlib.sha256(old_pcr + digest).hexdigest())
PY
}

assert_digest() {
    local label="$1"
    local digest="$2"

    if ! [[ "$digest" =~ ^[0-9a-f]{64}$ ]]; then
        echo "$label is not a 64-character lowercase hex digest: $digest" >&2
        exit 1
    fi
}

EK_CTX="$ARTIFACT_DIR/ek.ctx"
AK_CTX="$ARTIFACT_DIR/ak.ctx"
AK_PUB="$ARTIFACT_DIR/ak.pub.pem"
AK_NAME="$ARTIFACT_DIR/ak.name"
QUOTE_MSG="$ARTIFACT_DIR/quote.msg"
QUOTE_SIG="$ARTIFACT_DIR/quote.sig"
QUOTE_PCRS="$ARTIFACT_DIR/quote.pcrs"
PCR_SELECTION="$HASH_BANK:$PCR"

wait_for_swtpm

run_tpm2 "start TPM" tpm2_startup -c >/dev/null

echo "Creating EK..."
run_tpm2 "create EK" \
    tpm2_createek \
    -G rsa \
    -c "$EK_CTX" >/dev/null

echo "Creating AK..."
run_tpm2 "create AK" \
    tpm2_createak \
    -C "$EK_CTX" \
    -c "$AK_CTX" \
    -G rsa \
    -g "$HASH_BANK" \
    -s rsassa \
    -u "$AK_PUB" \
    -f pem \
    -n "$AK_NAME" >/dev/null

echo "Flushing transient TPM objects before quote..."
run_tpm2 "flush transient TPM objects" \
    tpm2_flushcontext -t >/dev/null

initial_pcr="$(pcr_read)"
assert_digest "initial PCR" "$initial_pcr"

run_tpm2 "reset PCR $PCR" tpm2_pcrreset "$PCR" >/dev/null

after_reset_pcr="$(pcr_read)"
assert_digest "PCR after reset" "$after_reset_pcr"

zero_digest="0000000000000000000000000000000000000000000000000000000000000000"

if [[ "$after_reset_pcr" != "$zero_digest" ]]; then
    echo "PCR $PCR did not reset to zero: $after_reset_pcr" >&2
    exit 1
fi

run_tpm2 "extend PCR $PCR" \
    tpm2_pcrextend "$PCR:$HASH_BANK=$DIGEST_HEX" >/dev/null

after_extend_pcr="$(pcr_read)"
assert_digest "PCR after extend" "$after_extend_pcr"

expected_pcr="$(expected_extend "$after_reset_pcr" "$DIGEST_HEX")"

if [[ "$after_extend_pcr" != "$expected_pcr" ]]; then
    echo "PCR extend mismatch before quote" >&2
    echo "expected: $expected_pcr" >&2
    echo "actual:   $after_extend_pcr" >&2
    exit 1
fi

echo "Generating quote..."
tpm2_quote \
    -c "$AK_CTX" \
    -l "$PCR_SELECTION" \
    -q "$NONCE_HEX" \
    -m "$QUOTE_MSG" \
    -s "$QUOTE_SIG" \
    -o "$QUOTE_PCRS" \
    -F values \
    -g "$HASH_BANK" >/dev/null

echo "Checking quote..."
run_tpm2 "check TPM quote" \
    tpm2_checkquote \
    -u "$AK_PUB" \
    -m "$QUOTE_MSG" \
    -s "$QUOTE_SIG" \
    -f "$QUOTE_PCRS" \
    -l "$PCR_SELECTION" \
    -q "$NONCE_HEX" \
    -g "$HASH_BANK" >/dev/null

cat <<EOF
TPM quote smoke test passed.
TCTI: $TPM2TOOLS_TCTI
PCR selection: $PCR_SELECTION
Initial PCR: $initial_pcr
After reset: $after_reset_pcr
Extended digest: $DIGEST_HEX
After extend: $after_extend_pcr
Expected PCR: $expected_pcr
Nonce: $NONCE_HEX
AK context: $AK_CTX
AK public: $AK_PUB
Quote message: $QUOTE_MSG
Quote signature: $QUOTE_SIG
Quote PCRs: $QUOTE_PCRS
EOF