#!/usr/bin/env bash
set -euo pipefail

CASE="${IRONSCOPE_ASYNC_CASE:?IRONSCOPE_ASYNC_CASE is required}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_SCRIPT="$SCRIPT_DIR/async_lifecycle_agent.py"
PYTHON_BIN="${PYTHON:-python3}"
BINARY="$PROJECT_DIR/target/release/ironscope"
IRONSCOPE_TMP="/tmp/ironscope"
CONFIG_FILE="$IRONSCOPE_TMP/async-lifecycle-${CASE}.yaml"
LOG_FILE="$IRONSCOPE_TMP/async-lifecycle-${CASE}.log"
JSON_FILE="$IRONSCOPE_TMP/async-lifecycle-${CASE}.json"
READY_FILE="$IRONSCOPE_TMP/async-lifecycle-${CASE}-ready"
STDOUT_FILE="/tmp/ironscope-async-lifecycle-${CASE}.out"
STDERR_FILE="/tmp/ironscope-async-lifecycle-${CASE}.err"
START_SIGNAL="/tmp/ironscope_async_lifecycle_${CASE}_start"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}PASS${NC}: $1"; }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}>>>${NC} $1"; }

AGENT_JOB=""; IRONSCOPE_PID=""
cleanup() {
    [ -n "$IRONSCOPE_PID" ] && sudo kill "$IRONSCOPE_PID" 2>/dev/null || true
    [ -n "$AGENT_JOB" ] && kill "$AGENT_JOB" 2>/dev/null || true
    sudo rm -f "$READY_FILE" 2>/dev/null || true
    rm -f "$START_SIGNAL"
}
trap cleanup EXIT

info "Checking prerequisites for async lifecycle case: $CASE"
grep -q bpf /sys/kernel/security/lsm 2>/dev/null || fail "BPF LSM is not active"
if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then fail "sudo is required"; fi
if ! "$PYTHON_BIN" - <<'PY' >/dev/null 2>&1
from langchain_core.tools import BaseTool
PY
then
    echo "SKIP: langchain-core is not installed for $PYTHON_BIN"
    exit 77
fi

[ -x "$BINARY" ] || (cd "$PROJECT_DIR" && cargo build --release)
mkdir -p "$IRONSCOPE_TMP"
sudo rm -f "$CONFIG_FILE" "$LOG_FILE" "$JSON_FILE" "$READY_FILE" 2>/dev/null || true
rm -f "$STDOUT_FILE" "$STDERR_FILE" "$START_SIGNAL"

IRONSCOPE_ASYNC_CASE="$CASE" \
IRONSCOPE_READY_FILE="$READY_FILE" \
IRONSCOPE_START_SIGNAL="$START_SIGNAL" \
"$PYTHON_BIN" "$AGENT_SCRIPT" >"$STDOUT_FILE" 2>"$STDERR_FILE" &
AGENT_JOB=$!

AGENT_PID=""
for _ in $(seq 1 100); do
    if [ -s "$STDOUT_FILE" ]; then AGENT_PID="$(head -1 "$STDOUT_FILE" | tr -d '[:space:]')"; break; fi
    sleep 0.05
done
[ -n "$AGENT_PID" ] || fail "async lifecycle workload did not print PID"

printf 'inner secret fixture
' > /tmp/ironscope_async_inner_secret.txt
printf 'outer secret fixture
' > /tmp/ironscope_async_outer_secret.txt
printf 'parallel a secret fixture
' > /tmp/ironscope_async_parallel_a_secret.txt
printf 'parallel b secret fixture
' > /tmp/ironscope_async_parallel_b_secret.txt

cat > "$CONFIG_FILE" <<YAML
ironscope:
  agents:
    - name: async-lifecycle-${CASE}
      pid: $AGENT_PID

  tools:
    - name: async_inner
      fs:
        deny:
          - /tmp/ironscope_async_inner_secret.txt
    - name: async_outer
      fs:
        deny:
          - /tmp/ironscope_async_outer_secret.txt
    - name: async_parallel_a
      fs:
        deny:
          - /tmp/ironscope_async_parallel_a_secret.txt
    - name: async_parallel_b
      fs:
        deny:
          - /tmp/ironscope_async_parallel_b_secret.txt
    - name: async_cancelled
    - name: async_exception

  mode: enforce
YAML

sudo -E env "PATH=$PATH" "$BINARY" --config "$CONFIG_FILE" --mode enforce --duration 25 --ready-file "$READY_FILE" --output "$JSON_FILE" > "$IRONSCOPE_TMP/async-lifecycle-${CASE}.stdout" 2>"$LOG_FILE" &
IRONSCOPE_PID=$!

READY=0
for _ in $(seq 1 100); do
    if grep -q "CPython runtime event loop running" "$LOG_FILE" 2>/dev/null; then READY=1; break; fi
    sleep 0.1
done
[ "$READY" -eq 1 ] || { cat "$LOG_FILE"; fail "IronScope did not become ready"; }

: > "$START_SIGNAL"
AGENT_RC=0
wait "$AGENT_JOB" || AGENT_RC=$?
AGENT_JOB=""
if [ "$AGENT_RC" -ne 0 ]; then
    echo "--- workload stdout ---"; cat "$STDOUT_FILE"
    echo "--- workload stderr ---"; cat "$STDERR_FILE"
    fail "async lifecycle workload failed for $CASE with exit $AGENT_RC"
fi

sleep 1
sudo kill -TERM "$IRONSCOPE_PID" 2>/dev/null || true
wait "$IRONSCOPE_PID" 2>/dev/null || true
IRONSCOPE_PID=""
[ -f "$JSON_FILE" ] || fail "IronScope did not write JSON"
"$PYTHON_BIN" "$PROJECT_DIR/tests/verifiers/audit_assertions.py" async-lifecycle "$JSON_FILE" "$CASE"
pass "async lifecycle assertions passed for $CASE"
echo "JSON: $JSON_FILE"
