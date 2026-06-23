#!/usr/bin/env bash
set -euo pipefail

CASE="${IRONSCOPE_WORKER_CASE:?IRONSCOPE_WORKER_CASE is required}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_SCRIPT="$SCRIPT_DIR/worker_lifecycle_agent.py"
PYTHON_BIN="${PYTHON:-python3}"
BINARY="$PROJECT_DIR/target/release/ironscope"
IRONSCOPE_TMP="/tmp/ironscope"
CONFIG_FILE="$IRONSCOPE_TMP/worker-lifecycle-${CASE}.yaml"
LOG_FILE="$IRONSCOPE_TMP/worker-lifecycle-${CASE}.log"
JSON_FILE="$IRONSCOPE_TMP/worker-lifecycle-${CASE}.json"
READY_FILE="$IRONSCOPE_TMP/worker-lifecycle-${CASE}-ready"
STDOUT_FILE="/tmp/ironscope-worker-lifecycle-${CASE}.out"
STDERR_FILE="/tmp/ironscope-worker-lifecycle-${CASE}.err"
START_SIGNAL="/tmp/ironscope_worker_lifecycle_${CASE}_start"

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

info "Checking prerequisites for worker lifecycle case: $CASE"
grep -q bpf /sys/kernel/security/lsm 2>/dev/null || fail "BPF LSM is not active"
if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then fail "sudo is required"; fi
if ! "$PYTHON_BIN" - <<'CHECK_LANGCHAIN' >/dev/null 2>&1
from langchain_core.tools import BaseTool
CHECK_LANGCHAIN
then
    echo "SKIP: langchain-core is not installed for $PYTHON_BIN"
    exit 77
fi
if [ "$CASE" = "langgraph_toolnode" ]; then
    if ! "$PYTHON_BIN" - <<'CHECK_LANGGRAPH' >/dev/null 2>&1
from langgraph.prebuilt import ToolNode
CHECK_LANGGRAPH
    then
        echo "SKIP: langgraph is not installed for $PYTHON_BIN"
        exit 77
    fi
fi

[ -x "$BINARY" ] || (cd "$PROJECT_DIR" && cargo build --release)
mkdir -p "$IRONSCOPE_TMP"
sudo rm -f "$CONFIG_FILE" "$LOG_FILE" "$JSON_FILE" "$READY_FILE" 2>/dev/null || true
rm -f "$STDOUT_FILE" "$STDERR_FILE" "$START_SIGNAL"

printf 'allowed fixture\n' > /tmp/ironscope_worker_allowed.txt
printf 'threadpool secret fixture\n' > /tmp/ironscope_worker_threadpool_secret.txt
printf 'threading secret fixture\n' > /tmp/ironscope_worker_threading_secret.txt
printf 'to_thread secret fixture\n' > /tmp/ironscope_worker_to_thread_secret.txt
printf 'background secret fixture\n' > /tmp/ironscope_worker_background_secret.txt
printf 'langgraph toolnode secret fixture\n' > /tmp/ironscope_worker_langgraph_toolnode_secret.txt

IRONSCOPE_WORKER_CASE="$CASE" \
IRONSCOPE_READY_FILE="$READY_FILE" \
IRONSCOPE_START_SIGNAL="$START_SIGNAL" \
"$PYTHON_BIN" "$AGENT_SCRIPT" >"$STDOUT_FILE" 2>"$STDERR_FILE" &
AGENT_JOB=$!

AGENT_PID=""
for _ in $(seq 1 100); do
    if [ -s "$STDOUT_FILE" ]; then AGENT_PID="$(head -1 "$STDOUT_FILE" | tr -d '[:space:]')"; break; fi
    sleep 0.05
done
[ -n "$AGENT_PID" ] || fail "worker lifecycle workload did not print PID"
kill -0 "$AGENT_PID" 2>/dev/null || fail "worker lifecycle workload is not running"
info "Worker lifecycle workload PID: $AGENT_PID"

cat > "$CONFIG_FILE" <<YAML
ironscope:
  agents:
    - name: worker-lifecycle-${CASE}
      pid: $AGENT_PID

  tools:
    - name: threadpool_reader
      fs:
        deny:
          - /tmp/ironscope_worker_threadpool_secret.txt
    - name: threading_reader
      fs:
        deny:
          - /tmp/ironscope_worker_threading_secret.txt
    - name: asyncio_to_thread_reader
      fs:
        deny:
          - /tmp/ironscope_worker_to_thread_secret.txt
    - name: background_popen
      fs:
        deny:
          - /tmp/ironscope_worker_background_secret.txt
    - name: langgraph_toolnode_reader
      fs:
        deny:
          - /tmp/ironscope_worker_langgraph_toolnode_secret.txt

  mode: enforce
YAML

sudo -E env "PATH=$PATH" "$BINARY" \
    \
    --config "$CONFIG_FILE" \
    --mode enforce \
    --duration 25 \
    --ready-file "$READY_FILE" \
    --output "$JSON_FILE" \
    > "$IRONSCOPE_TMP/worker-lifecycle-${CASE}.stdout" 2>"$LOG_FILE" &
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
    if [ "$AGENT_RC" -eq 77 ]; then
        echo "SKIP: workload dependency unavailable for $CASE"
        exit 77
    fi
    echo "--- workload stdout ---"; cat "$STDOUT_FILE"
    echo "--- workload stderr ---"; cat "$STDERR_FILE"
    fail "worker lifecycle workload failed for $CASE with exit $AGENT_RC"
fi

sleep 1
sudo kill -TERM "$IRONSCOPE_PID" 2>/dev/null || true
wait "$IRONSCOPE_PID" 2>/dev/null || true
IRONSCOPE_PID=""
[ -f "$JSON_FILE" ] || fail "IronScope did not write JSON"
"$PYTHON_BIN" "$PROJECT_DIR/tests/verifiers/audit_assertions.py" worker-lifecycle "$JSON_FILE" "$CASE"
pass "worker lifecycle assertions passed for $CASE"
echo "JSON: $JSON_FILE"
