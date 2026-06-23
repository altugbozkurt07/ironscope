#!/usr/bin/env bash
# Standalone LangGraph-style tool execution demo for IronScope.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEMO_SCRIPT="$PROJECT_DIR/examples/langgraph_tool_execution_daemon.py"
PYTHON_BIN="${PYTHON:-python3}"
BINARY="$PROJECT_DIR/target/release/ironscope"
IRONSCOPE_TMP="/tmp/ironscope"
CONFIG_FILE="$IRONSCOPE_TMP/langgraph-tool-execution-demo.yaml"
LOG_FILE="$IRONSCOPE_TMP/langgraph-tool-execution-demo.log"
JSON_FILE="$IRONSCOPE_TMP/langgraph-tool-execution-demo.json"
READY_FILE="$IRONSCOPE_TMP/langgraph-tool-execution-demo-ready"
START_SIGNAL="/tmp/ironscope_langgraph_tool_execution_demo_start"
STDOUT_FILE="/tmp/ironscope-langgraph-tool-execution-demo.out"
STDERR_FILE="/tmp/ironscope-langgraph-tool-execution-demo.err"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}PASS${NC}: $1"; }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}>>>${NC} $1"; }

DEMO_JOB=""
IRONSCOPE_PID=""
cleanup() {
    [ -n "$IRONSCOPE_PID" ] && sudo kill "$IRONSCOPE_PID" 2>/dev/null || true
    [ -n "$DEMO_JOB" ] && kill "$DEMO_JOB" 2>/dev/null || true
    rm -f "$START_SIGNAL" "$READY_FILE"
}
trap cleanup EXIT

info "Checking prerequisites"
grep -q bpf /sys/kernel/security/lsm 2>/dev/null || fail "BPF LSM is not active"
if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then fail "sudo is required"; fi
if ! "$PYTHON_BIN" - <<'CHECK_LANGCHAIN' >/dev/null 2>&1
from langchain_core.tools import BaseTool
CHECK_LANGCHAIN
then
    echo "SKIP: langchain-core is not installed for $PYTHON_BIN"
    exit 77
fi

[ -x "$BINARY" ] || (cd "$PROJECT_DIR" && cargo build --release)
mkdir -p "$IRONSCOPE_TMP"
sudo rm -f "$CONFIG_FILE" "$LOG_FILE" "$JSON_FILE" "$READY_FILE" 2>/dev/null || true
rm -f "$START_SIGNAL" "$STDOUT_FILE" "$STDERR_FILE"

info "Starting standalone LangGraph-style daemon"
IRONSCOPE_READY_FILE="$READY_FILE" \
IRONSCOPE_DEMO_START="$START_SIGNAL" \
"$PYTHON_BIN" "$DEMO_SCRIPT" --expect enforce >"$STDOUT_FILE" 2>"$STDERR_FILE" &
DEMO_JOB=$!

DEMO_PID=""
for _ in $(seq 1 100); do
    if [ -s "$STDOUT_FILE" ]; then
        DEMO_PID="$(head -1 "$STDOUT_FILE" | tr -d '[:space:]')"
        break
    fi
    sleep 0.05
done
[ -n "$DEMO_PID" ] || fail "demo daemon did not print PID"
kill -0 "$DEMO_PID" 2>/dev/null || fail "demo daemon is not running"
info "Demo daemon PID: $DEMO_PID"

cat > "$CONFIG_FILE" <<YAML
ironscope:
  agents:
    - name: langgraph-tool-execution-demo
      pid: $DEMO_PID

  unknown_tool_policy: allow
  resolver_error_policy: deny
  agent_child_scope: protect_only_tool_children

  tools:
    - name: read_file
      fs:
        deny:
          - /tmp/ironscope_demo_read_secret.txt
    - name: shell
      exec:
        deny:
          - /usr/bin/id
    - name: write_note
      fs:
        deny:
          - /etc/passwd
          - /etc/shadow
    - name: async_inner
      fs:
        deny:
          - /tmp/ironscope_demo_async_inner_secret.txt
    - name: async_outer
      fs:
        deny:
          - /tmp/ironscope_demo_async_outer_secret.txt
    - name: async_parallel_a
      fs:
        deny:
          - /tmp/ironscope_demo_parallel_a_secret.txt
    - name: async_parallel_b
      fs:
        deny:
          - /tmp/ironscope_demo_parallel_b_secret.txt
    - name: async_cancelled
    - name: async_exception
    - name: threadpool_reader
      fs:
        deny:
          - /tmp/ironscope_demo_threadpool_secret.txt
    - name: threading_reader
      fs:
        deny:
          - /tmp/ironscope_demo_threading_secret.txt
    - name: asyncio_to_thread_reader
      fs:
        deny:
          - /tmp/ironscope_demo_to_thread_secret.txt
    - name: background_popen
      fs:
        deny:
          - /tmp/ironscope_demo_background_secret.txt


  mode: enforce
YAML

info "Starting IronScope in enforce mode"
sudo -E env "PATH=$PATH" "$BINARY" \
  \
  --config "$CONFIG_FILE" \
  --mode enforce \
  --duration 45 \
  --ready-file "$READY_FILE" \
  --output "$JSON_FILE" \
  > "$IRONSCOPE_TMP/langgraph-tool-execution-demo.stdout" 2>"$LOG_FILE" &
IRONSCOPE_PID=$!

READY=0
for _ in $(seq 1 100); do
    if grep -q "CPython runtime event loop running" "$LOG_FILE" 2>/dev/null; then
        READY=1
        break
    fi
    sleep 0.1
done
[ "$READY" -eq 1 ] || { cat "$LOG_FILE"; fail "IronScope did not become ready"; }

info "Releasing daemon scenario"
: > "$START_SIGNAL"

DEMO_RC=0
wait "$DEMO_JOB" || DEMO_RC=$?
DEMO_JOB=""
if [ "$DEMO_RC" -ne 0 ]; then
    echo "--- daemon stdout ---"; cat "$STDOUT_FILE"
    echo "--- daemon stderr ---"; cat "$STDERR_FILE"
    fail "demo daemon failed with exit $DEMO_RC"
fi
pass "daemon observed expected tool denies and non-tool allows"

sleep 1
sudo kill -TERM "$IRONSCOPE_PID" 2>/dev/null || true
wait "$IRONSCOPE_PID" 2>/dev/null || true
IRONSCOPE_PID=""

[ -f "$JSON_FILE" ] || fail "IronScope did not write JSON output"
info "Verifying IronScope JSON"
"$PYTHON_BIN" "$PROJECT_DIR/tests/verifiers/audit_assertions.py" langgraph-demo "$JSON_FILE"
pass "IronScope JSON proves scoped monitoring/enforcement for standalone daemon"

echo "Daemon stdout: $STDOUT_FILE"
echo "Daemon stderr: $STDERR_FILE"
echo "IronScope log: $LOG_FILE"
echo "IronScope JSON: $JSON_FILE"
