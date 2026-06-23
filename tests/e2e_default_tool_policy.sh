#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_SCRIPT="$SCRIPT_DIR/default_tool_policy_agent.py"
PYTHON_BIN="${PYTHON:-python3}"
BINARY="$PROJECT_DIR/target/release/ironscope"
IRONSCOPE_TMP="/tmp/ironscope"
CONFIG_FILE="$IRONSCOPE_TMP/default-tool-policy.yaml"
LOG_FILE="$IRONSCOPE_TMP/default-tool-policy.log"
JSON_FILE="$IRONSCOPE_TMP/default-tool-policy.json"
READY_FILE="$IRONSCOPE_TMP/default-tool-policy-ready"
STDOUT_FILE="/tmp/ironscope-default-tool-policy-agent.out"
STDERR_FILE="/tmp/ironscope-default-tool-policy-agent.err"
START_SIGNAL="/tmp/ironscope_default_tool_policy_start"
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; exit 1; }
info() { echo ">>> $1"; }
AGENT_JOB=""
IRONSCOPE_PID=""
cleanup() {
    [ -n "$IRONSCOPE_PID" ] && sudo kill "$IRONSCOPE_PID" 2>/dev/null || true
    [ -n "$AGENT_JOB" ] && kill "$AGENT_JOB" 2>/dev/null || true
    rm -f "$CONFIG_FILE" "$START_SIGNAL" "$READY_FILE"
}
trap cleanup EXIT
info "Checking prerequisites"
if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then fail "BPF LSM is not active"; fi
if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then fail "sudo is required"; fi
if ! "$PYTHON_BIN" -c "from langchain_core.tools import BaseTool" >/dev/null 2>&1; then
    echo "SKIP: langchain-core is not installed for $PYTHON_BIN"
    exit 77
fi
info "Building release binary if needed"
if [ ! -x "$BINARY" ]; then (cd "$PROJECT_DIR" && cargo build --release); fi
mkdir -p "$IRONSCOPE_TMP"
rm -f "$LOG_FILE" "$JSON_FILE" "$STDOUT_FILE" "$STDERR_FILE" "$START_SIGNAL" "$READY_FILE"
info "Starting paused default_tool_policy workload"
IRONSCOPE_READY_FILE="$READY_FILE" "$PYTHON_BIN" "$AGENT_SCRIPT" >"$STDOUT_FILE" 2>"$STDERR_FILE" &
AGENT_JOB=$!
AGENT_PID=""
for _ in $(seq 1 100); do
    if [ -s "$STDOUT_FILE" ]; then AGENT_PID="$(head -1 "$STDOUT_FILE" | tr -d "[:space:]")"; break; fi
    sleep 0.05
done
[ -n "$AGENT_PID" ] || fail "agent did not print PID"
kill -0 "$AGENT_PID" 2>/dev/null || fail "agent is not running"
info "LangChain workload PID: $AGENT_PID"
cat > "$CONFIG_FILE" <<YAML
ironscope:
  agents:
    - name: default-tool-policy
      pid: $AGENT_PID
  default_tool_policy: deny
  unknown_tool_policy: allow
  resolver_error_policy: deny
  agent_child_scope: protect_only_tool_children
  tools:
    - name: shell
      fs:
        allow:
          - /bin/busybox
      exec:
        allow:
          - /bin/busybox
  mode: enforce
YAML
info "Starting IronScope CPython runtime with default_tool_policy=deny"
sudo -E env "PATH=$PATH" "$BINARY" --config "$CONFIG_FILE" --mode enforce --duration 25 --ready-file "$READY_FILE" --output "$JSON_FILE" > "$IRONSCOPE_TMP/default-tool-policy.stdout" 2>"$LOG_FILE" &
IRONSCOPE_PID=$!
READY=0
for _ in $(seq 1 100); do
    if grep -q "CPython runtime event loop running" "$LOG_FILE" 2>/dev/null; then READY=1; break; fi
    sleep 0.1
done
[ "$READY" -eq 1 ] || { cat "$LOG_FILE"; fail "IronScope did not become ready"; }
/usr/bin/true
pass "unrelated harness exec allowed while IronScope enforces"
info "Releasing workload"
: > "$START_SIGNAL"
AGENT_RC=0
wait "$AGENT_JOB" || AGENT_RC=$?
if [ "$AGENT_RC" -ne 0 ]; then
    echo "--- agent stdout ---"; cat "$STDOUT_FILE"
    echo "--- agent stderr ---"; cat "$STDERR_FILE"
    fail "default_tool_policy workload failed with exit $AGENT_RC"
fi
pass "workload observed expected default-tool allow/deny behavior"
sleep 1
sudo kill -TERM "$IRONSCOPE_PID" 2>/dev/null || true
wait "$IRONSCOPE_PID" 2>/dev/null || true
IRONSCOPE_PID=""
[ -f "$JSON_FILE" ] || fail "IronScope did not write JSON output"
info "Verifying default_tool_policy guard events"
"$PYTHON_BIN" "$PROJECT_DIR/tests/verifiers/audit_assertions.py" default-tool-policy "$JSON_FILE"
pass "IronScope JSON proves default_tool_policy fallback enforcement"
echo "Full log: $LOG_FILE"
echo "JSON: $JSON_FILE"
