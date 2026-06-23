#!/usr/bin/env bash
set -euo pipefail

CASE="${1:?case required: fs|exec|net}"
EXPECT="${2:?expect required: enforce|monitor}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_SCRIPT="$SCRIPT_DIR/resource_policy_agent.py"
PYTHON_BIN="${PYTHON:-python3}"
BINARY="$PROJECT_DIR/target/release/ironscope"
IRONSCOPE_TMP="/tmp/ironscope"
CONFIG_FILE="$IRONSCOPE_TMP/resource-policy-$CASE-$EXPECT.yaml"
LOG_FILE="$IRONSCOPE_TMP/resource-policy-$CASE-$EXPECT.log"
JSON_FILE="$IRONSCOPE_TMP/resource-policy-$CASE-$EXPECT.json"
READY_FILE="$IRONSCOPE_TMP/resource-policy-$CASE-$EXPECT-ready"
STDOUT_FILE="/tmp/ironscope-resource-policy-$CASE-$EXPECT.out"
STDERR_FILE="/tmp/ironscope-resource-policy-$CASE-$EXPECT.err"
START_SIGNAL="/tmp/ironscope_resource_policy_${CASE}_${EXPECT}_start"

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

if [ "$CASE" != "fs" ] && [ "$CASE" != "exec" ] && [ "$CASE" != "net" ]; then
    fail "invalid case: $CASE"
fi
if [ "$EXPECT" != "enforce" ] && [ "$EXPECT" != "monitor" ]; then
    fail "invalid expectation: $EXPECT"
fi

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

info "Starting paused resource policy workload case=$CASE expect=$EXPECT"
IRONSCOPE_READY_FILE="$READY_FILE" IRONSCOPE_RESOURCE_START="$START_SIGNAL" \
    "$PYTHON_BIN" "$AGENT_SCRIPT" --case "$CASE" --expect "$EXPECT" >"$STDOUT_FILE" 2>"$STDERR_FILE" &
AGENT_JOB=$!

AGENT_PID=""
ALLOW_PORT="0"
DENY_PORT="0"
for _ in $(seq 1 100); do
    if [ -s "$STDOUT_FILE" ]; then
        AGENT_PID="$(sed -n '1p' "$STDOUT_FILE" | tr -d '[:space:]')"
        PORT_LINE="$(sed -n '2p' "$STDOUT_FILE" || true)"
        if [ -n "$AGENT_PID" ] && [ -n "$PORT_LINE" ]; then
            set -- $PORT_LINE
            if [ "${1:-}" = "PORTS" ]; then
                ALLOW_PORT="${2:-0}"
                DENY_PORT="${3:-0}"
                break
            fi
        fi
    fi
    sleep 0.05
done
[ -n "$AGENT_PID" ] || fail "agent did not print PID"
kill -0 "$AGENT_PID" 2>/dev/null || fail "agent is not running"
info "Resource policy workload PID: $AGENT_PID"

MODE="$EXPECT"
cat > "$CONFIG_FILE" <<YAML
ironscope:
  agents:
    - name: resource-policy-$CASE-$EXPECT
      pid: $AGENT_PID
  unknown_tool_policy: allow
  resolver_error_policy: deny
  agent_child_scope: protect_only_tool_children
  default_tool_policy: allow
  tools:
YAML

if [ "$CASE" = "fs" ]; then
    cat >> "$CONFIG_FILE" <<YAML
    - name: file_tool
      fs:
        allow:
          - /tmp/ironscope_resource_allowed.txt
        deny:
          - /tmp/ironscope_resource_secret.txt
YAML
elif [ "$CASE" = "exec" ]; then
    cat >> "$CONFIG_FILE" <<YAML
    - name: exec_tool
      exec:
        allow:
          - /bin/true
        deny:
          - /usr/bin/id
YAML
else
    [ "$ALLOW_PORT" != "0" ] || fail "net case missing allow port"
    [ "$DENY_PORT" != "0" ] || fail "net case missing deny port"
    cat >> "$CONFIG_FILE" <<YAML
    - name: net_tool
      net:
        allow:
          - "127.0.0.1:$ALLOW_PORT"
        deny:
          - "127.0.0.1:$DENY_PORT"
YAML
fi

cat >> "$CONFIG_FILE" <<YAML
  mode: $MODE
YAML

info "Starting IronScope mode=$MODE for case=$CASE"
sudo -E env "PATH=$PATH" "$BINARY" --config "$CONFIG_FILE" --mode "$MODE" --duration 25 --ready-file "$READY_FILE" --output "$JSON_FILE" > "$IRONSCOPE_TMP/resource-policy-$CASE-$EXPECT.stdout" 2>"$LOG_FILE" &
IRONSCOPE_PID=$!

READY=0
for _ in $(seq 1 120); do
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
    fail "resource policy workload failed with exit $AGENT_RC"
fi
pass "workload observed expected case=$CASE behavior"

sleep 1
sudo kill -TERM "$IRONSCOPE_PID" 2>/dev/null || true
wait "$IRONSCOPE_PID" 2>/dev/null || true
IRONSCOPE_PID=""
[ -f "$JSON_FILE" ] || fail "IronScope did not write JSON output"

info "Verifying resource policy guard events"
"$PYTHON_BIN" "$PROJECT_DIR/tests/verifiers/audit_assertions.py" resource-policy "$JSON_FILE" "$CASE" "$EXPECT" "$DENY_PORT"
pass "IronScope JSON proves resource policy case=$CASE expect=$EXPECT"
echo "Full log: $LOG_FILE"
echo "JSON: $JSON_FILE"
