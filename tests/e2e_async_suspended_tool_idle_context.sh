#!/usr/bin/env bash
# Release-CLI E2E for asyncio suspended-tool context isolation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
SCENARIO="$SCRIPT_DIR/scenarios/async_suspended_tool_idle_context.py"
BINARY="$PROJECT_DIR/target/release/ironscope"
CONFIG_FILE="/tmp/ironscope-async-suspended-tool.yaml"
LOG_FILE="/tmp/ironscope-async-suspended-tool.log"
JSON_FILE="/tmp/ironscope-async-suspended-tool.json"
STDOUT_FILE="/tmp/ironscope-async-suspended-tool.out"
STDERR_FILE="/tmp/ironscope-async-suspended-tool.err"
START_SIGNAL="/tmp/ironscope_async_suspended_tool_start"
TARGET_FILE="/tmp/ironscope_async_policy_probe.txt"
READY_FILE="/tmp/ironscope/ready"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }
info() { echo ">>> $1"; }

SCENARIO_PID=""
IRONSCOPE_PID=""
cleanup() {
    [ -n "$IRONSCOPE_PID" ] && sudo kill "$IRONSCOPE_PID" 2>/dev/null || true
    [ -n "$SCENARIO_PID" ] && kill "$SCENARIO_PID" 2>/dev/null || true
}
trap cleanup EXIT

info "Checking prerequisites"
if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
    fail "BPF LSM is not active"
fi
if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then
    fail "sudo is required"
fi
if ! "$PYTHON_BIN" - <<'PYIMPORT' >/dev/null 2>&1
from langchain_core.tools import BaseTool
PYIMPORT
then
    echo "SKIP: langchain-core is unavailable for $PYTHON_BIN"
    exit 77
fi

info "Building release binary if needed"
if [ ! -x "$BINARY" ]; then
    (cd "$PROJECT_DIR" && cargo build --release)
fi

rm -f "$CONFIG_FILE" "$LOG_FILE" "$JSON_FILE" "$STDOUT_FILE" "$STDERR_FILE" "$START_SIGNAL" "$READY_FILE" "$TARGET_FILE"
mkdir -p /tmp/ironscope

info "Starting suspended-tool scenario"
IRONSCOPE_READY_FILE="$READY_FILE" \
IRONSCOPE_START_SIGNAL="$START_SIGNAL" \
IRONSCOPE_ASYNC_TARGET="$TARGET_FILE" \
"$PYTHON_BIN" "$SCENARIO" >"$STDOUT_FILE" 2>"$STDERR_FILE" &
SCENARIO_PID=$!

AGENT_PID=""
for _ in $(seq 1 100); do
    if [ -s "$STDOUT_FILE" ]; then
        AGENT_PID="$(head -1 "$STDOUT_FILE" | tr -d '[:space:]')"
        break
    fi
    sleep 0.05
done
[ -n "$AGENT_PID" ] || { cat "$STDOUT_FILE"; cat "$STDERR_FILE"; fail "scenario did not print PID"; }
kill -0 "$AGENT_PID" 2>/dev/null || fail "scenario process is not running"
info "Scenario PID: $AGENT_PID"

cat > "$CONFIG_FILE" <<YAML
ironscope:
  agents:
    - name: async-suspended-tool-idle-context
      pid: $AGENT_PID

  tools:
    - name: sensitive_reader
      fs:
        deny:
          - $TARGET_FILE

  mode: enforce
YAML

info "Starting IronScope with release-shaped CPython runtime CLI"
sudo -E env "PATH=$PATH" "$BINARY" \
  \
  --config "$CONFIG_FILE" \
  --mode enforce \
  --duration 30 \
  --ready-file "$READY_FILE" \
  --output "$JSON_FILE" \
  > /tmp/ironscope-async-suspended-tool.stdout \
  2> "$LOG_FILE" &
IRONSCOPE_PID=$!

READY=0
for _ in $(seq 1 150); do
    if grep -q "CPython runtime event loop running" "$LOG_FILE" 2>/dev/null; then
        READY=1
        break
    fi
    sleep 0.1
done
[ "$READY" -eq 1 ] || { cat "$LOG_FILE"; fail "IronScope did not enter CPython runtime loop"; }

info "Releasing scenario after IronScope is attached"
: > "$START_SIGNAL"

SCENARIO_RC=0
wait "$SCENARIO_PID" || SCENARIO_RC=$?
if [ "$SCENARIO_RC" -ne 0 ]; then
    echo "--- scenario stdout ---"
    cat "$STDOUT_FILE"
    echo "--- scenario stderr ---"
    cat "$STDERR_FILE"
    fail "scenario failed with exit $SCENARIO_RC"
fi
pass "scenario observed idle allow and tool deny"

sleep 1
sudo kill -TERM "$IRONSCOPE_PID" 2>/dev/null || true
wait "$IRONSCOPE_PID" 2>/dev/null || true
IRONSCOPE_PID=""

[ -f "$JSON_FILE" ] || { cat "$LOG_FILE"; fail "IronScope did not write JSON output"; }

info "Verifying JSON attribution"
"$PYTHON_BIN" - <<PYVERIFY
import json, sys
path = "$JSON_FILE"
target = "$TARGET_FILE"
o = json.load(open(path))
py_events = o.get("py_events", [])
guard = o.get("guard_events", [])
problems = []

starts = [e for e in py_events if e.get("kind") == 6]
ends = [e for e in py_events if e.get("kind") == 7]
if len(starts) != len(ends):
    problems.append(f"unbalanced tool lifecycle: starts={len(starts)} ends={len(ends)}")
if o.get("balanced") is not True:
    problems.append(f"top-level lifecycle balance is not true: {o.get('balanced')}")
if o.get("orphan_frame_ctx") != 0:
    problems.append(f"orphan_frame_ctx not zero: {o.get('orphan_frame_ctx')}")
if o.get("task_bind_count") != o.get("task_unbind_count"):
    problems.append(
        "task bind/unbind count mismatch: "
        f"{o.get('task_bind_count')} != {o.get('task_unbind_count')}"
    )
if o.get("bracket_check", {}).get("bracket_violations") != 0:
    problems.append(f"bracket violations: {o.get('bracket_check')}")

idle_allows = [
    g for g in guard
    if g.get("path") == target
    and g.get("action") == "allow"
    and g.get("ctx_id", 0) == 0
    and g.get("tool_id", 0) == 0
]
tool_denies = [
    g for g in guard
    if g.get("path") == target
    and g.get("action") == "deny"
    and g.get("ctx_id", 0) != 0
    and g.get("tool_name") == "sensitive_reader"
]
wrong_tool_idle = [
    g for g in guard
    if g.get("path") == target
    and g.get("action") == "deny"
    and g.get("ctx_id", 0) == 0
]
if not idle_allows:
    problems.append("missing idle allow on policy fixture with ctx=0/tool=0")
if not tool_denies:
    problems.append("missing sensitive_reader deny on same policy fixture with nonzero ctx")
if wrong_tool_idle:
    problems.append(f"idle/unattributed operation was denied: {wrong_tool_idle}")

final = o.get("final_state", {})
for key, value in sorted(final.items()):
    if value != 0:
        problems.append(f"final_state.{key} not empty: {value}")

if problems:
    for problem in problems:
        print("PROBLEM:", problem)
    print("target guard events:")
    for event in guard:
        if event.get("path") == target:
            print(event)
    sys.exit(1)

print("PASS: release CLI JSON proves suspended-tool context isolation")
print("tool_starts", len(starts), "tool_ends", len(ends))
print("idle_allow", idle_allows[0])
print("tool_deny", tool_denies[0])
print("final_state", final)
PYVERIFY
pass "IronScope enforced only the active tool context"

echo "Scenario stdout: $STDOUT_FILE"
echo "Scenario stderr: $STDERR_FILE"
echo "IronScope log: $LOG_FILE"
echo "IronScope JSON: $JSON_FILE"
