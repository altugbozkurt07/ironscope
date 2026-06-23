#!/usr/bin/env bash
# IronScope child-scope E2E.
#
# Verifies the V0.1 child process contract:
#   - default protect_only_tool_children does not protect/audit idle child execs
#   - child exec spawned inside a LangChain tool inherits the tool ctx and is denied
#   - protect_all_children changes only idle-child audit visibility by config
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_SCRIPT="$SCRIPT_DIR/child_scope_agent.py"
PYTHON_BIN="${PYTHON:-python3}"
BINARY="$PROJECT_DIR/target/release/ironscope"
IRONSCOPE_TMP="/tmp/ironscope"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC}: $1"; }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}>>>${NC} $1"; }

AGENT_JOB=""
IRONSCOPE_PID=""
cleanup() {
    [ -n "$IRONSCOPE_PID" ] && sudo kill "$IRONSCOPE_PID" 2>/dev/null || true
    [ -n "$AGENT_JOB" ] && kill "$AGENT_JOB" 2>/dev/null || true
}
trap cleanup EXIT

info "Checking prerequisites"
if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
    fail "BPF LSM is not active"
fi
if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then
    fail "sudo is required"
fi
if ! "$PYTHON_BIN" - <<'PY' >/dev/null 2>&1
from langchain_core.tools import BaseTool
PY
then
    echo "SKIP: langchain-core is not installed for $PYTHON_BIN"
    echo "Install with: $PYTHON_BIN -m pip install langchain-core"
    exit 77
fi

info "Building release binary if needed"
if [ ! -x "$BINARY" ]; then
    (cd "$PROJECT_DIR" && cargo build --release)
fi

mkdir -p "$IRONSCOPE_TMP"

run_scope() {
    local scope="$1"
    local label="$2"
    local config_file="$IRONSCOPE_TMP/child-scope-${label}.yaml"
    local log_file="$IRONSCOPE_TMP/child-scope-${label}.log"
    local json_file="$IRONSCOPE_TMP/child-scope-${label}.json"
    local stdout_file="/tmp/ironscope-child-scope-${label}.out"
    local stderr_file="/tmp/ironscope-child-scope-${label}.err"
    local ready_file="$IRONSCOPE_TMP/child-scope-${label}-ready"
    local start_signal="/tmp/ironscope_child_scope_${label}_start"

    info "Running child-scope scenario: $scope"
    sudo rm -f "$config_file" "$log_file" "$json_file" "$ready_file" 2>/dev/null || true
    rm -f "$stdout_file" "$stderr_file" "$start_signal"

    IRONSCOPE_READY_FILE="$ready_file" \
    IRONSCOPE_START_SIGNAL="$start_signal" \
    "$PYTHON_BIN" "$AGENT_SCRIPT" >"$stdout_file" 2>"$stderr_file" &
    AGENT_JOB=$!

    local agent_pid=""
    for _ in $(seq 1 100); do
        if [ -s "$stdout_file" ]; then
            agent_pid="$(head -1 "$stdout_file" | tr -d '[:space:]')"
            break
        fi
        sleep 0.05
    done
    [ -n "$agent_pid" ] || fail "child-scope workload did not print PID"
    kill -0 "$agent_pid" 2>/dev/null || fail "child-scope workload is not running"
    info "Child-scope workload PID: $agent_pid"

    cat > "$config_file" <<YAML
ironscope:
  agents:
    - name: child-scope-${label}
      pid: $agent_pid

  agent_child_scope: $scope

  tools:
    - name: child_exec
      exec:
        deny:
          - "*"

  mode: enforce
YAML

    sudo -E env "PATH=$PATH" "$BINARY" \
        \
        --config "$config_file" \
        --mode enforce \
        --duration 25 \
        --ready-file "$ready_file" \
        --output "$json_file" \
        > "$IRONSCOPE_TMP/child-scope-${label}.stdout" 2>"$log_file" &
    IRONSCOPE_PID=$!

    local ready=0
    for _ in $(seq 1 100); do
        if grep -q "CPython runtime event loop running" "$log_file" 2>/dev/null; then
            ready=1
            break
        fi
        sleep 0.1
    done
    [ "$ready" -eq 1 ] || { cat "$log_file"; fail "IronScope did not become ready for $scope"; }

    : > "$start_signal"

    local agent_rc=0
    wait "$AGENT_JOB" || agent_rc=$?
    AGENT_JOB=""
    if [ "$agent_rc" -ne 0 ]; then
        echo "--- workload stdout ($scope) ---"
        cat "$stdout_file"
        echo "--- workload stderr ($scope) ---"
        cat "$stderr_file"
        fail "child-scope workload failed for $scope with exit $agent_rc"
    fi

    local idle_child_pid=""
    idle_child_pid="$(grep '^IDLE_CHILD_PID ' "$stdout_file" | awk '{print $2}' | tail -1)"
    [ -n "$idle_child_pid" ] || fail "workload did not report idle child pid for $scope"

    sleep 1
    sudo kill -TERM "$IRONSCOPE_PID" 2>/dev/null || true
    wait "$IRONSCOPE_PID" 2>/dev/null || true
    IRONSCOPE_PID=""

    [ -f "$json_file" ] || fail "IronScope did not write JSON for $scope"
    "$PYTHON_BIN" "$PROJECT_DIR/tests/verifiers/audit_assertions.py" child-scope "$json_file" "$idle_child_pid" "$scope"
    pass "child-scope assertions passed for $scope"
}

run_scope "protect_only_tool_children" "tool-only"
run_scope "protect_all_children" "all-children"

pass "IronScope child-scope behavior is config-scoped and tool child inheritance works"
echo "JSON default: $IRONSCOPE_TMP/child-scope-tool-only.json"
echo "JSON protect_all: $IRONSCOPE_TMP/child-scope-all-children.json"
