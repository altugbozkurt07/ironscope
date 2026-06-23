#!/usr/bin/env python3
"""Deterministic child-scope workload for IronScope.

The workload creates one subprocess outside any LangChain tool and one
subprocess inside a LangChain BaseTool.invoke boundary. IronScope should not
attribute/protect the idle child under protect_only_tool_children, but the tool
child must inherit the active tool context and obey the tool exec policy.
"""

from __future__ import annotations

import errno
import os
import subprocess
import sys
import time
from pathlib import Path

START_SIGNAL = os.environ.get("IRONSCOPE_START_SIGNAL", "/tmp/ironscope_child_scope_start")
READY_PATH = os.environ.get("IRONSCOPE_READY_FILE", "/tmp/ironscope/child-scope-ready")
WARMUP_FILE = "/tmp/ironscope_child_scope_warmup.txt"

try:
    from langchain_core.tools import BaseTool
except Exception as exc:  # pragma: no cover - environment gate
    print(f"MISSING_LANGCHAIN_CORE: {exc}", file=sys.stderr, flush=True)
    sys.exit(77)


class ChildExecTool(BaseTool):
    name: str = "child_exec"
    description: str = "Run a deterministic child process."

    def _run(self, command: str, **_: object) -> str:
        if command == "warmup":
            return Path(WARMUP_FILE).read_text()
        if command != "id":
            raise ValueError("only id is used in this deterministic scenario")
        proc = subprocess.run(
            ["/usr/bin/id"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return proc.stdout + proc.stderr


def wait_for(path: str, timeout: float, label: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {label}: {path}")


def run_idle_child() -> int:
    proc = subprocess.Popen(
        ["/usr/bin/id"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    print(f"IDLE_CHILD_PID {proc.pid}", flush=True)
    out, err = proc.communicate(timeout=10)
    if proc.returncode != 0:
        raise AssertionError(
            f"idle child should be allowed, rc={proc.returncode}, stdout={out!r}, stderr={err!r}"
        )
    print("RESULT idle_child_allowed PASS", flush=True)
    return proc.pid


def expect_tool_child_denied(tool: ChildExecTool) -> None:
    try:
        tool.invoke("id")
    except PermissionError:
        print("RESULT tool_child_denied PASS", flush=True)
        return
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES):
            print(f"RESULT tool_child_denied PASS errno={exc.errno}", flush=True)
            return
        print(f"RESULT tool_child_denied FAIL unexpected_errno={exc.errno}", flush=True)
        raise
    print("RESULT tool_child_denied FAIL allowed", flush=True)
    raise AssertionError("tool child exec was allowed")


def main() -> int:
    print(os.getpid(), flush=True)
    wait_for(START_SIGNAL, 30, "start signal")

    Path(WARMUP_FILE).write_text("child scope warmup fixture\n")
    tool = ChildExecTool()
    wait_for(READY_PATH, 15, "ironscope ready marker")
    warmup = tool.invoke("warmup")
    if "child scope warmup" not in warmup:
        raise AssertionError(f"unexpected warmup result: {warmup!r}")
    time.sleep(0.5)

    print("CHILD_SCOPE_SCENARIO_START", flush=True)
    run_idle_child()
    expect_tool_child_denied(tool)
    time.sleep(0.25)
    print("CHILD_SCOPE_SCENARIO_DONE", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"SCENARIO_ERROR {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise
