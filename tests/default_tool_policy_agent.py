#!/usr/bin/env python3
"""LangChain workload for IronScope default_tool_policy E2E."""

from __future__ import annotations

import errno
import os
import subprocess
import sys
import time

START_SIGNAL = "/tmp/ironscope_default_tool_policy_start"
READY_PATH = os.environ.get("IRONSCOPE_READY_FILE", "/tmp/ironscope/ready")

try:
    from langchain_core.tools import BaseTool
except Exception as exc:  # pragma: no cover - environment gate
    print(f"MISSING_LANGCHAIN_CORE: {exc}", file=sys.stderr, flush=True)
    sys.exit(77)


class ShellTool(BaseTool):
    name: str = "shell"
    description: str = "Run deterministic binaries for IronScope policy tests."

    def _run(self, command: str, **_: object) -> str:
        commands = {
            "busybox_echo": ["/bin/busybox", "echo", "ironscope"],
            "whoami": ["/usr/bin/whoami"],
        }
        argv = commands[command]
        proc = subprocess.run(
            argv,
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


def expect_denied(label: str, func) -> None:
    try:
        func()
    except PermissionError:
        print(f"RESULT {label} PASS denied", flush=True)
        return
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES, 1, 13):
            print(f"RESULT {label} PASS denied_errno={exc.errno}", flush=True)
            return
        raise
    raise AssertionError(f"{label} was allowed")


def main() -> int:
    print(os.getpid(), flush=True)
    wait_for(START_SIGNAL, 30, "start signal")
    wait_for(READY_PATH, 15, "ironscope ready marker")

    tool = ShellTool()

    # First call may be unknown_tool_policy=allow while userspace resolves the tool.
    tool.invoke("busybox_echo")
    time.sleep(0.5)

    allowed = tool.invoke("busybox_echo")
    if "ironscope" not in allowed:
        raise AssertionError("busybox echo returned unexpected output")
    print("RESULT busybox_allowed PASS", flush=True)

    expect_denied("whoami_default_denied", lambda: tool.invoke("whoami"))
    time.sleep(0.25)
    print("DEFAULT_TOOL_POLICY_SCENARIO_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
