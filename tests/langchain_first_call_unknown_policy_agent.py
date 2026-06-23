#!/usr/bin/env python3
"""LangChain first-call unknown-policy workload for v0.1 first-call unknown-policy."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

START_SIGNAL = os.environ.get("IRONSCOPE_START_SIGNAL", "/tmp/ironscope_unknown_policy_start")
READY_PATH = os.environ.get("IRONSCOPE_READY_FILE", "/tmp/ironscope/unknown-policy-ready")
SECRET_FILE = "/tmp/ironscope_unknown_policy_secret.txt"
WARMUP_FILE = "/tmp/ironscope_unknown_policy_warmup.txt"

try:
    from langchain_core.tools import BaseTool
except Exception as exc:  # pragma: no cover
    print(f"MISSING_LANGCHAIN_CORE: {exc}", file=sys.stderr, flush=True)
    sys.exit(77)


class UnknownReaderTool(BaseTool):
    name: str = "unknown_reader"
    description: str = "Read a file without IronScope tool registration."

    def _run(self, path: str, **_: object) -> str:
        return Path(path).read_text()


def wait_for(path: str, timeout: float, label: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {label}: {path}")


def expect_denied(tool: UnknownReaderTool) -> None:
    try:
        tool.invoke(SECRET_FILE)
    except PermissionError:
        print("RESULT unknown_reader PASS denied", flush=True)
        return
    except OSError as exc:
        if exc.errno in (1, 13):
            print(f"RESULT unknown_reader PASS denied_errno={exc.errno}", flush=True)
            return
        raise
    raise AssertionError("unknown_reader was allowed")


def warm_framework_path(tool: UnknownReaderTool) -> None:
    Path(WARMUP_FILE).write_text("warmup fixture\n")
    tool.invoke(WARMUP_FILE)


def main() -> int:
    tool = UnknownReaderTool()
    warm_framework_path(tool)
    print(os.getpid(), flush=True)
    wait_for(START_SIGNAL, 30, "start signal")
    wait_for(READY_PATH, 15, "ironscope ready marker")
    print("UNKNOWN_POLICY_SCENARIO_START", flush=True)
    expect_denied(tool)
    time.sleep(0.35)
    print("UNKNOWN_POLICY_SCENARIO_DONE", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"SCENARIO_ERROR {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise
