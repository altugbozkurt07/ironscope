#!/usr/bin/env python3
"""Suspended-tool vs idle-coroutine context isolation scenario.

This workload is intentionally deterministic. It proves the invariant IronScope
needs for LSM enforcement on asyncio workloads:

  1. A LangChain async tool enters its tool context.
  2. The tool suspends at an await point.
  3. An unrelated idle coroutine runs on the same event loop and performs a
     filesystem operation against a harmless fixture file that the tool policy
     denies.
  4. The idle operation must be allowed because the suspended tool context must
     not remain active on the event-loop thread.
  5. The tool resumes and performs the same filesystem operation against the
     same fixture file, which must be denied under the tool policy.

Expected IronScope policy for this workload:

ironscope:
  agents:
    - name: async-suspended-tool-idle-context
      pid: <printed pid>
  tools:
    - name: sensitive_reader
      fs:
        deny:
          - /tmp/ironscope_async_policy_probe.txt
  mode: enforce

Manual flow:
  1. Start this script; it prints PID and waits for START_SIGNAL.
  2. Start IronScope for that PID.
  3. Create START_SIGNAL.
  4. IronScope writes /tmp/ironscope/ready.
  5. This script warms runtime tool resolution, then runs the deterministic interleaving and exits 0 only if the
     idle coroutine is allowed and the resumed tool is denied.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

START_SIGNAL = os.environ.get(
    "IRONSCOPE_START_SIGNAL", "/tmp/ironscope_async_suspended_tool_start"
)
READY_PATH = os.environ.get("IRONSCOPE_READY_FILE", "/tmp/ironscope/ready")
TARGET_FILE = os.environ.get(
    "IRONSCOPE_ASYNC_TARGET", "/tmp/ironscope_async_policy_probe.txt"
)
WARMUP_FILE = os.environ.get(
    "IRONSCOPE_ASYNC_WARMUP", "/tmp/ironscope_async_policy_warmup.txt"
)
START_TIMEOUT = float(os.environ.get("IRONSCOPE_START_TIMEOUT", "60"))
READY_TIMEOUT = float(os.environ.get("IRONSCOPE_READY_TIMEOUT", "30"))

try:
    from langchain_core.tools import BaseTool
except Exception as exc:  # pragma: no cover - environment gate
    print(f"MISSING_LANGCHAIN_CORE_OR_HELPER: {exc}", file=sys.stderr, flush=True)
    sys.exit(77)


def wait_for(path: str, timeout: float, label: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {label}: {path}")


def read_target(label: str) -> str:
    try:
        data = Path(TARGET_FILE).read_text()
    except PermissionError as exc:
        print(f"{label}_DENIED errno={exc.errno}", flush=True)
        return "denied"
    except OSError as exc:
        if exc.errno in (1, 13):
            print(f"{label}_DENIED errno={exc.errno}", flush=True)
            return "denied"
        raise
    print(f"{label}_ALLOWED bytes={len(data)}", flush=True)
    return "allowed"


class SensitiveReaderTool(BaseTool):
    name: str = "sensitive_reader"
    description: str = "Reads a sensitive file after a deterministic await."

    def __init__(
        self,
        *,
        tool_suspended: asyncio.Event,
        idle_done: asyncio.Event,
    ) -> None:
        super().__init__()
        object.__setattr__(self, "tool_suspended", tool_suspended)
        object.__setattr__(self, "idle_done", idle_done)

    def _run(self, *_: object, **__: object) -> str:
        raise RuntimeError("this scenario must use BaseTool.ainvoke")

    async def _arun(self, command: str = "go", **__: object) -> str:
        if command == "warmup":
            return Path(WARMUP_FILE).read_text()

        print("TOOL_ENTERED", flush=True)

        # At this point BaseTool.ainvoke has established the tool context.
        # The next await must suspend this coroutine and let the event loop run
        # idle_coroutine() without inheriting this tool context.
        self.tool_suspended.set()
        await self.idle_done.wait()

        print("TOOL_RESUMED opening_target", flush=True)
        return read_target("TOOL")


async def idle_coroutine(
    *,
    tool_suspended: asyncio.Event,
    idle_done: asyncio.Event,
) -> str:
    await tool_suspended.wait()
    print("IDLE_RUNNING opening_target", flush=True)
    result = read_target("IDLE")
    idle_done.set()
    return result


async def run_scenario() -> int:
    tool_suspended = asyncio.Event()
    idle_done = asyncio.Event()
    tool = SensitiveReaderTool(
        tool_suspended=tool_suspended,
        idle_done=idle_done,
    )

    wait_for(READY_PATH, READY_TIMEOUT, "IronScope ready marker")
    print("IRONSCOPE_READY", flush=True)
    warmup_task = asyncio.create_task(tool.ainvoke("warmup"), name="ironscope-warmup-task")
    warmup_result = await warmup_task
    if "ironscope async warmup" not in str(warmup_result):
        raise AssertionError(f"unexpected warmup result: {warmup_result!r}")
    await asyncio.sleep(0.5)

    print("SCENARIO_START", flush=True)
    tool_task = asyncio.create_task(tool.ainvoke("go"), name="ironscope-tool-task")
    idle_task = asyncio.create_task(
        idle_coroutine(tool_suspended=tool_suspended, idle_done=idle_done),
        name="ironscope-idle-task",
    )
    tool_result, idle_result = await asyncio.gather(tool_task, idle_task)
    print(f"RESULT tool={tool_result} idle={idle_result}", flush=True)

    if idle_result != "allowed":
        print(
            "FAIL: idle coroutine was denied, which indicates leaked tool context",
            file=sys.stderr,
            flush=True,
        )
        return 1
    if tool_result != "denied":
        print(
            "FAIL: resumed tool was not denied, which indicates missing tool enforcement",
            file=sys.stderr,
            flush=True,
        )
        return 1

    await asyncio.sleep(0.2)
    print("SCENARIO_PASS", flush=True)
    return 0


def main() -> int:
    target = Path(TARGET_FILE)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("ironscope async policy probe fixture\n")
    Path(WARMUP_FILE).write_text("ironscope async warmup fixture\n")

    print(os.getpid(), flush=True)
    print(f"TARGET_FILE {TARGET_FILE}", flush=True)
    print(f"WARMUP_FILE {WARMUP_FILE}", flush=True)
    print(f"READY_FILE {READY_PATH}", flush=True)
    wait_for(START_SIGNAL, START_TIMEOUT, "start signal")
    return asyncio.run(run_scenario())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"SCENARIO_ERROR {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise
