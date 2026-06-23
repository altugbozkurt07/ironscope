#!/usr/bin/env python3
"""Deterministic async lifecycle scenarios for IronScope v0.1 async lifecycle."""

from __future__ import annotations

import asyncio
import errno
import os
import sys
import time
from pathlib import Path

START_SIGNAL = os.environ.get("IRONSCOPE_START_SIGNAL", "/tmp/ironscope_async_lifecycle_start")
READY_PATH = os.environ.get("IRONSCOPE_READY_FILE", "/tmp/ironscope/async-lifecycle-ready")
CASE = os.environ.get("IRONSCOPE_ASYNC_CASE", "nested")

ALLOWED_FILE = "/tmp/ironscope_async_allowed.txt"
INNER_SECRET = "/tmp/ironscope_async_inner_secret.txt"
OUTER_SECRET = "/tmp/ironscope_async_outer_secret.txt"
PARALLEL_A_SECRET = "/tmp/ironscope_async_parallel_a_secret.txt"
PARALLEL_B_SECRET = "/tmp/ironscope_async_parallel_b_secret.txt"

try:
    from langchain_core.tools import BaseTool
except Exception as exc:  # pragma: no cover
    print(f"MISSING_LANGCHAIN_CORE: {exc}", file=sys.stderr, flush=True)
    sys.exit(77)


def wait_for(path: str, timeout: float, label: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {label}: {path}")


async def expect_denied(label: str, action) -> None:
    try:
        await action()
    except PermissionError:
        print(f"RESULT {label} PASS denied", flush=True)
        return
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES):
            print(f"RESULT {label} PASS denied_errno={exc.errno}", flush=True)
            return
        print(f"RESULT {label} FAIL unexpected_errno={exc.errno}", flush=True)
        raise
    print(f"RESULT {label} FAIL allowed", flush=True)
    raise AssertionError(f"{label} was allowed")


class AsyncInnerTool(BaseTool):
    name: str = "async_inner"
    description: str = "Read the inner async secret."

    def _run(self, *_: object, **__: object) -> str:
        raise NotImplementedError

    async def _arun(self, path: str = INNER_SECRET, **__: object) -> str:
        await asyncio.sleep(0.05)
        return Path(path).read_text()


INNER_TOOL = AsyncInnerTool()


class AsyncOuterTool(BaseTool):
    name: str = "async_outer"
    description: str = "Invoke an inner tool, then read the outer async secret."

    def _run(self, *_: object, **__: object) -> str:
        raise NotImplementedError

    async def _arun(self, command: str = "deny", **__: object) -> str:
        if command == "warmup":
            await INNER_TOOL.ainvoke(ALLOWED_FILE)
            await asyncio.sleep(0.05)
            return Path(ALLOWED_FILE).read_text()
        await expect_denied("nested_inner_denied", lambda: INNER_TOOL.ainvoke(INNER_SECRET))
        await asyncio.sleep(0.05)
        return Path(OUTER_SECRET).read_text()


class ParallelATool(BaseTool):
    name: str = "async_parallel_a"
    description: str = "Read parallel secret A."

    def _run(self, *_: object, **__: object) -> str:
        raise NotImplementedError

    async def _arun(self, path: str = PARALLEL_A_SECRET, **__: object) -> str:
        await asyncio.sleep(0.05)
        return Path(path).read_text()


class ParallelBTool(BaseTool):
    name: str = "async_parallel_b"
    description: str = "Read parallel secret B."

    def _run(self, *_: object, **__: object) -> str:
        raise NotImplementedError

    async def _arun(self, path: str = PARALLEL_B_SECRET, **__: object) -> str:
        await asyncio.sleep(0.02)
        return Path(path).read_text()


class CancelledTool(BaseTool):
    name: str = "async_cancelled"
    description: str = "Sleep until cancelled."

    def _run(self, *_: object, **__: object) -> str:
        raise NotImplementedError

    async def _arun(self, command: str = "cancel", **__: object) -> str:
        if command == "warmup":
            await asyncio.sleep(0.01)
            return "warmup"
        await asyncio.sleep(10)
        return "unexpected"


class ExceptionTool(BaseTool):
    name: str = "async_exception"
    description: str = "Raise after an await."

    def _run(self, *_: object, **__: object) -> str:
        raise NotImplementedError

    async def _arun(self, command: str = "boom", **__: object) -> str:
        if command == "warmup":
            await asyncio.sleep(0.01)
            return "warmup"
        await asyncio.sleep(0.05)
        raise RuntimeError("intentional async tool failure")


async def warm_resolver(tools: dict[str, BaseTool]) -> None:
    Path(ALLOWED_FILE).write_text("allowed async fixture\n")

    if CASE == "nested":
        await tools["async_outer"].ainvoke("warmup")
    elif CASE == "parallel":
        await asyncio.gather(
            tools["async_parallel_a"].ainvoke(ALLOWED_FILE),
            tools["async_parallel_b"].ainvoke(ALLOWED_FILE),
        )
    elif CASE == "cancelled":
        await tools["async_cancelled"].ainvoke("warmup")
    elif CASE == "exception":
        await tools["async_exception"].ainvoke("warmup")
    else:
        raise ValueError(f"unsupported IRONSCOPE_ASYNC_CASE={CASE!r}")
    await asyncio.sleep(0.5)


async def run_case(tools: dict[str, BaseTool]) -> None:
    for path in (ALLOWED_FILE, INNER_SECRET, OUTER_SECRET, PARALLEL_A_SECRET, PARALLEL_B_SECRET):
        Path(path).write_text(f"secret fixture for {path}\n")

    await warm_resolver(tools)

    if CASE == "nested":
        await expect_denied("nested_outer_denied", lambda: tools["async_outer"].ainvoke("outer"))
    elif CASE == "parallel":
        await asyncio.gather(
            expect_denied("parallel_a_denied", lambda: tools["async_parallel_a"].ainvoke(PARALLEL_A_SECRET)),
            expect_denied("parallel_b_denied", lambda: tools["async_parallel_b"].ainvoke(PARALLEL_B_SECRET)),
        )
    elif CASE == "cancelled":
        task = asyncio.create_task(tools["async_cancelled"].ainvoke("cancel"))
        await asyncio.sleep(0.2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            print("RESULT cancelled_tool PASS", flush=True)
        else:
            raise AssertionError("cancelled tool was not cancelled")
    elif CASE == "exception":
        try:
            await tools["async_exception"].ainvoke("boom")
        except RuntimeError:
            print("RESULT exception_tool PASS", flush=True)
        else:
            raise AssertionError("exception tool did not raise")
    else:
        raise ValueError(f"unsupported IRONSCOPE_ASYNC_CASE={CASE!r}")


def main() -> int:
    print(os.getpid(), flush=True)
    wait_for(START_SIGNAL, 30, "start signal")

    tools: dict[str, BaseTool] = {
        "async_inner": INNER_TOOL,
        "async_outer": AsyncOuterTool(),
        "async_parallel_a": ParallelATool(),
        "async_parallel_b": ParallelBTool(),
        "async_cancelled": CancelledTool(),
        "async_exception": ExceptionTool(),
    }
    wait_for(READY_PATH, 15, "ironscope ready marker")

    print(f"ASYNC_LIFECYCLE_CASE_START {CASE}", flush=True)
    asyncio.run(run_case(tools))
    time.sleep(0.25)
    print(f"ASYNC_LIFECYCLE_CASE_DONE {CASE}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"SCENARIO_ERROR {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise
