#!/usr/bin/env python3
"""Standalone LangGraph-style tool execution daemon for IronScope.

This intentionally avoids an LLM. It mimics the execution shape IronScope must
handle after a LangGraph/LangChain agent has selected tool calls: synchronous
BaseTool.invoke, asynchronous BaseTool.ainvoke, nested and parallel async tools,
thread offload, explicit thread creation, asyncio.to_thread, subprocesses that
outlive the Python tool frame, and non-tool work in the same process.
"""

from __future__ import annotations

import argparse
import asyncio
import errno
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

try:
    from langchain_core.tools import BaseTool
except Exception as exc:  # pragma: no cover - environment gate
    print(f"MISSING_LANGCHAIN_CORE: {exc}", file=sys.stderr, flush=True)
    sys.exit(77)

START_SIGNAL = os.environ.get("IRONSCOPE_DEMO_START", "/tmp/ironscope_langgraph_demo_start")
READY_FILE = os.environ.get("IRONSCOPE_READY_FILE", "/tmp/ironscope/langgraph-demo-ready")

ALLOWED_FILE = "/tmp/ironscope_demo_allowed.txt"
NOTE_FILE = "/tmp/ironscope_demo_note.txt"
READ_SECRET = "/tmp/ironscope_demo_read_secret.txt"
ASYNC_INNER_SECRET = "/tmp/ironscope_demo_async_inner_secret.txt"
ASYNC_OUTER_SECRET = "/tmp/ironscope_demo_async_outer_secret.txt"
PARALLEL_A_SECRET = "/tmp/ironscope_demo_parallel_a_secret.txt"
PARALLEL_B_SECRET = "/tmp/ironscope_demo_parallel_b_secret.txt"
THREADPOOL_SECRET = "/tmp/ironscope_demo_threadpool_secret.txt"
THREADING_SECRET = "/tmp/ironscope_demo_threading_secret.txt"
TO_THREAD_SECRET = "/tmp/ironscope_demo_to_thread_secret.txt"
BACKGROUND_SECRET = "/tmp/ironscope_demo_background_secret.txt"

BACKGROUND_CHILDREN: list[subprocess.Popen[str]] = []


def wait_for(path: str, timeout: float, label: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {label}: {path}")


def prepare_fixtures() -> None:
    fixtures = {
        ALLOWED_FILE: "allowed fixture\n",
        READ_SECRET: "read secret\n",
        ASYNC_INNER_SECRET: "async inner secret\n",
        ASYNC_OUTER_SECRET: "async outer secret\n",
        PARALLEL_A_SECRET: "parallel a secret\n",
        PARALLEL_B_SECRET: "parallel b secret\n",
        THREADPOOL_SECRET: "threadpool secret\n",
        THREADING_SECRET: "threading secret\n",
        TO_THREAD_SECRET: "to_thread secret\n",
        BACKGROUND_SECRET: "background secret\n",
    }
    for path, text in fixtures.items():
        Path(path).write_text(text)
    Path(NOTE_FILE).unlink(missing_ok=True)


def operation_denied(exc: OSError) -> bool:
    return exc.errno in (errno.EPERM, errno.EACCES, 1, 13)


def assert_policy_result(label: str, action: Callable[[], object], *, expect_enforce: bool) -> object | None:
    try:
        result = action()
    except PermissionError:
        if expect_enforce:
            print(f"RESULT {label} PASS denied", flush=True)
            return None
        raise AssertionError(f"{label} was denied in monitor mode")
    except OSError as exc:
        if expect_enforce and operation_denied(exc):
            print(f"RESULT {label} PASS denied_errno={exc.errno}", flush=True)
            return None
        raise
    if expect_enforce:
        raise AssertionError(f"{label} was allowed in enforce mode")
    print(f"RESULT {label} PASS allowed", flush=True)
    return result


async def assert_async_policy_result(label: str, action, *, expect_enforce: bool) -> object | None:
    try:
        result = await action()
    except PermissionError:
        if expect_enforce:
            print(f"RESULT {label} PASS denied", flush=True)
            return None
        raise AssertionError(f"{label} was denied in monitor mode")
    except OSError as exc:
        if expect_enforce and operation_denied(exc):
            print(f"RESULT {label} PASS denied_errno={exc.errno}", flush=True)
            return None
        raise
    if expect_enforce:
        raise AssertionError(f"{label} was allowed in enforce mode")
    print(f"RESULT {label} PASS allowed", flush=True)
    return result


def should_expect_read_deny(path: str, *, expect_enforce: bool) -> bool:
    return expect_enforce and path != ALLOWED_FILE


def read_with_policy(path: str, *, expect_enforce: bool) -> str:
    expect_deny = should_expect_read_deny(path, expect_enforce=expect_enforce)
    try:
        Path(path).read_text()
    except PermissionError:
        if expect_deny:
            return "denied"
        raise
    except OSError as exc:
        if expect_deny and operation_denied(exc):
            return f"denied_errno={exc.errno}"
        raise
    if expect_deny:
        raise AssertionError(f"expected read deny for {path}")
    return "allowed"


class ReadFileTool(BaseTool):
    name: str = "read_file"
    description: str = "Read a local file."

    def _run(self, path: str, **_: object) -> str:
        return Path(path).read_text()[:128]


class ShellTool(BaseTool):
    name: str = "shell"
    description: str = "Run /usr/bin/id."

    def _run(self, command: str, **_: object) -> str:
        if command != "id":
            raise ValueError("only id is supported by this deterministic demo")
        proc = subprocess.run(
            ["/usr/bin/id"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return proc.stdout + proc.stderr


class WriteNoteTool(BaseTool):
    name: str = "write_note"
    description: str = "Write a note under /tmp."

    def _run(self, text: str, **_: object) -> str:
        Path(NOTE_FILE).write_text(text)
        return NOTE_FILE


class AsyncInnerTool(BaseTool):
    name: str = "async_inner"
    description: str = "Read an async inner path."

    def _run(self, path: str, **_: object) -> str:
        return asyncio.run(self._arun(path))

    async def _arun(self, path: str, **_: object) -> str:
        await asyncio.sleep(0.03)
        return Path(path).read_text()


class AsyncOuterTool(BaseTool):
    name: str = "async_outer"
    description: str = "Invoke an inner async tool, then read an outer path."

    def __init__(self, inner: AsyncInnerTool, expect_enforce: bool) -> None:
        super().__init__()
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_expect_enforce", expect_enforce)

    def _run(self, mode: str, **_: object) -> str:
        return asyncio.run(self._arun(mode))

    async def _arun(self, mode: str, **_: object) -> str:
        if mode == "warmup":
            await self._inner.ainvoke(ALLOWED_FILE)
            return Path(ALLOWED_FILE).read_text()
        await assert_async_policy_result(
            "nested_inner", lambda: self._inner.ainvoke(ASYNC_INNER_SECRET), expect_enforce=self._expect_enforce
        )
        await asyncio.sleep(0.03)
        return Path(ASYNC_OUTER_SECRET).read_text()


class ParallelReaderTool(BaseTool):
    name: str
    description: str = "Read a path in an async parallel tool."

    def _run(self, path: str, **_: object) -> str:
        return asyncio.run(self._arun(path))

    async def _arun(self, path: str, **_: object) -> str:
        await asyncio.sleep(0.03)
        return Path(path).read_text()


class CancelledTool(BaseTool):
    name: str = "async_cancelled"
    description: str = "Sleep until cancelled."

    def _run(self, *_: object, **__: object) -> str:
        raise NotImplementedError

    async def _arun(self, *_: object, **__: object) -> str:
        await asyncio.sleep(10)
        return "unexpected"


class ExceptionTool(BaseTool):
    name: str = "async_exception"
    description: str = "Raise after an await."

    def _run(self, *_: object, **__: object) -> str:
        raise NotImplementedError

    async def _arun(self, *_: object, **__: object) -> str:
        await asyncio.sleep(0.03)
        raise RuntimeError("intentional async tool exception")


class ThreadPoolReaderTool(BaseTool):
    name: str = "threadpool_reader"
    description: str = "Read a path from ThreadPoolExecutor."

    def __init__(self, expect_enforce: bool) -> None:
        super().__init__()
        object.__setattr__(self, "_expect_enforce", expect_enforce)

    def _run(self, path: str, **_: object) -> str:
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="ag-demo-threadpool") as executor:
            return executor.submit(read_with_policy, path, expect_enforce=self._expect_enforce).result(timeout=5)


class ThreadingReaderTool(BaseTool):
    name: str = "threading_reader"
    description: str = "Read a path from threading.Thread."

    def __init__(self, expect_enforce: bool) -> None:
        super().__init__()
        object.__setattr__(self, "_expect_enforce", expect_enforce)

    def _run(self, path: str, **_: object) -> str:
        result: list[str] = []
        error: list[BaseException] = []

        def worker() -> None:
            try:
                result.append(read_with_policy(path, expect_enforce=self._expect_enforce))
            except BaseException as exc:
                error.append(exc)

        thread = threading.Thread(target=worker, name="ag-demo-threading-reader")
        thread.start()
        thread.join(timeout=5)
        if thread.is_alive():
            raise TimeoutError("threading reader did not finish")
        if error:
            raise error[0]
        return result[0]


class AsyncioToThreadReaderTool(BaseTool):
    name: str = "asyncio_to_thread_reader"
    description: str = "Read a path from asyncio.to_thread."

    def __init__(self, expect_enforce: bool) -> None:
        super().__init__()
        object.__setattr__(self, "_expect_enforce", expect_enforce)

    def _run(self, path: str, **_: object) -> str:
        return asyncio.run(self._arun(path))

    async def _arun(self, path: str, **_: object) -> str:
        return await asyncio.to_thread(read_with_policy, path, expect_enforce=self._expect_enforce)


class BackgroundPopenTool(BaseTool):
    name: str = "background_popen"
    description: str = "Spawn a child that reads after the Python tool frame returns."

    def __init__(self, expect_enforce: bool) -> None:
        super().__init__()
        object.__setattr__(self, "_expect_enforce", expect_enforce)

    def _run(self, path: str, **_: object) -> str:
        code = (
            "import errno, pathlib, sys, time\n"
            "path = sys.argv[1]\n"
            "expect = sys.argv[2] == '1'\n"
            "time.sleep(1.15)\n"
            "try:\n"
            "    pathlib.Path(path).read_text()\n"
            "except PermissionError:\n"
            "    print('CHILD_DENIED', flush=True)\n"
            "    raise SystemExit(0 if expect else 2)\n"
            "except OSError as exc:\n"
            "    if exc.errno in (errno.EPERM, errno.EACCES, 1, 13):\n"
            "        print(f'CHILD_DENIED_ERRNO {exc.errno}', flush=True)\n"
            "        raise SystemExit(0 if expect else 2)\n"
            "    raise\n"
            "print('CHILD_ALLOWED', flush=True)\n"
            "raise SystemExit(2 if expect else 0)\n"
        )
        proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                code,
                path,
                "1" if should_expect_read_deny(path, expect_enforce=self._expect_enforce) else "0",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        BACKGROUND_CHILDREN.append(proc)
        print(f"BACKGROUND_CHILD_PID {proc.pid}", flush=True)
        return str(proc.pid)


def build_tools(expect_enforce: bool) -> dict[str, BaseTool]:
    inner = AsyncInnerTool()
    return {
        "read_file": ReadFileTool(),
        "shell": ShellTool(),
        "write_note": WriteNoteTool(),
        "async_inner": inner,
        "async_outer": AsyncOuterTool(inner, expect_enforce),
        "async_parallel_a": ParallelReaderTool(name="async_parallel_a"),
        "async_parallel_b": ParallelReaderTool(name="async_parallel_b"),
        "async_cancelled": CancelledTool(),
        "async_exception": ExceptionTool(),
        "threadpool_reader": ThreadPoolReaderTool(expect_enforce),
        "threading_reader": ThreadingReaderTool(expect_enforce),
        "asyncio_to_thread_reader": AsyncioToThreadReaderTool(expect_enforce),
        "background_popen": BackgroundPopenTool(expect_enforce),
    }


async def warm_runtime_resolver(tools: dict[str, BaseTool]) -> None:
    print("DEMO_WARMUP_START", flush=True)
    tools["read_file"].invoke(ALLOWED_FILE)
    try:
        tools["shell"].invoke("id")
    except Exception:
        pass
    tools["write_note"].invoke("warmup note\n")
    await tools["async_inner"].ainvoke(ALLOWED_FILE)
    await tools["async_outer"].ainvoke("warmup")
    await asyncio.gather(
        tools["async_parallel_a"].ainvoke(ALLOWED_FILE),
        tools["async_parallel_b"].ainvoke(ALLOWED_FILE),
    )
    task = asyncio.create_task(tools["async_cancelled"].ainvoke("warmup"))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    try:
        await tools["async_exception"].ainvoke("warmup")
    except RuntimeError:
        pass
    tools["threadpool_reader"].invoke(ALLOWED_FILE)
    tools["threading_reader"].invoke(ALLOWED_FILE)
    await tools["asyncio_to_thread_reader"].ainvoke(ALLOWED_FILE)
    tools["background_popen"].invoke(ALLOWED_FILE)
    wait_background_child()
    await asyncio.sleep(0.5)
    print("DEMO_WARMUP_DONE", flush=True)


def wait_background_child() -> None:
    if not BACKGROUND_CHILDREN:
        return
    proc = BACKGROUND_CHILDREN.pop(0)
    out, err = proc.communicate(timeout=10)
    print(f"BACKGROUND_CHILD_RC {proc.returncode}", flush=True)
    print(f"BACKGROUND_CHILD_STDOUT {out.strip()}", flush=True)
    if err.strip():
        print(f"BACKGROUND_CHILD_STDERR {err.strip()}", flush=True)
    if proc.returncode != 0:
        raise AssertionError(f"background child failed: rc={proc.returncode} out={out!r} err={err!r}")


async def run_non_tool_checks() -> None:
    Path("/etc/passwd").read_text()
    subprocess.run(["/usr/bin/true"], check=True)
    await asyncio.sleep(0.05)
    Path("/etc/passwd").read_text()
    print("RESULT non_tool_activity PASS allowed", flush=True)


async def run_policy_scenarios(tools: dict[str, BaseTool], *, expect_enforce: bool) -> None:
    print("DEMO_SCENARIO_START", flush=True)
    await run_non_tool_checks()

    tools["read_file"].invoke(ALLOWED_FILE)
    print("RESULT read_allowed PASS", flush=True)
    assert_policy_result("read_secret", lambda: tools["read_file"].invoke(READ_SECRET), expect_enforce=expect_enforce)
    try:
        tools["shell"].invoke("id")
    except Exception:
        pass
    await asyncio.sleep(0.2)
    assert_policy_result("shell_id", lambda: tools["shell"].invoke("id"), expect_enforce=expect_enforce)
    # The first execution may seed IronScope's userspace resolver cache.
    # The second execution proves the resolved tool context is applied to
    # subsequent behavior, which is the V0.1 contract for newly seen tools.
    tools["write_note"].invoke("demo note warm resolver\n")
    await asyncio.sleep(0.2)
    note = tools["write_note"].invoke("demo note\n")
    if note != NOTE_FILE or not Path(NOTE_FILE).exists():
        raise AssertionError("write_note did not write expected note")
    print("RESULT write_note PASS", flush=True)

    await assert_async_policy_result(
        "nested_outer", lambda: tools["async_outer"].ainvoke("deny"), expect_enforce=expect_enforce
    )
    await asyncio.gather(
        assert_async_policy_result(
            "parallel_a", lambda: tools["async_parallel_a"].ainvoke(PARALLEL_A_SECRET), expect_enforce=expect_enforce
        ),
        assert_async_policy_result(
            "parallel_b", lambda: tools["async_parallel_b"].ainvoke(PARALLEL_B_SECRET), expect_enforce=expect_enforce
        ),
    )

    cancel_task = asyncio.create_task(tools["async_cancelled"].ainvoke("cancel"))
    await asyncio.sleep(0.1)
    cancel_task.cancel()
    try:
        await cancel_task
    except asyncio.CancelledError:
        print("RESULT async_cancelled PASS", flush=True)
    else:
        raise AssertionError("async_cancelled did not cancel")

    try:
        await tools["async_exception"].ainvoke("boom")
    except RuntimeError:
        print("RESULT async_exception PASS", flush=True)
    else:
        raise AssertionError("async_exception did not raise")

    for label, tool_name, path in (
        ("threadpool_reader", "threadpool_reader", THREADPOOL_SECRET),
        ("threading_reader", "threading_reader", THREADING_SECRET),
    ):
        result = str(tools[tool_name].invoke(path))
        expected = "denied" if expect_enforce else "allowed"
        if not result.startswith(expected):
            raise AssertionError(f"{label} expected {expected}, got {result!r}")
        print(f"RESULT {label} PASS {result}", flush=True)

    result = str(await tools["asyncio_to_thread_reader"].ainvoke(TO_THREAD_SECRET))
    expected = "denied" if expect_enforce else "allowed"
    if not result.startswith(expected):
        raise AssertionError(f"asyncio_to_thread_reader expected {expected}, got {result!r}")
    print(f"RESULT asyncio_to_thread_reader PASS {result}", flush=True)

    tools["background_popen"].invoke(BACKGROUND_SECRET)
    await asyncio.sleep(0.15)
    print("AFTER_BACKGROUND_TOOL_FRAME", flush=True)
    wait_background_child()

    await run_non_tool_checks()
    await asyncio.sleep(0.25)
    print("DEMO_SCENARIO_DONE", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expect",
        choices=("monitor", "enforce"),
        default=os.environ.get("IRONSCOPE_DEMO_EXPECT", "enforce"),
        help="expected IronScope mode; enforce expects configured tool denies, monitor expects allows",
    )
    parser.add_argument(
        "--start-signal",
        default=START_SIGNAL,
        help="path touched by operator/test to start the scenario",
    )
    parser.add_argument(
        "--ready-file",
        default=READY_FILE,
        help="IronScope ready marker to wait for after process attach",
    )
    parser.add_argument(
        "--start-timeout",
        type=float,
        default=120.0,
        help="seconds to wait for the operator/test start signal",
    )
    parser.add_argument(
        "--ready-timeout",
        type=float,
        default=60.0,
        help="seconds to wait for the IronScope ready marker",
    )
    parser.add_argument(
        "--no-wait-start",
        action="store_true",
        help="run immediately instead of waiting for start signal",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    expect_enforce = args.expect == "enforce"
    print(os.getpid(), flush=True)
    prepare_fixtures()
    print(f"DEMO_DAEMON_READY expect={args.expect}", flush=True)
    if not args.no_wait_start:
        wait_for(args.start_signal, args.start_timeout, "start signal")
    wait_for(args.ready_file, args.ready_timeout, "IronScope ready marker")

    tools = build_tools(expect_enforce)
    asyncio.run(warm_runtime_resolver(tools))
    asyncio.run(run_policy_scenarios(tools, expect_enforce=expect_enforce))
    print("DEMO_DONE", flush=True)
    time.sleep(1.0)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"DEMO_ERROR {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise
