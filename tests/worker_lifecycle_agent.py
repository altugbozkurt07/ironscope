#!/usr/bin/env python3
"""Deterministic worker/subprocess lifecycle scenarios for IronScope v0.1 worker lifecycle."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

START_SIGNAL = os.environ.get("IRONSCOPE_START_SIGNAL", "/tmp/ironscope_worker_lifecycle_start")
READY_PATH = os.environ.get("IRONSCOPE_READY_FILE", "/tmp/ironscope/worker-lifecycle-ready")
CASE = os.environ.get("IRONSCOPE_WORKER_CASE", "threadpool")

ALLOWED_FILE = "/tmp/ironscope_worker_allowed.txt"
THREADPOOL_SECRET = "/tmp/ironscope_worker_threadpool_secret.txt"
THREADING_SECRET = "/tmp/ironscope_worker_threading_secret.txt"
TO_THREAD_SECRET = "/tmp/ironscope_worker_to_thread_secret.txt"
BACKGROUND_SECRET = "/tmp/ironscope_worker_background_secret.txt"
LANGGRAPH_TOOLNODE_SECRET = "/tmp/ironscope_worker_langgraph_toolnode_secret.txt"

try:
    from langchain_core.tools import BaseTool
except Exception as exc:  # pragma: no cover - environment gate
    print(f"MISSING_LANGCHAIN_CORE: {exc}", file=sys.stderr, flush=True)
    sys.exit(77)

BACKGROUND_CHILDREN: list[subprocess.Popen[str]] = []


def wait_for(path: str, timeout: float, label: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {label}: {path}")


def read_expect_denied(path: str) -> str:
    try:
        Path(path).read_text()
    except PermissionError:
        return "denied"
    except OSError as exc:
        if exc.errno in (1, 13):
            return f"denied_errno={exc.errno}"
        raise
    raise AssertionError(f"read unexpectedly allowed: {path}")


def read_with_expected_policy(path: str) -> str:
    if path == ALLOWED_FILE:
        content = Path(path).read_text()
        if "allowed fixture" not in content:
            raise AssertionError(f"allowed fixture content mismatch: {content!r}")
        return "allowed"
    return read_expect_denied(path)


class ThreadPoolReaderTool(BaseTool):
    name: str = "threadpool_reader"
    description: str = "Read a file from a ThreadPoolExecutor worker."

    def _run(self, path: str, **_: object) -> str:
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="ironscope-threadpool") as executor:
            return executor.submit(read_with_expected_policy, path).result(timeout=5)


class ThreadingReaderTool(BaseTool):
    name: str = "threading_reader"
    description: str = "Read a file from a threading.Thread worker."

    def _run(self, path: str, **_: object) -> str:
        result: list[str] = []
        error: list[BaseException] = []

        def worker() -> None:
            try:
                result.append(read_with_expected_policy(path))
            except BaseException as exc:
                error.append(exc)

        thread = threading.Thread(target=worker, name="ironscope-threading-reader")
        thread.start()
        thread.join(timeout=5)
        if thread.is_alive():
            raise TimeoutError("threading_reader worker did not finish")
        if error:
            raise error[0]
        if not result:
            raise AssertionError("threading_reader worker produced no result")
        return result[0]


class AsyncioToThreadReaderTool(BaseTool):
    name: str = "asyncio_to_thread_reader"
    description: str = "Read a file from asyncio.to_thread."

    def _run(self, path: str, **_: object) -> str:
        return asyncio.run(self._arun(path))

    async def _arun(self, path: str, **_: object) -> str:
        return await asyncio.to_thread(read_with_expected_policy, path)


class BackgroundPopenTool(BaseTool):
    name: str = "background_popen"
    description: str = "Start a child that performs a delayed file read after the tool frame returns."

    def _run(self, path: str, **_: object) -> str:
        code = (
            "import pathlib, sys, time\n"
            "path = sys.argv[1]\n"
            "time.sleep(0.45)\n"
            "try:\n"
            "    content = pathlib.Path(path).read_text()\n"
            "except PermissionError:\n"
            "    print('CHILD_DENIED', flush=True)\n"
            "    raise SystemExit(0)\n"
            "except OSError as exc:\n"
            "    if exc.errno in (1, 13):\n"
            "        print(f'CHILD_DENIED_ERRNO {exc.errno}', flush=True)\n"
            "        raise SystemExit(0)\n"
            "    raise\n"
            "if 'allowed fixture' in content:\n"
            "    print('CHILD_ALLOWED', flush=True)\n"
            "    raise SystemExit(0)\n"
            "print('CHILD_UNEXPECTED_ALLOWED', flush=True)\n"
            "raise SystemExit(2)\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", code, path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        BACKGROUND_CHILDREN.append(proc)
        print(f"BACKGROUND_CHILD_PID {proc.pid}", flush=True)
        return str(proc.pid)


class LangGraphToolNodeReaderTool(BaseTool):
    name: str = "langgraph_toolnode_reader"
    description: str = "Read a file when dispatched by LangGraph ToolNode."

    def _run(self, path: str, **_: object) -> str:
        return read_with_expected_policy(path)


def assert_denied_result(label: str, value: str) -> None:
    if not value.startswith("denied"):
        raise AssertionError(f"{label} expected denied result, got {value!r}")
    print(f"RESULT {label} PASS {value}", flush=True)


def assert_allowed_result(label: str, value: str) -> None:
    if value != "allowed":
        raise AssertionError(f"{label} expected allowed result, got {value!r}")
    print(f"RESULT {label} PASS allowed", flush=True)


def wait_background_child(*, expect_denied: bool) -> None:
    if not BACKGROUND_CHILDREN:
        raise AssertionError("background child was not started")
    proc = BACKGROUND_CHILDREN[-1]
    out, err = proc.communicate(timeout=10)
    print(f"BACKGROUND_CHILD_RC {proc.returncode}", flush=True)
    print(f"BACKGROUND_CHILD_STDOUT {out.strip()}", flush=True)
    if err.strip():
        print(f"BACKGROUND_CHILD_STDERR {err.strip()}", flush=True)
    expected = "CHILD_DENIED" if expect_denied else "CHILD_ALLOWED"
    if proc.returncode != 0 or expected not in out:
        raise AssertionError(
            f"background child did not observe expected {expected}: rc={proc.returncode}"
        )


def main() -> int:
    print(os.getpid(), flush=True)
    wait_for(START_SIGNAL, 30, "start signal")

    tools: dict[str, BaseTool] = {
        "threadpool_reader": ThreadPoolReaderTool(),
        "threading_reader": ThreadingReaderTool(),
        "asyncio_to_thread_reader": AsyncioToThreadReaderTool(),
        "background_popen": BackgroundPopenTool(),
        "langgraph_toolnode_reader": LangGraphToolNodeReaderTool(),
    }
    wait_for(READY_PATH, 15, "ironscope ready marker")

    print(f"WORKER_SCENARIO_START {CASE}", flush=True)
    if CASE == "threadpool":
        assert_allowed_result("threadpool_reader_warmup", str(tools["threadpool_reader"].invoke(ALLOWED_FILE)))
        time.sleep(0.5)
        result = tools["threadpool_reader"].invoke(THREADPOOL_SECRET)
        assert_denied_result("threadpool_reader", str(result))
    elif CASE == "threading":
        assert_allowed_result("threading_reader_warmup", str(tools["threading_reader"].invoke(ALLOWED_FILE)))
        time.sleep(0.5)
        result = tools["threading_reader"].invoke(THREADING_SECRET)
        assert_denied_result("threading_reader", str(result))
    elif CASE == "to_thread":
        assert_allowed_result(
            "asyncio_to_thread_reader_warmup",
            str(asyncio.run(tools["asyncio_to_thread_reader"].ainvoke(ALLOWED_FILE))),
        )
        time.sleep(0.5)
        result = asyncio.run(tools["asyncio_to_thread_reader"].ainvoke(TO_THREAD_SECRET))
        assert_denied_result("asyncio_to_thread_reader", str(result))
    elif CASE == "background_popen":
        warmup = tools["background_popen"].invoke(ALLOWED_FILE)
        if not str(warmup).isdigit():
            raise AssertionError(f"background_popen warmup returned non-pid result: {warmup!r}")
        wait_background_child(expect_denied=False)
        time.sleep(0.5)
        result = tools["background_popen"].invoke(BACKGROUND_SECRET)
        if not str(result).isdigit():
            raise AssertionError(f"background_popen returned non-pid result: {result!r}")
        print("RESULT background_popen_started PASS", flush=True)
        time.sleep(0.15)
        print("AFTER_TOOL_FRAME_DELAY", flush=True)
        wait_background_child(expect_denied=True)
    elif CASE == "langgraph_toolnode":
        try:
            from langchain_core.messages import AIMessage
            from langgraph._internal._constants import CONF, CONFIG_KEY_RUNTIME
            from langgraph.prebuilt import ToolNode
            from langgraph.runtime import Runtime
        except Exception as exc:
            print(f"SKIP_LANGGRAPH_UNAVAILABLE {type(exc).__name__}: {exc}", flush=True)
            return 77

        node = ToolNode([tools["langgraph_toolnode_reader"]])
        warmup_message = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "langgraph_toolnode_reader",
                    "args": {"path": ALLOWED_FILE},
                    "id": "ironscope-warmup-call-1",
                    "type": "tool_call",
                }
            ],
        )
        warmup_output = node.invoke(
            {"messages": [warmup_message]},
            config={CONF: {CONFIG_KEY_RUNTIME: Runtime()}},
        )
        warmup_messages = warmup_output.get("messages", []) if isinstance(warmup_output, dict) else []
        if len(warmup_messages) != 1:
            raise AssertionError(f"unexpected ToolNode warmup output: {warmup_output!r}")
        assert_allowed_result("langgraph_toolnode_reader_warmup", str(warmup_messages[0].content))
        time.sleep(0.5)

        message = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "langgraph_toolnode_reader",
                    "args": {"path": LANGGRAPH_TOOLNODE_SECRET},
                    "id": "ironscope-call-1",
                    "type": "tool_call",
                }
            ],
        )
        output = node.invoke(
            {"messages": [message]},
            config={CONF: {CONFIG_KEY_RUNTIME: Runtime()}},
        )
        tool_messages = output.get("messages", []) if isinstance(output, dict) else []
        if len(tool_messages) != 1:
            raise AssertionError(f"unexpected ToolNode output: {output!r}")
        assert_denied_result("langgraph_toolnode_reader", str(tool_messages[0].content))
    else:
        raise ValueError(f"unsupported IRONSCOPE_WORKER_CASE={CASE!r}")

    time.sleep(0.35)
    print(f"WORKER_SCENARIO_DONE {CASE}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"SCENARIO_ERROR {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise
