#!/usr/bin/env python3
"""Real LangChain tool-policy workload for IronScope.

This intentionally avoids an external LLM so the test is deterministic. It
models the part of a real agent that matters for IronScope enforcement: after
an agent/model decides on tool calls, the calls execute through real
langchain_core.tools.BaseTool.invoke frames.

Expected policy behavior under IronScope:
  - read_file('/tmp/ironscope_langchain_allowed.txt') is allowed
  - read_file('/etc/passwd') is denied by read_file tool policy
  - shell('id') is denied by shell tool policy
  - write_note('/tmp/ironscope_langchain_note.txt') is allowed
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

START_SIGNAL = "/tmp/ironscope_langchain_start"
READY_PATH = os.environ.get("IRONSCOPE_READY_FILE", "/tmp/ironscope/ready")
ALLOWED_FILE = "/tmp/ironscope_langchain_allowed.txt"
NOTE_FILE = "/tmp/ironscope_langchain_note.txt"

try:
    from langchain_core.tools import BaseTool
except Exception as exc:  # pragma: no cover - environment gate
    print(f"MISSING_LANGCHAIN_CORE: {exc}", file=sys.stderr, flush=True)
    sys.exit(77)


class ReadFileTool(BaseTool):
    name: str = "read_file"
    description: str = "Read a local text file."

    def _run(self, path: str, **_: object) -> str:
        return Path(path).read_text()[:128]


class ShellTool(BaseTool):
    name: str = "shell"
    description: str = "Run a small shell command."

    def _run(self, command: str, **_: object) -> str:
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


class WriteNoteTool(BaseTool):
    name: str = "write_note"
    description: str = "Write a note under /tmp."

    def _run(self, text: str, **_: object) -> str:
        Path(NOTE_FILE).write_text(text)
        return NOTE_FILE


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
        if exc.errno in (1, 13):
            print(f"RESULT {label} PASS denied_errno={exc.errno}", flush=True)
            return
        print(f"RESULT {label} FAIL unexpected_errno={exc.errno}", flush=True)
        raise
    print(f"RESULT {label} FAIL allowed", flush=True)
    raise AssertionError(f"{label} was allowed")


def main() -> int:
    print(os.getpid(), flush=True)
    wait_for(START_SIGNAL, 30, "start signal")

    Path(ALLOWED_FILE).write_text("ironscope langchain allowed fixture\n")
    Path(NOTE_FILE).unlink(missing_ok=True)

    tools: dict[str, BaseTool] = {
        "read_file": ReadFileTool(),
        "shell": ShellTool(),
        "write_note": WriteNoteTool(),
    }
    wait_for(READY_PATH, 15, "ironscope ready marker")

    print("LANGCHAIN_SCENARIO_START", flush=True)

    # First executions intentionally warm the runtime resolver. The V0.1 seamless
    # path applies unknown_tool_policy on the first call, then userspace resolves
    # the candidate and later executions use per-tool policy.
    warmup = tools["read_file"].invoke(ALLOWED_FILE)
    if "allowed fixture" not in warmup:
        raise AssertionError("read_file warmup returned unexpected content")
    try:
        tools["shell"].invoke("warmup")
    except ValueError:
        pass
    tools["write_note"].invoke("resolver warmup note\n")
    time.sleep(0.5)

    allowed = tools["read_file"].invoke(ALLOWED_FILE)
    if "allowed fixture" not in allowed:
        raise AssertionError("allowed file read returned unexpected content")
    print("RESULT read_allowed PASS", flush=True)

    expect_denied("read_passwd_denied", lambda: tools["read_file"].invoke("/etc/passwd"))
    expect_denied("shell_id_denied", lambda: tools["shell"].invoke("id"))

    written = tools["write_note"].invoke("langchain agent wrote this note\n")
    if written != NOTE_FILE or not Path(NOTE_FILE).exists():
        raise AssertionError("write_note did not write expected file")
    print("RESULT write_allowed PASS", flush=True)

    time.sleep(0.25)
    print("LANGCHAIN_SCENARIO_DONE", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"SCENARIO_ERROR {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise
