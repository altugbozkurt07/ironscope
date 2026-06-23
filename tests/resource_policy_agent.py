#!/usr/bin/env python3
"""Deterministic LangChain resource-policy workload for IronScope E2E gates."""

from __future__ import annotations

import argparse
import errno
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

START_SIGNAL = os.environ.get("IRONSCOPE_RESOURCE_START", "/tmp/ironscope_resource_policy_start")
READY_PATH = os.environ.get("IRONSCOPE_READY_FILE", "/tmp/ironscope/resource-policy-ready")
ALLOWED_FILE = Path("/tmp/ironscope_resource_allowed.txt")
SECRET_FILE = Path("/tmp/ironscope_resource_secret.txt")

try:
    from langchain_core.tools import BaseTool
except Exception as exc:  # pragma: no cover - environment gate
    print(f"MISSING_LANGCHAIN_CORE: {exc}", file=sys.stderr, flush=True)
    sys.exit(77)


class TcpSink:
    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = int(self._sock.getsockname()[1])
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    conn.recv(16)
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=1)


class FileTool(BaseTool):
    name: str = "file_tool"
    description: str = "Read deterministic files for IronScope filesystem policy tests."

    def _run(self, operation: str, **_: object) -> str:
        if operation == "allowed":
            return ALLOWED_FILE.read_text(encoding="utf-8")
        if operation == "denied":
            return SECRET_FILE.read_text(encoding="utf-8")
        raise ValueError(operation)


class ExecTool(BaseTool):
    name: str = "exec_tool"
    description: str = "Run deterministic binaries for IronScope exec policy tests."

    def _run(self, operation: str, **_: object) -> str:
        if operation == "allowed":
            argv = ["/bin/true"]
        elif operation == "denied":
            argv = ["/usr/bin/id"]
        else:
            raise ValueError(operation)
        proc = subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return proc.stdout + proc.stderr


class NetTool(BaseTool):
    name: str = "net_tool"
    description: str = "Connect to deterministic local ports for IronScope network policy tests."
    allowed_port: int
    denied_port: int

    def _run(self, operation: str, **_: object) -> str:
        if operation == "allowed":
            port = self.allowed_port
        elif operation == "denied":
            port = self.denied_port
        else:
            raise ValueError(operation)
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.sendall(b"x")
        return f"connected:{port}"


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
    except subprocess.CalledProcessError as exc:
        if exc.returncode in (126, 127, 255):
            print(f"RESULT {label} PASS denied_rc={exc.returncode}", flush=True)
            return
        raise
    raise AssertionError(f"{label} was allowed")


def assert_allowed(label: str, func) -> None:
    func()
    print(f"RESULT {label} PASS allowed", flush=True)


def exercise_tool(tool: BaseTool, *, expect_enforce: bool) -> None:
    # First invocation may run under unknown_tool_policy while userspace resolves
    # the runtime tool identity. The second and denied invocations must use the
    # resolved tool context.
    tool.invoke("allowed")
    time.sleep(0.5)
    assert_allowed("allowed", lambda: tool.invoke("allowed"))
    if expect_enforce:
        expect_denied("denied", lambda: tool.invoke("denied"))
    else:
        assert_allowed("monitor_would_deny", lambda: tool.invoke("denied"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=("fs", "exec", "net"), required=True)
    parser.add_argument("--expect", choices=("enforce", "monitor"), required=True)
    args = parser.parse_args()

    ALLOWED_FILE.write_text("allowed\n", encoding="utf-8")
    SECRET_FILE.write_text("secret\n", encoding="utf-8")

    servers: list[TcpSink] = []
    allowed_port = 0
    denied_port = 0
    if args.case == "net":
        servers = [TcpSink(), TcpSink()]
        allowed_port = servers[0].port
        denied_port = servers[1].port

    print(os.getpid(), flush=True)
    print(f"PORTS {allowed_port} {denied_port}", flush=True)

    try:
        wait_for(START_SIGNAL, 30, "start signal")
        wait_for(READY_PATH, 15, "ironscope ready marker")

        # Non-tool activity in the protected process must remain allowed.
        Path("/etc/passwd").read_text(encoding="utf-8")
        print("RESULT non_tool_activity PASS allowed", flush=True)

        expect_enforce = args.expect == "enforce"
        if args.case == "fs":
            exercise_tool(FileTool(), expect_enforce=expect_enforce)
        elif args.case == "exec":
            exercise_tool(ExecTool(), expect_enforce=expect_enforce)
        else:
            exercise_tool(NetTool(allowed_port=allowed_port, denied_port=denied_port), expect_enforce=expect_enforce)

        print(f"RESOURCE_POLICY_SCENARIO_DONE case={args.case} expect={args.expect}", flush=True)
        return 0
    finally:
        for server in servers:
            server.close()


if __name__ == "__main__":
    raise SystemExit(main())
