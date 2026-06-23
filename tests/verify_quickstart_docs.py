#!/usr/bin/env python3
"""Verify the first-user LangChain shell-tool quickstart covers release requirements."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
QUICKSTART = ROOT / "docs" / "quickstart" / "langchain-shell-tool.md"
README = ROOT / "README.md"
LANGGRAPH_POLICY = ROOT / "examples" / "policies" / "langgraph-tool-execution-enforce.yaml"

REQUIRED_SNIPPETS = [
    "class ShellTool(BaseTool)",
    "subprocess.run",
    "unknown_tool_policy",
    "resolver_error_policy",
    "agent_child_scope",
    "default_tool_policy",
    "mode: monitor",
    "mode: enforce",
    "exec:",
    "fs:",
    "net:",
    "pgrep",
    "--contract-dir tools/python-contracts",
    "--mode monitor",
    "--mode enforce",
    "guard_events",
    'action: "deny"',
    "BPF LSM",
    "unsupported CPython contract",
    "unknown_tool_policy",
]


def main() -> int:
    problems: list[str] = []
    if not QUICKSTART.exists():
        problems.append(f"missing quickstart: {QUICKSTART.relative_to(ROOT)}")
    else:
        text = QUICKSTART.read_text()
        for snippet in REQUIRED_SNIPPETS:
            if snippet not in text:
                problems.append(f"quickstart missing required text: {snippet}")
    readme = README.read_text() if README.exists() else ""
    if "docs/quickstart/langchain-shell-tool.md" not in readme:
        problems.append("README does not link docs/quickstart/langchain-shell-tool.md")
    if "examples/policies/langgraph-tool-execution-enforce.yaml" not in readme:
        problems.append("README does not link examples/policies/langgraph-tool-execution-enforce.yaml")

    if not LANGGRAPH_POLICY.exists():
        problems.append(f"missing LangGraph edge-case policy: {LANGGRAPH_POLICY.relative_to(ROOT)}")
    else:
        policy = LANGGRAPH_POLICY.read_text()
        for snippet in (
            "read_file",
            "shell",
            "async_inner",
            "async_outer",
            "async_parallel_a",
            "async_parallel_b",
            "threadpool_reader",
            "threading_reader",
            "asyncio_to_thread_reader",
            "background_popen",
            "agent_child_scope: protect_only_tool_children",
        ):
            if snippet not in policy:
                problems.append(f"LangGraph edge-case policy missing required text: {snippet}")

    if problems:
        for problem in problems:
            print(f"PROBLEM: {problem}")
        return 1
    print("PASS: LangChain shell-tool quickstart covers release requirements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
