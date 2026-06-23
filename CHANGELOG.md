# Changelog

## v0.1.0-alpha - Unreleased

Experimental research preview for runtime-aware LangChain/LangGraph tool monitoring and enforcement.

### Supported

- CPython 3.12.3 aarch64 runtime contract loading and fail-closed startup when no matching contract exists.
- LangChain/LangGraph tool execution through `langchain_core.tools.BaseTool` boundaries.
- Runtime tool identity resolution from CPython object/frame state without application-level tool registration.
- Monitor and enforce modes for file open, exec, and IPv4 socket connect decisions.
- Async task lifecycle, nested/parallel async tools, cancellation/exception cleanup, supported worker-thread flows, and subprocess inheritance covered by deterministic tests.
- Structured JSON audit output with lifecycle, resolver, guard-event, bracket-check, and final-state sections.

### Not Supported

- CPython 3.10/3.11/3.13, x86_64, PyPy, no-GIL/free-threaded Python, or embedded Python.
- General-purpose CPython contract generation.
- Raw Python functions that bypass supported LangChain `BaseTool` boundaries.
- CPython tracing/coverage/debugger/profiler instrumentation paths.
- LLM provider payload parsing or traffic-based tool identity.
