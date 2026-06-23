# Security Policy

IronScope is an experimental research preview for CPython 3.12.3 aarch64 LangChain/LangGraph tool-context monitoring and BPF LSM enforcement.

## Supported Version

| Version | Supported | Scope |
| --- | --- | --- |
| v0.1.0-alpha | Yes | CPython 3.12.3 aarch64 with packaged contracts and validated LangChain/LangGraph BaseTool paths |
| Other Python versions, architectures, runtimes, or frameworks | No | Not covered unless explicitly validated in a later release |

## Reporting Vulnerabilities

Please report security issues privately to the project maintainer before public disclosure. Include:

- IronScope commit/version.
- Kernel version and BPF LSM status.
- Python version, architecture, and contract identity.
- Minimal policy and workload needed to reproduce the issue.
- Whether the issue affects monitor mode, enforce mode, or both.

## Expected Limitations Versus Bugs

The following are documented v0.1 limitations, not vulnerabilities by themselves:

- Unsupported Python versions, architectures, PyPy, no-GIL/free-threaded Python, and embedded Python are outside the support matrix.
- First execution of an unresolved live tool object follows `unknown_tool_policy`.
- Unsupported CPython instrumentation paths such as tracing, coverage, debuggers, profilers, and `sys.monitoring` are outside the validated lifecycle contract.
- IronScope enforces kernel-visible resources such as file open, exec, and socket connect; it does not parse shell command semantics or LLM provider payloads.

A vulnerability is behavior that violates the documented support matrix or policy semantics for a validated runtime path.
