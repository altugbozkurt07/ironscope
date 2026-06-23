# Runtime Tool Context

IronScope explores a runtime-first approach to monitoring and enforcing
agentic tool execution. The goal is to attribute kernel-visible behavior to the
exact tool invocation that caused it, then use that attribution for audit logs or
BPF LSM enforcement.

## Problem

Traffic-based monitoring is useful for understanding provider communication,
SDK behavior, and network-level activity around an agent. IronScope does not
try to replace that visibility. It focuses on a narrower problem: attributing
local system behavior to the exact tool execution that caused it. For that
problem, LLM API calls, SDK HTTP requests, or TLS activity are indirect signals
rather than the local tool execution boundary itself.

That indirect model can become difficult to use as the sole source of
attribution in modern agent services:

- HTTP requests and responses do not prove when a local tool function starts or
  ends.
- Async runtimes can interleave multiple logical tool executions on the same OS
  thread.
- Connection pooling, retries, streaming, batching, and SDK abstractions break a
  simple one-request-to-one-tool-call model.
- Tools can spawn worker threads, thread-pool jobs, subprocesses, or background
  work that outlives the request that selected the tool.
- TLS visibility often requires invasive SSL/library hooks or traffic
  termination, and provider payload formats change over time.
- Most importantly, traffic observation cannot reliably set a kernel-level
  enforcement context for the exact lifetime of one tool invocation.

The core issue is attribution. Timing correlation can show that a file open or
process execution happened near an LLM interaction. In concurrent agent
services, that may not be enough to confidently assign the operation to one
specific local tool call, especially when multiple tools, tasks, and workers
overlap.

```text
Traffic / SSL-Based Monitoring

+----------------------------------------------------------------------+
| USERSPACE: Agent Service                                             |
|                                                                      |
|  agent_loop()                                                        |
|      |                                                               |
|      |-- llm_client.chat(...)                                        |
|      |       |                                                       |
|      |       v                                                       |
|      |   HTTP client / SDK                                           |
|      |       |                                                       |
|      |       v                                                       |
|      |   TLS / SSL library        <---- traffic hook sees this       |
|      |       |                                                       |
|      |       v                                                       |
|      |   sendmsg()/recvmsg()                                         |
|      |                                                               |
|      `-- tool.invoke(...)                                            |
|              |                                                       |
|              v                                                       |
|          Python tool code                                            |
|              |                                                       |
|              |-- open("/tmp/secret")                                 |
|              |-- subprocess.Popen(...)                               |
|              `-- socket.connect(...)                                 |
|                                                                      |
+----------------------------------------------------------------------+
                         |
                         v
+----------------------------------------------------------------------+
| KERNEL                                                               |
|                                                                      |
|  file_open / exec / socket_connect                                   |
|                                                                      |
+----------------------------------------------------------------------+

The hook observes provider communication. Local tool lifecycle and system
behavior still need to be correlated by timing or framework-specific context.
```

## Design Choice

IronScope tracks tool execution from inside the application runtime instead of
using outbound traffic as the primary attribution signal.

In V0.1, the target runtime is CPython 3.12.3 and the target framework boundary
is LangChain/LangGraph-style execution through `langchain_core.tools.BaseTool`.
CPython is an interpreted runtime: high-level Python code is executed through
interpreter frames, coroutine objects, task state, and runtime-managed control
flow. Those internal structures contain the execution state needed to understand
which frame is running, when async work is suspended or resumed, and when a
tool frame exits.

IronScope uses validated CPython runtime contracts to attach eBPF uprobes at
the relevant execution lifecycle points. It then creates a unique tool context
when a supported tool boundary runs and keeps that context synchronized with the
runtime lifecycle.

## High-Level Flow

```text
IronScope Runtime Tool Context

+----------------------------------------------------------------------+
| USERSPACE: Agent Service                                             |
|                                                                      |
|  agent_loop()                                                        |
|      |                                                               |
|      v                                                               |
|  LangChain / LangGraph                                               |
|      |                                                               |
|      v                                                               |
|  BaseTool.invoke / BaseTool.ainvoke                                  |
|      |                                                               |
|      v                                                               |
|  CPython VM runtime                                                  |
|      |                                                               |
|      |-- frame starts            <---- IronScope uprobe             |
|      |-- async task resumes      <---- IronScope uprobe             |
|      |-- worker/subprocess bind  <---- IronScope lifecycle tracking |
|      `-- frame exits             <---- IronScope uprobe             |
|                                                                      |
|  Active runtime context:                                             |
|      ctx = { tool_name: "read_file", execution_id: 0x... }            |
|                                                                      |
+----------------------------------------------------------------------+
                         |
                         | runtime-derived ctx propagated to BPF maps
                         v
+----------------------------------------------------------------------+
| KERNEL                                                               |
|                                                                      |
|  BPF LSM hooks                                                       |
|      |-- file_open("/tmp/secret")      sees ctx=read_file            |
|      |-- exec("/usr/bin/id")           sees ctx=shell                |
|      `-- socket_connect(...)           sees ctx=current_tool         |
|                                                                      |
|  mode=monitor  -> emit audit event                                   |
|  mode=enforce  -> allow or deny syscall                              |
|                                                                      |
+----------------------------------------------------------------------+
```

The important distinction is that IronScope uses runtime execution state as
the primary attribution signal. It asks "which tool context is active in the
runtime right now?" rather than relying only on nearby HTTP traffic.

## Tracking CPython Execution Lifecycle

The state machine below is not a Python framework callback model. It shows how
IronScope maps CPython runtime execution state into a tool context that the
kernel can use.

```text
CPython Runtime Tool Lifecycle

+--------------------------------------------------------------------------------+
| USERSPACE: Agent Service                                                       |
|                                                                                |
|  high-level Python / framework code                                            |
|                                                                                |
|    agent_loop()                                                                |
|        |                                                                       |
|        v                                                                       |
|    LangChain / LangGraph                                                       |
|        |                                                                       |
|        v                                                                       |
|    BaseTool.invoke / BaseTool.ainvoke                                          |
|        |                                                                       |
|        v                                                                       |
|  CPython VM execution engine                                                   |
|                                                                                |
|    Sync execution state                                                        |
|                                                                                |
|      PyThreadState.current_frame                                               |
|          |                                                                     |
|          v                                                                     |
|      _PyInterpreterFrame                                                       |
|          |-- f_executable -> PyCodeObject                                      |
|          |-- previous      -> parent frame                                     |
|          `-- localsplus    -> local variables / self                           |
|                                                                                |
|      _PyEval_EvalFrameDefault                                                  |
|          |                                                                     |
|          |-- frame active       <--- IronScope uprobe                         |
|          |-- bytecode executes                                                 |
|          `-- return/exception <--- IronScope uprobe                           |
|                                                                                |
|    Async execution state                                                       |
|                                                                                |
|      _asyncio.Task                                                             |
|          |-- task_coro                                                         |
|          v                                                                     |
|      PyCoroObject / PyGenObject                                                |
|          |-- gi_iframe / coroutine frame                                       |
|          v                                                                     |
|      _PyInterpreterFrame                                                       |
|                                                                                |
|      task step / coroutine resume                                              |
|          |                                                                     |
|          |-- task resumes        <--- IronScope uprobe                        |
|          |-- frame active        <--- IronScope uprobe                        |
|          |-- await suspends      <--- ctx parked/cleared                       |
|          `-- return/cancel/error <--- IronScope cleanup                       |
|                                                                                |
|    Tool context state                                                          |
|                                                                                |
|      no ctx -> ctx created -> ctx active -> ctx parked -> ctx active -> closing |
|                         |          |                         |                  |
|                         |          |                         v                  |
|                         |          `---- worker/subprocess inherited ctx        |
|                         v                                                       |
|                    userspace resolver: tool object -> tool name                 |
|                                                                                |
+--------------------------------------------------------------------------------+
                                         |
                                         | active ctx exported into BPF maps
                                         v
+--------------------------------------------------------------------------------+
| KERNEL                                                                         |
|                                                                                |
|  BPF LSM hooks                                                                 |
|                                                                                |
|    file_open("/tmp/secret")      sees ctx=read_file                            |
|    exec("/usr/bin/id")           sees ctx=shell                                |
|    socket_connect(...)           sees ctx=current_tool                         |
|                                                                                |
|  monitor: emit audit event with ctx                                            |
|  enforce: allow or deny syscall with ctx                                       |
|                                                                                |
+--------------------------------------------------------------------------------+
```

Only `ctx active` and inherited worker/child contexts should affect kernel
policy decisions. Parked async contexts must not enforce against unrelated work
on the same event-loop thread.

This diagram is conceptual. The exact field offsets and instruction addresses
are not hardcoded from this model; they come from a validated CPython contract
for the target build.

## Monitoring And Enforcement

Monitoring and enforcement use the same runtime context, but they have different
effects.

In monitor mode, IronScope records structured audit events. A guard event with
`action: "deny"` means the policy would have denied the operation, but the
syscall is not blocked.

In enforce mode, IronScope can block kernel-visible behavior through BPF LSM
hooks when a matching active tool context exists. This lets policy apply to a
specific tool execution instead of the entire agent process.

The audit trail includes:

- Python lifecycle events such as tool start/end, task bind/unbind, and worker
  bind/unbind.
- Resolver events that show when userspace resolved a runtime tool object to a
  tool name.
- Guard events for file open, exec, and socket connect decisions.
- Final-state and bracket checks that show whether runtime context maps were
  cleaned up.

## Policy Fallbacks

Runtime-aware enforcement needs explicit behavior for states where identity is
not yet known or where work crosses process boundaries. V0.1 exposes those
states as policy fields instead of hiding them behind implicit defaults.

- `unknown_tool_policy` applies when a tool boundary is observed but the tool
  object has not yet been resolved to a configured tool name. This can happen
  on the first execution of a live tool object.
- `resolver_error_policy` applies when userspace cannot safely resolve a
  runtime candidate. This lets operators choose fail-open or fail-closed
  behavior for resolver failures.
- `agent_child_scope` defines whether child processes inherit protection only
  when spawned inside a tool context or whenever they descend from a protected
  agent process. The V0.1 default avoids treating idle child processes as tool
  work.
- `default_tool_policy` applies to known-tool resource accesses that do not
  match a specific resource rule. `allow` behaves like a deny-list fallback;
  `deny` behaves like an allow-list fallback.

These fields make ambiguous runtime states explicit in the audit trail and in
enforcement behavior.

## Reliability Model

The V0.1 reliability model depends on explicit runtime state transitions:

- A supported LangChain `BaseTool` boundary creates a tool context.
- CPython frame and task probes bind the context while the tool is executing.
- Async suspension clears or parks context so unrelated work is not attributed
  to the suspended tool.
- Async resume restores the correct context.
- Worker threads and subprocesses spawned inside a tool context inherit scoped
  context.
- Tool return, exception, cancellation, worker completion, and process cleanup
  remove context.
- Unsupported runtimes or missing contracts fail closed before runtime tool
  probes attach.

This model is tested against the V0.1 demo workload in
[`examples/langgraph_tool_execution_daemon.py`](../../examples/langgraph_tool_execution_daemon.py),
which covers sync tools, async tools, nested and parallel async execution,
cancellation, exceptions, thread pools, `threading.Thread`, `asyncio.to_thread`,
subprocess inheritance, and non-tool activity that must remain unattributed.

## Runtime Contracts

CPython internals are not a stable public ABI. The exact frame layout,
coroutine/task layout, and interpreter instruction offsets vary across Python
versions, build flags, distributions, and architectures.

IronScope therefore uses a runtime contract for each supported CPython build.
The contract tells IronScope where the relevant CPython lifecycle points and
object fields are for that exact runtime. At startup, IronScope detects the
target Python executable, build identity, `_asyncio` module identity, and
architecture, then loads a matching validated contract. If no matching validated
contract exists, the CPython runtime path fails closed.

V0.1 ships a validated CPython 3.12.3 aarch64 contract path. It does not claim
general-purpose contract discovery for arbitrary CPython versions. The
`profile detect` and `profile validate` commands are useful for identifying a
target runtime and checking whether a packaged contract matches it. Contract
generation for additional versions and architectures remains experimental
development work.

This is intentional. Guessing offsets would make enforcement unsafe.

## Known Limitations

V0.1 is intentionally narrow:

- Validated support is currently limited to CPython 3.12.3 with a matching
  contract profile.
- The supported framework boundary is LangChain/LangGraph-style tool execution
  through `BaseTool`, not arbitrary Python functions.
- First execution of a previously unseen tool object may use
  `unknown_tool_policy` while userspace resolves the tool identity.
- Unsupported runtimes such as CPython 3.10/3.11/3.13, PyPy,
  no-GIL/free-threaded Python, and embedded Python are not automatically
  supported.
- CPython instrumented opcode paths, such as workloads run under
  `sys.settrace`, `sys.monitoring`, coverage, debuggers, or profilers, are
  not part of the V0.1 supported lifecycle contract.
- The current enforcement surface is kernel-visible behavior such as file open,
  exec, and socket connect. IronScope does not parse semantic shell commands,
  HTTP payloads, or LLM provider messages.
- Native compiled languages are harder to support because high-level tool
  concepts may not exist in inspectable runtime state without instrumentation,
  debug information, or framework-specific contracts.

Traffic monitoring and runtime monitoring answer different questions. Traffic
monitoring provides broad network/provider visibility. Runtime monitoring can
provide more precise local tool attribution, but it is runtime- and
framework-specific. IronScope chooses the runtime-specific path for V0.1 and
keeps the support matrix explicit.

## Roadmap

The next research and engineering steps are:

- Build a reliable contract discovery engine for additional CPython versions.
  This requires proving interpreter lifecycle points such as frame activation,
  coroutine resume, normal return cleanup, exception cleanup, and `_asyncio`
  task transitions for each supported version and architecture.
- Validate additional CPython contracts and supported LangChain versions.
- Add x86_64 runtime contracts and test coverage.
- Improve self-service contract generation while preserving fail-closed
  behavior.
- Add longer-running stress tests for concurrent tools, workers, and
  subprocesses.
- Expand public documentation around policy semantics, audit schema, and
  operational troubleshooting.
