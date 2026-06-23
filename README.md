# IronScope

IronScope helps you understand and control what an AI agent's tools are doing
on the machine where they run.

If your app uses LangChain or LangGraph, the agent may call tools that read
files, start subprocesses, connect to services, or perform other local actions.
In normal logs, it can be hard to tell which exact tool caused which system
action, especially when agents use async code, background workers, retries, or
subprocesses.

IronScope watches supported Python tool execution at runtime and connects local
system activity back to the active tool call. That means you can see events
like:

- `read_file` opened `/tmp/report.txt`
- `shell` tried to execute `/usr/bin/id`
- `background_popen` started a child Python process
- `asyncio_to_thread_reader` accessed a protected file from a worker thread

You can run IronScope in monitor mode to audit what tools are doing, or enforce
mode to block specific file, process, or network actions per tool.

The core use case is giving agentic applications a runtime safety layer around
tool execution. Instead of only trusting application logs or network traces,
IronScope observes local behavior at the OS boundary and labels it with the
tool context that caused it.

In the current V0.1 scope, IronScope targets LangChain/LangGraph-style tools
running on validated CPython 3.12 Linux environments. It is useful for
developers who want to inspect, debug, or restrict real tool behavior without
rewriting their agent framework.

For the deeper design rationale and current limitations, see
[`docs/architecture/runtime-tool-context.md`](docs/architecture/runtime-tool-context.md).

For a first-user walkthrough, see [`docs/quickstart/langchain-shell-tool.md`](docs/quickstart/langchain-shell-tool.md). For broader async, worker-thread, subprocess, and nested-tool coverage, see [`examples/langgraph_tool_execution_daemon.py`](examples/langgraph_tool_execution_daemon.py) with [`examples/policies/langgraph-tool-execution-enforce.yaml`](examples/policies/langgraph-tool-execution-enforce.yaml).

## License

IronScope is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE).

## V0.1 Support Scope

Validated in V0.1:

- CPython 3.12.3 on aarch64 Linux with a matching validated contract profile.
- `langchain-core==1.4.7`.
- Tool execution through `BaseTool.invoke`, `BaseTool.ainvoke`, `BaseTool.run`, or `BaseTool.arun`.
- Tool shape coverage: privileged E2E tests exercise subclassed `BaseTool`; resolver tests cover `@tool`, `StructuredTool.from_function`, and subclassed `BaseTool` name resolution.
- Asyncio task lifecycle tracking, nested same-task tool calls, parallel async tools, cancellation/exception cleanup, `ThreadPoolExecutor`, `asyncio.to_thread`, `threading.Thread`, and subprocesses created inside tool context.
- Kernel-visible file open, exec, and socket connect monitoring/enforcement through LSM hooks.

Not claimed in V0.1:

- CPython 3.10/3.11/3.13, PyPy, no-GIL/free-threaded Python, x86_64, or embedded Python. These need separate validated contracts and are not part of the packaged V0.1 support claim.
- Raw function calls that bypass LangChain `BaseTool` boundaries.
- CPython instrumented opcode paths enabled by tracing, coverage, debuggers, profilers, or `sys.monitoring`.
- Arbitrary async runtimes that do not use supported CPython `_asyncio` task boundaries.
- Full per-tool policy for the first execution of a previously unseen tool object when the object has not yet been resolved. That execution is still inside a tool context, but it follows `unknown_tool_policy`; later executions of the same resolved live object use per-tool policy.
- HTTP payload parsing or LLM provider wire-format parsing. Tool identity comes from Python runtime state, not network inspection.

## How Runtime Tool Identity Works

1. eBPF probes CPython frame execution and returns early for unprotected processes.
2. Supported LangChain `BaseTool` boundary frames create a tool context.
3. Known tool objects use cached tool ids and per-tool policy.
4. Unknown tool objects use `unknown_tool_policy` and emit a resolver candidate.
5. Userspace reads CPython runtime memory, resolves the LangChain tool name, and updates the BPF cache.
6. Later executions of that live tool object use per-tool policy.

The V0.1 LangChain path does not require application-level tool registration. Tool identity is resolved from CPython runtime state after IronScope observes a supported LangChain tool boundary.

## Policy Controls

V0.1 policy fields live under `ironscope:`. `unknown_tool_policy` and `resolver_error_policy` currently accept `allow` or `deny`.

```yaml
ironscope:
  agents:
    - pid: 12345

  unknown_tool_policy: allow
  resolver_error_policy: deny
  agent_child_scope: protect_only_tool_children
  default_tool_policy: allow

  tools:
    - name: read_file
      fs:
        deny:
          - /etc/passwd
    - name: shell
      exec:
        deny:
          - /usr/bin/id


  mode: monitor
```

Policy control fields:

- `unknown_tool_policy`: decision for a supported tool execution before IronScope has resolved the runtime tool object to a known tool name. V0.1 may hit this on the first execution of a newly seen tool object; use `allow` for a less disruptive first run or `deny` to fail closed for unresolved tools.
- `resolver_error_policy`: decision when IronScope detects a possible tool boundary but userspace cannot safely resolve the runtime identity. Use `deny` when unresolved identity should fail closed.
- `agent_child_scope`: controls child-process protection. `protect_only_tool_children` means only children spawned inside an active tool context inherit tool protection; idle children outside tool context are not treated as tool work.
- `default_tool_policy`: fallback for known-tool resource accesses that do not match an explicit allow or deny rule. Use `allow` for deny-list style policies and `deny` for allow-list style policies.

These fields exist because runtime identity can be temporarily unknown, resolver failures must have explicit behavior, child processes can outlive the Python frame that spawned them, and known tools need a clear fallback when no resource-specific rule matches.

V0.1 does not expose a non-tool enforcement policy. Activity outside an active tool context is emitted as unattributed audit data and is not denied by IronScope.

## Audit Output

Structured JSON output uses schema `ironscope.audit.v1` and includes:

- `ctx_id`: unique context for a tool execution.
- `tool_name` and `tool_id`: resolved tool identity when known; `unknown`, `resolver_error`, or `unattributed` otherwise.
- `identity_state`: `known_tool`, `unknown_tool`, `resolver_error`, or `unattributed`.
- `policy_source`: `tool`, `unknown_tool`, `resolver_error`, `unattributed`, `default_allow`, or `monitor`.
- `py_events`: tool lifecycle, async task, worker, and cleanup events.
- `resolver_events`: CPython object/frame/code candidates used by the userspace resolver.
- `guard_events`: file open, exec, and socket connect decisions with allow/deny action.
- `bracket_check` and `final_state`: lifecycle attribution and cleanup evidence.

In monitor mode, `action: "deny"` means the policy decision was logged as a would-deny decision. Actual syscall blocking requires `--mode enforce` and active BPF LSM.

## CPython Contracts

IronScope does not guess CPython frame, object, or `_asyncio` offsets at runtime. The CPython runtime path detects the target process Python executable, Python build-id or SHA256 fallback, `_asyncio` module build-id, and architecture, then loads a matching contract from `--contract-dir` or `IRONSCOPE_CONTRACT_DIR`. If no validated contract matches, IronScope fails closed before attaching tool-context probes.

A contract describes where IronScope can safely observe CPython execution lifecycle state for one specific Python build. This is necessary because CPython internals are not a stable public ABI: frame layout, coroutine/task layout, and interpreter instruction offsets can change across Python versions, build flags, distributions, and CPU architectures.

The development tree currently ships a validated CPython 3.12.3 aarch64 contract under `tools/python-contracts/`. That is the validated V0.1 contract path. Production packages should install validated contracts under `/usr/share/ironscope/python-contracts`.

IronScope V0.1 does not provide general-purpose contract discovery for arbitrary CPython versions. Contract generation for additional CPython versions and architectures is experimental development work and is not part of the V0.1 support claim. Reliable generation requires proving version- and architecture-specific interpreter lifecycle points such as frame activation, coroutine resume, normal return cleanup, exception cleanup, and `_asyncio` task transitions.

Supported profile workflow:

```bash
# Inspect the target process runtime identity.
ironscope profile detect --pid 12345

# Validate that a packaged contract matches the target process identity
# and contains the required probe offsets.
ironscope profile validate --pid 12345 --contract tools/python-contracts/cpython-3.12.3-aarch64-*.json
```

V0.1 does not expose runtime contract generation. IronScope does not fetch debug symbols, download profiles, or synthesize missing contracts at enforcement startup. Missing profiles are release/support decisions, not runtime guesses.

## Build And Run

Prerequisites:

- Linux kernel with BPF LSM enabled and `bpf` listed in `/sys/kernel/security/lsm`.
- Root privileges for loading BPF programs and attaching LSM hooks.
- Rust toolchain for building the userspace binary and BPF object.
- A supported CPython 3.12.3 aarch64 target process.

```bash
cargo build --release
sudo ./target/release/ironscope \
  --config examples/policies/langchain-monitor.yaml \
  --contract-dir tools/python-contracts \
  --mode monitor \
  --duration 60 \
  --output /tmp/ironscope-audit.json
```

Use `--mode enforce` only after setting explicit `unknown_tool_policy`, `resolver_error_policy`, `agent_child_scope`, `default_tool_policy`, and per-tool rules for the workload.

Release images install runtime assets at the default paths IronScope searches automatically:

```text
/usr/bin/ironscope
/usr/share/ironscope/python-contracts/index.json
/usr/share/ironscope/python-contracts/*.json
/usr/share/ironscope/rules/framework_rules.yaml
/usr/share/ironscope/examples/policies/*.yaml
```

Build the release image with the verified Rust/Aya build path:

```bash
docker build -f docker/Dockerfile.release -t ironscope:v0.1.0-alpha .
```

The image is a packaging convenience, not a sandbox. Runtime monitoring and enforcement still need host privileges, host PID namespace access, BPF LSM, BTF, and a target process that matches a packaged CPython contract. A typical host attach run looks like:

```bash
docker run --rm \
  --privileged \
  --pid=host \
  -v /proc:/proc \
  -v /sys:/sys \
  -v /tmp/ironscope:/tmp/ironscope \
  ironscope:v0.1.0-alpha \
  --config /tmp/ironscope/policy.yaml \
  --contract-dir /usr/share/ironscope/python-contracts \
  --mode monitor \
  --duration 60 \
  --output /tmp/ironscope/audit.json
```

## Verification

Core deterministic gates for the V0.1 runtime path:

```bash
cargo fmt --all --check
cargo check
cargo test
python3 tools/verify_offsets.py --contract tools/python-contracts/cpython-3.12.3-aarch64-f44e82bd43207357844bfae18cf0460f0825d1ae.json
PYTHON=.venv-e2e-v1/bin/python bash tests/e2e_langchain_tool_policy.sh
PYTHON=.venv-e2e-v1/bin/python bash tests/e2e_langchain_first_call_unknown_policy.sh
PYTHON=.venv-e2e-v1/bin/python bash tests/e2e_langgraph_tool_execution_daemon.sh
IRONSCOPE_ASYNC_CASE=nested PYTHON=.venv-e2e-v1/bin/python bash tests/e2e_async_lifecycle_case.sh
IRONSCOPE_WORKER_CASE=threadpool PYTHON=.venv-e2e-v1/bin/python bash tests/e2e_worker_lifecycle_case.sh
PYTHON=.venv-e2e-v1/bin/python bash tests/e2e_resource_policy_case.sh fs enforce
```

Historical traffic/provider and phase-prototype test assets are not part of the V0.1 support claim and are not kept in the release-facing test tree.
