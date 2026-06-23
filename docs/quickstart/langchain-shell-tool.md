# LangChain Shell Tool Quickstart

This quickstart shows the minimal V0.1 path for attaching IronScope to a
CPython 3.12 LangChain process and auditing or enforcing kernel-visible tool
behavior. It uses a deterministic `BaseTool` shell tool; no LLM is required for
this validation because IronScope observes the tool execution boundary, not the
model provider call.

Validated release scope for this flow:

- CPython 3.12.3 with a matching contract under `tools/python-contracts`.
- `langchain-core==1.4.7` and tool execution through `BaseTool.invoke`.
- File open, executable identity, and IPv4 socket-connect policy.

## 1. Create A Minimal Agent Process

Save this as `/tmp/ironscope_shell_agent.py` or adapt it inside your own
LangChain service.

```python
#!/usr/bin/env python3
from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path

from langchain_core.tools import BaseTool

READY_FILE = "/tmp/ironscope-shell-ready"
START_FILE = "/tmp/ironscope-shell-start"
ALLOWED_FILE = "/tmp/ironscope-shell-allowed.txt"
SECRET_FILE = "/tmp/ironscope-shell-secret.txt"


class ShellTool(BaseTool):
    name: str = "shell"
    description: str = "Run a deterministic shell command."

    def _run(self, command: str, **_: object) -> str:
        if command == "id":
            proc = subprocess.run(
                ["/usr/bin/id"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return proc.stdout + proc.stderr
        if command == "true":
            proc = subprocess.run(["/usr/bin/true"], check=False)
            return str(proc.returncode)
        raise ValueError(f"unsupported command: {command}")


class ReadFileTool(BaseTool):
    name: str = "read_file"
    description: str = "Read a local file."

    def _run(self, path: str, **_: object) -> str:
        return Path(path).read_text()


class ConnectTool(BaseTool):
    name: str = "connect"
    description: str = "Open an IPv4 TCP connection."

    def _run(self, target: str, **_: object) -> str:
        host, port = target.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=1.0):
            return "connected"


if __name__ == "__main__":
    Path(ALLOWED_FILE).write_text("allowed\n")
    Path(SECRET_FILE).write_text("secret\n")
    Path(READY_FILE).write_text(str(Path.cwd()))
    print(f"AGENT_PID {__import__('os').getpid()}", flush=True)
    print("waiting for IronScope start signal", flush=True)
    while not Path(START_FILE).exists():
        time.sleep(0.05)

    tools = {
        "shell": ShellTool(),
        "read_file": ReadFileTool(),
        "connect": ConnectTool(),
    }
    tools["read_file"].invoke(ALLOWED_FILE)
    tools["read_file"].invoke(SECRET_FILE)
    tools["shell"].invoke("true")
    tools["shell"].invoke("id")
    print("DONE", flush=True)
```

Run it in one terminal:

```bash
rm -f /tmp/ironscope-shell-ready /tmp/ironscope-shell-start
.venv-e2e-v1/bin/python /tmp/ironscope_shell_agent.py
```

Get the PID from stdout or with `pgrep`:

```bash
pgrep -f ironscope_shell_agent.py
```

## 2. Monitor Mode Config

Create `/tmp/ironscope-shell-monitor.yaml` and replace `12345` with the process
PID.

```yaml
ironscope:
  agents:
    - pid: 12345

  unknown_tool_policy: allow
  resolver_error_policy: deny
  agent_child_scope: protect_only_tool_children
  default_tool_policy: allow

  tools:
    - name: shell
    - name: read_file
    - name: connect


  mode: monitor
```

Attach IronScope in another terminal:

```bash
sudo -E target/release/ironscope \
  --config /tmp/ironscope-shell-monitor.yaml \
  --contract-dir tools/python-contracts \
  --mode monitor \
  --duration 60 \
  --ready-file /tmp/ironscope-shell-ironscope-ready \
  --output /tmp/ironscope-shell-monitor.json
```

After IronScope is ready, release the workload:

```bash
touch /tmp/ironscope-shell-start
```

In monitor mode, policy decisions are audit decisions only. If a rule would deny
an operation, the syscall still succeeds and the audit event records
`action: "deny"` as a would-deny decision.

## 3. Enforce Mode Config

For allow-list style enforcement, set `default_tool_policy: deny` and list the
resources each known tool may use. Create `/tmp/ironscope-shell-enforce.yaml`:

```yaml
ironscope:
  agents:
    - pid: 12345

  unknown_tool_policy: allow
  resolver_error_policy: deny
  agent_child_scope: protect_only_tool_children
  default_tool_policy: deny

  tools:
    - name: shell
      exec:
        allow:
          - /usr/bin/true
    - name: read_file
      fs:
        allow:
          - /tmp/ironscope-shell-allowed.txt
    - name: connect
      net:
        allow:
          - 127.0.0.1:443


  mode: enforce
```

Run IronScope in enforce mode:

```bash
sudo -E target/release/ironscope \
  --config /tmp/ironscope-shell-enforce.yaml \
  --contract-dir tools/python-contracts \
  --mode enforce \
  --duration 60 \
  --ready-file /tmp/ironscope-shell-ironscope-ready \
  --output /tmp/ironscope-shell-enforce.json
```

Then release the workload:

```bash
touch /tmp/ironscope-shell-start
```

Expected behavior:

- `read_file` can open `/tmp/ironscope-shell-allowed.txt`.
- `read_file` is denied on `/tmp/ironscope-shell-secret.txt`.
- `shell` can execute `/usr/bin/true`.
- `shell` is denied on `/usr/bin/id`.
- Non-tool work is not denied as tool work unless it is inside an active tool
  context or covered by idle policy.

## 4. Review The Audit Trail

Inspect the generated JSON:

```bash
python3 -m json.tool /tmp/ironscope-shell-enforce.json | less
```

The most useful sections are:

- `py_events`: tool start, task bind/unbind, worker bind/unbind, and context end.
- `resolver_events`: runtime candidates that userspace resolved into tool names.
- `guard_events`: kernel-visible resource decisions.
- `bracket_check`: attribution consistency for guard events.
- `final_state`: BPF map cleanup at shutdown.

A denied known-tool event looks like this shape:

```json
{
  "kind_str": "EXEC",
  "tool_name": "shell",
  "identity_state": "known_tool",
  "policy_source": "tool",
  "path": "/usr/bin/id",
  "action": "deny"
}
```

A file event is reported under `guard_events` with the file `path`. A network
connect event includes `addr` and `port` when the kernel hook observes an IPv4
socket connect.

## Troubleshooting

BPF LSM is missing:

```bash
cat /sys/kernel/security/lsm
```

The list must include `bpf` for enforcement. Without BPF LSM, IronScope may be
able to monitor through fallback hooks, but syscall blocking requires
`--mode enforce` with active BPF LSM.

Root privileges are missing:

IronScope needs root privileges to load BPF programs and attach LSM hooks. Run
with `sudo -E` when using the local development tree.

Unsupported CPython contract:

If startup reports an unsupported CPython contract or no matching contract,
IronScope fails closed before attaching CPython tool-context probes. V0.1 ships
a validated CPython 3.12.3 aarch64 contract only. Use:

```bash
target/release/ironscope profile detect --pid 12345
target/release/ironscope profile validate   --pid 12345   --contract tools/python-contracts/cpython-3.12.3-aarch64-*.json
```

First-call unknown tool behavior:

The first execution of a newly seen tool object may use `unknown_tool_policy`
before userspace resolves the tool name. Use `unknown_tool_policy: allow` for a
less disruptive first run, or `unknown_tool_policy: deny` when unknown tool
execution should fail closed until the cache is populated.

Resolver errors:

`resolver_error_policy: deny` means IronScope fails closed when it sees a
possible tool boundary but cannot safely resolve runtime identity.

Network policy:

V0.1 network policy is IPv4 socket-connect policy. DNS names in config are
resolved at IronScope startup; later DNS/IP rotation is not tracked
continuously.
