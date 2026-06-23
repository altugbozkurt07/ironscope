# Contributing

IronScope v0.1 is intentionally narrow. Contributions should preserve the documented support matrix unless they include matching contracts, tests, and release documentation.

## Scope Rules

- Keep release-facing code on the CPython 3.12.3 aarch64 LangChain/LangGraph BaseTool path.
- Do not add app-level tool registration as the primary integration path.
- Do not add unsupported Python versions, architectures, or frameworks without validated contracts and deterministic tests.
- Do not reintroduce traffic/provider parsing as a release-facing tool identity path.

## Verification

Run the deterministic checks that match your change. At minimum for host-side changes:

```bash
cargo fmt --all --check
cargo check
cargo test --workspace --exclude ironscope-ebpf
python3 tests/verify_quickstart_docs.py
python3 tests/verify_release_packaging.py
```

Privileged BPF tests require BPF LSM and sudo. Run them sequentially because probes and maps are global to the host.

## Documentation

Update README, quickstart docs, and release notes whenever a change affects public behavior, policy fields, supported versions, output schema, or operational requirements.
