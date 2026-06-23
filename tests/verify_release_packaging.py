#!/usr/bin/env python3
"""Verify release Dockerfiles package IronScope runtime assets.

This is a static release gate. It checks the release image layout promised by
README/release docs without requiring a Docker daemon.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = [ROOT / "Dockerfile", ROOT / "docker" / "Dockerfile.release"]
REQUIRED_ASSETS = [
    ROOT / "tools" / "python-contracts" / "index.json",
    ROOT / "tools" / "rules" / "framework_rules.yaml",
    ROOT / "examples" / "policies" / "langchain-monitor.yaml",
    ROOT / "examples" / "policies" / "langgraph-tool-execution-enforce.yaml",
]
COPY_RULES = [
    (
        r"FROM\s+rust:1\.96-bookworm\s+AS\s+builder",
        "latest verified stable Rust builder image rust:1.96-bookworm",
    ),
    (
        r"apt-get\s+install\s+-y\s+--no-install-recommends(?s:.*?)clang(?s:.*?)libclang-dev(?s:.*?)libbpf-dev(?s:.*?)llvm(?s:.*?)pkg-config(?s:.*?)zlib1g-dev",
        "native build dependencies for bindgen, libbpf headers, clang BPF shim, and zlib",
    ),
    (
        r"rustup\s+toolchain\s+install\s+nightly\s+--profile\s+minimal\s+--component\s+rust-src",
        "nightly rust-src toolchain required by aya-build eBPF compilation",
    ),
    (
        r"cargo\s+\+nightly\s+install\s+bpf-linker\s+--locked",
        "bpf-linker installed for the aya eBPF build",
    ),
    (
        r"COPY\s+--from=builder\s+/build/tools/python-contracts\s+/usr/share/ironscope/python-contracts",
        "CPython contracts copied to /usr/share/ironscope/python-contracts",
    ),
    (
        r"COPY\s+--from=builder\s+/build/tools/rules/framework_rules\.yaml\s+/usr/share/ironscope/rules/framework_rules\.yaml",
        "framework rules copied to /usr/share/ironscope/rules/framework_rules.yaml",
    ),
    (
        r"COPY\s+--from=builder\s+/build/examples/policies\s+/usr/share/ironscope/examples/policies",
        "example policies copied to /usr/share/ironscope/examples/policies",
    ),
]


def main() -> int:
    problems: list[str] = []

    for asset in REQUIRED_ASSETS:
        if not asset.exists():
            problems.append(f"required asset missing from source tree: {asset.relative_to(ROOT)}")

    contract_files = [
        p for p in (ROOT / "tools" / "python-contracts").glob("*.json") if p.name != "index.json"
    ]
    if not contract_files:
        problems.append("no validated CPython contract JSON found under tools/python-contracts")

    for dockerfile in DOCKERFILES:
        if not dockerfile.exists():
            problems.append(f"Dockerfile missing: {dockerfile.relative_to(ROOT)}")
            continue
        text = dockerfile.read_text()
        for pattern, description in COPY_RULES:
            if not re.search(pattern, text):
                problems.append(f"{dockerfile.relative_to(ROOT)} does not package {description}")

    if problems:
        for problem in problems:
            print(f"PROBLEM: {problem}")
        return 1

    print(
        "PASS: release Dockerfiles use the verified Rust/Aya build path and package runtime assets"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
