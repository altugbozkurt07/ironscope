#!/usr/bin/env python3
"""Deterministic assertions for IronScope audit/enforcement JSON.

These helpers are intentionally framework-neutral. E2E scripts should use them
instead of embedding complex JSON checks in shell snippets so lifecycle,
attribution, policy-source, and final-state semantics stay consistent across
scenarios.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

VALID_IDENTITY = {
    "known_tool",
    "unknown_tool",
    "resolver_error",
    "unattributed",
}

VALID_POLICY_SOURCE = {
    "default_allow",
    "default_deny",
    "tool",
    "unattributed",
    "unknown_tool",
    "resolver_error",
    "monitor",
}

EVENT_TOOL_START = 6
EVENT_TOOL_CONTEXT_END = 7
EVENT_TOOL_END = EVENT_TOOL_CONTEXT_END
EVENT_WORKER_BIND = 10
EVENT_WORKER_UNBIND = 11
EVENT_WORKER_CARRIER_BIND = 21
EVENT_WORKER_CARRIER_UNBIND = 22
EVENT_CHILD_CTX_BIND = 23
EVENT_CHILD_CTX_UNBIND = 24
EVENT_TOOL_FRAME_END = 17
EVENT_RESOLVER_CANDIDATE = 18
EVENT_RESOLVER_FAILED = 20
CTX_MAP_KEYS = (
    "TOOL_CTX",
    "TASK_CTX",
    "TASK_CTX_STACK",
    "TASK_CTX_DEPTH",
    "PENDING_TOOL_CLOSE",
    "PENDING_FRAME_TOOL",
    "FORK_CTX",
    "WORKITEM_CTX",
    "PYTHREAD_OBJ_CTX",
    "PYTHREAD_OBJ_THREAD",
    "FRAME_CTX",
    "THREAD_ACTIVE_CTX",
    "THREAD_ACTIVE_TASK",
    "THREAD_CTX_STACK",
    "THREAD_CTX_DEPTH",
    "THREADPOOL_WORKER_FRAME",
    "THREADPOOL_WORKER_CTX",
    "THREADPOOL_WORKITEM_THREAD",
    "THREAD_CURRENT_FRAME",
    "FRAME_ENTRY_STASH",
    "FRAME_STASH_DEPTH",
    "WORKER_RUN_STACK",
    "WORKER_RUN_CARRIER",
    "WORKER_RUN_DEPTH",
)


class AuditAssertionError(AssertionError):
    """Raised when an IronScope audit artifact violates expected semantics."""


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise AuditAssertionError("IronScope JSON root must be an object")
    return doc


def py_events(doc: dict[str, Any]) -> list[dict[str, Any]]:
    events = doc.get("py_events")
    if not isinstance(events, list):
        raise AuditAssertionError("expected top-level py_events list")
    return events


def guard_events(doc: dict[str, Any]) -> list[dict[str, Any]]:
    events = doc.get("guard_events")
    if not isinstance(events, list):
        raise AuditAssertionError("expected top-level guard_events list")
    return events


def assert_guard_event_schema(
    doc: dict[str, Any],
    *,
    require_identity_states: Iterable[str] = (),
) -> None:
    events = guard_events(doc)
    if not events:
        raise AuditAssertionError("expected at least one guard event")

    seen: set[str] = set()
    for idx, event in enumerate(events):
        identity = event.get("identity_state")
        policy_source = event.get("policy_source")
        tool_name = event.get("tool_name")

        if identity not in VALID_IDENTITY:
            raise AuditAssertionError(
                f"guard_events[{idx}] has invalid identity_state: {identity!r}"
            )
        if policy_source not in VALID_POLICY_SOURCE:
            raise AuditAssertionError(
                f"guard_events[{idx}] has invalid policy_source: {policy_source!r}"
            )
        if tool_name == "idle":
            raise AuditAssertionError(
                f"guard_events[{idx}] rendered as idle instead of explicit identity"
            )

        seen.add(identity)
        if identity == "known_tool":
            if policy_source not in {"tool", "default_allow", "default_deny", "monitor"}:
                raise AuditAssertionError(
                    f"known tool event has incompatible policy_source: {policy_source}"
                )
            if not isinstance(tool_name, str) or not tool_name:
                raise AuditAssertionError("known tool event must render a non-empty tool_name")
        elif identity == "unknown_tool":
            if tool_name != "unknown":
                raise AuditAssertionError("unknown_tool event must render tool_name as 'unknown'")
            if policy_source != "unknown_tool":
                raise AuditAssertionError("unknown_tool event must use unknown_tool policy_source")
        elif identity == "resolver_error":
            if tool_name != "resolver_error":
                raise AuditAssertionError(
                    "resolver_error event must render tool_name as 'resolver_error'"
                )
            if policy_source != "resolver_error":
                raise AuditAssertionError(
                    "resolver_error event must use resolver_error policy_source"
                )
        elif identity == "unattributed":
            if tool_name != "unattributed":
                raise AuditAssertionError(
                    "unattributed event must render tool_name as 'unattributed'"
                )
            if policy_source not in {"unattributed", "monitor", "default_allow"}:
                raise AuditAssertionError(
                    f"unattributed event has incompatible policy_source: {policy_source}"
                )

    missing = sorted(set(require_identity_states) - seen)
    if missing:
        raise AuditAssertionError(
            "fixture did not exercise identity states: " + ", ".join(missing)
        )


def assert_tool_lifecycle_balanced(doc: dict[str, Any]) -> None:
    events = sorted(py_events(doc), key=lambda e: int(e.get("ts_ns", 0)))
    starts: dict[int, list[dict[str, Any]]] = defaultdict(list)
    frame_ends: dict[int, list[dict[str, Any]]] = defaultdict(list)
    context_ends: dict[int, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        ctx_id = int(event.get("ctx_id", 0) or 0)
        kind = event.get("kind")
        kind_str = event.get("kind_str")
        if kind == EVENT_TOOL_START:
            if ctx_id == 0:
                raise AuditAssertionError("tool_start must not use ctx_id=0")
            if kind_str not in (None, "tool_start"):
                raise AuditAssertionError(f"tool_start rendered with wrong kind_str: {kind_str}")
            starts[ctx_id].append(event)
        elif kind == EVENT_TOOL_FRAME_END:
            if ctx_id == 0:
                raise AuditAssertionError("tool_frame_end must not use ctx_id=0")
            if kind_str not in (None, "tool_frame_end"):
                raise AuditAssertionError(
                    f"tool_frame_end rendered with wrong kind_str: {kind_str}"
                )
            frame_ends[ctx_id].append(event)
        elif kind == EVENT_TOOL_CONTEXT_END:
            if ctx_id == 0:
                raise AuditAssertionError("tool_context_end must not use ctx_id=0")
            if kind_str not in (None, "tool_context_end"):
                raise AuditAssertionError(
                    f"tool_context_end rendered with wrong kind_str: {kind_str}"
                )
            context_ends[ctx_id].append(event)

    all_ctx = set(starts) | set(frame_ends) | set(context_ends)
    for ctx_id in sorted(all_ctx):
        if len(starts[ctx_id]) != 1 or len(context_ends[ctx_id]) != 1:
            raise AuditAssertionError(
                f"unbalanced or duplicate tool lifecycle for ctx={ctx_id:#x}: "
                f"starts={len(starts[ctx_id])} context_ends={len(context_ends[ctx_id])}"
            )
        if len(frame_ends[ctx_id]) > 1:
            raise AuditAssertionError(
                f"duplicate tool_frame_end for ctx={ctx_id:#x}: {len(frame_ends[ctx_id])}"
            )

        start = starts[ctx_id][0]
        context_end = context_ends[ctx_id][0]
        start_ts = int(start.get("ts_ns", 0))
        end_ts = int(context_end.get("ts_ns", 0))
        if end_ts < start_ts:
            raise AuditAssertionError(f"tool_context_end precedes tool_start for ctx={ctx_id:#x}")
        if start.get("tool_id") != context_end.get("tool_id"):
            raise AuditAssertionError(f"tool_id changed within context lifecycle for ctx={ctx_id:#x}")

        if frame_ends[ctx_id]:
            frame_end = frame_ends[ctx_id][0]
            frame_ts = int(frame_end.get("ts_ns", 0))
            if frame_ts < start_ts or frame_ts > end_ts:
                raise AuditAssertionError(
                    f"tool_frame_end outside context lifecycle for ctx={ctx_id:#x}"
                )
            if start.get("tool_id") != frame_end.get("tool_id"):
                raise AuditAssertionError(f"tool_id changed at frame end for ctx={ctx_id:#x}")


def assert_final_state_clean(doc: dict[str, Any], keys: Iterable[str] = CTX_MAP_KEYS) -> None:
    final_state = doc.get("final_state")
    if not isinstance(final_state, dict):
        raise AuditAssertionError("expected final_state object")
    for key in keys:
        value = final_state.get(key)
        if value != 0:
            raise AuditAssertionError(f"final_state.{key} not empty: {value}")


def assert_worker_lifecycle_events_balanced(doc: dict[str, Any]) -> None:
    bind_count = int(doc.get("worker_bind_count", 0) or 0)
    unbind_count = int(doc.get("worker_unbind_count", 0) or 0)
    if bind_count != unbind_count:
        raise AuditAssertionError(
            f"worker lifecycle events unbalanced: binds={bind_count} unbinds={unbind_count}"
        )


def assert_worker_carrier_lifecycle_balanced(doc: dict[str, Any]) -> None:
    carrier_binds: dict[tuple[int, int, int], list[dict[str, Any]]] = defaultdict(list)
    carrier_unbinds: dict[tuple[int, int, int], list[dict[str, Any]]] = defaultdict(list)
    for event in py_events(doc):
        kind = event.get("kind")
        if kind not in (EVENT_WORKER_CARRIER_BIND, EVENT_WORKER_CARRIER_UNBIND):
            continue
        key = (
            int(event.get("ctx_id", 0) or 0),
            int(event.get("tool_id", 0) or 0),
            int(event.get("carrier_ptr", 0) or 0),
        )
        if kind == EVENT_WORKER_CARRIER_BIND:
            carrier_binds[key].append(event)
        else:
            carrier_unbinds[key].append(event)

    keys = set(carrier_binds) | set(carrier_unbinds)
    for key in keys:
        binds = carrier_binds.get(key, [])
        unbinds = carrier_unbinds.get(key, [])
        if len(binds) != len(unbinds):
            raise AuditAssertionError(
                f"worker carrier lifecycle unbalanced for ctx/tool/carrier={key}: "
                f"binds={len(binds)} unbinds={len(unbinds)}"
            )
        for bind, unbind in zip(sorted(binds, key=lambda e: int(e.get("ts_ns", 0) or 0)),
                                sorted(unbinds, key=lambda e: int(e.get("ts_ns", 0) or 0))):
            if int(unbind.get("ts_ns", 0) or 0) < int(bind.get("ts_ns", 0) or 0):
                raise AuditAssertionError(
                    f"worker carrier unbind happened before bind for ctx/tool/carrier={key}"
                )


def assert_frame_end_for_each_started_context(doc: dict[str, Any]) -> None:
    starts = {int(e.get("ctx_id", 0) or 0) for e in py_events(doc) if e.get("kind") == EVENT_TOOL_START}
    frame_ends = [e for e in py_events(doc) if e.get("kind") == EVENT_TOOL_FRAME_END]
    by_ctx: dict[int, int] = defaultdict(int)
    for event in frame_ends:
        by_ctx[int(event.get("ctx_id", 0) or 0)] += 1
    missing = sorted(ctx_id for ctx_id in starts if by_ctx.get(ctx_id, 0) != 1)
    if missing:
        rendered = ", ".join(f"{ctx_id:#x}" for ctx_id in missing)
        raise AuditAssertionError(f"missing unique tool_frame_end for context(s): {rendered}")


def find_guard_event(
    doc: dict[str, Any],
    *,
    path_fragment: str,
    action: str,
    tool_name: str,
    kind_str: str | None = None,
    identity_state: str = "known_tool",
    policy_source: str | None = None,
    require_context: bool = True,
) -> dict[str, Any]:
    for event in guard_events(doc):
        if path_fragment not in str(event.get("path", "")):
            continue
        if event.get("action") != action:
            continue
        if event.get("tool_name") != tool_name:
            continue
        if kind_str is not None and event.get("kind_str") != kind_str:
            continue
        if event.get("identity_state") != identity_state:
            continue
        if policy_source is not None and event.get("policy_source") != policy_source:
            continue
        if require_context and not event.get("ctx_id"):
            continue
        return event
    raise AuditAssertionError(
        "missing guard event: "
        f"path~={path_fragment!r} action={action!r} tool={tool_name!r} "
        f"kind={kind_str!r} identity={identity_state!r} policy_source={policy_source!r}"
    )


def find_net_event(
    doc: dict[str, Any],
    *,
    addr: str,
    port: int,
    action: str,
    tool_name: str,
    identity_state: str = "known_tool",
    policy_source: str | None = None,
    require_context: bool = True,
) -> dict[str, Any]:
    for event in guard_events(doc):
        if event.get("kind_str") != "CONNECT":
            continue
        if event.get("addr") != addr:
            continue
        if int(event.get("port", 0) or 0) != port:
            continue
        if event.get("action") != action:
            continue
        if event.get("tool_name") != tool_name:
            continue
        if event.get("identity_state") != identity_state:
            continue
        if policy_source is not None and event.get("policy_source") != policy_source:
            continue
        if require_context and not event.get("ctx_id"):
            continue
        return event
    raise AuditAssertionError(
        "missing net guard event: "
        f"addr={addr!r} port={port!r} action={action!r} tool={tool_name!r} "
        f"identity={identity_state!r} policy_source={policy_source!r}"
    )


def assert_no_non_tool_denies(doc: dict[str, Any]) -> None:
    for idx, event in enumerate(guard_events(doc)):
        if event.get("identity_state") == "unattributed" and event.get("action") == "deny":
            raise AuditAssertionError(
                f"guard_events[{idx}] denied unattributed/non-tool behavior: {event}"
            )


def assert_langchain_policy_e2e(doc: dict[str, Any]) -> None:
    assert_guard_event_schema(doc)
    assert_tool_lifecycle_balanced(doc)
    assert_frame_end_for_each_started_context(doc)
    assert_final_state_clean(doc)
    assert_no_non_tool_denies(doc)

    candidates = [
        event
        for event in resolver_events(doc)
        if event.get("kind") == EVENT_RESOLVER_CANDIDATE
    ]
    if len(candidates) < 3:
        raise AuditAssertionError(
            f"expected at least three runtime resolver candidates, got {len(candidates)}"
        )
    for idx, candidate in enumerate(candidates):
        for field in ("self_ptr", "type_ptr", "frame_ptr", "code_ptr"):
            if int(candidate.get(field, 0) or 0) == 0:
                raise AuditAssertionError(
                    f"resolver candidate {idx} missing non-zero {field}: {candidate}"
                )
    failures = [
        event
        for event in resolver_events(doc)
        if event.get("kind") == EVENT_RESOLVER_FAILED
    ]
    if failures:
        raise AuditAssertionError(f"unexpected resolver failures: {failures}")

    find_guard_event(
        doc,
        path_fragment="/tmp/ironscope_langchain_allowed.txt",
        action="allow",
        tool_name="read_file",
        identity_state="known_tool",
    )
    find_guard_event(
        doc,
        path_fragment="/etc/passwd",
        action="deny",
        tool_name="read_file",
        kind_str="FILE_OPEN",
        identity_state="known_tool",
        policy_source="tool",
    )
    find_guard_event(
        doc,
        path_fragment="/usr/bin/id",
        action="deny",
        tool_name="shell",
        kind_str="EXEC",
        identity_state="known_tool",
        policy_source="tool",
    )
    find_guard_event(
        doc,
        path_fragment="/tmp/ironscope_langchain_note.txt",
        action="allow",
        tool_name="write_note",
        identity_state="known_tool",
    )


def assert_child_scope_e2e(
    doc: dict[str, Any],
    *,
    idle_child_pid: int,
    scope: str,
) -> None:
    assert_guard_event_schema(doc)
    assert_tool_lifecycle_balanced(doc)
    assert_frame_end_for_each_started_context(doc)
    assert_final_state_clean(doc)
    assert_no_non_tool_denies(doc)

    tool_exec = find_guard_event(
        doc,
        path_fragment="/usr/bin/id",
        action="deny",
        tool_name="child_exec",
        kind_str="EXEC",
        identity_state="known_tool",
        policy_source="tool",
    )
    if int(tool_exec.get("ctx_id", 0) or 0) == 0:
        raise AuditAssertionError("tool child exec deny must carry a non-zero ctx_id")

    idle_events = [
        event
        for event in guard_events(doc)
        if int(event.get("pid", 0) or 0) == idle_child_pid
        and event.get("kind_str") == "EXEC"
        and "/usr/bin/id" in str(event.get("path", ""))
    ]

    if scope == "protect_only_tool_children":
        if idle_events:
            raise AuditAssertionError(
                "idle child produced protected exec event under protect_only_tool_children: "
                + repr(idle_events)
            )
        return

    if scope == "protect_all_children":
        if len(idle_events) != 1:
            raise AuditAssertionError(
                f"expected one protected idle child exec event under protect_all_children, got {len(idle_events)}"
            )
        event = idle_events[0]
        if event.get("identity_state") != "unattributed":
            raise AuditAssertionError(
                f"protect_all idle child should be unattributed, got {event.get('identity_state')!r}"
            )
        if event.get("policy_source") != "unattributed":
            raise AuditAssertionError(
                f"protect_all idle child should use unattributed policy, got {event.get('policy_source')!r}"
            )
        if event.get("action") != "allow":
            raise AuditAssertionError(
                f"protect_all idle child should be audited/allowed by default, got {event.get('action')!r}"
            )
        return

    raise AuditAssertionError(f"unsupported child scope for verifier: {scope!r}")


def assert_async_lifecycle_case(doc: dict[str, Any], *, case: str) -> None:
    if guard_events(doc):
        assert_guard_event_schema(doc)
        assert_no_non_tool_denies(doc)
    assert_tool_lifecycle_balanced(doc)
    assert_frame_end_for_each_started_context(doc)
    assert_final_state_clean(doc)

    if case == "nested":
        inner = find_guard_event(
            doc,
            path_fragment="/tmp/ironscope_async_inner_secret.txt",
            action="deny",
            tool_name="async_inner",
            kind_str="FILE_OPEN",
            policy_source="tool",
        )
        outer = find_guard_event(
            doc,
            path_fragment="/tmp/ironscope_async_outer_secret.txt",
            action="deny",
            tool_name="async_outer",
            kind_str="FILE_OPEN",
            policy_source="tool",
        )
        if inner.get("ctx_id") == outer.get("ctx_id"):
            raise AuditAssertionError("nested inner and outer tools must use distinct ctx_id values")
        if int(outer.get("ts_ns", 0)) <= int(inner.get("ts_ns", 0)):
            raise AuditAssertionError("outer deny should occur after inner deny in nested scenario")
        return

    if case == "parallel":
        a = find_guard_event(
            doc,
            path_fragment="/tmp/ironscope_async_parallel_a_secret.txt",
            action="deny",
            tool_name="async_parallel_a",
            kind_str="FILE_OPEN",
            policy_source="tool",
        )
        b = find_guard_event(
            doc,
            path_fragment="/tmp/ironscope_async_parallel_b_secret.txt",
            action="deny",
            tool_name="async_parallel_b",
            kind_str="FILE_OPEN",
            policy_source="tool",
        )
        if a.get("ctx_id") == b.get("ctx_id"):
            raise AuditAssertionError("parallel tools must use distinct ctx_id values")
        return

    if case in {"cancelled", "exception"}:
        starts = [event for event in py_events(doc) if event.get("kind") == EVENT_TOOL_START]
        if not starts:
            raise AuditAssertionError(f"{case} scenario expected at least one tool_start")
        return

    raise AuditAssertionError(f"unsupported async lifecycle case: {case!r}")


WORKER_CASES = {
    "threadpool": (
        "threadpool_reader",
        "/tmp/ironscope_worker_threadpool_secret.txt",
        True,
    ),
    "threading": (
        "threading_reader",
        "/tmp/ironscope_worker_threading_secret.txt",
        True,
    ),
    "to_thread": (
        "asyncio_to_thread_reader",
        "/tmp/ironscope_worker_to_thread_secret.txt",
        True,
    ),
    "background_popen": (
        "background_popen",
        "/tmp/ironscope_worker_background_secret.txt",
        False,
    ),
    "langgraph_toolnode": (
        "langgraph_toolnode_reader",
        "/tmp/ironscope_worker_langgraph_toolnode_secret.txt",
        True,
    ),
}


def _py_events_for_ctx(doc: dict[str, Any], ctx_id: int, kind: int) -> list[dict[str, Any]]:
    return [
        event
        for event in py_events(doc)
        if int(event.get("ctx_id", 0) or 0) == ctx_id and event.get("kind") == kind
    ]


def assert_worker_lifecycle_case(doc: dict[str, Any], *, case: str) -> None:
    if case not in WORKER_CASES:
        raise AuditAssertionError(f"unsupported worker lifecycle case: {case!r}")

    tool_name, path, require_worker_unbind = WORKER_CASES[case]
    assert_guard_event_schema(doc)
    assert_tool_lifecycle_balanced(doc)
    assert_frame_end_for_each_started_context(doc)
    assert_final_state_clean(doc)
    assert_no_non_tool_denies(doc)
    assert_worker_lifecycle_events_balanced(doc)
    assert_worker_carrier_lifecycle_balanced(doc)

    guard = find_guard_event(
        doc,
        path_fragment=path,
        action="deny",
        tool_name=tool_name,
        kind_str="FILE_OPEN",
        policy_source="tool",
    )
    ctx_id = int(guard.get("ctx_id", 0) or 0)
    guard_ts = int(guard.get("ts_ns", 0) or 0)

    if not require_worker_unbind:
        starts = _py_events_for_ctx(doc, ctx_id, EVENT_TOOL_START)
        frame_ends = _py_events_for_ctx(doc, ctx_id, EVENT_TOOL_FRAME_END)
        context_ends = _py_events_for_ctx(doc, ctx_id, EVENT_TOOL_CONTEXT_END)
        if len(starts) != 1 or len(frame_ends) != 1 or len(context_ends) != 1:
            raise AuditAssertionError(
                f"background_popen expected one start/frame/context end for ctx={ctx_id:#x}"
            )
        frame_ts = int(frame_ends[0].get("ts_ns", 0) or 0)
        context_ts = int(context_ends[0].get("ts_ns", 0) or 0)
        if not (guard_ts < context_ts):
            raise AuditAssertionError(
                "background child syscall must occur before tool_context_end: "
                f"frame={frame_ts} guard={guard_ts} context={context_ts}"
            )

        child_binds = _py_events_for_ctx(doc, ctx_id, EVENT_CHILD_CTX_BIND)
        if not child_binds:
            raise AuditAssertionError(
                f"background_popen expected CHILD_CTX_BIND for ctx={ctx_id:#x}"
            )
        if not any(int(event.get("ts_ns", 0) or 0) < guard_ts for event in child_binds):
            raise AuditAssertionError(
                "background child syscall must occur after CHILD_CTX_BIND: "
                f"guard={guard_ts} binds={[int(e.get('ts_ns', 0) or 0) for e in child_binds]}"
            )
        return

    binds = _py_events_for_ctx(doc, ctx_id, EVENT_WORKER_BIND)
    if case == "langgraph_toolnode":
        guard_tid = int(guard.get("tid", 0) or 0)
        if guard_tid == int(guard.get("pid", 0) or 0):
            raise AuditAssertionError(
                "langgraph_toolnode deny should occur on ToolNode executor thread, got main tid"
            )
        starts = _py_events_for_ctx(doc, ctx_id, EVENT_TOOL_START)
        if not starts or int(starts[0].get("tid", 0) or 0) != guard_tid:
            raise AuditAssertionError(
                "langgraph_toolnode tool context must start on the same executor thread as the deny"
            )
        return

    if not binds:
        raise AuditAssertionError(f"{case} expected WORKER_BIND for ctx={ctx_id:#x}")

    if require_worker_unbind:
        unbinds = _py_events_for_ctx(doc, ctx_id, EVENT_WORKER_UNBIND)
        if not unbinds:
            raise AuditAssertionError(f"{case} expected WORKER_UNBIND for ctx={ctx_id:#x}")
        guard_tid = int(guard.get("tid", 0) or 0)
        if guard_tid == int(guard.get("pid", 0) or 0):
            raise AuditAssertionError(f"{case} deny should occur on a worker thread, got main tid")
        if guard_tid not in {int(event.get("tid", 0) or 0) for event in unbinds}:
            raise AuditAssertionError(
                f"{case} worker deny tid={guard_tid} did not match any WORKER_UNBIND tid"
            )
        return



def resolver_events(doc: dict[str, Any]) -> list[dict[str, Any]]:
    events = doc.get("resolver_events")
    if not isinstance(events, list):
        raise AuditAssertionError("expected top-level resolver_events list")
    return events


def assert_first_call_unknown_policy(doc: dict[str, Any]) -> None:
    assert_guard_event_schema(doc, require_identity_states=("unknown_tool",))
    assert_tool_lifecycle_balanced(doc)
    assert_frame_end_for_each_started_context(doc)
    assert_final_state_clean(doc)
    assert_no_non_tool_denies(doc)

    guard = find_guard_event(
        doc,
        path_fragment="/tmp/ironscope_unknown_policy_secret.txt",
        action="deny",
        tool_name="unknown",
        kind_str="FILE_OPEN",
        identity_state="unknown_tool",
        policy_source="unknown_tool",
    )
    ctx_id = int(guard.get("ctx_id", 0) or 0)
    candidates = [
        event
        for event in resolver_events(doc)
        if int(event.get("ctx_id", 0) or 0) == ctx_id
        and event.get("kind") == EVENT_RESOLVER_CANDIDATE
    ]
    if len(candidates) != 1:
        raise AuditAssertionError(
            f"expected one resolver candidate for unknown ctx={ctx_id:#x}, got {len(candidates)}"
        )
    candidate = candidates[0]
    for field in ("self_ptr", "type_ptr", "frame_ptr", "code_ptr"):
        if int(candidate.get(field, 0) or 0) == 0:
            raise AuditAssertionError(f"resolver candidate missing non-zero {field}: {candidate}")
    if int(candidate.get("pid", 0) or 0) != int(guard.get("pid", 0) or 0):
        raise AuditAssertionError("resolver candidate pid must match guarded process pid")



def assert_langgraph_demo_daemon(doc: dict[str, Any]) -> None:
    assert_guard_event_schema(doc, require_identity_states=("known_tool", "unattributed"))
    assert_tool_lifecycle_balanced(doc)
    assert_frame_end_for_each_started_context(doc)
    assert_final_state_clean(doc)
    assert_no_non_tool_denies(doc)
    assert_worker_lifecycle_events_balanced(doc)
    assert_worker_carrier_lifecycle_balanced(doc)

    candidates = [event for event in resolver_events(doc) if event.get("kind") == EVENT_RESOLVER_CANDIDATE]
    if len(candidates) < 10:
        raise AuditAssertionError(
            f"expected at least 10 runtime resolver candidates for demo tools, got {len(candidates)}"
        )
    for idx, candidate in enumerate(candidates):
        for field in ("self_ptr", "type_ptr", "frame_ptr", "code_ptr"):
            if int(candidate.get(field, 0) or 0) == 0:
                raise AuditAssertionError(
                    f"resolver candidate {idx} missing non-zero {field}: {candidate}"
                )
    failures = [event for event in resolver_events(doc) if event.get("kind") == EVENT_RESOLVER_FAILED]
    if failures:
        raise AuditAssertionError(f"unexpected resolver failures in demo: {failures}")

    expected_denies = (
        ("read_file", "/tmp/ironscope_demo_read_secret.txt", "FILE_OPEN"),
        ("shell", "/usr/bin/id", "EXEC"),
        ("async_inner", "/tmp/ironscope_demo_async_inner_secret.txt", "FILE_OPEN"),
        ("async_outer", "/tmp/ironscope_demo_async_outer_secret.txt", "FILE_OPEN"),
        ("async_parallel_a", "/tmp/ironscope_demo_parallel_a_secret.txt", "FILE_OPEN"),
        ("async_parallel_b", "/tmp/ironscope_demo_parallel_b_secret.txt", "FILE_OPEN"),
        ("threadpool_reader", "/tmp/ironscope_demo_threadpool_secret.txt", "FILE_OPEN"),
        ("threading_reader", "/tmp/ironscope_demo_threading_secret.txt", "FILE_OPEN"),
        ("asyncio_to_thread_reader", "/tmp/ironscope_demo_to_thread_secret.txt", "FILE_OPEN"),
        ("background_popen", "/tmp/ironscope_demo_background_secret.txt", "FILE_OPEN"),
    )
    deny_events: dict[str, dict[str, Any]] = {}
    for tool_name, path, kind_str in expected_denies:
        event = find_guard_event(
            doc,
            path_fragment=path,
            action="deny",
            tool_name=tool_name,
            kind_str=kind_str,
            identity_state="known_tool",
            policy_source="tool",
        )
        deny_events[tool_name] = event

    find_guard_event(
        doc,
        path_fragment="/tmp/ironscope_demo_allowed.txt",
        action="allow",
        tool_name="read_file",
        kind_str="FILE_OPEN",
        identity_state="known_tool",
    )
    find_guard_event(
        doc,
        path_fragment="/tmp/ironscope_demo_note.txt",
        action="allow",
        tool_name="write_note",
        kind_str="FILE_OPEN",
        identity_state="known_tool",
    )
    find_guard_event(
        doc,
        path_fragment="/etc/passwd",
        action="allow",
        tool_name="unattributed",
        kind_str="FILE_OPEN",
        identity_state="unattributed",
        policy_source="unattributed",
        require_context=False,
    )
    for tool_name in ("threadpool_reader", "threading_reader", "asyncio_to_thread_reader"):
        guard = deny_events[tool_name]
        ctx_id = int(guard.get("ctx_id", 0) or 0)
        binds = _py_events_for_ctx(doc, ctx_id, EVENT_WORKER_BIND)
        unbinds = _py_events_for_ctx(doc, ctx_id, EVENT_WORKER_UNBIND)
        if not binds or not unbinds:
            raise AuditAssertionError(f"{tool_name} expected worker bind/unbind for ctx={ctx_id:#x}")
        if int(guard.get("tid", 0) or 0) == int(guard.get("pid", 0) or 0):
            raise AuditAssertionError(f"{tool_name} deny should occur on a worker thread")

    background = deny_events["background_popen"]
    ctx_id = int(background.get("ctx_id", 0) or 0)
    guard_ts = int(background.get("ts_ns", 0) or 0)
    frame_ends = _py_events_for_ctx(doc, ctx_id, EVENT_TOOL_FRAME_END)
    context_ends = _py_events_for_ctx(doc, ctx_id, EVENT_TOOL_CONTEXT_END)
    if len(frame_ends) != 1 or len(context_ends) != 1:
        raise AuditAssertionError(f"background_popen expected one frame/context end for ctx={ctx_id:#x}")
    frame_ts = int(frame_ends[0].get("ts_ns", 0) or 0)
    context_ts = int(context_ends[0].get("ts_ns", 0) or 0)
    if not (guard_ts < context_ts):
        raise AuditAssertionError(
            "background child syscall must occur before tool_context_end: "
            f"frame={frame_ts} guard={guard_ts} context={context_ts}"
        )
    binds = _py_events_for_ctx(doc, ctx_id, EVENT_WORKER_BIND)
    child_binds = _py_events_for_ctx(doc, ctx_id, EVENT_CHILD_CTX_BIND)
    if not child_binds:
        raise AuditAssertionError(
            f"background_popen expected CHILD_CTX_BIND for ctx={ctx_id:#x}"
        )
    if not any(int(event.get("ts_ns", 0) or 0) < guard_ts for event in child_binds):
        raise AuditAssertionError(
            "background child syscall must occur after CHILD_CTX_BIND: "
            f"guard={guard_ts}"
        )

def _cmd_schema(args: argparse.Namespace) -> None:
    states = args.require_identity_state or []
    assert_guard_event_schema(load_json(args.json_path), require_identity_states=states)


def _cmd_langchain_policy(args: argparse.Namespace) -> None:
    assert_langchain_policy_e2e(load_json(args.json_path))


def _cmd_child_scope(args: argparse.Namespace) -> None:
    assert_child_scope_e2e(
        load_json(args.json_path),
        idle_child_pid=int(args.idle_child_pid),
        scope=args.scope,
    )


def _cmd_async_lifecycle(args: argparse.Namespace) -> None:
    assert_async_lifecycle_case(load_json(args.json_path), case=args.case)



def assert_default_tool_policy(doc: dict[str, Any]) -> None:
    assert_guard_event_schema(doc)
    assert_tool_lifecycle_balanced(doc)
    assert_frame_end_for_each_started_context(doc)
    assert_final_state_clean(doc)
    assert_no_non_tool_denies(doc)

    find_guard_event(
        doc,
        path_fragment="/bin/busybox",
        action="allow",
        tool_name="shell",
        kind_str="EXEC",
        identity_state="known_tool",
        policy_source="tool",
    )
    find_guard_event(
        doc,
        path_fragment="/usr/bin/whoami",
        action="deny",
        tool_name="shell",
        kind_str="FILE_OPEN",
        identity_state="known_tool",
        policy_source="default_deny",
    )

def assert_resource_policy_case(doc: dict[str, Any], *, case: str, expectation: str, deny_port: int) -> None:
    assert_guard_event_schema(doc, require_identity_states=("known_tool", "unattributed"))
    assert_tool_lifecycle_balanced(doc)
    assert_frame_end_for_each_started_context(doc)
    assert_final_state_clean(doc)
    assert_no_non_tool_denies(doc)

    expected_deny_action = "deny"
    if case == "fs":
        tool_name = "file_tool"
        find_guard_event(
            doc,
            path_fragment="/tmp/ironscope_resource_allowed.txt",
            action="allow",
            tool_name=tool_name,
            kind_str="FILE_OPEN",
            identity_state="known_tool",
            policy_source="tool",
        )
        denied = find_guard_event(
            doc,
            path_fragment="/tmp/ironscope_resource_secret.txt",
            action=expected_deny_action,
            tool_name=tool_name,
            kind_str="FILE_OPEN",
            identity_state="known_tool",
            policy_source="tool",
        )
    elif case == "exec":
        tool_name = "exec_tool"
        find_guard_event(
            doc,
            path_fragment="/bin/true",
            action="allow",
            tool_name=tool_name,
            kind_str="EXEC",
            identity_state="known_tool",
            policy_source="tool",
        )
        denied = find_guard_event(
            doc,
            path_fragment="/usr/bin/id",
            action=expected_deny_action,
            tool_name=tool_name,
            kind_str="EXEC",
            identity_state="known_tool",
            policy_source="tool",
        )
    elif case == "net":
        tool_name = "net_tool"
        allow_events = [
            event for event in guard_events(doc)
            if event.get("kind_str") == "CONNECT"
            and event.get("tool_name") == tool_name
            and event.get("addr") == "127.0.0.1"
            and event.get("action") == "allow"
            and event.get("policy_source") == "tool"
        ]
        if not allow_events:
            raise AuditAssertionError("missing known-tool net allow event for net_tool")
        denied = find_net_event(
            doc,
            addr="127.0.0.1",
            port=deny_port,
            action=expected_deny_action,
            tool_name=tool_name,
            identity_state="known_tool",
            policy_source="tool",
        )
    else:
        raise AuditAssertionError(f"unsupported resource policy case: {case}")

    if expectation == "monitor":
        if denied.get("action") != "deny":
            raise AuditAssertionError("monitor would-deny case did not record deny decision")
    elif expectation != "enforce":
        raise AuditAssertionError(f"unsupported resource policy expectation: {expectation}")


def _cmd_resource_policy(args: argparse.Namespace) -> None:
    assert_resource_policy_case(
        load_json(args.json_path),
        case=args.case,
        expectation=args.expectation,
        deny_port=int(args.deny_port),
    )


def _cmd_worker_lifecycle(args: argparse.Namespace) -> None:
    assert_worker_lifecycle_case(load_json(args.json_path), case=args.case)


def _cmd_first_call_unknown(args: argparse.Namespace) -> None:
    assert_first_call_unknown_policy(load_json(args.json_path))


def _cmd_langgraph_demo(args: argparse.Namespace) -> None:
    assert_langgraph_demo_daemon(load_json(args.json_path))


def _cmd_default_tool_policy(args: argparse.Namespace) -> None:
    assert_default_tool_policy(load_json(args.json_path))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    schema = sub.add_parser("schema", help="validate guard event schema")
    schema.add_argument("json_path")
    schema.add_argument(
        "--require-identity-state",
        action="append",
        choices=sorted(VALID_IDENTITY),
        help="identity state that must be present; repeatable",
    )
    schema.set_defaults(func=_cmd_schema)

    langchain = sub.add_parser(
        "langchain-policy", help="validate the deterministic LangChain policy E2E artifact"
    )
    langchain.add_argument("json_path")
    langchain.set_defaults(func=_cmd_langchain_policy)

    child_scope = sub.add_parser(
        "child-scope",
        help="validate child process scope semantics for protected agent processes",
    )
    child_scope.add_argument("json_path")
    child_scope.add_argument("idle_child_pid", type=int)
    child_scope.add_argument(
        "scope",
        choices=("protect_only_tool_children", "protect_all_children"),
    )
    child_scope.set_defaults(func=_cmd_child_scope)


    async_lifecycle = sub.add_parser(
        "async-lifecycle",
        help="validate v0.1 async lifecycle async lifecycle scenario output",
    )
    async_lifecycle.add_argument("json_path")
    async_lifecycle.add_argument(
        "case",
        choices=("nested", "parallel", "cancelled", "exception"),
    )
    async_lifecycle.set_defaults(func=_cmd_async_lifecycle)

    worker_lifecycle = sub.add_parser(
        "worker-lifecycle",
        help="validate v0.1 worker lifecycle worker/subprocess lifecycle scenario output",
    )
    worker_lifecycle.add_argument("json_path")
    worker_lifecycle.add_argument(
        "case",
        choices=tuple(sorted(WORKER_CASES)),
    )
    worker_lifecycle.set_defaults(func=_cmd_worker_lifecycle)

    first_call_unknown = sub.add_parser(
        "first-call-unknown",
        help="validate v0.1 first-call unknown-policy first-call unknown-policy resolver candidate output",
    )
    first_call_unknown.add_argument("json_path")
    first_call_unknown.set_defaults(func=_cmd_first_call_unknown)

    langgraph_demo = sub.add_parser(
        "langgraph-demo",
        help="validate the standalone LangGraph-style tool execution daemon artifact",
    )
    langgraph_demo.add_argument("json_path")
    langgraph_demo.set_defaults(func=_cmd_langgraph_demo)

    default_tool_policy = sub.add_parser(
        "default-tool-policy",
        help="validate known-tool default_tool_policy fallback enforcement",
    )
    default_tool_policy.add_argument("json_path")
    default_tool_policy.set_defaults(func=_cmd_default_tool_policy)

    resource_policy = sub.add_parser(
        "resource-policy",
        help="validate deterministic FS/exec/net resource policy E2E artifacts",
    )
    resource_policy.add_argument("json_path")
    resource_policy.add_argument("case", choices=("fs", "exec", "net"))
    resource_policy.add_argument("expectation", choices=("enforce", "monitor"))
    resource_policy.add_argument("deny_port", nargs="?", default="0")
    resource_policy.set_defaults(func=_cmd_resource_policy)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except AuditAssertionError as exc:
        parser.exit(1, f"FAIL: {exc}\n")
    print("PASS: audit assertions verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
