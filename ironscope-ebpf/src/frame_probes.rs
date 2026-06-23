use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user,
};
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::EbpfContext;
use aya_log_ebpf::info;

use crate::code_classifier;
use crate::maps::*;
use crate::ownership;
use crate::tool_identity;
use crate::worker_probes;
use ironscope_common::types::*;

#[inline(always)]
fn py_object_key(ptr: u64) -> PyObjectKey {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    PyObjectKey {
        tgid: (pid_tgid >> 32) as u32,
        _pad: 0,
        ptr,
    }
}

#[inline(always)]
unsafe fn read_frame_from_ctx(ctx: &ProbeContext) -> Option<u64> {
    let frame_reg_idx = *PYTHON_OFFSETS.get(OFF_FRAME_REG_IDX)? as u64;
    if frame_reg_idx > 30 {
        return None;
    }
    let ctx_base = ctx.as_ptr() as u64;
    let reg_addr = ctx_base + frame_reg_idx * 8;
    bpf_probe_read_kernel(reg_addr as *const u64).ok()
}

#[inline(always)]
fn read_parent_ptr(frame_ptr: u64) -> Result<u64, i64> {
    let off_previous = unsafe { *PYTHON_OFFSETS.get(OFF_FRAME_PREVIOUS).ok_or(1i64)? } as u64;
    Ok(unsafe { bpf_probe_read_user((frame_ptr + off_previous) as *const u64) }.unwrap_or(0))
}

#[inline(always)]
fn start_cached_self_tool_root(
    tid: u32,
    frame_ptr: u64,
    parent_ptr: u64,
    tool_id: u32,
    flags: u32,
) -> Result<(), i64> {
    if tool_id == TOOL_IDLE {
        return Ok(());
    }

    let ctx_id = ownership::alloc_ctx_id().ok_or(1i64)?;
    let tool_ctx = ToolCtx {
        tool_id,
        generation: 0,
        carrier_count: 1,
        flags: TOOL_CTX_FLAG_RESOLVED | flags,
        started_ns: unsafe { bpf_ktime_get_ns() },
        last_seen_ns: 0,
    };
    let _ = unsafe { TOOL_CTX.insert(&ctx_id, &tool_ctx, 0) };
    let _ = unsafe { FRAME_CTX.insert(&py_object_key(frame_ptr), &ctx_id, 0) };

    if ownership::ctx_stack_push(tid, ctx_id).is_err() {
        let _ = unsafe { FRAME_CTX.remove(&py_object_key(frame_ptr)) };
        let _ = unsafe { TOOL_CTX.remove(&ctx_id) };
        return Ok(());
    }
    ownership::tool_stack_push(tid, ctx_id, frame_ptr, parent_ptr, tool_id);
    ownership::emit_py_event(EVENT_TOOL_START, ctx_id, tool_id);

    if let Some(&task_ptr) = unsafe { THREAD_ACTIVE_TASK.get(&tid) } {
        if task_ptr != 0 {
            let _ = ownership::task_ctx_push(tid, task_ptr, ctx_id, tool_id);
        }
    }
    Ok(())
}

#[inline(always)]
fn start_cached_parent_tool_if_needed(tid: u32, parent_ptr: u64) -> Result<(), i64> {
    if parent_ptr == 0 {
        return Ok(());
    }
    if unsafe { FRAME_CTX.get(&py_object_key(parent_ptr)).is_some() } {
        return Ok(());
    }

    let off_exec = unsafe { *PYTHON_OFFSETS.get(OFF_FRAME_F_EXECUTABLE).ok_or(1i64)? } as u64;
    let code_ptr: u64 =
        unsafe { bpf_probe_read_user((parent_ptr + off_exec) as *const u64) }.unwrap_or(0);
    if code_ptr == 0 {
        return Ok(());
    }
    if !unsafe { code_classifier::qualname_has_tool_impl_suffix(code_ptr) } {
        return Ok(());
    }

    let tool_id = unsafe { tool_identity::cached_frame_self_tool_id(parent_ptr) };
    if tool_id == TOOL_IDLE {
        return Ok(());
    }

    let grandparent_ptr = read_parent_ptr(parent_ptr)?;
    ownership::frame_stash_push(tid, parent_ptr);
    let off_flags = unsafe { *PYTHON_OFFSETS.get(OFF_CODE_FLAGS).ok_or(1i64)? } as u64;
    let co_flags: u32 =
        unsafe { bpf_probe_read_user((code_ptr + off_flags) as *const u32) }.unwrap_or(0);
    let tool_flags = if co_flags & CO_FLAGS_GENERATOR_MASK != 0 {
        TOOL_CTX_FLAG_ASYNC_FRAME
    } else {
        0
    };
    start_cached_self_tool_root(tid, parent_ptr, grandparent_ptr, tool_id, tool_flags)
}

#[inline(always)]
fn find_root_rule(kind: u8) -> Option<&'static RootRule> {
    let mut i = 0u32;
    while i < 64 {
        if let Some(rule) = unsafe { ROOT_RULES.get(i) } {
            if rule.kind == kind && rule.extractor_kind != EXTRACTOR_NONE {
                return Some(rule);
            }
        }
        i += 1;
    }
    None
}

#[inline(never)]
fn handle_tool_frame_entry_for_ptr_inner(
    ctx: &ProbeContext,
    frame_ptr: u64,
    skip_new_generator_frames: bool,
) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let off_exec = unsafe { *PYTHON_OFFSETS.get(OFF_FRAME_F_EXECUTABLE).ok_or(1i64)? } as u64;
    let code_ptr: u64 =
        unsafe { bpf_probe_read_user((frame_ptr + off_exec) as *const u64) }.map_err(|_| 1i64)?;
    if code_ptr == 0 {
        return Ok(());
    }

    let off_owner = unsafe { *PYTHON_OFFSETS.get(OFF_FRAME_OWNER).ok_or(1i64)? } as u64;
    let frame_owner: u8 =
        unsafe { bpf_probe_read_user((frame_ptr + off_owner) as *const u8) }.unwrap_or(255);

    let off_flags = unsafe { *PYTHON_OFFSETS.get(OFF_CODE_FLAGS).ok_or(1i64)? } as u64;
    let co_flags: u32 =
        unsafe { bpf_probe_read_user((code_ptr + off_flags) as *const u32) }.unwrap_or(0);

    let ck_key = CodeKindKey {
        tgid: pid,
        _pad: 0,
        code_ptr,
    };
    let kind = match unsafe { CODE_KIND.get(&ck_key) } {
        Some(&k) => k,
        None => unsafe { code_classifier::classify(pid, code_ptr, ctx) },
    };

    if kind == CODE_KIND_WORKITEM_CTOR
        || kind == CODE_KIND_WORKITEM_RUN
        || kind == CODE_KIND_THREAD_CTOR
        || kind == CODE_KIND_THREAD_RUN
    {
        return Ok(());
    }

    if skip_new_generator_frames && frame_owner == 0 {
        if co_flags & CO_FLAGS_GENERATOR_MASK != 0 {
            if kind == CODE_KIND_TOOL_ROOT_LC {
                if let Some(rule) = find_root_rule(kind) {
                    unsafe {
                        tool_identity::extract_and_resolve(frame_ptr, code_ptr, rule, 0);
                    }
                }
            }
            return Ok(());
        }
    }

    if kind == CODE_KIND_IGNORE {
        if unsafe { code_classifier::qualname_has_tool_impl_suffix(code_ptr) } {
            let parent_ptr = read_parent_ptr(frame_ptr)?;
            start_cached_parent_tool_if_needed(tid, parent_ptr)?;
            let cached_tool_id = unsafe { tool_identity::cached_frame_self_tool_id(frame_ptr) };
            if cached_tool_id == TOOL_IDLE {
                unsafe {
                    tool_identity::emit_frame_self_resolver_candidate(frame_ptr, code_ptr, kind)
                };
            }
            if let Some(&ctx_id) = unsafe { FRAME_CTX.get(&py_object_key(frame_ptr)) } {
                let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
                    .map(|c| c.tool_id)
                    .unwrap_or(TOOL_IDLE);
                if cached_tool_id != TOOL_IDLE && cached_tool_id != tool_id {
                    if let Some(entry) =
                        ownership::tool_stack_remove_frame_ctx(tid, frame_ptr, ctx_id)
                    {
                        close_tool_stack_entry(tid, entry)?;
                    }
                    ownership::frame_stash_push(tid, frame_ptr);
                    let tool_flags = if co_flags & CO_FLAGS_GENERATOR_MASK != 0 {
                        TOOL_CTX_FLAG_ASYNC_FRAME
                    } else {
                        0
                    };
                    start_cached_self_tool_root(
                        tid,
                        frame_ptr,
                        parent_ptr,
                        cached_tool_id,
                        tool_flags,
                    )?;
                } else {
                    ownership::tool_stack_refresh(tid, ctx_id, frame_ptr, parent_ptr, tool_id);
                    let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &ctx_id, 0) };
                    if let Some(&task_ptr) = unsafe { THREAD_ACTIVE_TASK.get(&tid) } {
                        if task_ptr != 0 {
                            ownership::cancel_deferred_tool_close(task_ptr, ctx_id, frame_ptr);
                            let _ = ownership::task_ctx_push(tid, task_ptr, ctx_id, tool_id);
                        }
                    }
                }
            } else if cached_tool_id != TOOL_IDLE {
                if let Some(active_ctx) = ownership::get_active_ctx(tid) {
                    let active_tool_id = unsafe { TOOL_CTX.get(&active_ctx) }
                        .map(|tool| tool.tool_id)
                        .unwrap_or(TOOL_IDLE);
                    if active_tool_id == cached_tool_id {
                        return Ok(());
                    }
                }
                ownership::frame_stash_push(tid, frame_ptr);
                let tool_flags = if co_flags & CO_FLAGS_GENERATOR_MASK != 0 {
                    TOOL_CTX_FLAG_ASYNC_FRAME
                } else {
                    0
                };
                start_cached_self_tool_root(
                    tid,
                    frame_ptr,
                    parent_ptr,
                    cached_tool_id,
                    tool_flags,
                )?;
            }
        }
        return Ok(());
    }

    // Read parent_ptr from the version-specific CPython contract so
    // TOOL_END parent matching works across supported interpreter builds.
    let parent_ptr = read_parent_ptr(frame_ptr)?;

    // A coroutine creation frame can be discovered before it is driven by
    // asyncio. Keep that discovery as metadata only; create a live TOOL_CTX
    // here, when the frame is actually resumed/executing.
    if !skip_new_generator_frames {
        let frame_key = py_object_key(frame_ptr);
        if unsafe { FRAME_CTX.get(&frame_key).is_none() } {
            if let Some(&pending_tool_id) = unsafe { PENDING_FRAME_TOOL.get(&frame_key) } {
                let _ = unsafe { PENDING_FRAME_TOOL.remove(&frame_key) };
                if pending_tool_id != TOOL_IDLE {
                    if let Some(&task_ptr) = unsafe { THREAD_ACTIVE_TASK.get(&tid) } {
                        if task_ptr != 0
                            && ownership::task_ctx_contains_tool(task_ptr, pending_tool_id)
                        {
                            return Ok(());
                        }
                    }
                    ownership::frame_stash_push(tid, frame_ptr);
                    start_cached_self_tool_root(
                        tid,
                        frame_ptr,
                        parent_ptr,
                        pending_tool_id,
                        TOOL_CTX_FLAG_ASYNC_FRAME,
                    )?;
                    return Ok(());
                }
            }
        }
    }

    // Async coroutine frames can re-enter _PyEval_EvalFrameDefault on resume.
    // Reuse the existing tool ctx and refresh its parent pointer so the final
    // end probe can close the original logical invocation without emitting a
    // duplicate TOOL_START.
    if let Some(&ctx_id) = unsafe { FRAME_CTX.get(&py_object_key(frame_ptr)) } {
        let tool = unsafe { TOOL_CTX.get(&ctx_id).copied() };
        let tool_id = tool.map(|c| c.tool_id).unwrap_or(TOOL_IDLE);
        let flags = tool.map(|c| c.flags).unwrap_or(0);
        if flags & TOOL_CTX_FLAG_PENDING_START != 0 {
            if let Some(entry) = unsafe { TOOL_CTX.get_ptr_mut(&ctx_id) } {
                unsafe { (*entry).flags &= !TOOL_CTX_FLAG_PENDING_START };
            }
            if ownership::ctx_stack_push(tid, ctx_id).is_err() {
                let _ = unsafe { FRAME_CTX.remove(&py_object_key(frame_ptr)) };
                let _ = unsafe { TOOL_CTX.remove(&ctx_id) };
                return Ok(());
            }
            ownership::tool_stack_push(tid, ctx_id, frame_ptr, parent_ptr, tool_id);
            ownership::emit_py_event(EVENT_TOOL_START, ctx_id, tool_id);
            if let Some(&task_ptr) = unsafe { THREAD_ACTIVE_TASK.get(&tid) } {
                if task_ptr != 0 {
                    let _ = ownership::task_ctx_push(tid, task_ptr, ctx_id, tool_id);
                }
            }
            return Ok(());
        }
        let current_tool_id = unsafe { tool_identity::cached_frame_self_tool_id(frame_ptr) };
        if current_tool_id != TOOL_IDLE && current_tool_id != tool_id {
            if let Some(entry) = ownership::tool_stack_remove_frame_ctx(tid, frame_ptr, ctx_id) {
                close_tool_stack_entry(tid, entry)?;
            } else {
                let _ = unsafe { FRAME_CTX.remove(&py_object_key(frame_ptr)) };
                ownership::ctx_stack_remove(tid, ctx_id);
                ownership::emit_py_event(EVENT_TOOL_FRAME_END, ctx_id, tool_id);
                ownership::ctx_carrier_dec(ctx_id);
            }
        } else {
            ownership::tool_stack_refresh(tid, ctx_id, frame_ptr, parent_ptr, tool_id);
            let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &ctx_id, 0) };
            if let Some(&task_ptr) = unsafe { THREAD_ACTIVE_TASK.get(&tid) } {
                if task_ptr != 0 {
                    ownership::cancel_deferred_tool_close(task_ptr, ctx_id, frame_ptr);
                    let _ = ownership::task_ctx_push(tid, task_ptr, ctx_id, tool_id);
                }
            }
            return Ok(());
        }
    }

    ownership::frame_stash_push(tid, frame_ptr);

    match kind {
        CODE_KIND_TOOL_ROOT_LC => {
            info!(ctx, "frame_entry: TOOL_ROOT kind={} pid={}", kind, pid);

            let tool_flags = if co_flags & CO_FLAGS_GENERATOR_MASK != 0 {
                TOOL_CTX_FLAG_ASYNC_FRAME
            } else {
                0
            };

            let ctx_id = ownership::alloc_ctx_id().ok_or(1i64)?;
            let tool_ctx = ToolCtx {
                tool_id: TOOL_IDLE,
                generation: 0,
                carrier_count: 1,
                flags: tool_flags,
                started_ns: unsafe { bpf_ktime_get_ns() },
                last_seen_ns: 0,
            };
            let _ = unsafe { TOOL_CTX.insert(&ctx_id, &tool_ctx, 0) };
            let _ = unsafe { FRAME_CTX.insert(&py_object_key(frame_ptr), &ctx_id, 0) };

            if ownership::ctx_stack_push(tid, ctx_id).is_err() {
                let _ = unsafe { FRAME_CTX.remove(&py_object_key(frame_ptr)) };
                let _ = unsafe { TOOL_CTX.remove(&ctx_id) };
                return Ok(());
            }

            let resolved_id = match find_root_rule(kind) {
                Some(rule) => unsafe {
                    tool_identity::extract_and_resolve(frame_ptr, code_ptr, rule, ctx_id)
                },
                None => TOOL_IDLE,
            };
            let current_tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
                .map(|tool| tool.tool_id)
                .unwrap_or(resolved_id);

            if current_tool_id != TOOL_IDLE {
                if co_flags & CO_FLAGS_GENERATOR_MASK != 0 {
                    if let Some(active_ctx) = ownership::get_active_ctx(tid) {
                        let active = unsafe { TOOL_CTX.get(&active_ctx).copied() };
                        let active_tool_id = active.map(|tool| tool.tool_id).unwrap_or(TOOL_IDLE);
                        let active_flags = active.map(|tool| tool.flags).unwrap_or(0);
                        if active_ctx != ctx_id
                            && active_tool_id != TOOL_IDLE
                            && active_tool_id != current_tool_id
                            && active_flags & TOOL_CTX_FLAG_ASYNC_FRAME != 0
                            && unsafe {
                                PENDING_FRAME_TOOL.get(&py_object_key(frame_ptr)).is_none()
                            }
                        {
                            let _ = ownership::ctx_stack_remove(tid, ctx_id);
                            let _ = unsafe { FRAME_CTX.remove(&py_object_key(frame_ptr)) };
                            let _ = unsafe { TOOL_CTX.remove(&ctx_id) };
                            return Ok(());
                        }
                    }
                }
                if let Some(&task_ptr) = unsafe { THREAD_ACTIVE_TASK.get(&tid) } {
                    if task_ptr != 0 && ownership::task_ctx_contains_tool(task_ptr, current_tool_id)
                    {
                        let _ = ownership::ctx_stack_remove(tid, ctx_id);
                        let _ = unsafe { FRAME_CTX.remove(&py_object_key(frame_ptr)) };
                        let _ = unsafe { TOOL_CTX.remove(&ctx_id) };
                        return Ok(());
                    }
                }
                if let Some(active_ctx) = ownership::get_active_ctx(tid) {
                    let active_tool_id = unsafe { TOOL_CTX.get(&active_ctx) }
                        .map(|tool| tool.tool_id)
                        .unwrap_or(TOOL_IDLE);
                    if active_ctx != ctx_id && active_tool_id == current_tool_id {
                        let _ = ownership::ctx_stack_remove(tid, ctx_id);
                        let _ = unsafe { FRAME_CTX.remove(&py_object_key(frame_ptr)) };
                        let _ = unsafe { TOOL_CTX.remove(&ctx_id) };
                        return Ok(());
                    }
                }
            }

            // Parent-frame keyed TOOL stack — used by end probes to fire
            // TOOL_END without depending on per-Python-frame push/pop balance.
            ownership::tool_stack_push(tid, ctx_id, frame_ptr, parent_ptr, current_tool_id);
            ownership::emit_py_event(EVENT_TOOL_START, ctx_id, current_tool_id);

            if let Some(&task_ptr) = unsafe { THREAD_ACTIVE_TASK.get(&tid) } {
                if task_ptr != 0 {
                    let _ = ownership::task_ctx_push(tid, task_ptr, ctx_id, current_tool_id);
                }
            }
        }
        CODE_KIND_TOOL_ROOT_LG => {
            info!(ctx, "frame_entry: TOOL_ROOT_LG pid={}", pid);

            let ctx_id = ownership::alloc_ctx_id().ok_or(1i64)?;
            let tool_ctx = ToolCtx {
                tool_id: TOOL_IDLE,
                generation: 0,
                carrier_count: 1,
                flags: if co_flags & CO_FLAGS_GENERATOR_MASK != 0 {
                    TOOL_CTX_FLAG_ASYNC_FRAME
                } else {
                    0
                },
                started_ns: unsafe { bpf_ktime_get_ns() },
                last_seen_ns: 0,
            };
            let _ = unsafe { TOOL_CTX.insert(&ctx_id, &tool_ctx, 0) };
            let _ = unsafe { FRAME_CTX.insert(&py_object_key(frame_ptr), &ctx_id, 0) };

            if ownership::ctx_stack_push(tid, ctx_id).is_err() {
                let _ = unsafe { FRAME_CTX.remove(&py_object_key(frame_ptr)) };
                let _ = unsafe { TOOL_CTX.remove(&ctx_id) };
                return Ok(());
            }
            ownership::emit_py_event(EVENT_TOOL_START, ctx_id, TOOL_IDLE);
        }
        CODE_KIND_TOOL_ID_RULE => {
            if let Some(active_ctx) = ownership::get_active_ctx(tid) {
                if let Some(rule) = find_root_rule(kind) {
                    unsafe {
                        tool_identity::extract_and_resolve(frame_ptr, code_ptr, rule, active_ctx)
                    };
                }
            }
        }
        _ => {
            return Ok(());
        }
    }

    Ok(())
}

#[inline(always)]
pub fn handle_frame_entry(ctx: &ProbeContext) -> Result<(), i64> {
    let frame_ptr = unsafe { read_frame_from_ctx(ctx) }.ok_or(1i64)?;
    handle_tool_frame_entry_for_ptr_inner(ctx, frame_ptr, true)
}

#[inline(always)]
pub fn handle_frame_resume(ctx: &ProbeContext) -> Result<(), i64> {
    let frame_ptr = unsafe { read_frame_from_ctx(ctx) }.ok_or(1i64)?;
    handle_tool_frame_entry_for_ptr_inner(ctx, frame_ptr, false)
}

#[inline(always)]
pub fn handle_frame_func_entry(ctx: &ProbeContext) -> Result<(), i64> {
    let frame_ptr: u64 = ctx.arg(1).ok_or(1i64)?;
    handle_tool_frame_entry_for_ptr_inner(ctx, frame_ptr, true)
}

/// Called from all 3 interior end probes (RETURN_VALUE, RETURN_CONST,
/// exception unwind). The dying frame's pointer is unrecoverable
/// (already freed by `_PyEvalFrameClearAndPop`); LIFO order from
/// the frame stash is the source of truth.
/// Read the aarch64 register at index `reg_idx` from the probe context.
/// Used by end probes to recover the parent frame_ptr (the new current
/// frame after `_PyEvalFrameClearAndPop` returns).
#[inline(always)]
unsafe fn read_register(ctx: &ProbeContext, reg_idx: u32) -> Option<u64> {
    if reg_idx > 30 {
        return None;
    }
    let ctx_base = ctx.as_ptr() as u64;
    let reg_addr = ctx_base + (reg_idx as u64) * 8;
    bpf_probe_read_kernel(reg_addr as *const u64).ok()
}

#[inline(always)]
fn close_tool_stack_entry(tid: u32, entry: ToolStackEntry) -> Result<(), i64> {
    match unsafe { FRAME_CTX.get(&py_object_key(entry.frame_ptr)) } {
        Some(&ctx_id) if ctx_id == entry.ctx_id => {}
        _ => return Ok(()),
    }

    if let Some(&task_ptr) = unsafe { THREAD_ACTIVE_TASK.get(&tid) } {
        if task_ptr != 0 {
            let flags = unsafe { TOOL_CTX.get(&entry.ctx_id) }
                .map(|ctx| ctx.flags)
                .unwrap_or(0);
            if flags & TOOL_CTX_FLAG_ASYNC_FRAME != 0 && entry.tool_id != TOOL_IDLE {
                ownership::defer_tool_close(task_ptr, entry);
                ownership::task_ctx_remove(tid, task_ptr, entry.ctx_id);
                return Ok(());
            }
            ownership::task_ctx_remove(tid, task_ptr, entry.ctx_id);
        }
    }

    ownership::finish_tool_close(tid, entry);
    Ok(())
}

/// Called from RV/RC end probes (frame_reg_idx = OFF_FRAME_REG_IDX).
/// At probe time, this register holds the *parent* of the just-completed
/// frame.
#[inline(always)]
pub fn handle_frame_exit_normal(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tid = pid_tgid as u32;
    let reg_idx = unsafe { *PYTHON_OFFSETS.get(OFF_FRAME_REG_IDX).ok_or(1i64)? };
    let parent_ptr = unsafe { read_register(ctx, reg_idx) }.unwrap_or(0);
    if parent_ptr != 0 {
        if worker_probes::dispatch_exit_for_parent(tid, parent_ptr) {
            return Ok(());
        }
        if let Some(frame_ptr) = ownership::frame_stash_peek(tid) {
            if let Some(entry) =
                ownership::tool_stack_pop_if_frame_parent(tid, frame_ptr, parent_ptr)
            {
                let _ = ownership::frame_stash_pop(tid);
                close_tool_stack_entry(tid, entry)?;
                return Ok(());
            }
        }
    }
    handle_frame_exit_legacy(tid)
}

/// Called from EXC end probe (different aarch64 register holds the
/// parent frame).
#[inline(always)]
pub fn handle_frame_exit_exception(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tid = pid_tgid as u32;
    let reg_idx = unsafe {
        *PYTHON_OFFSETS
            .get(OFF_EXCEPTION_FRAME_REG_IDX)
            .ok_or(1i64)?
    };
    let parent_ptr = unsafe { read_register(ctx, reg_idx) }.unwrap_or(0);
    if parent_ptr != 0 {
        if worker_probes::dispatch_exit_for_parent(tid, parent_ptr) {
            return Ok(());
        }
        if let Some(frame_ptr) = ownership::frame_stash_peek(tid) {
            if let Some(entry) =
                ownership::tool_stack_pop_if_frame_parent(tid, frame_ptr, parent_ptr)
            {
                let _ = ownership::frame_stash_pop(tid);
                close_tool_stack_entry(tid, entry)?;
                return Ok(());
            }
        }
    }
    handle_frame_exit_legacy(tid)
}

#[inline(always)]
fn handle_frame_exit_legacy(tid: u32) -> Result<(), i64> {
    let frame_ptr = match ownership::frame_stash_pop(tid) {
        Some(fp) => fp,
        None => return Ok(()),
    };

    let ctx_id = match unsafe { FRAME_CTX.get(&py_object_key(frame_ptr)) } {
        Some(&cid) => cid,
        None => {
            return Ok(());
        }
    };

    if let Some(tool_ctx) = unsafe { TOOL_CTX.get(&ctx_id) } {
        if tool_ctx.flags & TOOL_CTX_FLAG_PENDING_START != 0 {
            let _ = unsafe { FRAME_CTX.remove(&py_object_key(frame_ptr)) };
            let _ = unsafe { TOOL_CTX.remove(&ctx_id) };
            return Ok(());
        }
        if tool_ctx.last_seen_ns == 0 {
            ownership::frame_stash_push(tid, frame_ptr);
            return Ok(());
        }
    }

    if let Some(entry) = ownership::tool_stack_remove_frame_ctx(tid, frame_ptr, ctx_id) {
        close_tool_stack_entry(tid, entry)?;
        return Ok(());
    }

    let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
        .map(|c| c.tool_id)
        .unwrap_or(TOOL_IDLE);

    let _ = unsafe { FRAME_CTX.remove(&py_object_key(frame_ptr)) };
    ownership::ctx_stack_remove(tid, ctx_id);
    ownership::emit_py_event(EVENT_TOOL_FRAME_END, ctx_id, tool_id);
    ownership::ctx_carrier_dec(ctx_id);

    Ok(())
}
