use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_ktime_get_ns};

use crate::lifecycle;
use crate::maps::*;
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
fn task_stack_key(task_ptr: u64, depth: u32) -> TaskStackKey {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    TaskStackKey {
        tgid: (pid_tgid >> 32) as u32,
        depth,
        task_ptr,
    }
}

#[inline(always)]
pub fn alloc_ctx_id() -> Option<u64> {
    let cpu = unsafe { bpf_get_smp_processor_id() };
    let counter_ptr = unsafe { CTX_COUNTER.get_ptr_mut(0)? };
    let mut val = unsafe { *counter_ptr };
    if val == 0 {
        val = 1;
    }
    unsafe { *counter_ptr = val + 1 };
    Some(((cpu as u64) << 56) | val)
}

#[inline(always)]
pub fn ctx_is_live(ctx_id: u64) -> bool {
    unsafe { TOOL_CTX.get(&ctx_id).is_some() }
}

#[inline(always)]
pub fn get_active_ctx(tid: u32) -> Option<u64> {
    match unsafe { THREAD_ACTIVE_CTX.get(&tid).copied() } {
        Some(ctx_id) if ctx_is_live(ctx_id) => Some(ctx_id),
        Some(_) => {
            let _ = unsafe { THREAD_ACTIVE_CTX.remove(&tid) };
            None
        }
        None => None,
    }
}

#[inline(always)]
pub fn ctx_stack_top(tid: u32) -> Option<u64> {
    let depth = unsafe { THREAD_CTX_DEPTH.get(&tid).copied() }?;
    if depth == 0 {
        return None;
    }
    let key = ((tid as u64) << 8) | ((depth - 1) as u64);
    match unsafe { THREAD_CTX_STACK.get(&key).copied() } {
        Some(ctx_id) if ctx_is_live(ctx_id) => Some(ctx_id),
        _ => None,
    }
}

#[inline(always)]
pub fn ctx_stack_contains(tid: u32, ctx_id: u64) -> bool {
    let depth = unsafe { THREAD_CTX_DEPTH.get(&tid).copied() }.unwrap_or(0);
    let mut i: u8 = 0;
    while i < 8 {
        if i >= depth {
            break;
        }
        let key = ((tid as u64) << 8) | (i as u64);
        if let Some(&current) = unsafe { THREAD_CTX_STACK.get(&key) } {
            if current == ctx_id && ctx_is_live(current) {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[inline(always)]
pub fn ctx_carrier_inc(ctx_id: u64) {
    lifecycle::carrier_inc(ctx_id);
}

#[inline(always)]
pub fn ctx_carrier_dec(ctx_id: u64) {
    lifecycle::carrier_dec(ctx_id);
}

#[inline(always)]
pub fn ctx_stack_push(tid: u32, ctx_id: u64) -> Result<(), ()> {
    let depth = unsafe { THREAD_CTX_DEPTH.get(&tid).copied() }.unwrap_or(0);
    if depth >= MAX_CTX_STACK_DEPTH {
        emit_py_event_aux(EVENT_AUDIT_STACK_OVERFLOW, ctx_id, 0, depth as u64);
        return Err(());
    }
    let key = ((tid as u64) << 8) | (depth as u64);
    let _ = unsafe { THREAD_CTX_STACK.insert(&key, &ctx_id, 0) };
    let new_depth = depth + 1;
    let _ = unsafe { THREAD_CTX_DEPTH.insert(&tid, &new_depth, 0) };
    let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &ctx_id, 0) };
    Ok(())
}

#[inline(always)]
pub fn ctx_stack_remove(tid: u32, ctx_id: u64) -> Option<u64> {
    let depth_raw = unsafe { THREAD_CTX_DEPTH.get(&tid).copied() }?;
    let depth = depth_raw as u32;
    if depth == 0 {
        return None;
    }

    let mut found_idx: i32 = -1;
    let mut i: u32 = 0;
    while i < 8 {
        if i >= depth {
            break;
        }
        let key = ((tid as u64) << 8) | (i as u64);
        if let Some(&current) = unsafe { THREAD_CTX_STACK.get(&key) } {
            if current == ctx_id {
                found_idx = i as i32;
                break;
            }
        }
        i += 1;
    }

    if found_idx < 0 {
        return ctx_stack_top(tid);
    }

    let fi = found_idx as u32;
    let _ = unsafe { THREAD_CTX_STACK.remove(&(((tid as u64) << 8) | (fi as u64))) };

    let mut j: u32 = 0;
    while j < 7 {
        let src_idx = fi + 1 + j;
        if src_idx >= depth {
            break;
        }
        let src_key = ((tid as u64) << 8) | (src_idx as u64);
        let dst_key = ((tid as u64) << 8) | ((src_idx - 1) as u64);
        if let Some(v) = unsafe { THREAD_CTX_STACK.get(&src_key).copied() } {
            let _ = unsafe { THREAD_CTX_STACK.insert(&dst_key, &v, 0) };
            let _ = unsafe { THREAD_CTX_STACK.remove(&src_key) };
        } else {
            break;
        }
        j += 1;
    }

    let new_depth = depth - 1;
    if new_depth == 0 {
        let _ = unsafe { THREAD_CTX_DEPTH.remove(&tid) };
        let _ = unsafe { THREAD_ACTIVE_CTX.remove(&tid) };
        return None;
    }

    let new_depth_raw = new_depth as u8;
    let _ = unsafe { THREAD_CTX_DEPTH.insert(&tid, &new_depth_raw, 0) };
    let parent_key = ((tid as u64) << 8) | ((new_depth - 1) as u64);
    let parent_ctx = unsafe { THREAD_CTX_STACK.get(&parent_key).copied() };
    if let Some(pctx) = parent_ctx {
        let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &pctx, 0) };
    } else {
        let _ = unsafe { THREAD_ACTIVE_CTX.remove(&tid) };
    }
    parent_ctx
}

#[inline(always)]
pub fn task_ctx_current(task_ptr: u64) -> Option<u64> {
    unsafe { TASK_CTX.get(&py_object_key(task_ptr)).copied() }
}

#[inline(always)]
pub fn task_ctx_depth_for(task_ptr: u64) -> u32 {
    unsafe { TASK_CTX_DEPTH.get(&py_object_key(task_ptr)).copied() }.unwrap_or(0)
}

#[inline(always)]
pub fn task_ctx_contains_tool(task_ptr: u64, tool_id: u32) -> bool {
    if tool_id == TOOL_IDLE {
        return false;
    }

    let task_key = py_object_key(task_ptr);
    let depth = unsafe { TASK_CTX_DEPTH.get(&task_key).copied() }.unwrap_or(0);
    let mut i: u32 = 0;
    while i < 8 {
        if i >= depth {
            break;
        }
        let key = task_stack_key(task_ptr, i);
        if let Some(&ctx_id) = unsafe { TASK_CTX_STACK.get(&key) } {
            if let Some(ctx) = unsafe { TOOL_CTX.get(&ctx_id) } {
                if ctx.tool_id == tool_id && ctx_is_live(ctx_id) {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

#[inline(always)]
pub fn task_ctx_push(tid: u32, task_ptr: u64, ctx_id: u64, tool_id: u32) -> Result<(), ()> {
    let task_key = py_object_key(task_ptr);
    if let Some(&current) = unsafe { TASK_CTX.get(&task_key) } {
        if current == ctx_id {
            let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &ctx_id, 0) };
            return Ok(());
        }
    }

    let depth = unsafe { TASK_CTX_DEPTH.get(&task_key).copied() }.unwrap_or(0);
    if depth >= MAX_CTX_STACK_DEPTH as u32 {
        emit_py_event_aux(EVENT_AUDIT_STACK_OVERFLOW, ctx_id, tool_id, depth as u64);
        return Err(());
    }

    let stack_key = task_stack_key(task_ptr, depth);
    let _ = unsafe { TASK_CTX_STACK.insert(&stack_key, &ctx_id, 0) };
    let new_depth = depth + 1;
    let _ = unsafe { TASK_CTX_DEPTH.insert(&task_key, &new_depth, 0) };
    let _ = unsafe { TASK_CTX.insert(&task_key, &ctx_id, 0) };
    let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &ctx_id, 0) };
    ctx_carrier_inc(ctx_id);
    emit_py_event_carrier(EVENT_TASK_BIND, ctx_id, tool_id, task_ptr);
    Ok(())
}

#[inline(always)]
pub fn task_ctx_remove(tid: u32, task_ptr: u64, expected_ctx: u64) -> Option<u64> {
    let task_key = py_object_key(task_ptr);
    let depth = unsafe { TASK_CTX_DEPTH.get(&task_key).copied() }?;
    if depth == 0 {
        return None;
    }

    let mut found_idx: i32 = -1;
    let mut i: u32 = 0;
    while i < 8 {
        if i >= depth {
            break;
        }
        let key = task_stack_key(task_ptr, i);
        if let Some(&ctx_id) = unsafe { TASK_CTX_STACK.get(&key) } {
            if ctx_id == expected_ctx {
                found_idx = i as i32;
                break;
            }
        }
        i += 1;
    }

    if found_idx < 0 {
        return unsafe { TASK_CTX.get(&task_key).copied() };
    }

    let fi = found_idx as u32;
    let remove_key = task_stack_key(task_ptr, fi);
    let tool_id = unsafe { TOOL_CTX.get(&expected_ctx) }
        .map(|c| c.tool_id)
        .unwrap_or(TOOL_IDLE);
    emit_py_event_carrier(EVENT_TASK_UNBIND, expected_ctx, tool_id, task_ptr);
    let _ = unsafe { TASK_CTX_STACK.remove(&remove_key) };
    ctx_carrier_dec(expected_ctx);

    let mut j: u32 = 0;
    while j < 7 {
        let src_idx = fi + 1 + j;
        if src_idx >= depth {
            break;
        }
        let src_key = task_stack_key(task_ptr, src_idx);
        let dst_key = task_stack_key(task_ptr, src_idx - 1);
        if let Some(ctx_id) = unsafe { TASK_CTX_STACK.get(&src_key).copied() } {
            let _ = unsafe { TASK_CTX_STACK.insert(&dst_key, &ctx_id, 0) };
            let _ = unsafe { TASK_CTX_STACK.remove(&src_key) };
        } else {
            break;
        }
        j += 1;
    }

    let new_depth = depth - 1;
    if new_depth == 0 {
        let _ = unsafe { TASK_CTX_DEPTH.remove(&task_key) };
        let _ = unsafe { TASK_CTX.remove(&task_key) };
        let _ = unsafe { THREAD_ACTIVE_CTX.remove(&tid) };
        return None;
    }

    let _ = unsafe { TASK_CTX_DEPTH.insert(&task_key, &new_depth, 0) };
    let top_key = task_stack_key(task_ptr, new_depth - 1);
    if let Some(parent_ctx) = unsafe { TASK_CTX_STACK.get(&top_key).copied() } {
        let _ = unsafe { TASK_CTX.insert(&task_key, &parent_ctx, 0) };
        let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &parent_ctx, 0) };
        return Some(parent_ctx);
    }

    let _ = unsafe { TASK_CTX.remove(&task_key) };
    let _ = unsafe { THREAD_ACTIVE_CTX.remove(&tid) };
    None
}

#[inline(always)]
pub fn task_ctx_clear(tid: u32, task_ptr: u64) {
    let task_key = py_object_key(task_ptr);
    let depth = unsafe { TASK_CTX_DEPTH.get(&task_key).copied() }.unwrap_or(0);
    let mut i: u32 = 0;
    while i < 8 {
        if i >= depth {
            break;
        }
        let idx = depth - 1 - i;
        let stack_key = task_stack_key(task_ptr, idx);
        if let Some(ctx_id) = unsafe { TASK_CTX_STACK.get(&stack_key).copied() } {
            let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
                .map(|c| c.tool_id)
                .unwrap_or(TOOL_IDLE);
            emit_py_event_carrier(EVENT_TASK_UNBIND, ctx_id, tool_id, task_ptr);
            finish_deferred_tool_close_at_depth(tid, task_ptr, idx, ctx_id);
            if let Some(entry) = tool_stack_remove_ctx(tid, ctx_id) {
                finish_tool_close(tid, entry);
            }
            ctx_carrier_dec(ctx_id);
        }
        let _ = unsafe { TASK_CTX_STACK.remove(&stack_key) };
        let pending_key = task_stack_key(task_ptr, idx);
        let _ = unsafe { PENDING_TOOL_CLOSE.remove(&pending_key) };
        i += 1;
    }
    let mut pending_i: u32 = 0;
    while pending_i < 8 {
        let pending_key = task_stack_key(task_ptr, pending_i);
        if let Some(entry) = unsafe { PENDING_TOOL_CLOSE.get(&pending_key).copied() } {
            let _ = unsafe { PENDING_TOOL_CLOSE.remove(&pending_key) };
            finish_tool_close(tid, entry);
        }
        pending_i += 1;
    }
    let _ = unsafe { TASK_CTX_DEPTH.remove(&task_key) };
    let _ = unsafe { TASK_CTX.remove(&task_key) };
}

/// Push a TOOL_ROOT frame entry keyed by its parent frame_ptr.
/// At end-probe time, the appropriate aarch64 register holds this same
/// parent frame_ptr; matching the top of the stack against it tells us
/// whether the just-completed frame was our TOOL_ROOT.
#[inline(always)]
pub fn tool_stack_push(tid: u32, ctx_id: u64, frame_ptr: u64, parent_ptr: u64, tool_id: u32) {
    let depth = unsafe { TOOL_STACK_DEPTH.get(&tid).copied() }.unwrap_or(0);
    if depth as usize >= MAX_CTX_STACK_DEPTH as usize {
        return;
    }
    let key = ((tid as u64) << 32) | (depth as u64);
    let entry = ToolStackEntry {
        ctx_id,
        frame_ptr,
        parent_ptr,
        tool_id,
        _pad: 0,
    };
    let _ = unsafe { TOOL_STACK.insert(&key, &entry, 0) };
    let new_depth = depth + 1;
    let _ = unsafe { TOOL_STACK_DEPTH.insert(&tid, &new_depth, 0) };
}

#[inline(always)]
pub fn tool_stack_refresh(tid: u32, ctx_id: u64, frame_ptr: u64, parent_ptr: u64, tool_id: u32) {
    let depth = unsafe { TOOL_STACK_DEPTH.get(&tid).copied() }.unwrap_or(0);
    let mut i: u32 = 0;
    while i < 8 {
        if i >= depth {
            break;
        }
        let key = ((tid as u64) << 32) | (i as u64);
        if let Some(entry) = unsafe { TOOL_STACK.get(&key).copied() } {
            if entry.frame_ptr == frame_ptr && entry.ctx_id == ctx_id {
                let refreshed = ToolStackEntry {
                    ctx_id,
                    frame_ptr,
                    parent_ptr,
                    tool_id,
                    _pad: 0,
                };
                let _ = unsafe { TOOL_STACK.insert(&key, &refreshed, 0) };
                return;
            }
        }
        i += 1;
    }
    tool_stack_push(tid, ctx_id, frame_ptr, parent_ptr, tool_id);
}
#[inline(always)]
pub fn tool_stack_remove_ctx(tid: u32, ctx_id: u64) -> Option<ToolStackEntry> {
    let depth = unsafe { TOOL_STACK_DEPTH.get(&tid).copied() }?;
    if depth == 0 {
        return None;
    }

    let mut found_idx: i32 = -1;
    let mut found_entry: Option<ToolStackEntry> = None;
    let mut i: u32 = 0;
    while i < 8 {
        if i >= depth {
            break;
        }
        let key = ((tid as u64) << 32) | (i as u64);
        if let Some(entry) = unsafe { TOOL_STACK.get(&key).copied() } {
            if entry.ctx_id == ctx_id {
                found_idx = i as i32;
                found_entry = Some(entry);
                break;
            }
        }
        i += 1;
    }

    let entry = found_entry?;
    let fi = found_idx as u32;
    let _ = unsafe { TOOL_STACK.remove(&(((tid as u64) << 32) | (fi as u64))) };

    let mut j: u32 = 0;
    while j < 7 {
        let src_idx = fi + 1 + j;
        if src_idx >= depth {
            break;
        }
        let src_key = ((tid as u64) << 32) | (src_idx as u64);
        let dst_key = ((tid as u64) << 32) | ((src_idx - 1) as u64);
        if let Some(v) = unsafe { TOOL_STACK.get(&src_key).copied() } {
            let _ = unsafe { TOOL_STACK.insert(&dst_key, &v, 0) };
            let _ = unsafe { TOOL_STACK.remove(&src_key) };
        } else {
            break;
        }
        j += 1;
    }

    let new_depth = depth - 1;
    if new_depth == 0 {
        let _ = unsafe { TOOL_STACK_DEPTH.remove(&tid) };
    } else {
        let _ = unsafe { TOOL_STACK_DEPTH.insert(&tid, &new_depth, 0) };
    }

    Some(entry)
}

#[inline(always)]
pub fn tool_stack_pop_if_frame_parent(
    tid: u32,
    frame_ptr: u64,
    parent_ptr: u64,
) -> Option<ToolStackEntry> {
    let depth = unsafe { TOOL_STACK_DEPTH.get(&tid).copied() }?;
    if depth == 0 {
        return None;
    }

    let mut found_idx: i32 = -1;
    let mut found_entry: Option<ToolStackEntry> = None;
    let mut i: u32 = 0;
    while i < 8 {
        if i >= depth {
            break;
        }
        let key = ((tid as u64) << 32) | (i as u64);
        if let Some(entry) = unsafe { TOOL_STACK.get(&key).copied() } {
            if entry.frame_ptr == frame_ptr && entry.parent_ptr == parent_ptr {
                found_idx = i as i32;
                found_entry = Some(entry);
                break;
            }
        }
        i += 1;
    }

    let entry = found_entry?;
    let fi = found_idx as u32;
    let _ = unsafe { TOOL_STACK.remove(&(((tid as u64) << 32) | (fi as u64))) };

    let mut j: u32 = 0;
    while j < 7 {
        let src_idx = fi + 1 + j;
        if src_idx >= depth {
            break;
        }
        let src_key = ((tid as u64) << 32) | (src_idx as u64);
        let dst_key = ((tid as u64) << 32) | ((src_idx - 1) as u64);
        if let Some(v) = unsafe { TOOL_STACK.get(&src_key).copied() } {
            let _ = unsafe { TOOL_STACK.insert(&dst_key, &v, 0) };
            let _ = unsafe { TOOL_STACK.remove(&src_key) };
        } else {
            break;
        }
        j += 1;
    }

    let new_depth = depth - 1;
    if new_depth == 0 {
        let _ = unsafe { TOOL_STACK_DEPTH.remove(&tid) };
    } else {
        let _ = unsafe { TOOL_STACK_DEPTH.insert(&tid, &new_depth, 0) };
    }

    Some(entry)
}

pub fn tool_stack_remove_frame_ctx(
    tid: u32,
    frame_ptr: u64,
    ctx_id: u64,
) -> Option<ToolStackEntry> {
    let depth = unsafe { TOOL_STACK_DEPTH.get(&tid).copied() }?;
    if depth == 0 {
        return None;
    }

    let mut found_idx: i32 = -1;
    let mut found_entry: Option<ToolStackEntry> = None;
    let mut i: u32 = 0;
    while i < 8 {
        if i >= depth {
            break;
        }
        let key = ((tid as u64) << 32) | (i as u64);
        if let Some(entry) = unsafe { TOOL_STACK.get(&key).copied() } {
            if entry.frame_ptr == frame_ptr && entry.ctx_id == ctx_id {
                found_idx = i as i32;
                found_entry = Some(entry);
                break;
            }
        }
        i += 1;
    }

    let entry = found_entry?;
    let fi = found_idx as u32;
    let _ = unsafe { TOOL_STACK.remove(&(((tid as u64) << 32) | (fi as u64))) };

    let mut j: u32 = 0;
    while j < 7 {
        let src_idx = fi + 1 + j;
        if src_idx >= depth {
            break;
        }
        let src_key = ((tid as u64) << 32) | (src_idx as u64);
        let dst_key = ((tid as u64) << 32) | ((src_idx - 1) as u64);
        if let Some(v) = unsafe { TOOL_STACK.get(&src_key).copied() } {
            let _ = unsafe { TOOL_STACK.insert(&dst_key, &v, 0) };
            let _ = unsafe { TOOL_STACK.remove(&src_key) };
        } else {
            break;
        }
        j += 1;
    }

    let new_depth = depth - 1;
    if new_depth == 0 {
        let _ = unsafe { TOOL_STACK_DEPTH.remove(&tid) };
    } else {
        let _ = unsafe { TOOL_STACK_DEPTH.insert(&tid, &new_depth, 0) };
    }

    Some(entry)
}

#[inline(always)]
pub fn defer_tool_close(task_ptr: u64, entry: ToolStackEntry) {
    if let Some(ctx) = unsafe { TOOL_CTX.get_ptr_mut(&entry.ctx_id) } {
        unsafe { (*ctx).last_seen_ns = bpf_ktime_get_ns() };
    }
    let task_key = py_object_key(task_ptr);
    let depth = unsafe { TASK_CTX_DEPTH.get(&task_key).copied() }.unwrap_or(1);
    let pending_depth = if depth == 0 { 0 } else { depth - 1 };
    let stack_key = task_stack_key(task_ptr, pending_depth);
    let _ = unsafe { PENDING_TOOL_CLOSE.insert(&stack_key, &entry, 0) };
}

#[inline(always)]
pub fn cancel_deferred_tool_close(task_ptr: u64, ctx_id: u64, frame_ptr: u64) {
    let task_key = py_object_key(task_ptr);
    let depth = unsafe { TASK_CTX_DEPTH.get(&task_key).copied() }.unwrap_or(0);
    let mut i: u32 = 0;
    while i < 8 {
        if i >= depth {
            break;
        }
        let stack_key = task_stack_key(task_ptr, i);
        if let Some(entry) = unsafe { PENDING_TOOL_CLOSE.get(&stack_key).copied() } {
            if entry.ctx_id == ctx_id && entry.frame_ptr == frame_ptr {
                let _ = unsafe { PENDING_TOOL_CLOSE.remove(&stack_key) };
                return;
            }
        }
        i += 1;
    }
}

#[inline(always)]
pub fn deferred_tool_ctx_for_worker(task_ptr: u64) -> Option<u64> {
    let mut i: u32 = 0;
    while i < MAX_TASK_CTX_STACK_DEPTH {
        let idx = MAX_TASK_CTX_STACK_DEPTH - 1 - i;
        let stack_key = task_stack_key(task_ptr, idx);
        if let Some(entry) = unsafe { PENDING_TOOL_CLOSE.get(&stack_key).copied() } {
            if ctx_is_live(entry.ctx_id) {
                return Some(entry.ctx_id);
            }
        }
        i += 1;
    }
    None
}

pub fn restore_deferred_tool_close(tid: u32, task_ptr: u64) -> Option<u64> {
    let mut i: u32 = 0;
    while i < 8 {
        let idx = 7 - i;
        let stack_key = task_stack_key(task_ptr, idx);
        if let Some(entry) = unsafe { PENDING_TOOL_CLOSE.get(&stack_key).copied() } {
            if !ctx_is_live(entry.ctx_id) {
                let _ = unsafe { PENDING_TOOL_CLOSE.remove(&stack_key) };
                return None;
            }
            let _ = unsafe { PENDING_TOOL_CLOSE.remove(&stack_key) };
            tool_stack_push(
                tid,
                entry.ctx_id,
                entry.frame_ptr,
                entry.parent_ptr,
                entry.tool_id,
            );
            if task_ctx_push(tid, task_ptr, entry.ctx_id, entry.tool_id).is_ok() {
                return Some(entry.ctx_id);
            }
            return None;
        }
        i += 1;
    }
    None
}

#[inline(always)]
pub fn finish_tool_close(tid: u32, entry: ToolStackEntry) -> bool {
    let frame_key = py_object_key(entry.frame_ptr);
    match unsafe { FRAME_CTX.get(&frame_key) } {
        Some(&ctx_id) if ctx_id == entry.ctx_id => {}
        _ => return false,
    }

    let _ = unsafe { FRAME_CTX.remove(&frame_key) };
    ctx_stack_remove(tid, entry.ctx_id);
    emit_py_event(EVENT_TOOL_FRAME_END, entry.ctx_id, entry.tool_id);
    ctx_carrier_dec(entry.ctx_id);
    true
}

#[inline(always)]
fn finish_deferred_tool_close_at_depth(tid: u32, task_ptr: u64, depth: u32, ctx_id: u64) {
    let stack_key = task_stack_key(task_ptr, depth);
    if let Some(entry) = unsafe { PENDING_TOOL_CLOSE.get(&stack_key).copied() } {
        if entry.ctx_id == ctx_id {
            let _ = unsafe { PENDING_TOOL_CLOSE.remove(&stack_key) };
            finish_tool_close(tid, entry);
        }
    }
}

#[inline(always)]
pub fn finish_deferred_tool_close(tid: u32, task_ptr: u64, ctx_id: u64) {
    let mut i: u32 = 0;
    while i < 8 {
        finish_deferred_tool_close_at_depth(tid, task_ptr, i, ctx_id);
        i += 1;
    }
}

#[inline(always)]
pub fn frame_stash_push(tid: u32, frame_ptr: u64) {
    let depth = unsafe { FRAME_STASH_DEPTH.get(&tid).copied() }.unwrap_or(0);
    let key = ((tid as u64) << 16) | (depth as u64);
    let _ = unsafe { FRAME_ENTRY_STASH.insert(&key, &frame_ptr, 0) };
    let new_depth = depth + 1;
    let _ = unsafe { FRAME_STASH_DEPTH.insert(&tid, &new_depth, 0) };
}

#[inline(always)]
pub fn frame_stash_pop(tid: u32) -> Option<u64> {
    let depth = unsafe { FRAME_STASH_DEPTH.get(&tid).copied() }?;
    if depth == 0 {
        return None;
    }
    let new_depth = depth - 1;
    let key = ((tid as u64) << 16) | (new_depth as u64);
    let val = unsafe { FRAME_ENTRY_STASH.get(&key).copied() };
    let _ = unsafe { FRAME_ENTRY_STASH.remove(&key) };
    if new_depth == 0 {
        let _ = unsafe { FRAME_STASH_DEPTH.remove(&tid) };
    } else {
        let _ = unsafe { FRAME_STASH_DEPTH.insert(&tid, &new_depth, 0) };
    }
    val
}

#[inline(always)]
pub fn frame_stash_peek(tid: u32) -> Option<u64> {
    let depth = unsafe { FRAME_STASH_DEPTH.get(&tid).copied() }?;
    if depth == 0 {
        return None;
    }
    let key = ((tid as u64) << 16) | ((depth - 1) as u64);
    unsafe { FRAME_ENTRY_STASH.get(&key).copied() }
}

#[inline(always)]
pub fn emit_py_event(kind: u8, ctx_id: u64, tool_id: u32) {
    let pid_tid = unsafe { bpf_get_current_pid_tgid() };
    if let Some(mut entry) = PY_EVENTS.reserve::<PyEvent>(0) {
        unsafe {
            (*entry.as_mut_ptr()) = PyEvent {
                pid: (pid_tid >> 32) as u32,
                tid: pid_tid as u32,
                ts_ns: bpf_ktime_get_ns(),
                kind,
                _pad: [0; 3],
                ctx_id,
                tool_id,
                _pad2: 0,
                carrier_ptr: 0,
                aux: 0,
            };
        }
        entry.submit(0);
    }
}

#[inline(always)]
pub fn emit_py_event_carrier(kind: u8, ctx_id: u64, tool_id: u32, carrier_ptr: u64) {
    let pid_tid = unsafe { bpf_get_current_pid_tgid() };
    if let Some(mut entry) = PY_EVENTS.reserve::<PyEvent>(0) {
        unsafe {
            (*entry.as_mut_ptr()) = PyEvent {
                pid: (pid_tid >> 32) as u32,
                tid: pid_tid as u32,
                ts_ns: bpf_ktime_get_ns(),
                kind,
                _pad: [0; 3],
                ctx_id,
                tool_id,
                _pad2: 0,
                carrier_ptr,
                aux: 0,
            };
        }
        entry.submit(0);
    }
}

#[inline(always)]
pub fn emit_py_event_carrier_for_tid(
    kind: u8,
    ctx_id: u64,
    tool_id: u32,
    carrier_ptr: u64,
    tid: u32,
) {
    let pid_tid = unsafe { bpf_get_current_pid_tgid() };
    if let Some(mut entry) = PY_EVENTS.reserve::<PyEvent>(0) {
        unsafe {
            (*entry.as_mut_ptr()) = PyEvent {
                pid: (pid_tid >> 32) as u32,
                tid,
                ts_ns: bpf_ktime_get_ns(),
                kind,
                _pad: [0; 3],
                ctx_id,
                tool_id,
                _pad2: 0,
                carrier_ptr,
                aux: 0,
            };
        }
        entry.submit(0);
    }
}

#[inline(always)]
pub fn emit_py_event_fork(kind: u8, ctx_id: u64, tool_id: u32, child_pid: u32) {
    let pid_tid = unsafe { bpf_get_current_pid_tgid() };
    if let Some(mut entry) = PY_EVENTS.reserve::<PyEvent>(0) {
        unsafe {
            (*entry.as_mut_ptr()) = PyEvent {
                pid: child_pid,
                tid: child_pid,
                ts_ns: bpf_ktime_get_ns(),
                kind,
                _pad: [0; 3],
                ctx_id,
                tool_id,
                _pad2: 0,
                carrier_ptr: 0,
                aux: 1,
            };
        }
        entry.submit(0);
    }
}

#[inline(always)]
pub fn emit_py_event_aux(kind: u8, ctx_id: u64, tool_id: u32, aux: u64) {
    let pid_tid = unsafe { bpf_get_current_pid_tgid() };
    if let Some(mut entry) = PY_EVENTS.reserve::<PyEvent>(0) {
        unsafe {
            (*entry.as_mut_ptr()) = PyEvent {
                pid: (pid_tid >> 32) as u32,
                tid: pid_tid as u32,
                ts_ns: bpf_ktime_get_ns(),
                kind,
                _pad: [0; 3],
                ctx_id,
                tool_id,
                _pad2: 0,
                carrier_ptr: 0,
                aux,
            };
        }
        entry.submit(0);
    }
}
