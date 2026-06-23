use aya_ebpf::helpers::bpf_get_current_pid_tgid;

use crate::maps::*;
use crate::ownership;
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
fn pending_tool_resolve_key(tgid: u32, self_ptr: u64) -> PendingToolResolveKey {
    PendingToolResolveKey {
        tgid,
        _pad: 0,
        self_ptr,
    }
}

#[inline(always)]
pub fn carrier_inc(ctx_id: u64) {
    if let Some(ctx) = unsafe { TOOL_CTX.get_ptr_mut(&ctx_id) } {
        unsafe { (*ctx).carrier_count += 1 };
    }
}

#[inline(always)]
pub fn carrier_dec(ctx_id: u64) {
    if let Some(ctx) = unsafe { TOOL_CTX.get_ptr_mut(&ctx_id) } {
        let count = unsafe { (*ctx).carrier_count };
        let tool_id = unsafe { (*ctx).tool_id };
        if count > 1 {
            unsafe {
                (*ctx).carrier_count = count - 1;
                (*ctx).generation += 1;
            };
        } else {
            unsafe { (*ctx).generation += 1 };
            ownership::emit_py_event(EVENT_TOOL_CONTEXT_END, ctx_id, tool_id);
            let _ = unsafe { TOOL_CTX.remove(&ctx_id) };
        }
    }
}

#[inline(always)]
pub fn handle_pyobj_dealloc(obj_ptr: u64) {
    if obj_ptr == 0 {
        return;
    }
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tgid = (pid_tgid >> 32) as u32;
    if unsafe { PROTECTED_TGIDS.get(&tgid).is_none() } {
        return;
    }

    let key = py_object_key(obj_ptr);
    let mut frame_ctx_key = key;
    let _ = unsafe { TOOL_OBJ.remove(&key) };
    let _ = unsafe { PENDING_FRAME_TOOL.remove(&key) };
    if let Some(&gi_iframe_off) = unsafe { PYTHON_OFFSETS.get(OFF_GEN_IFRAME) } {
        if gi_iframe_off != 0 {
            let frame_key = py_object_key(obj_ptr + gi_iframe_off as u64);
            let _ = unsafe { PENDING_FRAME_TOOL.remove(&frame_key) };
            if unsafe { FRAME_CTX.get(&frame_key).is_some() } {
                frame_ctx_key = frame_key;
            }
        }
    }
    let pending = pending_tool_resolve_key(tgid, obj_ptr);
    let _ = unsafe { PENDING_TOOL_RESOLVE.remove(&pending) };

    if let Some(&ctx_id) = unsafe { TASK_CTX.get(&key) } {
        let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
        let tid = pid_tgid as u32;
        let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
            .map(|c| c.tool_id)
            .unwrap_or(TOOL_IDLE);
        ownership::emit_py_event_carrier(EVENT_DEALLOC_CLEANUP, ctx_id, tool_id, obj_ptr);
        ownership::task_ctx_clear(tid, obj_ptr);
        return;
    }

    if let Some(&ctx_id) = unsafe { FRAME_CTX.get(&frame_ctx_key) } {
        let tool = unsafe { TOOL_CTX.get(&ctx_id).copied() };
        let tool_id = tool.map(|c| c.tool_id).unwrap_or(TOOL_IDLE);
        let flags = tool.map(|c| c.flags).unwrap_or(0);
        let _ = unsafe { FRAME_CTX.remove(&frame_ctx_key) };
        if flags & TOOL_CTX_FLAG_PENDING_START != 0 {
            let _ = unsafe { TOOL_CTX.remove(&ctx_id) };
            return;
        }
        let tid = pid_tgid as u32;
        let _ = ownership::tool_stack_remove_frame_ctx(tid, frame_ctx_key.ptr, ctx_id);
        ownership::ctx_stack_remove(tid, ctx_id);
        ownership::emit_py_event_carrier(EVENT_DEALLOC_CLEANUP, ctx_id, tool_id, obj_ptr);
        ownership::emit_py_event_aux(EVENT_TOOL_FRAME_END, ctx_id, tool_id, 1);
        carrier_dec(ctx_id);
        return;
    }

    worker_probes::clear_threadpool_worker_for_object(pid_tgid as u32, obj_ptr);

    if let Some(&ctx_id) = unsafe { WORKITEM_CTX.get(&key) } {
        let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
            .map(|c| c.tool_id)
            .unwrap_or(TOOL_IDLE);
        worker_probes::finalize_worker_run_for_object(obj_ptr, ctx_id, tool_id);
        ownership::emit_py_event_carrier(EVENT_WORKER_CARRIER_UNBIND, ctx_id, tool_id, obj_ptr);
        ownership::emit_py_event_carrier(EVENT_DEALLOC_CLEANUP, ctx_id, tool_id, obj_ptr);
        let _ = unsafe { WORKITEM_CTX.remove(&key) };
        carrier_dec(ctx_id);
        return;
    }

    if let Some(&ctx_id) = unsafe { PYTHREAD_OBJ_CTX.get(&key) } {
        let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
            .map(|c| c.tool_id)
            .unwrap_or(TOOL_IDLE);
        worker_probes::finalize_worker_run_for_object(obj_ptr, ctx_id, tool_id);
        ownership::emit_py_event_carrier(EVENT_WORKER_CARRIER_UNBIND, ctx_id, tool_id, obj_ptr);
        let _ = unsafe { PYTHREAD_OBJ_THREAD.remove(&key) };
        ownership::emit_py_event_carrier(EVENT_DEALLOC_CLEANUP, ctx_id, tool_id, obj_ptr);
        let _ = unsafe { PYTHREAD_OBJ_CTX.remove(&key) };
        carrier_dec(ctx_id);
        return;
    }
}

#[inline(always)]
pub fn reap_thread(tid: u32) {
    let depth = unsafe { THREAD_CTX_DEPTH.get(&tid).copied() }.unwrap_or(0);
    let mut i: u8 = 0;
    while i < depth && i < MAX_CTX_STACK_DEPTH {
        let key = ((tid as u64) << 8) | (i as u64);
        if let Some(&ctx_id) = unsafe { THREAD_CTX_STACK.get(&key) } {
            let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
                .map(|c| c.tool_id)
                .unwrap_or(TOOL_IDLE);
            ownership::emit_py_event_aux(EVENT_TOOL_FRAME_END, ctx_id, tool_id, 1);
            carrier_dec(ctx_id);
        }
        let _ = unsafe { THREAD_CTX_STACK.remove(&key) };
        i += 1;
    }
    let _ = unsafe { THREAD_CTX_DEPTH.remove(&tid) };

    if depth == 0 {
        if let Some(&ctx_id) = unsafe { FORK_CTX.get(&tid) } {
            let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
                .map(|c| c.tool_id)
                .unwrap_or(TOOL_IDLE);
            ownership::emit_py_event_fork(EVENT_CHILD_CTX_UNBIND, ctx_id, tool_id, tid);
            let _ = unsafe { FORK_CTX.remove(&tid) };
            carrier_dec(ctx_id);
        }
    }
    let _ = unsafe { THREAD_ACTIVE_CTX.remove(&tid) };

    let _ = unsafe { THREAD_ACTIVE_TASK.remove(&tid) };
    let _ = unsafe { PENDING_WORKER_SPAWN.remove(&tid) };
    worker_probes::clear_threadpool_worker_for_thread(tid);

    let frame_depth = unsafe { FRAME_STASH_DEPTH.get(&tid).copied() }.unwrap_or(0);
    let mut j: u32 = 0;
    while j < frame_depth && j < 256 {
        let key = ((tid as u64) << 16) | (j as u64);
        let _ = unsafe { FRAME_ENTRY_STASH.remove(&key) };
        j += 1;
    }
    let _ = unsafe { FRAME_STASH_DEPTH.remove(&tid) };

    worker_probes::clear_worker_runs_for_thread(tid);

    let _ = unsafe { TASK_STEP_STASH.remove(&tid) };
    let _ = unsafe { TASK_STEP_PREV_TASK.remove(&tid) };
}
