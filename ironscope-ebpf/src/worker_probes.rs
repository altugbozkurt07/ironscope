use crate::maps::*;
use crate::ownership;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user};
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::EbpfContext;
use ironscope_common::types::*;

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;
const MAX_HASH_BYTES: usize = 64;

#[inline(always)]
fn fnv1a_64(buf: &[u8; MAX_HASH_BYTES], len: usize) -> u64 {
    let mut hash = FNV_OFFSET;
    let mut i = 0usize;
    while i < MAX_HASH_BYTES {
        if i < len {
            hash ^= buf[i] as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        i += 1;
    }
    hash
}

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
fn read_frame_local(frame_ptr: u64, slot_index: u64) -> Option<u64> {
    let localsplus_off = unsafe { *PYTHON_OFFSETS.get(OFF_FRAME_LOCALSPLUS)? } as u64;
    let slot_addr = frame_ptr + localsplus_off + slot_index * 8;
    let obj_ptr: u64 = unsafe { bpf_probe_read_user(slot_addr as *const u64) }.ok()?;
    if obj_ptr == 0 {
        None
    } else {
        Some(obj_ptr)
    }
}

#[inline(always)]
fn read_self_from_frame(frame_ptr: u64) -> Option<u64> {
    read_frame_local(frame_ptr, 0)
}

#[inline(always)]
fn read_parent_ptr(frame_ptr: u64) -> u64 {
    let off_previous = match unsafe { PYTHON_OFFSETS.get(OFF_FRAME_PREVIOUS) } {
        Some(&off) => off as u64,
        None => return 0,
    };
    unsafe { bpf_probe_read_user((frame_ptr + off_previous) as *const u64) }.unwrap_or(0)
}

#[inline(always)]
unsafe fn worker_kind_for_frame(pid: u32, frame_ptr: u64) -> u8 {
    if frame_ptr == 0 {
        return CODE_KIND_IGNORE;
    }

    let off_exec = match PYTHON_OFFSETS.get(OFF_FRAME_F_EXECUTABLE) {
        Some(off) => *off as u64,
        None => return CODE_KIND_IGNORE,
    };
    let code_ptr: u64 = match bpf_probe_read_user((frame_ptr + off_exec) as *const u64) {
        Ok(ptr) => ptr,
        Err(_) => return CODE_KIND_IGNORE,
    };
    if code_ptr == 0 {
        return CODE_KIND_IGNORE;
    }

    let key = CodeKindKey {
        tgid: pid,
        _pad: 0,
        code_ptr,
    };
    match CODE_KIND.get(&key) {
        Some(&k) => k,
        None => {
            let detected = classify_worker_kind(code_ptr);
            if is_worker_kind(detected) {
                let _ = CODE_KIND.insert(&key, &detected, 0);
            }
            detected
        }
    }
}

#[inline(always)]
unsafe fn classify_worker_kind(code_ptr: u64) -> u8 {
    let off_qualname = match PYTHON_OFFSETS.get(OFF_CODE_QUALNAME) {
        Some(off) => *off as u64,
        None => return CODE_KIND_IGNORE,
    };
    let off_compact = match PYTHON_OFFSETS.get(OFF_UNICODE_COMPACT_DATA) {
        Some(off) => *off as u64,
        None => return CODE_KIND_IGNORE,
    };

    let qualname_ptr: u64 = match bpf_probe_read_user((code_ptr + off_qualname) as *const u64) {
        Ok(ptr) => ptr,
        Err(_) => return CODE_KIND_IGNORE,
    };
    if qualname_ptr == 0 {
        return CODE_KIND_IGNORE;
    }

    let scratch = match CLASSIFIER_SCRATCH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => return CODE_KIND_IGNORE,
    };
    let buf = &mut (*scratch).buf;
    let ret = aya_ebpf::helpers::gen::bpf_probe_read_user(
        buf.as_mut_ptr() as *mut core::ffi::c_void,
        64u32,
        (qualname_ptr + off_compact) as *const core::ffi::c_void,
    );
    if ret < 0 {
        return CODE_KIND_IGNORE;
    }

    let mut len = 0usize;
    while len < 64 {
        if buf[len] == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return CODE_KIND_IGNORE;
    }

    let hash = fnv1a_64(buf, len);
    let mut i = 0u32;
    while i < 64 {
        if let Some(rule) = ROOT_RULES.get(i) {
            if is_worker_kind(rule.kind) && rule.qualname_hash == hash {
                return rule.kind;
            }
        }
        i += 1;
    }

    CODE_KIND_IGNORE
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
fn remember_tstate(ctx: &ProbeContext, tid: u32, overwrite: bool) {
    if !overwrite && unsafe { THREAD_TSTATE.get(&tid).is_some() } {
        return;
    }
    let tstate: u64 = match ctx.arg(0) {
        Some(ptr) if ptr != 0 => ptr,
        _ => return,
    };
    let _ = unsafe { THREAD_TSTATE.insert(&tid, &tstate, 0) };
}

#[inline(always)]
fn read_tstate_current_frame(tid: u32) -> Option<u64> {
    let tstate = unsafe { THREAD_TSTATE.get(&tid).copied() }?;
    if tstate == 0 {
        return None;
    }
    let off = unsafe { PYTHON_OFFSETS.get(OFF_TSTATE_CURRENT_FRAME).copied() }? as u64;
    if off == 0 {
        return None;
    }
    let frame_ptr: u64 = unsafe { bpf_probe_read_user((tstate + off) as *const u64) }.ok()?;
    if frame_ptr == 0 {
        None
    } else {
        Some(frame_ptr)
    }
}

#[inline(always)]
fn is_worker_kind(kind: u8) -> bool {
    kind == CODE_KIND_WORKITEM_CTOR
        || kind == CODE_KIND_WORKITEM_RUN
        || kind == CODE_KIND_THREAD_CTOR
        || kind == CODE_KIND_THREAD_RUN
        || kind == CODE_KIND_THREADPOOL_WORKER
}

#[inline(always)]
fn handle_worker_frame_for_ptr(ctx: &ProbeContext, frame_ptr: u64) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    if unsafe { PROTECTED_TGIDS.get(&pid).is_none() } {
        return Ok(());
    }
    remember_tstate(ctx, tid, false);
    if frame_ptr == 0 {
        return Ok(());
    }

    let _ = unsafe { THREAD_CURRENT_FRAME.insert(&tid, &frame_ptr, 0) };
    let kind = unsafe { worker_kind_for_frame(pid, frame_ptr) };
    if !is_worker_kind(kind) {
        return Ok(());
    }

    dispatch_entry(kind, tid, frame_ptr);
    Ok(())
}

#[inline(always)]
pub fn handle_frame_entry(ctx: &ProbeContext) -> Result<(), i64> {
    let frame_ptr = unsafe { read_frame_from_ctx(ctx) }.ok_or(1i64)?;
    handle_worker_frame_for_ptr(ctx, frame_ptr)
}

#[inline(always)]
pub fn handle_frame_func_entry(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    remember_tstate(ctx, pid_tgid as u32, true);
    let frame_ptr: u64 = ctx.arg(1).ok_or(1i64)?;
    handle_worker_frame_for_ptr(ctx, frame_ptr)
}

#[inline(always)]
pub fn handle_frame_resume(ctx: &ProbeContext) -> Result<(), i64> {
    let frame_ptr = unsafe { read_frame_from_ctx(ctx) }.ok_or(1i64)?;
    handle_worker_frame_for_ptr(ctx, frame_ptr)
}

#[inline(always)]
fn worker_stack_push(tid: u32, entry: &WorkerRunEntry) {
    let depth = unsafe { WORKER_RUN_DEPTH.get(&tid).copied() }.unwrap_or(0);
    if depth >= 64 {
        return;
    }
    let key = ((tid as u64) << 8) | (depth as u64);
    let _ = unsafe { WORKER_RUN_STACK.insert(&key, entry, 0) };
    let new_depth = depth + 1;
    let _ = unsafe { WORKER_RUN_DEPTH.insert(&tid, &new_depth, 0) };
}

#[inline(always)]
fn worker_stack_peek(tid: u32) -> Option<WorkerRunEntry> {
    let depth = unsafe { WORKER_RUN_DEPTH.get(&tid).copied() }?;
    if depth == 0 {
        return None;
    }
    let key = ((tid as u64) << 8) | ((depth - 1) as u64);
    unsafe { WORKER_RUN_STACK.get(&key).copied() }
}
#[inline(always)]
fn worker_stack_remove_at(tid: u32, idx: u32, depth: u32) -> Option<WorkerRunEntry> {
    if idx >= depth || depth == 0 {
        return None;
    }

    let key = ((tid as u64) << 8) | (idx as u64);
    let val = unsafe { WORKER_RUN_STACK.get(&key).copied() };
    let _ = unsafe { WORKER_RUN_STACK.remove(&key) };

    let mut cur = idx;
    while cur < 63 {
        let next = cur + 1;
        if next >= depth {
            break;
        }
        let src_key = ((tid as u64) << 8) | (next as u64);
        let dst_key = ((tid as u64) << 8) | (cur as u64);
        if let Some(entry) = unsafe { WORKER_RUN_STACK.get(&src_key).copied() } {
            let _ = unsafe { WORKER_RUN_STACK.insert(&dst_key, &entry, 0) };
        }
        let _ = unsafe { WORKER_RUN_STACK.remove(&src_key) };
        cur += 1;
    }

    let new_depth = depth - 1;
    if new_depth == 0 {
        let _ = unsafe { WORKER_RUN_DEPTH.remove(&tid) };
    } else {
        let _ = unsafe { WORKER_RUN_DEPTH.insert(&tid, &new_depth, 0) };
    }
    val
}

#[inline(always)]
fn worker_stack_pop_for_parent(tid: u32, parent_ptr: u64) -> Option<WorkerRunEntry> {
    let depth = unsafe { WORKER_RUN_DEPTH.get(&tid).copied() }?;
    if depth == 0 {
        return None;
    }

    let top_idx = depth - 1;
    let top_key = ((tid as u64) << 8) | (top_idx as u64);
    if let Some(entry) = unsafe { WORKER_RUN_STACK.get(&top_key).copied() } {
        if entry.parent_ptr != 0 && entry.parent_ptr == parent_ptr {
            return worker_stack_remove_at(tid, top_idx, depth);
        }
    }

    if depth > 1 {
        let below_idx = depth - 2;
        let below_key = ((tid as u64) << 8) | (below_idx as u64);
        if let Some(entry) = unsafe { WORKER_RUN_STACK.get(&below_key).copied() } {
            if entry.parent_ptr != 0 && entry.parent_ptr == parent_ptr {
                return worker_stack_remove_at(tid, below_idx, depth);
            }
        }
    }

    None
}

#[inline(always)]
fn worker_stack_remove_for_object(tid: u32, self_obj: u64) -> Option<WorkerRunEntry> {
    let depth = unsafe { WORKER_RUN_DEPTH.get(&tid).copied() }?;
    if depth == 0 {
        return None;
    }

    let top_idx = depth - 1;
    let top_key = ((tid as u64) << 8) | (top_idx as u64);
    if let Some(entry) = unsafe { WORKER_RUN_STACK.get(&top_key).copied() } {
        if entry.self_obj == self_obj {
            return worker_stack_remove_at(tid, top_idx, depth);
        }
    }

    if depth > 1 {
        let below_idx = depth - 2;
        let below_key = ((tid as u64) << 8) | (below_idx as u64);
        if let Some(entry) = unsafe { WORKER_RUN_STACK.get(&below_key).copied() } {
            if entry.self_obj == self_obj {
                return worker_stack_remove_at(tid, below_idx, depth);
            }
        }
    }

    None
}

#[inline(always)]
pub fn dispatch_entry(kind: u8, tid: u32, frame_ptr: u64) {
    match kind {
        CODE_KIND_WORKITEM_CTOR => handle_ctor_entry(tid, frame_ptr, CODE_KIND_WORKITEM_CTOR),
        CODE_KIND_THREAD_CTOR => handle_ctor_entry(tid, frame_ptr, CODE_KIND_THREAD_CTOR),
        CODE_KIND_WORKITEM_RUN => handle_run_entry(tid, frame_ptr, CODE_KIND_WORKITEM_RUN),
        CODE_KIND_THREAD_RUN => handle_run_entry(tid, frame_ptr, CODE_KIND_THREAD_RUN),
        CODE_KIND_THREADPOOL_WORKER => handle_threadpool_worker_entry(tid, frame_ptr),
        _ => {}
    }
}

#[inline(always)]
fn handle_threadpool_worker_entry(tid: u32, frame_ptr: u64) {
    let _ = unsafe { THREADPOOL_WORKER_FRAME.insert(&tid, &frame_ptr, 0) };
}

#[inline(always)]
fn handle_ctor_entry(tid: u32, frame_ptr: u64, kind: u8) {
    let mut pending_task_ptr = 0u64;
    let mut ctx_id = 0u64;

    if kind == CODE_KIND_WORKITEM_CTOR {
        if let Some(&task_ptr) = unsafe { THREAD_ACTIVE_TASK.get(&tid) } {
            if task_ptr != 0 {
                if let Some(cid) = ownership::deferred_tool_ctx_for_worker(task_ptr) {
                    ctx_id = cid;
                    pending_task_ptr = task_ptr;
                }
            }
        }
    }

    if ctx_id == 0 {
        ctx_id = match ownership::get_active_ctx(tid) {
            Some(cid) => cid,
            None => return,
        };
    }

    // Skip if ctx is only from fork inheritance — no tool root frame
    // or worker run entry on this thread. Prevents spurious binds
    // when child processes create _MainThread during Python startup.
    let frame_depth = unsafe { THREAD_CTX_DEPTH.get(&tid).copied() }.unwrap_or(0);
    let worker_depth = unsafe { WORKER_RUN_DEPTH.get(&tid).copied() }.unwrap_or(0);
    if pending_task_ptr == 0 && frame_depth == 0 && worker_depth == 0 {
        return;
    }

    let self_obj = match read_self_from_frame(frame_ptr) {
        Some(obj) => obj,
        None => return,
    };

    let carrier_map = if kind == CODE_KIND_WORKITEM_CTOR {
        &WORKITEM_CTX
    } else {
        &PYTHREAD_OBJ_CTX
    };

    let self_key = py_object_key(self_obj);
    if let Some(&existing_ctx) = unsafe { carrier_map.get(&self_key) } {
        if existing_ctx == ctx_id {
            if pending_task_ptr != 0 {
                ownership::finish_deferred_tool_close(tid, pending_task_ptr, ctx_id);
            }
            return;
        }
        if pending_task_ptr == 0 {
            return;
        }
        ownership::ctx_carrier_dec(existing_ctx);
    }

    let _ = unsafe { carrier_map.insert(&self_key, &ctx_id, 0) };
    ownership::ctx_carrier_inc(ctx_id);

    if kind == CODE_KIND_WORKITEM_CTOR && pending_task_ptr != 0 {
        let pending = PendingWorkerSpawn {
            ctx_id,
            work_item: self_obj,
        };
        let _ = unsafe { PENDING_WORKER_SPAWN.insert(&tid, &pending, 0) };
    }

    let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
        .map(|c| c.tool_id)
        .unwrap_or(TOOL_IDLE);
    ownership::emit_py_event_carrier(EVENT_WORKER_CARRIER_BIND, ctx_id, tool_id, self_obj);

    if pending_task_ptr != 0 {
        ownership::finish_deferred_tool_close(tid, pending_task_ptr, ctx_id);
    }
}

#[inline(always)]
fn clear_threadpool_worker_ctx(tid: u32, entry: WorkerLocalCtx) {
    let _ = unsafe { THREADPOOL_WORKER_CTX.remove(&tid) };
    let work_key = py_object_key(entry.work_item);
    let _ = unsafe { THREADPOOL_WORKITEM_THREAD.remove(&work_key) };

    if ownership::get_active_ctx(tid) == Some(entry.ctx_id) {
        if entry.prev_ctx != 0 {
            let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &entry.prev_ctx, 0) };
        } else {
            let _ = unsafe { THREAD_ACTIVE_CTX.remove(&tid) };
        }
    }

    ownership::ctx_carrier_dec(entry.ctx_id);
}

#[inline(always)]
pub fn clear_threadpool_worker_for_object(tid: u32, obj_ptr: u64) {
    if obj_ptr == 0 {
        return;
    }

    if let Some(entry) = unsafe { THREADPOOL_WORKER_CTX.get(&tid).copied() } {
        if entry.work_item == obj_ptr {
            clear_threadpool_worker_ctx(tid, entry);
            return;
        }
    }

    let work_key = py_object_key(obj_ptr);
    if let Some(worker_tid) = unsafe { THREADPOOL_WORKITEM_THREAD.get(&work_key).copied() } {
        if let Some(entry) = unsafe { THREADPOOL_WORKER_CTX.get(&worker_tid).copied() } {
            if entry.work_item == obj_ptr {
                clear_threadpool_worker_ctx(worker_tid, entry);
                return;
            }
        }
        let _ = unsafe { THREADPOOL_WORKITEM_THREAD.remove(&work_key) };
    }
}

#[inline(always)]
pub fn clear_threadpool_worker_for_thread(tid: u32) {
    if let Some(entry) = unsafe { THREADPOOL_WORKER_CTX.get(&tid).copied() } {
        clear_threadpool_worker_ctx(tid, entry);
    }
    let _ = unsafe { THREADPOOL_WORKER_FRAME.remove(&tid) };
    let _ = unsafe { THREAD_CURRENT_FRAME.remove(&tid) };
    let _ = unsafe { THREAD_TSTATE.remove(&tid) };
}

#[inline(always)]
pub fn finalize_worker_run_for_object(obj_ptr: u64, ctx_id: u64, tool_id: u32) {
    if obj_ptr == 0 {
        return;
    }

    let key = py_object_key(obj_ptr);
    let worker_tid = match unsafe { WORKER_RUN_CARRIER.get(&key).copied() } {
        Some(tid) => tid,
        None => return,
    };
    let _ = unsafe { WORKER_RUN_CARRIER.remove(&key) };
    let _ = worker_stack_remove_for_object(worker_tid, obj_ptr);
    ownership::emit_py_event_carrier_for_tid(
        EVENT_WORKER_UNBIND,
        ctx_id,
        tool_id,
        obj_ptr,
        worker_tid,
    );
}

#[inline(always)]
pub fn clear_worker_runs_for_thread(tid: u32) {
    let worker_depth = unsafe { WORKER_RUN_DEPTH.get(&tid).copied() }.unwrap_or(0);
    let mut k: u32 = 0;
    while k < worker_depth && k < 64 {
        let key = ((tid as u64) << 8) | (k as u64);
        if let Some(entry) = unsafe { WORKER_RUN_STACK.get(&key).copied() } {
            let obj_key = py_object_key(entry.self_obj);
            if unsafe { WORKER_RUN_CARRIER.get(&obj_key).is_some() } {
                let carrier_map = if entry.kind == CODE_KIND_WORKITEM_RUN {
                    &WORKITEM_CTX
                } else {
                    &PYTHREAD_OBJ_CTX
                };
                if let Some(&ctx_id) = unsafe { carrier_map.get(&obj_key) } {
                    let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
                        .map(|c| c.tool_id)
                        .unwrap_or(TOOL_IDLE);
                    ownership::emit_py_event_carrier_for_tid(
                        EVENT_WORKER_UNBIND,
                        ctx_id,
                        tool_id,
                        entry.self_obj,
                        tid,
                    );
                }
                let _ = unsafe { WORKER_RUN_CARRIER.remove(&obj_key) };
            }
        }
        let _ = unsafe { WORKER_RUN_STACK.remove(&key) };
        k += 1;
    }
    let _ = unsafe { WORKER_RUN_DEPTH.remove(&tid) };
}

#[inline(always)]
fn find_mapped_work_item_in_frame(frame_ptr: u64) -> Option<u64> {
    let mut slot = 0u64;
    while slot < MAX_WORKITEM_LOCAL_SCAN_SLOTS {
        if let Some(obj) = read_frame_local(frame_ptr, slot) {
            let key = py_object_key(obj);
            if unsafe { WORKITEM_CTX.get(&key).is_some() } {
                return Some(obj);
            }
        }
        slot += 1;
    }
    None
}

#[inline(always)]
fn find_mapped_work_item_in_current_chain(tid: u32) -> Option<(u64, u64)> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let mut frame_ptr = match read_tstate_current_frame(tid) {
        Some(frame) => frame,
        None => unsafe { THREAD_CURRENT_FRAME.get(&tid).copied() }?,
    };
    let mut depth = 0u8;

    while frame_ptr != 0 && depth < MAX_WORKER_FRAME_CHAIN_DEPTH {
        let kind = unsafe { worker_kind_for_frame(pid, frame_ptr) };
        if kind == CODE_KIND_WORKITEM_RUN {
            if let Some(obj) = read_self_from_frame(frame_ptr) {
                let key = py_object_key(obj);
                if unsafe { WORKITEM_CTX.get(&key).is_some() } {
                    return Some((obj, frame_ptr));
                }
            }
            if let Some(obj) = find_mapped_work_item_in_frame(frame_ptr) {
                return Some((obj, frame_ptr));
            }
        }
        if kind == CODE_KIND_THREADPOOL_WORKER {
            if let Some(obj) = find_mapped_work_item_in_frame(frame_ptr) {
                return Some((obj, frame_ptr));
            }
        }
        frame_ptr = read_parent_ptr(frame_ptr);
        depth += 1;
    }

    None
}

#[inline(always)]
fn bind_threadpool_worker_context(tid: u32, work_item: u64, frame_ptr: u64) {
    if let Some(existing) = unsafe { THREADPOOL_WORKER_CTX.get(&tid).copied() } {
        if work_item != 0 && work_item == existing.work_item {
            if unsafe { TOOL_CTX.get(&existing.ctx_id).is_some() } {
                if ownership::get_active_ctx(tid) != Some(existing.ctx_id) {
                    let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &existing.ctx_id, 0) };
                }
                return;
            }
        }
        clear_threadpool_worker_ctx(tid, existing);
    }

    if work_item == 0 {
        return;
    }

    let work_key = py_object_key(work_item);
    let ctx_id = match unsafe { WORKITEM_CTX.get(&work_key).copied() } {
        Some(ctx_id) => ctx_id,
        None => return,
    };
    if unsafe { TOOL_CTX.get(&ctx_id).is_none() } {
        return;
    }

    if ownership::get_active_ctx(tid) == Some(ctx_id) {
        return;
    }

    let prev_ctx = ownership::get_active_ctx(tid).unwrap_or(0);
    let entry = WorkerLocalCtx {
        ctx_id,
        work_item,
        frame_ptr,
        prev_ctx,
    };
    let _ = unsafe { THREADPOOL_WORKER_CTX.insert(&tid, &entry, 0) };
    let _ = unsafe { THREADPOOL_WORKITEM_THREAD.insert(&work_key, &tid, 0) };
    let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &ctx_id, 0) };
    ownership::ctx_carrier_inc(ctx_id);
}

#[inline(always)]
pub fn refresh_threadpool_worker_context(tid: u32) {
    if let Some((work_item, frame_ptr)) = find_mapped_work_item_in_current_chain(tid) {
        bind_threadpool_worker_context(tid, work_item, frame_ptr);
        return;
    }

    if let Some(frame_ptr) = unsafe { THREADPOOL_WORKER_FRAME.get(&tid).copied() } {
        if frame_ptr != 0 {
            let work_item = find_mapped_work_item_in_frame(frame_ptr).unwrap_or(0);
            bind_threadpool_worker_context(tid, work_item, frame_ptr);
            return;
        }
    }

    bind_threadpool_worker_context(tid, 0, 0);
}

#[inline(always)]
fn handle_run_entry(tid: u32, frame_ptr: u64, kind: u8) {
    let self_obj = match read_self_from_frame(frame_ptr) {
        Some(obj) => obj,
        None => return,
    };

    let carrier_map = if kind == CODE_KIND_WORKITEM_RUN {
        &WORKITEM_CTX
    } else {
        &PYTHREAD_OBJ_CTX
    };

    let self_key = py_object_key(self_obj);
    let ctx_id = match unsafe { carrier_map.get(&self_key).copied() } {
        Some(cid) => cid,
        None => {
            ownership::emit_py_event_carrier(EVENT_AUDIT_UNATTRIBUTED, 0, 0, self_obj);
            return;
        }
    };

    let mut prev_ctx = ownership::get_active_ctx(tid).unwrap_or(0);
    if unsafe { FORK_CTX.get(&tid).copied() } == Some(ctx_id) {
        let _ = unsafe { FORK_CTX.remove(&tid) };
        ownership::ctx_carrier_dec(ctx_id);
        prev_ctx = 0;
    }

    if let Some(existing) = worker_stack_peek(tid) {
        if existing.kind == kind && existing.frame_ptr == frame_ptr && existing.self_obj == self_obj
        {
            if ownership::get_active_ctx(tid) != Some(ctx_id) {
                let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &ctx_id, 0) };
            }
            return;
        }
    }

    let entry = WorkerRunEntry {
        kind,
        _wpad: [0; 7],
        frame_ptr,
        parent_ptr: read_parent_ptr(frame_ptr),
        self_obj,
        prev_ctx,
    };
    worker_stack_push(tid, &entry);
    let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &ctx_id, 0) };
    if kind == CODE_KIND_THREAD_RUN {
        let _ = unsafe { PYTHREAD_OBJ_THREAD.insert(&self_key, &tid, 0) };
    }

    let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
        .map(|c| c.tool_id)
        .unwrap_or(TOOL_IDLE);
    ownership::emit_py_event_carrier(EVENT_WORKER_BIND, ctx_id, tool_id, self_obj);
    let _ = unsafe { WORKER_RUN_CARRIER.insert(&self_key, &tid, 0) };
}

#[inline(always)]
pub fn dispatch_exit_for_parent(tid: u32, parent_ptr: u64) -> bool {
    let entry = match worker_stack_pop_for_parent(tid, parent_ptr) {
        Some(e) => e,
        None => return false,
    };

    let carrier_map = if entry.kind == CODE_KIND_WORKITEM_RUN {
        &WORKITEM_CTX
    } else {
        &PYTHREAD_OBJ_CTX
    };

    let self_key = py_object_key(entry.self_obj);
    if let Some(&ctx_id) = unsafe { carrier_map.get(&self_key) } {
        let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
            .map(|c| c.tool_id)
            .unwrap_or(TOOL_IDLE);
        ownership::emit_py_event_carrier(EVENT_WORKER_UNBIND, ctx_id, tool_id, entry.self_obj);
        let _ = unsafe { WORKER_RUN_CARRIER.remove(&self_key) };
        ownership::emit_py_event_carrier(
            EVENT_WORKER_CARRIER_UNBIND,
            ctx_id,
            tool_id,
            entry.self_obj,
        );
        if entry.kind == CODE_KIND_THREAD_RUN {
            let _ = unsafe { PYTHREAD_OBJ_THREAD.remove(&self_key) };
        }
        let _ = carrier_map.remove(&self_key);
        ownership::ctx_carrier_dec(ctx_id);
    }

    if entry.prev_ctx != 0 {
        let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &entry.prev_ctx, 0) };
    } else {
        let _ = THREAD_ACTIVE_CTX.remove(&tid);
    }

    true
}
