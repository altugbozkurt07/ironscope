use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_log_ebpf::info;

use crate::maps::*;
use crate::ownership;
use ironscope_common::types::*;

#[inline(always)]
fn py_object_key(tgid: u32, ptr: u64) -> PyObjectKey {
    PyObjectKey { tgid, _pad: 0, ptr }
}

#[inline(always)]
fn select_task_step_ptr(ctx: &ProbeContext, tgid: u32) -> Result<u64, i64> {
    let arg0: u64 = ctx.arg(0).unwrap_or(0);
    let arg1: u64 = ctx.arg(1).unwrap_or(0);

    if arg0 != 0 {
        let key0 = py_object_key(tgid, arg0);
        if unsafe { TASK_CTX.get(&key0).is_some() } {
            return Ok(arg0);
        }
    }
    if arg1 != 0 {
        let key1 = py_object_key(tgid, arg1);
        if unsafe { TASK_CTX.get(&key1).is_some() } {
            return Ok(arg1);
        }
    }

    if arg1 != 0 {
        return Ok(arg1);
    }
    if arg0 != 0 {
        return Ok(arg0);
    }
    Err(1i64)
}

#[inline(always)]
pub fn handle_task_init(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // _asyncio_Task___init___impl is inlined into tp_init on this build:
    // signature is (TaskObj *self, PyObject *args, PyObject *kwds)
    let task_ptr: u64 = ctx.arg(0).ok_or(1i64)?;
    if task_ptr == 0 {
        return Ok(());
    }

    let ctx_id = match ownership::get_active_ctx(tid) {
        Some(cid) => cid,
        None => return Ok(()),
    };

    let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
        .map(|c| c.tool_id)
        .unwrap_or(TOOL_IDLE);

    let parent_task = unsafe { THREAD_ACTIVE_TASK.get(&tid).copied() }.unwrap_or(0);
    if parent_task != 0
        && parent_task != task_ptr
        && ownership::task_ctx_current(parent_task) == Some(ctx_id)
        && ownership::task_ctx_depth_for(parent_task) > 1
    {
        let _ = ownership::task_ctx_remove(tid, parent_task, ctx_id);
    }

    let _ = ownership::task_ctx_push(tid, task_ptr, ctx_id, tool_id);
    info!(
        ctx,
        "task_init: task={} ctx={} tid={}", task_ptr, ctx_id, tid
    );

    Ok(())
}

#[inline(always)]
pub fn handle_task_step_entry(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let task_ptr = select_task_step_ptr(ctx, tgid)?;
    if task_ptr == 0 {
        return Ok(());
    }

    let prev_ctx = ownership::get_active_ctx(tid).unwrap_or(0);
    let prev_task = unsafe { THREAD_ACTIVE_TASK.get(&tid).copied() }.unwrap_or(0);
    let _ = unsafe { TASK_STEP_STASH.insert(&tid, &prev_ctx, 0) };
    let _ = unsafe { TASK_STEP_PREV_TASK.insert(&tid, &prev_task, 0) };

    let _ = unsafe { THREAD_ACTIVE_TASK.insert(&tid, &task_ptr, 0) };

    let task_key = py_object_key(tgid, task_ptr);
    if let Some(&ctx_id) = unsafe { TASK_CTX.get(&task_key) } {
        if !ownership::ctx_is_live(ctx_id) {
            ownership::task_ctx_clear(tid, task_ptr);
            let _ = unsafe { THREAD_ACTIVE_CTX.remove(&tid) };
        } else if ownership::ctx_stack_contains(tid, ctx_id) {
            let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &ctx_id, 0) };
        } else {
            let live_ctx = ownership::ctx_stack_top(tid).unwrap_or(0);
            if live_ctx != 0 {
                let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &live_ctx, 0) };
            } else {
                let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &ctx_id, 0) };
            }
        }
    } else if let Some(ctx_id) = ownership::restore_deferred_tool_close(tid, task_ptr) {
        let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &ctx_id, 0) };
    } else {
        let _ = unsafe { THREAD_ACTIVE_CTX.remove(&tid) };
    }

    info!(ctx, "task_step_entry: task={} tid={}", task_ptr, tid);

    Ok(())
}

#[inline(always)]
pub fn handle_task_step_return(ctx: &RetProbeContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let task_ptr = match unsafe { THREAD_ACTIVE_TASK.get(&tid).copied() } {
        Some(tp) if tp != 0 => tp,
        _ => return Ok(()),
    };

    let task_state_off = match unsafe { PYTHON_OFFSETS.get(OFF_TASK_STATE) } {
        Some(&off) => off as u64,
        None => return Err(1),
    };

    let task_state: u8 =
        unsafe { bpf_probe_read_user((task_ptr + task_state_off) as *const u8) }.unwrap_or(0);

    let task_key = py_object_key(tgid, task_ptr);

    if task_state >= 1 {
        let ctx_id = unsafe { TASK_CTX.get(&task_key).copied() }.unwrap_or(0);
        ownership::task_ctx_clear(tid, task_ptr);

        info!(
            ctx,
            "task_done: task={} state={} ctx={}", task_ptr, task_state, ctx_id
        );
    }

    let prev_ctx = unsafe { TASK_STEP_STASH.get(&tid).copied() }.unwrap_or(0);
    let prev_task = unsafe { TASK_STEP_PREV_TASK.get(&tid).copied() }.unwrap_or(0);

    let restore_ctx = if prev_ctx != 0 && ownership::ctx_stack_contains(tid, prev_ctx) {
        prev_ctx
    } else {
        ownership::ctx_stack_top(tid).unwrap_or(0)
    };

    if restore_ctx != 0 {
        let _ = unsafe { THREAD_ACTIVE_CTX.insert(&tid, &restore_ctx, 0) };
    } else {
        let _ = unsafe { THREAD_ACTIVE_CTX.remove(&tid) };
    }

    if prev_task != 0 {
        let _ = unsafe { THREAD_ACTIVE_TASK.insert(&tid, &prev_task, 0) };
    } else {
        let _ = unsafe { THREAD_ACTIVE_TASK.remove(&tid) };
    }

    let _ = unsafe { TASK_STEP_STASH.remove(&tid) };
    let _ = unsafe { TASK_STEP_PREV_TASK.remove(&tid) };

    Ok(())
}
