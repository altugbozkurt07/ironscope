use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::programs::BtfTracePointContext;

use crate::lifecycle;
use crate::maps::*;
use crate::ownership;
use ironscope_common::co_re::task_struct;
use ironscope_common::types::*;

pub fn handle_sched_fork(ctx: &BtfTracePointContext) -> Result<u32, u32> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let parent_tgid = (pid_tgid >> 32) as u32;
    let parent_tid = pid_tgid as u32;

    let parent_protected = unsafe { PROTECTED_TGIDS.get(&parent_tgid).is_some() };
    let mut ctx_id = ownership::get_active_ctx(parent_tid);
    if let Some(active_ctx) = ctx_id {
        let flags = unsafe { TOOL_CTX.get(&active_ctx) }
            .map(|c| c.flags)
            .unwrap_or(0);
        let worker_depth = unsafe { WORKER_RUN_DEPTH.get(&parent_tid).copied() }.unwrap_or(0);
        if flags & TOOL_CTX_FLAG_ASYNC_FRAME != 0 && worker_depth == 0 {
            ctx_id = None;
        }
    }

    if ctx_id.is_none() {
        if let Some(pending) = unsafe { PENDING_WORKER_SPAWN.get(&parent_tid).copied() } {
            let work_key = PyObjectKey {
                tgid: parent_tgid,
                _pad: 0,
                ptr: pending.work_item,
            };
            let live_work_ctx = unsafe { WORKITEM_CTX.get(&work_key).copied() };
            if live_work_ctx == Some(pending.ctx_id)
                && unsafe { TOOL_CTX.get(&pending.ctx_id).is_some() }
            {
                ctx_id = Some(pending.ctx_id);
                let _ = unsafe { PENDING_WORKER_SPAWN.remove(&parent_tid) };
            }
        }
    }

    let child_scope = unsafe { IRONSCOPE_CONFIG.get(&0) }
        .map(|config| config.child_scope)
        .unwrap_or(CHILD_SCOPE_TOOL_ONLY);
    let protect_idle_child = parent_protected && ctx_id.is_none() && child_scope == CHILD_SCOPE_ALL;

    if ctx_id.is_none() && !protect_idle_child {
        return Ok(0);
    }

    let child_ptr: *const core::ffi::c_void = unsafe { ctx.arg::<*const core::ffi::c_void>(1) };
    if child_ptr.is_null() {
        return Ok(0);
    }
    let child_ts = unsafe { task_struct::from_ctx_arg(child_ptr as *mut _) };
    let child_tid = unsafe { child_ts.pid() }.ok_or(1u32)? as u32;
    if child_tid == 0 {
        return Ok(0);
    }

    let child_tgid = unsafe { child_ts.tgid() }.ok_or(1u32)? as u32;
    if child_tgid != 0 {
        let protected: u8 = 1;
        let _ = unsafe { PROTECTED_TGIDS.insert(&child_tgid, &protected, 0) };
    }

    if let Some(ctx_id) = ctx_id {
        let _ = unsafe { THREAD_ACTIVE_CTX.insert(&child_tid, &ctx_id, 0) };
        let _ = unsafe { FORK_CTX.insert(&child_tid, &ctx_id, 0) };
        ownership::ctx_carrier_inc(ctx_id);

        let tool_id = unsafe { TOOL_CTX.get(&ctx_id) }
            .map(|c| c.tool_id)
            .unwrap_or(TOOL_IDLE);
        ownership::emit_py_event_fork(EVENT_CHILD_CTX_BIND, ctx_id, tool_id, child_tid);
    }

    Ok(0)
}

pub fn handle_sched_exit(_ctx: &BtfTracePointContext) -> Result<u32, u32> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    lifecycle::reap_thread(tid);
    if tid == tgid {
        let _ = unsafe { PROTECTED_TGIDS.remove(&tgid) };
    }
    Ok(0)
}

pub fn handle_sched_exec(_ctx: &BtfTracePointContext) -> Result<u32, u32> {
    Ok(0)
}
