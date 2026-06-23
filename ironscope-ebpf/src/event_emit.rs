/// Event emission helpers.
/// Allocates GuardEvent from per-CPU allocator, populates fields,
/// and submits to GUARD_EVENTS ring buffer.
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns};

use ironscope_common::co_re;
use ironscope_common::path::{Path, MAX_PATH_DEPTH};
use ironscope_common::types::*;

use crate::alloc;
use crate::maps::GUARD_EVENTS;

/// Emit a filesystem open event.
#[inline(always)]
pub fn emit_fs_event(
    f: &co_re::file,
    tool_id: u32,
    ctx_id: u64,
    identity_state: u8,
    policy_source: u8,
    action: u8,
) {
    let _ = unsafe { try_emit_fs_event(f, tool_id, ctx_id, identity_state, policy_source, action) };
}

#[inline(always)]
unsafe fn try_emit_fs_event(
    f: &co_re::file,
    tool_id: u32,
    ctx_id: u64,
    identity_state: u8,
    policy_source: u8,
    action: u8,
) -> Result<(), u32> {
    alloc::init()?;
    let event = alloc::alloc_zero::<GuardEvent>()?;
    let path_buf = alloc::alloc_zero::<Path>()?;

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = pid_tgid as u32;
    event.kind = EVENT_FS_OPEN;
    event.action = action;
    event.tool_id = tool_id;
    event.ctx_id = ctx_id;
    event.identity_state = identity_state;
    event.policy_source = policy_source;
    event.ts_ns = bpf_ktime_get_ns();

    // Resolve full path
    path_buf.core_resolve_file(f, MAX_PATH_DEPTH)?;
    copy_path_to_event(event, path_buf);

    submit_event(event);
    Ok(())
}

/// Emit an exec event (from bprm_check LSM hook).
#[inline(always)]
pub fn emit_exec_event(
    f: &co_re::file,
    tool_id: u32,
    ctx_id: u64,
    identity_state: u8,
    policy_source: u8,
    action: u8,
) {
    let _ =
        unsafe { try_emit_exec_event(f, tool_id, ctx_id, identity_state, policy_source, action) };
}

#[inline(always)]
unsafe fn try_emit_exec_event(
    f: &co_re::file,
    tool_id: u32,
    ctx_id: u64,
    identity_state: u8,
    policy_source: u8,
    action: u8,
) -> Result<(), u32> {
    alloc::init()?;
    let event = alloc::alloc_zero::<GuardEvent>()?;
    let path_buf = alloc::alloc_zero::<Path>()?;

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = pid_tgid as u32;
    event.kind = EVENT_EXEC;
    event.action = action;
    event.tool_id = tool_id;
    event.ctx_id = ctx_id;
    event.identity_state = identity_state;
    event.policy_source = policy_source;
    event.ts_ns = bpf_ktime_get_ns();

    // Resolve binary path
    path_buf.core_resolve_file(f, MAX_PATH_DEPTH)?;
    copy_path_to_event(event, path_buf);

    submit_event(event);
    Ok(())
}

/// Emit a network connect event.
#[inline(always)]
pub fn emit_net_event(
    pid: u32,
    tool_id: u32,
    ctx_id: u64,
    identity_state: u8,
    policy_source: u8,
    action: u8,
    addr: u32,
    port: u16,
) {
    let _ = unsafe {
        try_emit_net_event(
            pid,
            tool_id,
            ctx_id,
            identity_state,
            policy_source,
            action,
            addr,
            port,
        )
    };
}

#[inline(always)]
unsafe fn try_emit_net_event(
    pid: u32,
    tool_id: u32,
    ctx_id: u64,
    identity_state: u8,
    policy_source: u8,
    action: u8,
    addr: u32,
    port: u16,
) -> Result<(), u32> {
    alloc::init()?;
    let event = alloc::alloc_zero::<GuardEvent>()?;

    let tid = bpf_get_current_pid_tgid() as u32;
    event.pid = pid;
    event.tid = tid;
    event.kind = EVENT_NET_CONNECT;
    event.action = action;
    event.tool_id = tool_id;
    event.ctx_id = ctx_id;
    event.identity_state = identity_state;
    event.policy_source = policy_source;
    event.ts_ns = bpf_ktime_get_ns();
    event.addr = addr;
    event.port = port;

    submit_event(event);
    Ok(())
}

#[inline(always)]
fn copy_path_to_event(event: &mut GuardEvent, path_buf: &Path) {
    let path = path_buf.as_slice();
    let len = path.len().min(MAX_EVENT_PATH_LEN);
    if len == 0 {
        return;
    }
    unsafe {
        bpf_probe_read_kernel(
            event.path.as_mut_ptr() as *mut core::ffi::c_void,
            len as u32,
            path.as_ptr() as *const core::ffi::c_void,
        );
    }
    event.path_len = len as u16;
}

#[inline(always)]
fn submit_event(event: &GuardEvent) {
    if let Some(mut buf) = GUARD_EVENTS.reserve::<GuardEvent>(0) {
        let dst = unsafe { &mut *buf.as_mut_ptr() };
        dst.pid = event.pid;
        dst.tid = event.tid;
        dst.ppid = event.ppid;
        dst.tool_id = event.tool_id;
        dst.ctx_id = event.ctx_id;
        dst.ts_ns = event.ts_ns;
        dst.kind = event.kind;
        dst.action = event.action;
        dst.identity_state = event.identity_state;
        dst.policy_source = event.policy_source;
        dst.port = event.port;
        dst.addr = event.addr;
        dst.child_pid = event.child_pid;
        dst.path_len = event.path_len;
        dst.argv_len = event.argv_len;
        dst.comm = event.comm;
        dst.path = event.path;
        dst.argv = event.argv;
        buf.submit(0);
    }
}

// BPF helpers for memory reads
use aya_ebpf::helpers::gen::bpf_probe_read_kernel;
