use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::{FEntryContext, LsmContext};
use aya_log_ebpf::info;

use crate::event_emit;
use crate::maps::{
    FRAME_STASH_DEPTH, IRONSCOPE_CONFIG, PROTECTED_TGIDS, TOOL_CTX, TOOL_EXEC_POLICY,
    TOOL_FS_POLICY, TOOL_NET_POLICY,
};
use crate::ownership;
use ironscope_common::co_re::{file, linux_binprm, sockaddr, sockaddr_in};
use ironscope_common::types::*;

#[inline(always)]
fn enforce_permission(denied: bool) -> i32 {
    if !denied {
        return 0;
    }

    let config = match unsafe { IRONSCOPE_CONFIG.get(&0) } {
        Some(c) => *c,
        None => return 0,
    };

    match config.mode {
        MODE_ENFORCE => -1,
        _ => 0,
    }
}

#[inline(always)]
fn identity_state(ctx_id: u64, tool_id: u32, flags: u32) -> u8 {
    if ctx_id == 0 {
        IDENTITY_STATE_UNATTRIBUTED
    } else if flags & TOOL_CTX_FLAG_RESOLVER_ERROR != 0 {
        IDENTITY_STATE_RESOLVER_ERROR
    } else if tool_id == TOOL_IDLE {
        IDENTITY_STATE_UNKNOWN_TOOL
    } else {
        IDENTITY_STATE_KNOWN_TOOL
    }
}

#[inline(always)]
fn resolve_ctx(tid: u32) -> (u64, u32, u8) {
    crate::worker_probes::refresh_threadpool_worker_context(tid);
    if let Some(ctx_id) = ownership::get_active_ctx(tid) {
        if let Some(tool_ctx) = unsafe { TOOL_CTX.get(&ctx_id) } {
            let identity = identity_state(ctx_id, tool_ctx.tool_id, tool_ctx.flags);
            return (ctx_id, tool_ctx.tool_id, identity);
        }
    }
    (0, TOOL_IDLE, IDENTITY_STATE_UNATTRIBUTED)
}

#[inline(always)]
fn mark_ctx_seen(ctx_id: u64) {
    if ctx_id == 0 {
        return;
    }
    if let Some(ctx) = unsafe { TOOL_CTX.get_ptr_mut(&ctx_id) } {
        unsafe {
            (*ctx).last_seen_ns = bpf_ktime_get_ns();
        }
    }
}

#[inline(always)]
fn identity_policy_decision(identity: u8) -> Option<(bool, u8)> {
    let config = unsafe { IRONSCOPE_CONFIG.get(&0) }?;
    match identity {
        IDENTITY_STATE_UNATTRIBUTED => Some((
            config.unattributed_policy == UNATTRIBUTED_DENY,
            POLICY_SOURCE_UNATTRIBUTED,
        )),
        IDENTITY_STATE_UNKNOWN_TOOL => Some((
            config.unknown_tool_policy == UNKNOWN_TOOL_DENY,
            POLICY_SOURCE_UNKNOWN_TOOL,
        )),
        IDENTITY_STATE_RESOLVER_ERROR => Some((
            config.resolver_error_policy == RESOLVER_ERROR_DENY,
            POLICY_SOURCE_RESOLVER_ERROR,
        )),
        _ => None,
    }
}

#[inline(always)]
fn decide_known_tool_permission(permission: Option<u8>, policy_source: u8) -> (bool, u8) {
    if let Some(perm) = permission {
        return (perm == PERM_DENY, policy_source);
    }

    let config = match unsafe { IRONSCOPE_CONFIG.get(&0) } {
        Some(c) => *c,
        None => return (false, POLICY_SOURCE_DEFAULT_ALLOW),
    };

    if config.default_tool_policy == DEFAULT_TOOL_DENY {
        (true, POLICY_SOURCE_DEFAULT_DENY)
    } else {
        (false, POLICY_SOURCE_DEFAULT_ALLOW)
    }
}

#[inline(always)]
fn is_protected_subject(tgid: u32, tid: u32) -> bool {
    if unsafe { PROTECTED_TGIDS.get(&tgid).is_some() } {
        return true;
    }

    // A propagated tool context is also protected. This covers child workers
    // forked while a tool is active, where enforcement should follow the tool.
    ownership::get_active_ctx(tid).is_some()
}

#[inline(always)]
fn audit_unprotected_python_thread(tid: u32, event_kind: u8) {
    if unsafe { FRAME_STASH_DEPTH.get(&tid).is_some() } {
        ownership::emit_py_event_aux(EVENT_AUDIT_UNATTRIBUTED, 0, 0, event_kind as u64);
    }
}

#[inline(always)]
unsafe fn get_file_identity(f: &file) -> Option<(u32, u64)> {
    let ino_obj = f.f_inode()?;
    let ino = ino_obj.i_ino()?;
    let sb = ino_obj.i_sb()?;
    let dev = sb.s_dev()?;
    Some((dev as u32, ino))
}

/// LSM file_open hook — enforce per-tool filesystem access policy.
pub fn handle_file_open(ctx: &LsmContext) -> i32 {
    match unsafe { try_file_open(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_file_open(ctx: &LsmContext) -> Result<i32, i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    if !is_protected_subject(tgid, tid) {
        audit_unprotected_python_thread(tid, EVENT_FS_OPEN);
        return Ok(0);
    }

    let (ctx_id, tool_id, identity_state) = resolve_ctx(tid);
    mark_ctx_seen(ctx_id);

    if ctx_id == 0 {
        ownership::emit_py_event_aux(EVENT_AUDIT_UNATTRIBUTED, 0, 0, EVENT_FS_OPEN as u64);
    }

    let f = file::from_ptr(ctx.arg::<*const core::ffi::c_void>(0) as *const _);
    if f.is_null() {
        return Ok(0);
    }

    let (dev, ino) = get_file_identity(&f).ok_or(0)?;

    let key = ToolPolicyKey { tool_id, dev, ino };

    let mut policy_source = POLICY_SOURCE_DEFAULT_ALLOW;
    let permission = if let Some(perm) = TOOL_FS_POLICY.get(&key) {
        policy_source = POLICY_SOURCE_TOOL;
        Some(*perm)
    } else {
        None
    };

    let (denied, policy_source) = if let Some(decision) = identity_policy_decision(identity_state) {
        decision
    } else {
        decide_known_tool_permission(permission, policy_source)
    };
    let action = if denied { ACTION_DENY } else { ACTION_ALLOW };

    if denied {
        info!(
            ctx,
            "file_open denied: pid={} tool={} dev={} ino={}", tgid, tool_id, dev, ino
        );
    }

    event_emit::emit_fs_event(&f, tool_id, ctx_id, identity_state, policy_source, action);

    Ok(enforce_permission(denied))
}

/// LSM bprm_check_security hook — enforce per-tool exec policy.
pub fn handle_bprm_check(ctx: &LsmContext) -> i32 {
    match unsafe { try_bprm_check(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_bprm_check(ctx: &LsmContext) -> Result<i32, i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    if !is_protected_subject(tgid, tid) {
        audit_unprotected_python_thread(tid, EVENT_EXEC);
        return Ok(0);
    }

    let (ctx_id, tool_id, identity_state) = resolve_ctx(tid);
    mark_ctx_seen(ctx_id);

    if ctx_id == 0 {
        ownership::emit_py_event_aux(EVENT_AUDIT_UNATTRIBUTED, 0, 0, EVENT_EXEC as u64);
    }

    let bprm = linux_binprm::from_ptr(ctx.arg::<*const core::ffi::c_void>(0) as *const _);
    if bprm.is_null() {
        return Ok(0);
    }

    let bprm_file = bprm.file().ok_or(0)?;
    let (dev, ino) = get_file_identity(&bprm_file).ok_or(0)?;

    let key = ToolExecKey { tool_id, dev, ino };

    let mut policy_source = POLICY_SOURCE_DEFAULT_ALLOW;
    let permission = if let Some(perm) = TOOL_EXEC_POLICY.get(&key) {
        policy_source = POLICY_SOURCE_TOOL;
        Some(*perm)
    } else {
        let wildcard_key = ToolExecKey {
            tool_id,
            dev: 0,
            ino: 0,
        };
        if let Some(perm) = TOOL_EXEC_POLICY.get(&wildcard_key) {
            policy_source = POLICY_SOURCE_TOOL;
            Some(*perm)
        } else {
            None
        }
    };

    let (denied, policy_source) = if let Some(decision) = identity_policy_decision(identity_state) {
        decision
    } else {
        decide_known_tool_permission(permission, policy_source)
    };
    let action = if denied { ACTION_DENY } else { ACTION_ALLOW };

    if denied {
        info!(
            ctx,
            "bprm_check denied: pid={} tool={} dev={} ino={}", tgid, tool_id, dev, ino
        );
    }

    event_emit::emit_exec_event(
        &bprm_file,
        tool_id,
        ctx_id,
        identity_state,
        policy_source,
        action,
    );

    Ok(enforce_permission(denied))
}

/// LSM socket_connect hook — enforce per-tool network egress policy.
pub fn handle_socket_connect(ctx: &LsmContext) -> i32 {
    match unsafe { try_socket_connect(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_socket_connect(ctx: &LsmContext) -> Result<i32, i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    if !is_protected_subject(tgid, tid) {
        audit_unprotected_python_thread(tid, EVENT_NET_CONNECT);
        return Ok(0);
    }

    let (ctx_id, tool_id, identity_state) = resolve_ctx(tid);
    mark_ctx_seen(ctx_id);

    if ctx_id == 0 {
        ownership::emit_py_event_aux(EVENT_AUDIT_UNATTRIBUTED, 0, 0, EVENT_NET_CONNECT as u64);
    }

    let sa = sockaddr::from_ptr(ctx.arg::<*const core::ffi::c_void>(1) as *const _);
    if sa.is_null() {
        return Ok(0);
    }

    let family = sa.sa_family().ok_or(0)?;

    if family != 2 {
        return Ok(0);
    }

    let sa_in = sockaddr_in::from_ptr(sa.as_ptr() as *const _);
    let addr = sa_in.sin_addr().ok_or(0)?;
    let port = sa_in.sin_port().ok_or(0)?;

    let net_data = ToolNetData {
        tool_id,
        addr,
        port,
        _pad: 0,
    };
    let lpm_key = Key::new(96, net_data);

    let mut policy_source = POLICY_SOURCE_DEFAULT_ALLOW;
    let permission = if let Some(perm) = TOOL_NET_POLICY.get(&lpm_key) {
        policy_source = POLICY_SOURCE_TOOL;
        Some(*perm)
    } else {
        None
    };

    let (denied, policy_source) = if let Some(decision) = identity_policy_decision(identity_state) {
        decision
    } else {
        decide_known_tool_permission(permission, policy_source)
    };
    let action = if denied { ACTION_DENY } else { ACTION_ALLOW };

    if denied {
        info!(
            ctx,
            "socket_connect denied: pid={} tool={} addr={} port={}", tgid, tool_id, addr, port
        );
    }

    event_emit::emit_net_event(
        tgid,
        tool_id,
        ctx_id,
        identity_state,
        policy_source,
        action,
        addr,
        port,
    );

    Ok(enforce_permission(denied))
}

// --- fentry fallback handlers (monitoring only) ---
// Used when BPF LSM is not in the kernel's active security module list.
// These fire regardless of LSM registration but cannot enforce (deny).

pub fn handle_fentry_file_open(ctx: &FEntryContext) {
    let _ = unsafe { try_fentry_file_open(ctx) };
}

unsafe fn try_fentry_file_open(ctx: &FEntryContext) -> Result<(), i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;

    let (ctx_id, tool_id, identity_state) = resolve_ctx(tid);
    mark_ctx_seen(ctx_id);

    if ctx_id == 0 {
        if FRAME_STASH_DEPTH.get(&tid).is_some() {
            ownership::emit_py_event_aux(EVENT_AUDIT_UNATTRIBUTED, 0, 0, EVENT_FS_OPEN as u64);
        }
        return Ok(());
    }

    let f = file::from_ptr(ctx.arg::<*const core::ffi::c_void>(0) as *const _);
    if f.is_null() {
        return Ok(());
    }

    event_emit::emit_fs_event(
        &f,
        tool_id,
        ctx_id,
        identity_state,
        POLICY_SOURCE_MONITOR,
        ACTION_ALLOW,
    );
    Ok(())
}

pub fn handle_fentry_bprm_check(ctx: &FEntryContext) {
    let _ = unsafe { try_fentry_bprm_check(ctx) };
}

unsafe fn try_fentry_bprm_check(ctx: &FEntryContext) -> Result<(), i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;

    let (ctx_id, tool_id, identity_state) = resolve_ctx(tid);
    mark_ctx_seen(ctx_id);

    if ctx_id == 0 {
        if FRAME_STASH_DEPTH.get(&tid).is_some() {
            ownership::emit_py_event_aux(EVENT_AUDIT_UNATTRIBUTED, 0, 0, EVENT_EXEC as u64);
        }
        return Ok(());
    }

    let bprm = linux_binprm::from_ptr(ctx.arg::<*const core::ffi::c_void>(0) as *const _);
    if bprm.is_null() {
        return Ok(());
    }

    let bprm_file = bprm.file().ok_or(0)?;
    event_emit::emit_exec_event(
        &bprm_file,
        tool_id,
        ctx_id,
        identity_state,
        POLICY_SOURCE_MONITOR,
        ACTION_ALLOW,
    );
    Ok(())
}

pub fn handle_fentry_socket_connect(ctx: &FEntryContext) {
    let _ = unsafe { try_fentry_socket_connect(ctx) };
}

unsafe fn try_fentry_socket_connect(ctx: &FEntryContext) -> Result<(), i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let (ctx_id, tool_id, identity_state) = resolve_ctx(tid);
    mark_ctx_seen(ctx_id);

    if ctx_id == 0 {
        if FRAME_STASH_DEPTH.get(&tid).is_some() {
            ownership::emit_py_event_aux(EVENT_AUDIT_UNATTRIBUTED, 0, 0, EVENT_NET_CONNECT as u64);
        }
        return Ok(());
    }

    let sa = sockaddr::from_ptr(ctx.arg::<*const core::ffi::c_void>(1) as *const _);
    if sa.is_null() {
        return Ok(());
    }

    let family = sa.sa_family().ok_or(0)?;
    if family != 2 {
        return Ok(());
    }

    let sa_in = sockaddr_in::from_ptr(sa.as_ptr() as *const _);
    let addr = sa_in.sin_addr().ok_or(0)?;
    let port = sa_in.sin_port().ok_or(0)?;

    event_emit::emit_net_event(
        tgid,
        tool_id,
        ctx_id,
        identity_state,
        POLICY_SOURCE_MONITOR,
        ACTION_ALLOW,
        addr,
        port,
    );
    Ok(())
}
