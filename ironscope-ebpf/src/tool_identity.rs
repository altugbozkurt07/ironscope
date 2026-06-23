use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user};

use crate::maps::*;
use crate::ownership;
use ironscope_common::types::*;

#[inline(always)]
pub unsafe fn extract_and_resolve(
    frame_ptr: u64,
    code_ptr: u64,
    rule: &RootRule,
    ctx_id: u64,
) -> u32 {
    let localsplus_off = match PYTHON_OFFSETS.get(OFF_FRAME_LOCALSPLUS) {
        Some(&off) => off as u64,
        None => return 0,
    };
    let slot = rule.slot_index as u64;
    let slot_addr = frame_ptr + localsplus_off + slot * 8;
    let obj_ptr: u64 = match bpf_probe_read_user(slot_addr as *const u64) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if obj_ptr == 0 {
        emit_audit_unresolved(ctx_id, rule.kind);
        return 0;
    }

    match rule.extractor_kind {
        EXTRACTOR_SLOT_OBJ => {
            let key = py_object_key(obj_ptr);
            if let Some(entry) = TOOL_OBJ.get(&key) {
                let actual_type_ptr = read_type_ptr(obj_ptr);
                if entry.tool_id != 0 && entry.type_ptr != 0 && entry.type_ptr == actual_type_ptr {
                    set_ctx_tool_id(ctx_id, entry.tool_id);
                    return entry.tool_id;
                }

                // Stale cache hit: the Python address is known, but no longer
                // has the resolved type identity. Treat this as resolver_error
                // instead of falling back to known-tool policy.
                let _ = TOOL_OBJ.remove(&key);
                let pid_tgid = bpf_get_current_pid_tgid();
                let pending = pending_tool_resolve_key((pid_tgid >> 32) as u32, obj_ptr);
                let _ = PENDING_TOOL_RESOLVE.remove(&pending);
                mark_resolver_error(ctx_id, rule.kind);
                emit_resolver_failed(
                    ctx_id,
                    rule.kind,
                    obj_ptr,
                    frame_ptr,
                    code_ptr,
                    actual_type_ptr,
                );
                return 0;
            }
            emit_resolver_candidate(ctx_id, rule.kind, obj_ptr, frame_ptr, code_ptr);
            0
        }
        EXTRACTOR_SLOT_NAME => {
            let compact_off = match PYTHON_OFFSETS.get(OFF_UNICODE_COMPACT_DATA) {
                Some(&off) => off as u64,
                None => return 0,
            };
            let scratch = match CLASSIFIER_SCRATCH.get_ptr_mut(0) {
                Some(ptr) => ptr,
                None => {
                    emit_audit_unresolved(ctx_id, rule.kind);
                    return 0;
                }
            };
            let buf = &mut (*scratch).buf;
            let ret = aya_ebpf::helpers::gen::bpf_probe_read_user(
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                64,
                (obj_ptr + compact_off) as *const core::ffi::c_void,
            );
            if ret < 0 {
                emit_audit_unresolved(ctx_id, rule.kind);
                return 0;
            }
            let tool_id = fnv1a_32(buf);
            set_ctx_tool_id(ctx_id, tool_id);
            tool_id
        }
        _ => {
            emit_audit_unresolved(ctx_id, rule.kind);
            0
        }
    }
}

#[inline(always)]
pub unsafe fn emit_frame_self_resolver_candidate(frame_ptr: u64, code_ptr: u64, code_kind: u8) {
    let localsplus_off = match PYTHON_OFFSETS.get(OFF_FRAME_LOCALSPLUS) {
        Some(&off) => off as u64,
        None => return,
    };
    let obj_ptr: u64 = match bpf_probe_read_user((frame_ptr + localsplus_off) as *const u64) {
        Ok(v) => v,
        Err(_) => return,
    };
    if obj_ptr == 0 {
        return;
    }

    let key = py_object_key(obj_ptr);
    if TOOL_OBJ.get(&key).is_some() {
        return;
    }
    emit_resolver_candidate(0, code_kind, obj_ptr, frame_ptr, code_ptr);
}

#[inline(always)]
pub unsafe fn cached_frame_self_tool_id(frame_ptr: u64) -> u32 {
    let localsplus_off = match PYTHON_OFFSETS.get(OFF_FRAME_LOCALSPLUS) {
        Some(&off) => off as u64,
        None => return 0,
    };
    let obj_ptr: u64 = match bpf_probe_read_user((frame_ptr + localsplus_off) as *const u64) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if obj_ptr == 0 {
        return 0;
    }

    let key = py_object_key(obj_ptr);
    if let Some(entry) = TOOL_OBJ.get(&key) {
        let actual_type_ptr = read_type_ptr(obj_ptr);
        if entry.tool_id != 0 && entry.type_ptr != 0 && entry.type_ptr == actual_type_ptr {
            return entry.tool_id;
        }
    }
    0
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
unsafe fn read_type_ptr(obj_ptr: u64) -> u64 {
    let off = match PYTHON_OFFSETS.get(OFF_OBJ_TYPE) {
        Some(&off) => off as u64,
        None => return 0,
    };
    bpf_probe_read_user((obj_ptr + off) as *const u64).unwrap_or(0)
}

#[inline(always)]
fn emit_resolver_candidate(
    ctx_id: u64,
    code_kind: u8,
    self_ptr: u64,
    frame_ptr: u64,
    code_ptr: u64,
) {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let key = pending_tool_resolve_key(tgid, self_ptr);
    if unsafe { PENDING_TOOL_RESOLVE.get(&key).is_some() } {
        return;
    }
    let _ = unsafe { PENDING_TOOL_RESOLVE.insert(&key, &ctx_id, 0) };

    if let Some(mut event) = unsafe { RESOLVER_EVENTS.reserve::<ResolverEvent>(0) } {
        let out = event.as_mut_ptr();
        unsafe {
            (*out).pid = tgid;
            (*out).tid = tid;
            (*out).ts_ns = bpf_ktime_get_ns();
            (*out).kind = EVENT_RESOLVER_CANDIDATE;
            (*out).code_kind = code_kind;
            (*out)._pad = [0; 2];
            (*out).ctx_id = ctx_id;
            (*out).self_ptr = self_ptr;
            (*out).type_ptr = read_type_ptr(self_ptr);
            (*out).frame_ptr = frame_ptr;
            (*out).code_ptr = code_ptr;
        }
        event.submit(0);
    }
}

#[inline(always)]
fn emit_resolver_failed(
    ctx_id: u64,
    code_kind: u8,
    self_ptr: u64,
    frame_ptr: u64,
    code_ptr: u64,
    type_ptr: u64,
) {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    if let Some(mut event) = unsafe { RESOLVER_EVENTS.reserve::<ResolverEvent>(0) } {
        let out = event.as_mut_ptr();
        unsafe {
            (*out).pid = tgid;
            (*out).tid = tid;
            (*out).ts_ns = bpf_ktime_get_ns();
            (*out).kind = EVENT_RESOLVER_FAILED;
            (*out).code_kind = code_kind;
            (*out)._pad = [0; 2];
            (*out).ctx_id = ctx_id;
            (*out).self_ptr = self_ptr;
            (*out).type_ptr = type_ptr;
            (*out).frame_ptr = frame_ptr;
            (*out).code_ptr = code_ptr;
        }
        event.submit(0);
    }
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
fn fnv1a_32(buf: &[u8; 64]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    let mut i = 0usize;
    while i < 64 {
        if buf[i] == 0 {
            break;
        }
        h ^= buf[i] as u32;
        h = h.wrapping_mul(0x01000193);
        i += 1;
    }
    if h == 0 {
        1
    } else {
        h
    }
}

#[inline(always)]
fn set_ctx_tool_id(ctx_id: u64, tool_id: u32) {
    if let Some(entry) = unsafe { TOOL_CTX.get_ptr_mut(&ctx_id) } {
        unsafe {
            (*entry).tool_id = tool_id;
            (*entry).flags |= TOOL_CTX_FLAG_RESOLVED;
        }
    }
}

#[inline(always)]
fn mark_resolver_error(ctx_id: u64, code_kind: u8) {
    if let Some(entry) = unsafe { TOOL_CTX.get_ptr_mut(&ctx_id) } {
        unsafe {
            (*entry).flags |= TOOL_CTX_FLAG_RESOLVER_ERROR;
        }
    }
    ownership::emit_py_event(EVENT_AUDIT_UNRESOLVED, ctx_id, code_kind as u32);
}

#[inline(always)]
fn emit_audit_unresolved(ctx_id: u64, code_kind: u8) {
    mark_resolver_error(ctx_id, code_kind);
}
