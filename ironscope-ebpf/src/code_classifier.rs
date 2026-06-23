use aya_ebpf::helpers::bpf_probe_read_user;
use aya_ebpf::programs::ProbeContext;
use aya_log_ebpf::info;

use crate::maps::*;
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
unsafe fn read_qualname_hash(code_ptr: u64, _ctx: &ProbeContext) -> Option<u64> {
    let off_qualname = (*PYTHON_OFFSETS.get(OFF_CODE_QUALNAME)?) as u64;
    let off_compact = (*PYTHON_OFFSETS.get(OFF_UNICODE_COMPACT_DATA)?) as u64;

    let qualname_ptr: u64 = bpf_probe_read_user((code_ptr + off_qualname) as *const u64).ok()?;
    if qualname_ptr == 0 {
        return None;
    }

    let data_addr = qualname_ptr + off_compact;
    let scratch = CLASSIFIER_SCRATCH.get_ptr_mut(0)?;
    let buf = &mut (*scratch).buf;
    let ret = aya_ebpf::helpers::gen::bpf_probe_read_user(
        buf.as_mut_ptr() as *mut core::ffi::c_void,
        MAX_HASH_BYTES as u32,
        data_addr as *const core::ffi::c_void,
    );
    if ret < 0 {
        return None;
    }

    let mut len = 0usize;
    while len < MAX_HASH_BYTES {
        if buf[len] == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return None;
    }

    Some(fnv1a_64(buf, len))
}

pub unsafe fn qualname_has_tool_impl_suffix(code_ptr: u64) -> bool {
    let off_qualname = match PYTHON_OFFSETS.get(OFF_CODE_QUALNAME) {
        Some(off) => *off as u64,
        None => return false,
    };
    let off_compact = match PYTHON_OFFSETS.get(OFF_UNICODE_COMPACT_DATA) {
        Some(off) => *off as u64,
        None => return false,
    };

    let qualname_ptr: u64 = match bpf_probe_read_user((code_ptr + off_qualname) as *const u64) {
        Ok(ptr) => ptr,
        Err(_) => return false,
    };
    if qualname_ptr == 0 {
        return false;
    }

    let scratch = match CLASSIFIER_SCRATCH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => return false,
    };
    let buf = &mut (*scratch).buf;
    let ret = aya_ebpf::helpers::gen::bpf_probe_read_user(
        buf.as_mut_ptr() as *mut core::ffi::c_void,
        MAX_HASH_BYTES as u32,
        (qualname_ptr + off_compact) as *const core::ffi::c_void,
    );
    if ret < 0 {
        return false;
    }

    let mut len = 0usize;
    while len < MAX_HASH_BYTES {
        if buf[len] == 0 {
            break;
        }
        len += 1;
    }

    if len >= 5 {
        let i = len - 5;
        if buf[i] == b'.'
            && buf[i + 1] == b'_'
            && buf[i + 2] == b'r'
            && buf[i + 3] == b'u'
            && buf[i + 4] == b'n'
        {
            return true;
        }
    }
    if len >= 6 {
        let i = len - 6;
        if buf[i] == b'.'
            && buf[i + 1] == b'_'
            && buf[i + 2] == b'a'
            && buf[i + 3] == b'r'
            && buf[i + 4] == b'u'
            && buf[i + 5] == b'n'
        {
            return true;
        }
    }

    false
}

#[inline(always)]
pub unsafe fn classify(tgid: u32, code_ptr: u64, ctx: &ProbeContext) -> u8 {
    let key = CodeKindKey {
        tgid,
        _pad: 0,
        code_ptr,
    };

    let hash = match read_qualname_hash(code_ptr, ctx) {
        Some(h) => h,
        None => {
            let kind = CODE_KIND_IGNORE;
            let _ = CODE_KIND.insert(&key, &kind, 0);
            return kind;
        }
    };

    let mut i = 0u32;
    while i < 64 {
        if let Some(rule) = ROOT_RULES.get(i) {
            if rule.kind != 0 && rule.qualname_hash == hash {
                let kind = rule.kind;
                info!(
                    ctx,
                    "MATCH: rule={} kind={} hash={} code_ptr={}", i, kind, hash, code_ptr
                );
                let _ = CODE_KIND.insert(&key, &kind, 0);
                return kind;
            }
        }
        i += 1;
    }

    let kind = CODE_KIND_IGNORE;
    let _ = CODE_KIND.insert(&key, &kind, 0);
    kind
}
