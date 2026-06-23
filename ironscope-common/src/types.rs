/// Type aliases for ownership model.
pub type CtxId = u64;
pub type ToolId = u32;

/// PYTHON_OFFSETS array indices.
pub const OFF_FRAME_F_EXECUTABLE: u32 = 0;
pub const OFF_CODE_QUALNAME: u32 = 1;
pub const OFF_CODE_FILENAME: u32 = 2;
pub const OFF_UNICODE_COMPACT_DATA: u32 = 3;
pub const OFF_CODE_FIRSTLINENO: u32 = 4;
pub const OFF_FRAME_LOCALSPLUS: u32 = 5;
pub const OFF_FRAME_PREVIOUS: u32 = 6;
pub const OFF_FRAME_OWNER: u32 = 7;
pub const OFF_TASK_STATE: u32 = 8;
pub const OFF_TASK_CORO: u32 = 9;
/// Which aarch64 callee-saved register (19..28) holds `frame` at the
/// `start_frame:` label inside `_PyEval_EvalFrameDefault`. Discovered
/// in Phase 0 by disassembling the function prologue; read from
/// pt_regs.regs[N] at the probe.
pub const OFF_FRAME_REG_IDX: u32 = 10;
pub const OFF_CODE_FLAGS: u32 = 11;
pub const OFF_GEN_IFRAME: u32 = 12;
pub const OFF_TSTATE_CURRENT_FRAME: u32 = 13;
pub const OFF_OBJ_TYPE: u32 = 14;
pub const OFF_GEN_FRAME_STATE: u32 = 15;
/// Which aarch64 register holds the parent frame at the exception unwind
/// attach point. This is discovered per CPython contract and may differ from
/// OFF_FRAME_REG_IDX.
pub const OFF_EXCEPTION_FRAME_REG_IDX: u32 = 16;
pub const OFF_COUNT: u32 = 17;

/// Mask for co_flags values that indicate RETURN_GENERATOR bytecode
/// (coroutine/generator/async-generator creation frames).
/// CPython 3.12: CO_GENERATOR=0x20, CO_COROUTINE=0x80, CO_ASYNC_GENERATOR=0x200.
pub const CO_FLAGS_GENERATOR_MASK: u32 = 0x2A0;

/// Maximum context stack depth per thread.
pub const MAX_CTX_STACK_DEPTH: u8 = 8;
pub const MAX_TASK_CTX_STACK_DEPTH: u32 = 8;
pub const MAX_WORKER_FRAME_CHAIN_DEPTH: u8 = 8;
pub const MAX_WORKITEM_LOCAL_SCAN_SLOTS: u64 = 32;

/// Tool invocation states.
pub const TOOL_IDLE: u32 = 0;

/// Permission bits.
pub const PERM_ALLOW: u8 = 1;
pub const PERM_DENY: u8 = 0;

/// Enforcement modes.
pub const MODE_MONITOR: u8 = 0;
pub const MODE_ENFORCE: u8 = 2;

/// CODE_KIND constants for the CODE_KIND BPF map.
pub const CODE_KIND_UNKNOWN: u8 = 255;
pub const CODE_KIND_IGNORE: u8 = 0;
pub const CODE_KIND_TOOL_ROOT_LG: u8 = 1;
pub const CODE_KIND_TOOL_ROOT_LC: u8 = 4;
pub const CODE_KIND_TOOL_ID_RULE: u8 = 10;
pub const CODE_KIND_TOOL_CTOR: u8 = 11;
pub const CODE_KIND_WORKITEM_CTOR: u8 = 20;
pub const CODE_KIND_WORKITEM_RUN: u8 = 21;
pub const CODE_KIND_THREAD_CTOR: u8 = 22;
pub const CODE_KIND_THREAD_RUN: u8 = 23;
pub const CODE_KIND_THREADPOOL_WORKER: u8 = 24;

/// Extractor kinds for RootRule — how to resolve tool identity from a frame.
pub const EXTRACTOR_NONE: u32 = 0;
pub const EXTRACTOR_SLOT_OBJ: u32 = 1;
pub const EXTRACTOR_SLOT_NAME: u32 = 2;

// --- Guard Event Types ---

pub const MAX_EVENT_PATH_LEN: usize = 1024;
pub const MAX_EVENT_ARGV_LEN: usize = 256;
pub const MAX_EVENT_COMM_LEN: usize = 16;

/// Guard event kinds (GUARD_EVENTS ring buffer).
pub const EVENT_FS_OPEN: u8 = 1;
pub const EVENT_EXEC: u8 = 2;
pub const EVENT_NET_CONNECT: u8 = 3;
pub const EVENT_FORK: u8 = 4;
pub const EVENT_EXIT: u8 = 5;
pub const EVENT_TOOL_START: u8 = 6;
/// Authoritative context close. Kept at the historical TOOL_END id for compatibility.
pub const EVENT_TOOL_CONTEXT_END: u8 = 7;
pub const EVENT_TOOL_END: u8 = EVENT_TOOL_CONTEXT_END;

/// Python ownership event kinds (PY_EVENTS ring buffer).
pub const EVENT_TASK_BIND: u8 = 8;
pub const EVENT_TASK_UNBIND: u8 = 9;
pub const EVENT_WORKER_BIND: u8 = 10;
pub const EVENT_WORKER_UNBIND: u8 = 11;
pub const EVENT_AUDIT_UNATTRIBUTED: u8 = 12;
pub const EVENT_AUDIT_UNRESOLVED: u8 = 13;
pub const EVENT_AUDIT_STACK_OVERFLOW: u8 = 14;
pub const EVENT_AUDIT_BUILD_MISMATCH: u8 = 15;
pub const EVENT_DEALLOC_CLEANUP: u8 = 16;
/// Non-authoritative root frame close for a tool execution.
pub const EVENT_TOOL_FRAME_END: u8 = 17;
/// Resolver protocol event: userspace should resolve an unknown tool object.
pub const EVENT_RESOLVER_CANDIDATE: u8 = 18;
/// Resolver protocol event: userspace resolved a tool object.
pub const EVENT_RESOLVER_RESOLVED: u8 = 19;
/// Resolver protocol event: userspace failed to resolve a tool object.
pub const EVENT_RESOLVER_FAILED: u8 = 20;
/// A Python worker carrier object was associated with a tool context.
pub const EVENT_WORKER_CARRIER_BIND: u8 = 21;
/// A Python worker carrier object association was removed.
pub const EVENT_WORKER_CARRIER_UNBIND: u8 = 22;
/// A forked child inherited an active tool context.
pub const EVENT_CHILD_CTX_BIND: u8 = 23;
/// A forked child context association was removed.
pub const EVENT_CHILD_CTX_UNBIND: u8 = 24;

/// Guard event actions.
pub const ACTION_ALLOW: u8 = 0;
pub const ACTION_DENY: u8 = 1;

/// Tool context flags.
pub const TOOL_CTX_FLAG_RESOLVED: u32 = 1 << 0;
pub const TOOL_CTX_FLAG_RESOLVER_ERROR: u32 = 1 << 1;
pub const TOOL_CTX_FLAG_PENDING_START: u32 = 1 << 2;
pub const TOOL_CTX_FLAG_ASYNC_FRAME: u32 = 1 << 3;

/// Guard-event identity state.
pub const IDENTITY_STATE_UNATTRIBUTED: u8 = 0;
pub const IDENTITY_STATE_KNOWN_TOOL: u8 = 1;
pub const IDENTITY_STATE_UNKNOWN_TOOL: u8 = 2;
pub const IDENTITY_STATE_RESOLVER_ERROR: u8 = 3;

/// Guard-event policy source.
pub const POLICY_SOURCE_DEFAULT_ALLOW: u8 = 0;
pub const POLICY_SOURCE_TOOL: u8 = 1;
pub const POLICY_SOURCE_UNATTRIBUTED: u8 = 3;
pub const POLICY_SOURCE_UNKNOWN_TOOL: u8 = 4;
pub const POLICY_SOURCE_RESOLVER_ERROR: u8 = 5;
pub const POLICY_SOURCE_MONITOR: u8 = 6;
pub const POLICY_SOURCE_DEFAULT_DENY: u8 = 7;

/// Unattributed access policy.
pub const UNATTRIBUTED_AUDIT_ONLY: u8 = 0;
pub const UNATTRIBUTED_DENY: u8 = 1;

/// Policy for tool-boundary executions whose tool object identity has not
/// been resolved yet.
pub const UNKNOWN_TOOL_ALLOW: u8 = 0;
pub const UNKNOWN_TOOL_DENY: u8 = 1;

/// Policy for executions where userspace attempted tool resolution but failed.
pub const RESOLVER_ERROR_ALLOW: u8 = 0;
pub const RESOLVER_ERROR_DENY: u8 = 1;

/// Default policy for known tool-context accesses that do not match a
/// tool-specific resource rule.
pub const DEFAULT_TOOL_ALLOW: u8 = 0;
pub const DEFAULT_TOOL_DENY: u8 = 1;

/// Child process protection scope.
pub const CHILD_SCOPE_TOOL_ONLY: u8 = 0;
pub const CHILD_SCOPE_ALL: u8 = 1;

/// CODE_KIND map key: (tgid, code_ptr) to prevent cross-process VA collisions.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CodeKindKey {
    pub tgid: u32,
    pub _pad: u32,
    pub code_ptr: u64,
}

/// Process-qualified Python object pointer key.
/// Python object virtual addresses are only unique inside a process; BPF maps
/// that track object carriers must include TGID to avoid cross-process aliasing.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PyObjectKey {
    pub tgid: u32,
    pub _pad: u32,
    pub ptr: u64,
}

/// Process-qualified per-task stack key. `depth` distinguishes nested tool
/// contexts carried by the same asyncio Task.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TaskStackKey {
    pub tgid: u32,
    pub depth: u32,
    pub task_ptr: u64,
}

/// Debounce key for unresolved tool object candidates.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PendingToolResolveKey {
    pub tgid: u32,
    pub _pad: u32,
    pub self_ptr: u64,
}

/// Resolved high-level tool object identity cached by eBPF.
///
/// `type_ptr` is validated against `self.ob_type` on every cache hit so a
/// reused Python object address cannot inherit a stale tool id.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ToolObjCacheEntry {
    pub type_ptr: u64,
    pub tool_id: u32,
    pub name_hash: u32,
    pub generation: u32,
    pub _pad: u32,
}

/// Userspace resolver event emitted when eBPF sees a supported tool boundary
/// but cannot resolve the high-level tool object from the current BPF cache.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverEvent {
    pub pid: u32,
    pub tid: u32,
    pub ts_ns: u64,
    pub kind: u8,
    pub code_kind: u8,
    pub _pad: [u8; 2],
    pub ctx_id: u64,
    pub self_ptr: u64,
    pub type_ptr: u64,
    pub frame_ptr: u64,
    pub code_ptr: u64,
}

/// Per-tid TOOL_ROOT stack entry. The interior end probes look this up by
/// parent frame_ptr (= the new current frame visible after
/// `_PyEvalFrameClearAndPop` returns) to detect TOOL_ROOT frame exit
/// without depending on per-Python-frame push/pop balance.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ToolStackEntry {
    pub ctx_id: u64,
    pub frame_ptr: u64,
    pub parent_ptr: u64,
    pub tool_id: u32,
    pub _pad: u32,
}

// --- Ownership types ---

/// Tool context tracked by ctx_id.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ToolCtx {
    pub tool_id: u32,
    pub generation: u32,
    pub carrier_count: u32,
    pub flags: u32,
    pub started_ns: u64,
    pub last_seen_ns: u64,
}

/// Per-code-object extraction rule.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RootRule {
    pub kind: u8,
    pub _rule_pad: [u8; 3],
    pub slot_index: u32,
    pub extractor_kind: u32,
    pub _rule_pad2: u32,
    pub filename_hash: u64,
    pub qualname_hash: u64,
    pub firstline: u32,
    pub _rule_pad3: u32,
}

/// Worker run frame stash — stores state needed at worker frame exit.
/// Stored in WORKER_RUN_STACK map (per-tid stack).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct WorkerRunEntry {
    pub kind: u8,
    pub _wpad: [u8; 7],
    pub frame_ptr: u64,
    pub parent_ptr: u64,
    pub self_obj: u64,
    pub prev_ctx: u64,
}

/// Short-lived handoff from an async tool task to a worker thread spawn.
///
/// This is used only after a concrete `_WorkItem` object has been created
/// under a pending async tool close. It lets sched_fork propagate that
/// specific tool context to a just-spawned worker thread without treating any
/// arbitrary suspended async task as active work.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PendingWorkerSpawn {
    pub ctx_id: u64,
    pub work_item: u64,
}

/// Per-thread context derived from a live ThreadPoolExecutor `_worker` frame.
///
/// CPython may miss the `_WorkItem.run` interior join point on some builds, or
/// the long-lived `_worker` frame may not expose the current work item through
/// a stable fast-local slot. This entry records a scoped context recovered from
/// the active Python frame chain before a policy decision.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct WorkerLocalCtx {
    pub ctx_id: u64,
    pub work_item: u64,
    pub frame_ptr: u64,
    pub prev_ctx: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ScratchBuf64 {
    pub buf: [u8; 64],
}

impl Default for ScratchBuf64 {
    fn default() -> Self {
        Self { buf: [0; 64] }
    }
}

/// Python ownership event emitted via PY_EVENTS ring buffer.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PyEvent {
    pub pid: u32,
    pub tid: u32,
    pub ts_ns: u64,
    pub kind: u8,
    pub _pad: [u8; 3],
    pub ctx_id: u64,
    pub tool_id: u32,
    pub _pad2: u32,
    pub carrier_ptr: u64,
    pub aux: u64,
}

// --- Policy types ---

/// Composite key for per-tool filesystem policy.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ToolPolicyKey {
    pub tool_id: u32,
    pub dev: u32,
    pub ino: u64,
}

/// Composite key for per-tool exec policy.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ToolExecKey {
    pub tool_id: u32,
    pub dev: u32,
    pub ino: u64,
}

/// LPM trie key for per-tool network policy (compiler intermediate).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ToolNetKey {
    pub prefixlen: u32,
    pub tool_id: u32,
    pub addr: u32,
    pub port: u16,
    pub _pad: u16,
}

/// BPF LPM trie data for per-tool network policy.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ToolNetData {
    pub tool_id: u32,
    pub addr: u32,
    pub port: u16,
    pub _pad: u16,
}

/// Global agent guard configuration.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IronScopeConfig {
    pub mode: u8,
    pub discover: u8,
    pub unattributed_policy: u8,
    pub unknown_tool_policy: u8,
    pub resolver_error_policy: u8,
    pub child_scope: u8,
    pub default_tool_policy: u8,
    pub _pad: [u8; 1],
}

/// Guard event emitted via GUARD_EVENTS ring buffer.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GuardEvent {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub tool_id: u32,
    pub ctx_id: u64,
    pub ts_ns: u64,
    pub kind: u8,
    pub action: u8,
    pub identity_state: u8,
    pub policy_source: u8,
    pub port: u16,
    pub addr: u32,
    pub child_pid: u32,
    pub path_len: u16,
    pub argv_len: u16,
    pub comm: [u8; MAX_EVENT_COMM_LEN],
    pub path: [u8; MAX_EVENT_PATH_LEN],
    pub argv: [u8; MAX_EVENT_ARGV_LEN],
}

// --- Zeroed defaults ---

impl Default for ToolCtx {
    fn default() -> Self {
        Self {
            tool_id: 0,
            generation: 0,
            carrier_count: 0,
            flags: 0,
            started_ns: 0,
            last_seen_ns: 0,
        }
    }
}

impl Default for RootRule {
    fn default() -> Self {
        Self {
            kind: 0,
            _rule_pad: [0; 3],
            slot_index: 0,
            extractor_kind: 0,
            _rule_pad2: 0,
            filename_hash: 0,
            qualname_hash: 0,
            firstline: 0,
            _rule_pad3: 0,
        }
    }
}

impl Default for WorkerRunEntry {
    fn default() -> Self {
        Self {
            kind: 0,
            _wpad: [0; 7],
            frame_ptr: 0,
            parent_ptr: 0,
            self_obj: 0,
            prev_ctx: 0,
        }
    }
}

impl Default for PendingWorkerSpawn {
    fn default() -> Self {
        Self {
            ctx_id: 0,
            work_item: 0,
        }
    }
}

impl Default for WorkerLocalCtx {
    fn default() -> Self {
        Self {
            ctx_id: 0,
            work_item: 0,
            frame_ptr: 0,
            prev_ctx: 0,
        }
    }
}

impl Default for PyEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            tid: 0,
            ts_ns: 0,
            kind: 0,
            _pad: [0; 3],
            ctx_id: 0,
            tool_id: 0,
            _pad2: 0,
            carrier_ptr: 0,
            aux: 0,
        }
    }
}

impl Default for ToolPolicyKey {
    fn default() -> Self {
        Self {
            tool_id: 0,
            dev: 0,
            ino: 0,
        }
    }
}

impl Default for ToolExecKey {
    fn default() -> Self {
        Self {
            tool_id: 0,
            dev: 0,
            ino: 0,
        }
    }
}

impl Default for ToolNetKey {
    fn default() -> Self {
        Self {
            prefixlen: 0,
            tool_id: 0,
            addr: 0,
            port: 0,
            _pad: 0,
        }
    }
}

impl Default for ToolNetData {
    fn default() -> Self {
        Self {
            tool_id: 0,
            addr: 0,
            port: 0,
            _pad: 0,
        }
    }
}

impl Default for IronScopeConfig {
    fn default() -> Self {
        Self {
            mode: MODE_MONITOR,
            discover: 0,
            unattributed_policy: UNATTRIBUTED_AUDIT_ONLY,
            unknown_tool_policy: UNKNOWN_TOOL_ALLOW,
            resolver_error_policy: RESOLVER_ERROR_DENY,
            child_scope: CHILD_SCOPE_TOOL_ONLY,
            default_tool_policy: DEFAULT_TOOL_ALLOW,
            _pad: [0; 1],
        }
    }
}

impl Default for GuardEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            tid: 0,
            ppid: 0,
            tool_id: 0,
            ctx_id: 0,
            ts_ns: 0,
            kind: 0,
            action: 0,
            identity_state: IDENTITY_STATE_UNATTRIBUTED,
            policy_source: POLICY_SOURCE_DEFAULT_ALLOW,
            port: 0,
            addr: 0,
            child_pid: 0,
            path_len: 0,
            argv_len: 0,
            comm: [0u8; MAX_EVENT_COMM_LEN],
            path: [0u8; MAX_EVENT_PATH_LEN],
            argv: [0u8; MAX_EVENT_ARGV_LEN],
        }
    }
}

#[cfg(feature = "userspace")]
mod pod_impls {
    use super::*;

    unsafe impl aya::Pod for ToolCtx {}
    unsafe impl aya::Pod for RootRule {}
    unsafe impl aya::Pod for PyEvent {}
    unsafe impl aya::Pod for ToolPolicyKey {}
    unsafe impl aya::Pod for ToolExecKey {}
    unsafe impl aya::Pod for ToolNetKey {}
    unsafe impl aya::Pod for ToolNetData {}
    unsafe impl aya::Pod for IronScopeConfig {}
    unsafe impl aya::Pod for GuardEvent {}
    unsafe impl aya::Pod for CodeKindKey {}
    unsafe impl aya::Pod for PyObjectKey {}
    unsafe impl aya::Pod for TaskStackKey {}
    unsafe impl aya::Pod for PendingToolResolveKey {}
    unsafe impl aya::Pod for ToolObjCacheEntry {}
    unsafe impl aya::Pod for ResolverEvent {}
    unsafe impl aya::Pod for ToolStackEntry {}
    unsafe impl aya::Pod for WorkerRunEntry {}
    unsafe impl aya::Pod for PendingWorkerSpawn {}
    unsafe impl aya::Pod for WorkerLocalCtx {}
    unsafe impl aya::Pod for ScratchBuf64 {}
}
