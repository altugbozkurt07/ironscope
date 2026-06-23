use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, RingBuf},
};

use ironscope_common::types::*;

// --- Ownership infrastructure ---

#[map]
pub static PYTHON_OFFSETS: Array<u32> = Array::with_max_entries(64, 0);

#[map]
pub static CTX_COUNTER: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static CLASSIFIER_SCRATCH: PerCpuArray<ScratchBuf64> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static TOOL_CTX: HashMap<u64, ToolCtx> = HashMap::with_max_entries(4096, 0);

#[map]
pub static TOOL_OBJ: HashMap<PyObjectKey, ToolObjCacheEntry> = HashMap::with_max_entries(4096, 0);

#[map]
pub static CODE_KIND: HashMap<CodeKindKey, u8> = HashMap::with_max_entries(8192, 0);

#[map]
pub static ROOT_RULES: Array<RootRule> = Array::with_max_entries(64, 0);

#[map]
pub static PENDING_TOOL_RESOLVE: HashMap<PendingToolResolveKey, u64> =
    HashMap::with_max_entries(4096, 0);

// --- Carrier maps ---

#[map]
pub static PENDING_FRAME_TOOL: LruHashMap<PyObjectKey, u32> = LruHashMap::with_max_entries(8192, 0);

#[map]
pub static FORK_CTX: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

#[map]
pub static FRAME_CTX: LruHashMap<PyObjectKey, u64> = LruHashMap::with_max_entries(8192, 0);

#[map]
pub static TASK_CTX: LruHashMap<PyObjectKey, u64> = LruHashMap::with_max_entries(4096, 0);

#[map]
pub static TASK_CTX_STACK: HashMap<TaskStackKey, u64> = HashMap::with_max_entries(8192, 0);

#[map]
pub static TASK_CTX_DEPTH: HashMap<PyObjectKey, u32> = HashMap::with_max_entries(4096, 0);

#[map]
pub static WORKITEM_CTX: LruHashMap<PyObjectKey, u64> = LruHashMap::with_max_entries(4096, 0);

#[map]
pub static PYTHREAD_OBJ_CTX: LruHashMap<PyObjectKey, u64> = LruHashMap::with_max_entries(1024, 0);

#[map]
pub static PYTHREAD_OBJ_THREAD: HashMap<PyObjectKey, u32> = HashMap::with_max_entries(1024, 0);

#[map]
pub static PENDING_WORKER_SPAWN: HashMap<u32, PendingWorkerSpawn> =
    HashMap::with_max_entries(4096, 0);

#[map]
pub static THREADPOOL_WORKER_FRAME: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

#[map]
pub static THREADPOOL_WORKER_CTX: HashMap<u32, WorkerLocalCtx> = HashMap::with_max_entries(4096, 0);

#[map]
pub static THREADPOOL_WORKITEM_THREAD: HashMap<PyObjectKey, u32> =
    HashMap::with_max_entries(4096, 0);

#[map]
pub static WORKER_RUN_CARRIER: HashMap<PyObjectKey, u32> = HashMap::with_max_entries(4096, 0);

#[map]
pub static THREAD_CURRENT_FRAME: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

#[map]
pub static THREAD_TSTATE: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

// Per-tid TOOL_ROOT stack keyed by depth, value carries (ctx_id,
// frame_ptr, parent_ptr, tool_id). The interior end probes (RV/RC/EXC)
// read the parent frame_ptr from the appropriate aarch64 register at
// probe entry — that's the new current frame after `_PyEvalFrameClearAndPop`
// returns, == the parent of the frame that just died. If it matches our
// top entry's stored parent_ptr, we know the TOOL_ROOT just exited and
// emit TOOL_END. This avoids the per-Python-frame push/pop balance
// problem: generator/coroutine resumes that yield mid-execution don't
// disturb our stack because we only push TOOL_ROOT entries here.
//
// Key: (tid as u64) << 32 | depth.
#[map]
pub static TOOL_STACK: HashMap<u64, ToolStackEntry> = HashMap::with_max_entries(4096, 0);

#[map]
pub static TOOL_STACK_DEPTH: HashMap<u32, u32> = HashMap::with_max_entries(4096, 0);

// Tool-root frames that reached an end probe while their asyncio Task still
// carried the same ctx. A later re-entry cancels this; task completion closes it.
#[map]
pub static PENDING_TOOL_CLOSE: HashMap<TaskStackKey, ToolStackEntry> =
    HashMap::with_max_entries(4096, 0);

// --- Per-thread active state ---

#[map]
pub static THREAD_ACTIVE_CTX: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

#[map]
pub static THREAD_ACTIVE_TASK: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

#[map]
pub static THREAD_CTX_STACK: HashMap<u64, u64> = HashMap::with_max_entries(32768, 0);

#[map]
pub static THREAD_CTX_DEPTH: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

// --- Entry/return correlation stashes ---

#[map]
pub static FRAME_ENTRY_STASH: HashMap<u64, u64> = HashMap::with_max_entries(32768, 0);

#[map]
pub static FRAME_STASH_DEPTH: HashMap<u32, u32> = HashMap::with_max_entries(4096, 0);

#[map]
pub static TASK_STEP_STASH: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
pub static TASK_STEP_PREV_TASK: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
pub static WORKER_RUN_STACK: HashMap<u64, WorkerRunEntry> = HashMap::with_max_entries(4096, 0);

#[map]
pub static WORKER_RUN_DEPTH: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

// Process TGIDs that are in the configured agent scope. LSM hooks are global,
// so enforcement must allow immediately unless the current TGID is protected.
#[map]
pub static PROTECTED_TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

// --- Policy maps ---

#[map]
pub static TOOL_FS_POLICY: HashMap<ToolPolicyKey, u8> = HashMap::with_max_entries(1024, 0);

#[map]
pub static TOOL_EXEC_POLICY: HashMap<ToolExecKey, u8> = HashMap::with_max_entries(256, 0);

#[map]
pub static TOOL_NET_POLICY: LpmTrie<ToolNetData, u8> = LpmTrie::with_max_entries(256, 0);

#[map]
pub static IRONSCOPE_CONFIG: HashMap<u32, IronScopeConfig> = HashMap::with_max_entries(1, 0);

// --- Event ring buffers ---

#[map]
pub static GUARD_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub static PY_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

#[map]
pub static RESOLVER_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);
