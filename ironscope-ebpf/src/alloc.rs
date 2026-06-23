/// Per-CPU allocator for large eBPF structs.
/// eBPF stack limit is 512 bytes, so GuardEvent (~1.3KB) and Path (~1KB)
/// must be allocated from per-CPU maps.
/// Ported from security-agent-common/src/alloc/bpf.rs.
use aya_ebpf::{
    macros::map,
    maps::{PerCpuArray, PerCpuHashMap},
};
use core::mem;

/// Maximum allocation size — must be >= size_of::<GuardEvent>() (~1324 bytes).
const HEAP_MAX_ALLOC_SIZE: usize = 2048;

/// Maximum number of allocations per init() cycle.
const MAX_ALLOCS: u32 = 8;

const ZEROS: [u8; HEAP_MAX_ALLOC_SIZE] = [0; HEAP_MAX_ALLOC_SIZE];

#[map]
static HEAP: PerCpuHashMap<u32, [u8; HEAP_MAX_ALLOC_SIZE]> =
    PerCpuHashMap::with_max_entries(MAX_ALLOCS, 0);

#[map]
static ALLOC_STATE: PerCpuArray<Allocator> = PerCpuArray::with_max_entries(1, 0);

#[repr(C)]
pub struct Allocator {
    pub i_next: u32,
}

/// Reset the allocator for a new event emission cycle.
#[inline(always)]
pub fn init() -> Result<(), u32> {
    let ptr = ALLOC_STATE.get_ptr_mut(0).ok_or(1u32)?;
    let a = unsafe { &mut *ptr };
    a.i_next = 0;
    Ok(())
}

/// Allocate a zeroed instance of T from the per-CPU heap.
#[inline(always)]
pub fn alloc_zero<T>() -> Result<&'static mut T, u32> {
    let ptr = ALLOC_STATE.get_ptr_mut(0).ok_or(1u32)?;
    let a = unsafe { &mut *ptr };

    let sizeof = mem::size_of::<T>();

    if a.i_next >= MAX_ALLOCS {
        return Err(1);
    }

    let k = a.i_next;
    HEAP.insert(&k, &ZEROS, 0).map_err(|_| 1u32)?;

    if let Some(alloc) = HEAP.get_ptr_mut(&k) {
        let alloc = unsafe { &mut *alloc };
        if sizeof > alloc.len() {
            return Err(1);
        }
        a.i_next += 1;
        return Ok(unsafe { core::mem::transmute(alloc.as_mut_ptr()) });
    }

    Err(1)
}
