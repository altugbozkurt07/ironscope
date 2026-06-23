/// Clamp a value for the BPF verifier.
/// On BPF targets, ensures the value is within [min, max].
/// On non-BPF targets, returns the value unchanged.
#[inline(always)]
#[allow(unused_variables)]
pub fn bound_value_for_verifier(v: isize, min: isize, max: isize) -> isize {
    #[cfg(target_arch = "bpf")]
    {
        if v < min {
            return min;
        }
        if v > max {
            return max;
        }
    }
    v
}

/// Cap a size value for BPF probe reads.
/// On BPF targets, returns `size % cap` if size >= cap, otherwise size.
/// On non-BPF targets, returns size unchanged.
#[inline(always)]
#[allow(
    unused_variables,
    unused_mut,
    unused_assignments,
    clippy::let_and_return
)]
pub fn cap_size(size: u32, cap: u32) -> u32 {
    let mut ret = size;
    #[cfg(target_arch = "bpf")]
    {
        if size >= cap {
            return cap;
        }
        ret = size % cap;
    }
    ret
}
