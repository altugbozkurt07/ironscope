/// Fixed-size buffer for BPF-safe memory reads.
/// Ported from security-agent-common/src/buffer.rs.
use core::cmp::min;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Buffer<const N: usize> {
    pub buf: [u8; N],
    len: usize,
}

impl<const N: usize> Default for Buffer<N> {
    fn default() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }
}

impl<const N: usize> Buffer<N> {
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..min(self.len(), N)]
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// BPF-specific methods
#[cfg(target_arch = "bpf")]
mod bpf {
    use super::*;

    use aya_ebpf::helpers::gen::bpf_probe_read_user;

    impl<const N: usize> Buffer<N> {
        /// Read user-space memory into the buffer.
        #[inline(always)]
        pub unsafe fn read_user_memory<P>(&mut self, from: *const P, size: u32) -> Result<(), u32> {
            let size = (size as i64).clamp(0, N as i64);

            let ret = bpf_probe_read_user(
                self.buf.as_mut_ptr() as *mut _,
                size as u32,
                from as *const _,
            );
            if ret != 0 {
                return Err(1);
            }

            self.len = size as usize;
            Ok(())
        }
    }
}
