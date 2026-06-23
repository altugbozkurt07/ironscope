/// Kernel path resolution via dentry walk.
/// Ported from security-agent-common/src/path.rs.
use crate::utils::bound_value_for_verifier;
#[cfg(target_arch = "bpf")]
use crate::utils::cap_size;

pub const MAX_PATH_LEN: usize = 1024;
pub const MAX_PATH_DEPTH: u16 = 128;
pub const MAX_NAME: usize = u8::MAX as usize;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Path {
    buffer: [u8; MAX_PATH_LEN],
    len: u32,
    depth: u16,
}

impl Default for Path {
    fn default() -> Self {
        Self {
            buffer: [0u8; MAX_PATH_LEN],
            len: 0,
            depth: 0,
        }
    }
}

impl Path {
    /// Get the resolved path as a byte slice.
    /// Path is built in prepend mode (right-to-left in the buffer).
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        let len =
            bound_value_for_verifier(self.len as isize, 0, (MAX_PATH_LEN - 1) as isize) as usize;
        &self.buffer[(self.buffer.len() - len)..]
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    #[cfg(target_arch = "bpf")]
    #[inline(always)]
    fn space_left(&self) -> usize {
        MAX_PATH_LEN - self.len as usize
    }

    /// Prepend a '/' separator.
    #[cfg(target_arch = "bpf")]
    #[inline(always)]
    fn prepend_path_sep(&mut self) -> Result<(), u32> {
        let left = self.space_left();
        if left < 1 {
            return Err(1);
        }
        let i = left - 1;
        if i >= self.buffer.len() {
            return Err(1);
        }
        self.buffer[i] = b'/';
        self.len += 1;
        Ok(())
    }
}

// BPF-specific path resolution methods
#[cfg(target_arch = "bpf")]
mod bpf {
    use super::*;
    use crate::co_re;
    use crate::core_read_kernel;
    use aya_ebpf::helpers::gen;

    impl Path {
        /// Resolve full path from a file struct.
        #[inline(always)]
        pub unsafe fn core_resolve_file(
            &mut self,
            f: &co_re::file,
            max_depth: u16,
        ) -> Result<(), u32> {
            if !f.is_null() {
                return self.core_resolve(&f.f_path().ok_or(1u32)?, max_depth);
            }
            Ok(())
        }

        /// Walk the dentry chain to build the full path.
        /// Handles mount boundaries by following mnt_parent/mnt_mountpoint.
        #[inline(always)]
        pub unsafe fn core_resolve(&mut self, p: &co_re::path, max_depth: u16) -> Result<(), u32> {
            if p.is_null() {
                return Ok(());
            }

            let mut entry = p.dentry().ok_or(1u32)?;
            let mnt = p.mnt().ok_or(1u32)?;
            let mut mount = mnt.mount();
            let mut mnt_parent = mount.mnt_parent().ok_or(1u32)?;
            let mut mnt_root = mnt.mnt_root().ok_or(1u32)?;

            for _i in 0..max_depth {
                // Check if we've reached the mount root
                if entry == mnt_root {
                    // At the filesystem root — check if there's a parent mount
                    if mount == mnt_parent {
                        break;
                    }
                    // Cross mount boundary
                    entry = mount.mnt_mountpoint().ok_or(1u32)?;
                    mount = mnt_parent;
                    mnt_parent = mount.mnt_parent().ok_or(1u32)?;
                    mnt_root = core_read_kernel!(mount, mnt, mnt_root).ok_or(1u32)?;
                    continue;
                }

                let parent = entry.d_parent().ok_or(1u32)?;
                // Reached root (d_parent == self)
                if entry == parent {
                    break;
                }

                if !self.is_empty() {
                    self.prepend_path_sep()?;
                }

                self.prepend_dentry(&entry)?;

                if parent.is_null() {
                    break;
                }
                entry = parent;
            }

            // Prepend the root dentry (typically "/")
            self.prepend_dentry(&entry)?;

            Ok(())
        }

        /// Prepend a dentry's name component.
        #[inline(always)]
        pub unsafe fn prepend_dentry(&mut self, entry: &co_re::dentry) -> Result<(), u32> {
            let name = core_read_kernel!(entry, d_name, name).ok_or(1u32)?;
            let len = core_read_kernel!(entry, d_name, len).ok_or(1u32)?;
            self.prepend_qstr_name(name, len)
        }

        /// Prepend a qstr name into the buffer (right-to-left).
        #[inline(always)]
        unsafe fn prepend_qstr_name(&mut self, name: *const u8, qstr_len: u32) -> Result<(), u32> {
            let left = self.space_left() as u32;
            let size = (qstr_len as u8) as u32;

            if qstr_len > MAX_NAME as u32 {
                return Err(1);
            }

            if left < qstr_len {
                return Err(1);
            }

            let i = left - size;
            if i as usize > self.buffer.len() {
                return Err(1);
            }

            let dst = &mut self.buffer[i as usize..];

            if gen::bpf_probe_read(
                dst.as_mut_ptr() as *mut _,
                cap_size(qstr_len, MAX_NAME as u32),
                name as *const _,
            ) >= 0
            {
                self.len += size;
                self.depth += 1;
            } else {
                return Err(1);
            }

            Ok(())
        }
    }
}
