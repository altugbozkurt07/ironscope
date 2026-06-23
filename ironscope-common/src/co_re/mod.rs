#[allow(non_camel_case_types, dead_code, non_upper_case_globals)]
mod gen;

/// Core wrapper for CO-RE kernel type pointers.
#[derive(Clone, Copy)]
pub struct Core<T> {
    ptr: *const T,
}

impl<T> Core<T> {
    #[inline(always)]
    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }

    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }

    pub fn as_ptr_mut(&self) -> *mut T {
        self.ptr as *mut _
    }

    pub fn from_ptr(ptr: *const T) -> Self {
        Core { ptr }
    }
}

impl<T> PartialEq for Core<T> {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr
    }
}

impl<T> Eq for Core<T> {}

/// Macro to implement a CO-RE field accessor via the C shim.
macro_rules! rust_shim_kernel_impl {
    ($pub:vis, $fn_name:ident, $struct:ident, $member:ident, $ret:ty) => {
        #[inline(always)]
        $pub unsafe fn $fn_name(&self) -> Option<$ret> {
            if !self.is_null()
                && paste::paste! { gen::[<shim_ $struct _ $member _exists>] }(self.as_ptr_mut())
            {
                return Some(
                    paste::paste! { gen::[<shim_ $struct _ $member>] }(self.as_ptr_mut()).into(),
                );
            }
            None
        }
    };
    // Shorthand: function name == member name
    ($struct:ident, $member:ident, $ret:ty) => {
        rust_shim_kernel_impl!(pub, $member, $struct, $member, $ret);
    };
}

// ---- task_struct ----
pub type task_struct = Core<gen::task_struct>;

impl task_struct {
    #[inline(always)]
    pub unsafe fn from_ctx_arg(ptr: *mut core::ffi::c_void) -> Self {
        Self::from_ptr(ptr as *const _)
    }

    rust_shim_kernel_impl!(task_struct, pid, i32);
    rust_shim_kernel_impl!(task_struct, tgid, i32);
    rust_shim_kernel_impl!(task_struct, flags, u32);
    rust_shim_kernel_impl!(task_struct, real_parent, task_struct);
    rust_shim_kernel_impl!(task_struct, group_leader, task_struct);
    rust_shim_kernel_impl!(task_struct, mm, mm_struct);

    #[inline(always)]
    pub unsafe fn comm(&self) -> Option<*mut u8> {
        if !self.is_null() && gen::shim_task_struct_comm_exists(self.as_ptr_mut()) {
            Some(gen::shim_task_struct_comm(self.as_ptr_mut()))
        } else {
            None
        }
    }

    #[inline(always)]
    pub unsafe fn comm_array(&self) -> Option<[u8; 16]> {
        let comm_ptr = self.comm()?;
        let mut comm = [0u8; 16];
        if bpf_probe_read_kernel(
            comm.as_mut_ptr() as *mut core::ffi::c_void,
            16,
            comm_ptr as *const core::ffi::c_void,
        ) < 0
        {
            return None;
        }
        Some(comm)
    }
}

impl From<*mut gen::task_struct> for task_struct {
    fn from(ptr: *mut gen::task_struct) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- mm_struct ----
pub type mm_struct = Core<gen::mm_struct>;

impl mm_struct {
    rust_shim_kernel_impl!(mm_struct, arg_start, u64);
    rust_shim_kernel_impl!(mm_struct, arg_end, u64);
    rust_shim_kernel_impl!(mm_struct, exe_file, file);

    #[inline(always)]
    pub unsafe fn arg_len(&self) -> Option<u64> {
        let start = self.arg_start()?;
        let end = self.arg_end()?;
        Some(if end == 0 || start >= end {
            0
        } else {
            end - start
        })
    }
}

impl From<*mut gen::mm_struct> for mm_struct {
    fn from(ptr: *mut gen::mm_struct) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- super_block ----
pub type super_block = Core<gen::super_block>;

impl super_block {
    rust_shim_kernel_impl!(super_block, s_dev, u64);
    rust_shim_kernel_impl!(super_block, s_root, dentry);
}

impl From<*mut gen::super_block> for super_block {
    fn from(ptr: *mut gen::super_block) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- inode ----
pub type inode = Core<gen::inode>;

impl inode {
    rust_shim_kernel_impl!(inode, i_ino, u64);
    rust_shim_kernel_impl!(inode, i_mode, u16);
    rust_shim_kernel_impl!(inode, i_sb, super_block);
}

impl From<*mut gen::inode> for inode {
    fn from(ptr: *mut gen::inode) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- qstr ----
pub type qstr = Core<gen::qstr>;

impl qstr {
    rust_shim_kernel_impl!(qstr, name, *const u8);
    rust_shim_kernel_impl!(qstr, hash_len, u64);

    /// Extract length from hash_len (upper 32 bits).
    #[inline(always)]
    pub unsafe fn len(&self) -> Option<u32> {
        Some((self.hash_len()? >> 32) as u32)
    }
}

impl From<*mut gen::qstr> for qstr {
    fn from(ptr: *mut gen::qstr) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- dentry ----
pub type dentry = Core<gen::dentry>;

impl dentry {
    rust_shim_kernel_impl!(dentry, d_flags, u32);
    rust_shim_kernel_impl!(dentry, d_parent, dentry);
    rust_shim_kernel_impl!(dentry, d_sb, super_block);
    rust_shim_kernel_impl!(dentry, d_inode, inode);

    #[inline(always)]
    pub unsafe fn d_name(&self) -> Option<qstr> {
        if !self.is_null() && gen::shim_dentry_d_name_exists(self.as_ptr_mut()) {
            Some(qstr::from_ptr(
                gen::shim_dentry_d_name(self.as_ptr_mut()) as *const _
            ))
        } else {
            None
        }
    }
}

impl From<*mut gen::dentry> for dentry {
    fn from(ptr: *mut gen::dentry) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- path ----
pub type path = Core<gen::path>;

impl path {
    rust_shim_kernel_impl!(path, mnt, vfsmount);
    rust_shim_kernel_impl!(path, dentry, dentry);
}

impl From<*mut gen::path> for path {
    fn from(ptr: *mut gen::path) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- vfsmount ----
pub type vfsmount = Core<gen::vfsmount>;

impl vfsmount {
    rust_shim_kernel_impl!(vfsmount, mnt_root, dentry);

    /// Get the containing mount struct (container_of).
    #[inline(always)]
    pub unsafe fn mount(&self) -> mount {
        mount::from_ptr(gen::shim_mount_from_vfsmount(self.as_ptr_mut()))
    }
}

impl From<*mut gen::vfsmount> for vfsmount {
    fn from(ptr: *mut gen::vfsmount) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- mount ----
pub type mount = Core<gen::mount>;

impl mount {
    rust_shim_kernel_impl!(mount, mnt_parent, mount);
    rust_shim_kernel_impl!(mount, mnt_mountpoint, dentry);

    #[inline(always)]
    pub unsafe fn mnt(&self) -> Option<vfsmount> {
        if !self.is_null() && gen::shim_mount_mnt_exists(self.as_ptr_mut()) {
            Some(vfsmount::from_ptr(
                gen::shim_mount_mnt(self.as_ptr_mut()) as *const _
            ))
        } else {
            None
        }
    }
}

impl From<*mut gen::mount> for mount {
    fn from(ptr: *mut gen::mount) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- file ----
pub type file = Core<gen::file>;

impl file {
    rust_shim_kernel_impl!(file, f_inode, inode);
    rust_shim_kernel_impl!(file, f_flags, u32);

    #[inline(always)]
    pub unsafe fn f_path(&self) -> Option<path> {
        if !self.is_null() && gen::shim_file_f_path_exists(self.as_ptr_mut()) {
            Some(path::from_ptr(
                gen::shim_file_f_path(self.as_ptr_mut()) as *const _
            ))
        } else {
            None
        }
    }
}

impl From<*mut gen::file> for file {
    fn from(ptr: *mut gen::file) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- linux_binprm ----
pub type linux_binprm = Core<gen::linux_binprm>;

impl linux_binprm {
    rust_shim_kernel_impl!(linux_binprm, file, file);
}

impl From<*mut gen::linux_binprm> for linux_binprm {
    fn from(ptr: *mut gen::linux_binprm) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- sockaddr ----
pub type sockaddr = Core<gen::sockaddr>;

impl sockaddr {
    rust_shim_kernel_impl!(sockaddr, sa_family, u16);
}

impl From<*mut gen::sockaddr> for sockaddr {
    fn from(ptr: *mut gen::sockaddr) -> Self {
        Self::from_ptr(ptr)
    }
}

// ---- sockaddr_in ----
pub type sockaddr_in = Core<gen::sockaddr_in>;

impl sockaddr_in {
    rust_shim_kernel_impl!(sockaddr_in, sin_family, u16);
    rust_shim_kernel_impl!(sockaddr_in, sin_port, u16);

    #[inline(always)]
    pub unsafe fn sin_addr(&self) -> Option<u32> {
        if !self.is_null() && gen::shim_sockaddr_in_s_addr_exists(self.as_ptr_mut()) {
            Some(gen::shim_sockaddr_in_s_addr(self.as_ptr_mut()) as u32)
        } else {
            None
        }
    }
}

impl From<*mut gen::sockaddr_in> for sockaddr_in {
    fn from(ptr: *mut gen::sockaddr_in) -> Self {
        Self::from_ptr(ptr)
    }
}

/// Chain CO-RE field accesses with automatic Option propagation.
#[macro_export]
macro_rules! core_read_kernel {
    ($struc:expr, $field:ident) => {
        $struc.$field()
    };
    ($struc:expr, $first:ident, $($rest:ident),+) => {
        $struc.$first()
            $(.and_then(|r| r.$rest()))+
    };
}

// BPF helper for kernel memory reads (used by comm_array and path resolution).
use aya_ebpf::helpers::gen::bpf_probe_read_kernel;
