#![cfg_attr(target_arch = "bpf", no_std)]
#![allow(macro_expanded_macro_exports_accessed_by_absolute_paths)]

pub mod buffer;
pub mod path;
pub mod types;
pub mod utils;

cfg_if::cfg_if! {
    if #[cfg(target_arch = "bpf")] {
        pub mod co_re;
    }
}
