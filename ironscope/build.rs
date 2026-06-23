use aya_build::{build_ebpf, Package, Toolchain};
use std::path::Path;

fn main() {
    build_ebpf(
        [Package {
            name: "ironscope-ebpf",
            root_dir: "../ironscope-ebpf",
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Nightly,
    )
    .expect("failed to build eBPF programs");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let src = Path::new(&out_dir).join("ironscope");
    let workspace_root = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    let dst_dir = workspace_root.join("target/bpfel-unknown-none/release");
    if src.exists() {
        std::fs::create_dir_all(&dst_dir).ok();
        std::fs::copy(&src, dst_dir.join("ironscope")).ok();
    }
}
