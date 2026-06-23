use std::path::Path;
use std::process::Command;

fn bindgen_shim<P: AsRef<Path>, Q: AsRef<Path>>(file: P, out_dir: Q) {
    let out_file = out_dir.as_ref().join("gen.rs");

    let bindings = bindgen::builder()
        .header(file.as_ref().to_string_lossy())
        .layout_tests(false)
        .use_core()
        .allowlist_function("shim_.*")
        .size_t_is_usize(false)
        .clang_arg("-I/usr/include/aarch64-linux-gnu")
        .clang_arg("-target")
        .clang_arg("bpf")
        .generate()
        .expect("failed to generate CO-RE bindings");

    std::fs::create_dir_all(&out_dir).expect("failed to create CO-RE output directory");

    bindings
        .write_to_file(out_file)
        .expect("failed to write generated bindings");
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let shim_dir = Path::new("src/co_re/c-bindings");
    let shim_file = shim_dir.join("shim.c");

    // Generate Rust bindings from C shim
    bindgen_shim(&shim_file, "src/co_re");

    // Only compile C shim when targeting BPF
    if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default() == "bpf" {
        let status = Command::new("clang")
            .arg("-I")
            .arg("src/")
            .arg("-I")
            .arg("/usr/include/aarch64-linux-gnu")
            .arg("-O2")
            .arg("-emit-llvm")
            .arg("-target")
            .arg("bpf")
            .arg("-c")
            .arg("-g")
            .arg(&shim_file)
            .arg("-o")
            .arg(format!("{out_dir}/c-shim.o"))
            .status()
            .expect("failed to compile C shim with clang");

        if !status.success() {
            panic!("C shim compilation failed");
        }

        println!("cargo:rustc-link-search=native={out_dir}");
        println!("cargo:rustc-link-lib=link-arg={out_dir}/c-shim.o");
    }

    println!("cargo:rerun-if-changed={}", shim_file.to_string_lossy());
}
