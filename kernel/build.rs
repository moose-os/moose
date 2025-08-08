use std::{env, process::Command};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static=hypercall");
    println!("cargo::rerun-if-changed=src/driver/trampoline.asm");
    println!("cargo::rerun-if-changed=src/driver/hv/hyperv/hypercall.asm");

    let status = Command::new("nasm")
        .arg("-f")
        .arg("bin")
        .arg("-o")
        .arg(format!("{out_dir}/trampoline"))
        .arg("src/driver/trampoline.asm")
        .status()
        .expect("Failed to run nasm");

    if !status.success() {
        panic!("NASM failed with exit status {status}");
    }

    let status = Command::new("nasm")
        .arg("-f")
        .arg("elf64")
        .arg("-o")
        .arg(format!("{out_dir}/hypercall.o"))
        .arg("src/driver/hv/hyperv/hypercall.asm")
        .status()
        .expect("Failed to run nasm");

    if !status.success() {
        panic!("NASM failed with exit status {status}");
    }

    let status = Command::new("ar")
        .arg("rcs")
        .arg(format!("{out_dir}/libhypercall.a"))
        .arg(format!("{out_dir}/hypercall.o"))
        .status()
        .expect("Failed to run nasm");

    if !status.success() {
        panic!("NASM failed with exit status {status}");
    }
}
