use std::process::Command;

fn main() {
    // Secure Enclave key persistence exists only in CryptoKit, so an
    // irreducible sliver of Swift gets compiled into a static archive and
    // linked straight into the daemon. No second process, no shipped dylib —
    // the Swift runtime itself lives in /usr/lib/swift on every macOS.
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    let lib = format!("{out}/libkwse.a");

    let status = Command::new("swiftc")
        .args(["-O", "-emit-library", "-static", "-o", &lib, "kwse.swift"])
        .status()
        .expect("swiftc not found — Xcode command line tools are required");
    assert!(status.success(), "failed to compile kwse.swift");

    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=static=kwse");
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-arg=-L/usr/lib/swift");
    for f in ["CryptoKit", "LocalAuthentication", "Security", "Foundation"] {
        println!("cargo:rustc-link-lib=framework={f}");
    }
    for l in ["swiftCore", "swiftFoundation", "swiftDarwin", "swiftObjectiveC", "objc"] {
        println!("cargo:rustc-link-lib=dylib={l}");
    }
    println!("cargo:rerun-if-changed=kwse.swift");
}
