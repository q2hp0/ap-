use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let lib_dir = match env::var("AP_LIB_DIR") {
        Ok(value) => PathBuf::from(value),
        Err(_) => manifest.join("../build"),
    };
    let lib_dir = lib_dir.canonicalize().unwrap_or(lib_dir);
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=apnet");
    println!("cargo:rustc-link-lib=static=apflow");
    println!("cargo:rustc-link-lib=static=apintrusion");
    println!("cargo:rustc-link-lib=static=apdestructive");
    println!("cargo:rustc-link-lib=static=apbeacon");
    println!("cargo:rustc-link-lib=static=aprisk");
    println!("cargo:rustc-link-lib=static=aptrace");
    println!("cargo:rustc-link-lib=static=apsys");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rerun-if-env-changed=AP_LIB_DIR");
    for name in [
        "libapnet.a",
        "libapflow.a",
        "libapintrusion.a",
        "libapdestructive.a",
        "libapbeacon.a",
        "libaprisk.a",
        "libaptrace.a",
        "libapsys.a",
    ] {
        println!("cargo:rerun-if-changed={}", lib_dir.join(name).display());
    }
}
