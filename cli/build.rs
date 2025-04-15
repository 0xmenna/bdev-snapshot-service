fn main() {
    // Tell cargo to rerun the build script if any file in "lib/" changes.
    println!("cargo:rerun-if-changed=user_lib/snapshot.h");
    println!("cargo:rerun-if-changed=user_lib/snapshot.c");

    // Compile the C library
    cc::Build::new()
        .include("user_lib")
        .file("user_lib/snapshot.c")
        .compile("snapshot");

    // Link the system zlib
    println!("cargo:rustc-link-lib=z");

    // Cargo will automatically link the produced static library
}
