fn main() {
    // Tell cargo to rerun the build script if any file in "lib/" changes.
    println!("cargo:rerun-if-changed=lib/snapshot.h");
    println!("cargo:rerun-if-changed=lib/snapshot_ioctl.c");

    // Compile the C library
    cc::Build::new()
        .include("lib")
        .file("lib/snapshot.c")
        .compile("snapshot");

    // Cargo will automatically link the produced static library
}
