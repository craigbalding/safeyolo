#[path = "../scripts/rust_build_identity.rs"]
mod build_identity;

fn main() {
    build_identity::emit();
    println!(
        "cargo:rustc-env=SAFEYOLO_HOST_EXECUTOR_TARGET={}",
        std::env::var("TARGET").expect("Cargo supplies the target")
    );
}
