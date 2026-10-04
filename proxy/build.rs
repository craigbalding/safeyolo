use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=SAFEYOLO_BUILD_REVISION");
    let revision = env::var("SAFEYOLO_BUILD_REVISION")
        .unwrap_or_else(|_| "unknown".to_string())
        .to_ascii_lowercase();
    assert!(
        revision == "unknown"
            || ((revision.len() == 40 || revision.len() == 64)
                && revision.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "SAFEYOLO_BUILD_REVISION must be a full Git object ID"
    );
    println!("cargo:rustc-env=SAFEYOLO_BUILD_REVISION={revision}");
    let profile = env::var("PROFILE").expect("Cargo supplies the build profile");
    let profile = if profile == "release" {
        "production"
    } else {
        "debug"
    };
    println!("cargo:rustc-env=SAFEYOLO_BUILD_PROFILE={profile}");
}
