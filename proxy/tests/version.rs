#[test]
fn version_reports_the_compiled_source_and_profile() {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo-proxy"))
        .arg("--version")
        .output()
        .expect("run the built proxy");
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).expect("UTF-8 version");
    assert!(text.contains(&format!("commit={}", env!("SAFEYOLO_BUILD_REVISION"))));
    assert!(text.contains(&format!("profile={}", env!("SAFEYOLO_BUILD_PROFILE"))));
}

#[test]
fn guest_build_script_stamps_identity_without_proxy_dependencies() {
    let guest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("guest/command");
    let scratch = tempfile::tempdir().unwrap();
    let executable = scratch.path().join("guest-build-script");
    let compiled = std::process::Command::new("rustc")
        .current_dir(&guest)
        .args(["--edition=2024", "build.rs", "-o"])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let revision = "0123456789abcdef0123456789abcdef01234567";
    for (profile, expected) in [("debug", "debug"), ("release", "production")] {
        let output = std::process::Command::new(&executable)
            .current_dir(&guest)
            .env("SAFEYOLO_BUILD_REVISION", revision)
            .env("PROFILE", profile)
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains(&format!(
            "cargo:rustc-env=SAFEYOLO_BUILD_REVISION={revision}"
        )));
        assert!(text.contains(&format!(
            "cargo:rustc-env=SAFEYOLO_BUILD_PROFILE={expected}"
        )));
        assert!(!text.contains("SAFEYOLO_DEFINITION_VERSION"));
    }
    let invalid = std::process::Command::new(executable)
        .current_dir(guest)
        .env("SAFEYOLO_BUILD_REVISION", "short-id")
        .env("PROFILE", "debug")
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("must be a full Git object ID"));
}

#[inline(never)]
fn controlled_panic() {
    panic!("controlled production backtrace probe");
}

#[test]
fn panic_backtrace_has_function_file_and_line() {
    const CHILD: &str = "SAFEYOLO_TEST_BACKTRACE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        controlled_panic();
    }
    // Run the same compiled test in a child so its expected panic cannot pass
    // merely because the test harness caught it. No running proxy is involved.
    let result = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "panic_backtrace_has_function_file_and_line",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("RUST_BACKTRACE", "1")
        .output()
        .expect("run the controlled panic");
    assert_eq!(result.status.code(), Some(101));
    let stderr = String::from_utf8(result.stderr).expect("UTF-8 backtrace");
    let frame =
        regex::Regex::new(r"(?m)version::controlled_panic\n\s+at .*tests/version\.rs:[1-9][0-9]*")
            .expect("backtrace frame pattern");
    assert!(
        frame.is_match(&stderr),
        "missing function/file/line frame: {stderr}"
    );
}
