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
