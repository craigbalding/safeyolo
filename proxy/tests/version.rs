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
