//! Keep the native proxy's three former host seams free of a Python runtime.

#[test]
fn production_host_seams_do_not_dispatch_an_installed_python_module() {
    let sources = [
        ("provider_stream", include_str!("../src/provider_stream.rs")),
        ("desktop_present", include_str!("../src/desktop_present.rs")),
        ("command_centre", include_str!("../src/command_centre.rs")),
        ("host_platform", include_str!("../src/host_platform.rs")),
        ("host_lifecycle", include_str!("../src/host_lifecycle.rs")),
        ("desktop_preview", include_str!("../src/desktop_preview.rs")),
        ("tailnet", include_str!("../src/tailnet.rs")),
    ];
    for (name, source) in sources {
        for forbidden in [
            "SAFEYOLO_PROVIDER_PYTHON",
            "SAFEYOLO_DESKTOP_PRESENTER_PYTHON",
            "SAFEYOLO_OPERATOR_HOST_PYTHON",
            "safeyolo.provider_stream",
            "safeyolo.desktop_presenter_rpc",
            "safeyolo.command_centre_agent_host",
            "safeyolo.command_centre_tailnet_host",
            "Command::new(\"python",
            "Command::new(\"/usr/bin/python",
            ".arg(\"-m\")",
        ] {
            assert!(!source.contains(forbidden), "{name} contains {forbidden}");
        }
    }
}
