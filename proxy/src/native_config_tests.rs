use crate::native_config;

#[test]
fn config_paths_belong_to_the_selected_root_and_replaced_choices_are_named() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(
        &path,
        "admin_port=0\n[[listeners]]\nagent_id='alice'\nsocket_path='data/alice.sock'\n",
    )
    .unwrap();
    let config = native_config::read(&path).unwrap();
    assert!(config.native_product);
    assert_eq!(
        config.policy_file.unwrap(),
        directory.path().join("policy.toml")
    );
    assert_eq!(
        config.listeners[0].socket_path,
        directory.path().join("data/alice.sock")
    );
    for key in [
        "addons",
        "network_guard_block",
        "credguard_block",
        "native_product",
    ] {
        std::fs::write(&path, format!("{key}=false\n")).unwrap();
        assert!(
            native_config::read(&path)
                .unwrap_err()
                .to_string()
                .contains(key)
        );
    }
}
