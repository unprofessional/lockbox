fn main() {
    // Every app command must be listed here; each one then needs an explicit
    // `allow-*` permission in capabilities/default.json before the webview can
    // call it. This keeps the IPC surface (BRIEF §8) enumerable in one place.
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(
            tauri_build::AppManifest::new().commands(&[
                "vault_exists",
                "is_locked",
                "create_vault",
                "unlock",
                "lock",
                "change_password",
                "settings_get",
                "settings_set",
            ]),
        ),
    )
    .expect("failed to run tauri-build");
}
