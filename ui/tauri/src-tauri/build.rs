fn main() {
    // The app's own commands (src/main.rs): declared, so they get allow-*
    // permissions and only what capabilities/default.json grants may call
    // them.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(&[
        "daemon_status",
        "daemon_start",
        "daemon_stop",
        "daemon_restart",
        "daemon_log",
    ])))
    .expect("tauri build");
}
