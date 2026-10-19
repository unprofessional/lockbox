//! Native macOS save panel for backups (BRIEF §7), run from Rust so the
//! webview never picks or sees a path to write to, and no dialog/fs plugin
//! is needed. Only the user can choose where a backup goes.

use objc2::MainThreadMarker;
use objc2_app_kit::{NSModalResponseOK, NSSavePanel};
use objc2_foundation::NSString;
use std::path::PathBuf;
use tauri::{AppHandle, Runtime};

/// Shows the save panel on the main thread and waits for the user.
/// `Ok(None)` if they cancelled.
pub fn choose_save_path<R: Runtime>(
    app: &AppHandle<R>,
    default_name: &str,
) -> Result<Option<PathBuf>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let name = default_name.to_string();
    app.run_on_main_thread(move || {
        let mtm = MainThreadMarker::new().expect("run_on_main_thread runs on the main thread");
        let panel = NSSavePanel::savePanel(mtm);
        panel.setNameFieldStringValue(&NSString::from_str(&name));
        panel.setCanCreateDirectories(true);
        panel.setMessage(Some(&NSString::from_str(
            "Save an encrypted lockbox backup. It opens with your current master password.",
        )));
        let path = (panel.runModal() == NSModalResponseOK)
            .then(|| panel.URL())
            .flatten()
            .and_then(|url| url.path())
            .map(|p| PathBuf::from(p.to_string()));
        let _ = tx.send(path);
    })
    .map_err(|e| format!("couldn't open the save dialog: {e}"))?;
    rx.recv()
        .map_err(|_| "the save dialog closed unexpectedly".to_string())
}
