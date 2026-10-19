use std::path::Path;
use std::process::Command;

fn main() {
    embed_build_info();

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
                "list_entries",
                "get_codes",
                "hotp_next",
                "entry_preview_uri",
                "entry_preview_manual",
                "entry_confirm",
                "edit_entry",
                "delete_entry",
                "settings_get",
                "settings_set",
                "app_info",
                "update_check",
                "update_install",
            ]),
        ),
    )
    .expect("failed to run tauri-build");
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Bakes in what the in-app updater needs (see src/update.rs): the commit this
/// build came from, the main repo checkout to update from, and the PATH the
/// build ran with (apps launched from Finder get a bare PATH with no cargo/npm).
fn embed_build_info() {
    let sha = git(&["rev-parse", "HEAD"]).unwrap_or_default();
    let dirty = git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty());
    // The common dir is the main repo's .git even when building from a worktree.
    let repo = git(&["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .and_then(|d| Path::new(&d).parent().map(|p| p.display().to_string()))
        .unwrap_or_default();

    println!("cargo:rustc-env=LOCKBOX_GIT_SHA={sha}");
    println!("cargo:rustc-env=LOCKBOX_GIT_DIRTY={dirty}");
    println!("cargo:rustc-env=LOCKBOX_REPO_DIR={repo}");
    println!(
        "cargo:rustc-env=LOCKBOX_BUILD_PATH={}",
        std::env::var("PATH").unwrap_or_default()
    );

    // Re-run when the checked-out commit or working tree changes.
    for p in ["HEAD", "index", "refs", "packed-refs"] {
        if let Some(path) = git(&["rev-parse", "--path-format=absolute", "--git-path", p]) {
            if Path::new(&path).exists() {
                println!("cargo:rerun-if-changed={path}");
            }
        }
    }
    println!("cargo:rerun-if-env-changed=PATH");
}
