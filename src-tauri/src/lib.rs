mod settings;
mod vault;

use settings::Settings;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{Manager, State};
use vault::{KdfParams, Vault, VaultError};
use zeroize::Zeroizing;

struct AppState {
    settings_path: PathBuf,
    settings: Mutex<Settings>,
    vault_path: PathBuf,
    /// `None` = locked. Dropping the `Vault` zeroizes its key and entries.
    vault: Mutex<Option<Vault>>,
}

const LOCKED: &str = "vault is locked";

// IPC surface (BRIEF §8). Every command here must also be listed in build.rs
// and granted in capabilities/default.json. Everything except vault_exists,
// is_locked, create_vault, unlock and settings_get rejects while locked.
//
// Vault commands are async so the ~0.3s Argon2id derivation runs off the main
// thread and the window stays responsive. Passwords are wrapped in
// `Zeroizing` as soon as they arrive.

#[tauri::command]
async fn vault_exists(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(Vault::exists(&state.vault_path))
}

#[tauri::command]
fn is_locked(state: State<'_, AppState>) -> bool {
    state.vault.lock().unwrap().is_none()
}

#[tauri::command]
async fn create_vault(state: State<'_, AppState>, password: String) -> Result<bool, String> {
    let password = Zeroizing::new(password);
    let vault = Vault::create(&state.vault_path, &password, KdfParams::DEFAULT)
        .map_err(|e| e.to_string())?;
    *state.vault.lock().unwrap() = Some(vault);
    Ok(true)
}

/// `Ok(false)` for a wrong password; `Err` for anything else (missing,
/// tampered or unreadable vault).
#[tauri::command]
async fn unlock(state: State<'_, AppState>, password: String) -> Result<bool, String> {
    let password = Zeroizing::new(password);
    match Vault::unlock(&state.vault_path, &password) {
        Ok(vault) => {
            *state.vault.lock().unwrap() = Some(vault);
            Ok(true)
        }
        Err(VaultError::WrongPassword) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn lock(state: State<'_, AppState>) {
    state.vault.lock().unwrap().take();
}

/// `Ok(false)` if `old` is wrong.
#[tauri::command]
async fn change_password(
    state: State<'_, AppState>,
    old: String,
    new: String,
) -> Result<bool, String> {
    let (old, new) = (Zeroizing::new(old), Zeroizing::new(new));
    let mut guard = state.vault.lock().unwrap();
    let vault = guard.as_mut().ok_or(LOCKED)?;
    match vault.change_password(&old, &new) {
        Ok(()) => Ok(true),
        Err(VaultError::WrongPassword) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

/// Allowed while locked: the lock screen needs the theme, and settings hold
/// nothing secret.
#[tauri::command]
fn settings_get(state: State<'_, AppState>) -> Settings {
    state.settings.lock().unwrap().clone()
}

#[tauri::command]
fn settings_set(state: State<'_, AppState>, settings: Settings) -> Result<Settings, String> {
    if state.vault.lock().unwrap().is_none() {
        return Err(LOCKED.into());
    }
    settings.validate()?;
    settings::save(&state.settings_path, &settings)
        .map_err(|e| format!("could not save settings: {e}"))?;
    *state.settings.lock().unwrap() = settings.clone();
    Ok(settings)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // ~/Library/Application Support/lockbox (BRIEF §6.1), not the
            // identifier-named dir Tauri would pick by default.
            let dir = app
                .path()
                .home_dir()?
                .join("Library/Application Support/lockbox");
            let settings_path = dir.join("settings.json");
            let settings = settings::load(&settings_path);
            app.manage(AppState {
                settings_path,
                settings: Mutex::new(settings),
                vault_path: dir.join("vault.enc"),
                vault: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            is_locked,
            create_vault,
            unlock,
            lock,
            change_password,
            settings_get,
            settings_set
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
