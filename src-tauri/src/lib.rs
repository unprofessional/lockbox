mod settings;

use settings::Settings;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{Manager, State};

struct AppState {
    settings_path: PathBuf,
    settings: Mutex<Settings>,
}

// IPC surface (BRIEF §8). Every command here must also be listed in build.rs
// and granted in capabilities/default.json.

#[tauri::command]
fn is_locked() -> bool {
    // No vault until M2, so there is never anything unlocked.
    true
}

#[tauri::command]
fn settings_get(state: State<'_, AppState>) -> Settings {
    state.settings.lock().unwrap().clone()
}

#[tauri::command]
fn settings_set(state: State<'_, AppState>, settings: Settings) -> Result<Settings, String> {
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
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![is_locked, settings_get, settings_set])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
