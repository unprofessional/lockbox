mod otp;
mod settings;
mod update;
mod vault;

use aes_gcm::aead::Generate;
use otp::{ManualForm, NewEntry};
use serde::Serialize;
use settings::Settings;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, Manager, State};
use vault::{Entry, EntryMeta, KdfParams, Vault, VaultError};
use zeroize::Zeroizing;

struct AppState {
    settings_path: PathBuf,
    settings: Mutex<Settings>,
    vault_path: PathBuf,
    /// `None` = locked. Dropping the `Vault` zeroizes its key and entries.
    vault: Mutex<Option<Vault>>,
    /// A parsed account waiting for the user to confirm its preview. Holds a
    /// seed, so it's cleared on lock.
    pending: Mutex<Option<Pending>>,
    /// Bundled update-helper.sh; the only thing the app may run.
    update_helper: PathBuf,
    /// One update check or install at a time.
    update_busy: AtomicBool,
}

struct Pending {
    token: String,
    entry: NewEntry,
}

const LOCKED: &str = "vault is locked";

// IPC surface (BRIEF §8). Every command here must also be listed in build.rs
// and granted in capabilities/default.json, and classified in the contract
// tests below. Everything except vault_exists, is_locked, create_vault,
// unlock, lock, settings_get and app_info rejects while locked.
//
// Commands that derive keys or write the vault are async so the work runs off
// the main thread. Passwords are wrapped in `Zeroizing` as soon as they arrive.
// No command ever returns a seed.

/// Runs `f` on the unlocked vault, or fails with `LOCKED`.
fn with_vault<T>(
    state: &AppState,
    f: impl FnOnce(&mut Vault) -> Result<T, VaultError>,
) -> Result<T, String> {
    let mut guard = state.vault.lock().unwrap();
    let vault = guard.as_mut().ok_or(LOCKED)?;
    f(vault).map_err(|e| e.to_string())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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
    state.pending.lock().unwrap().take();
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

// ---- accounts and codes (BRIEF §7, §8) ----

#[tauri::command]
fn list_entries(state: State<'_, AppState>) -> Result<Vec<EntryMeta>, String> {
    with_vault(&state, |v| Ok(v.entries().iter().map(Entry::meta).collect()))
}

#[derive(Serialize)]
struct CodeOut {
    id: String,
    code: String,
    seconds_remaining: u64,
    period: u32,
}

/// Current codes for every TOTP account, all computed at one instant.
/// HOTP accounts are skipped; they produce codes on demand via `hotp_next`.
#[tauri::command]
fn get_codes(state: State<'_, AppState>) -> Result<Vec<CodeOut>, String> {
    let t = now();
    with_vault(&state, |v| {
        v.entries()
            .iter()
            .filter(|e| e.kind == otp::Kind::Totp)
            .map(|e| {
                Ok(CodeOut {
                    id: e.id.clone(),
                    code: e.totp_code(t).map_err(VaultError::Invalid)?,
                    seconds_remaining: otp::seconds_remaining(e.period, t),
                    period: e.period,
                })
            })
            .collect()
    })
}

/// The next HOTP code; advances and saves the counter.
#[tauri::command]
async fn hotp_next(state: State<'_, AppState>, id: String) -> Result<String, String> {
    with_vault(&state, |v| v.next_hotp(&id))
}

/// What the user confirms before an account is saved. No seed.
#[derive(Serialize)]
struct Preview {
    token: String,
    issuer: String,
    account: String,
    digits: u32,
    period: u32,
    algorithm: otp::Algo,
    kind: otp::Kind,
    counter: Option<u64>,
    /// Same issuer + account + seed already in the vault (BRIEF §7.5).
    duplicate: Option<EntryMeta>,
}

fn stage(state: &AppState, parsed: Result<NewEntry, String>) -> Result<Preview, String> {
    let duplicate = with_vault(state, |_| Ok(()))
        .and_then(|()| parsed)
        .and_then(|entry| {
            let dup = with_vault(state, |v| Ok(v.find_duplicate(&entry).map(Entry::meta)))?;
            Ok((entry, dup))
        });
    let (entry, duplicate) = duplicate?;
    let token: String = <[u8; 16]>::generate().iter().map(|b| format!("{b:02x}")).collect();
    let preview = Preview {
        token: token.clone(),
        issuer: entry.issuer.clone(),
        account: entry.account.clone(),
        digits: entry.digits,
        period: entry.period,
        algorithm: entry.algorithm,
        kind: entry.kind,
        counter: entry.counter,
        duplicate,
    };
    *state.pending.lock().unwrap() = Some(Pending { token, entry });
    Ok(preview)
}

/// Step 1 of adding from a link: parse and preview. Nothing is saved yet.
#[tauri::command]
fn entry_preview_uri(state: State<'_, AppState>, uri: String) -> Result<Preview, String> {
    let uri = Zeroizing::new(uri);
    stage(&state, otp::parse_uri(&uri))
}

/// Step 1 of adding by hand: validate and preview. Nothing is saved yet.
#[tauri::command]
fn entry_preview_manual(state: State<'_, AppState>, form: ManualForm) -> Result<Preview, String> {
    stage(&state, otp::from_manual(form))
}

/// Step 2: save the previewed account. With `replace`, a duplicate is
/// replaced; without it, adding a duplicate is refused.
#[tauri::command]
async fn entry_confirm(
    state: State<'_, AppState>,
    token: String,
    replace: bool,
) -> Result<String, String> {
    with_vault(&state, |_| Ok(()))?;
    let pending = {
        let mut guard = state.pending.lock().unwrap();
        match guard.take() {
            Some(p) if p.token == token => p,
            other => {
                *guard = other;
                return Err("This preview has expired. Add the account again.".into());
            }
        }
    };
    with_vault(&state, |v| {
        let dup = v.find_duplicate(&pending.entry).map(|e| e.id.clone());
        match (dup, replace) {
            (Some(_), false) => Err(VaultError::Invalid(
                "This account is already in your vault.".into(),
            )),
            (dup, _) => v.add(&pending.entry, dup.as_deref()),
        }
    })
}

#[tauri::command]
async fn edit_entry(
    state: State<'_, AppState>,
    id: String,
    issuer: String,
    account: String,
    tags: Vec<String>,
) -> Result<(), String> {
    with_vault(&state, |v| v.edit(&id, &issuer, &account, tags))
}

#[tauri::command]
async fn delete_entry(state: State<'_, AppState>, id: String) -> Result<(), String> {
    with_vault(&state, |v| v.delete(&id))
}

// ---- settings ----

/// Allowed while locked: the lock screen needs the theme, and settings hold
/// nothing secret.
#[tauri::command]
fn settings_get(state: State<'_, AppState>) -> Settings {
    state.settings.lock().unwrap().clone()
}

#[tauri::command]
fn settings_set(state: State<'_, AppState>, settings: Settings) -> Result<Settings, String> {
    with_vault(&state, |_| Ok(()))?;
    settings.validate()?;
    settings::save(&state.settings_path, &settings)
        .map_err(|e| format!("could not save settings: {e}"))?;
    *state.settings.lock().unwrap() = settings.clone();
    Ok(settings)
}

// ---- updates ----

/// Version and the commit this build came from. Nothing secret.
#[tauri::command]
fn app_info<R: tauri::Runtime>(app: AppHandle<R>) -> update::AppInfo {
    update::app_info(app.package_info().version.to_string())
}

/// Runs `f` while holding the single update slot. Requires an unlocked vault;
/// with `password`, also requires it to be the master password.
fn with_update_slot<T>(
    state: &AppState,
    password: Option<&str>,
    f: impl FnOnce(&std::path::Path) -> Result<T, String>,
) -> Result<T, String> {
    {
        let guard = state.vault.lock().unwrap();
        let vault = guard.as_ref().ok_or(LOCKED)?;
        if let Some(pw) = password {
            vault.verify_password(pw).map_err(|e| match e {
                VaultError::WrongPassword => "Wrong password.".to_string(),
                e => e.to_string(),
            })?;
        }
    }
    if state.update_busy.swap(true, Ordering::SeqCst) {
        return Err("an update check or install is already running".into());
    }
    let result = f(&state.update_helper);
    state.update_busy.store(false, Ordering::SeqCst);
    result
}

/// Fetches master (via git, in the bundled helper) and compares it with the
/// commit this build came from.
#[tauri::command]
async fn update_check(state: State<'_, AppState>) -> Result<update::CheckResult, String> {
    with_update_slot(&state, None, update::check)
}

/// Builds master and installs it. Installing new code needs fresh proof of the
/// master password, not just an unlocked session (BRIEF §9, desktop agents).
/// On success the app is quit and relaunched by the release script, so this
/// only returns on failure.
#[tauri::command]
async fn update_install(state: State<'_, AppState>, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    with_update_slot(&state, Some(&password), update::install)
}

fn app_state(dir: PathBuf, update_helper: PathBuf) -> AppState {
    let settings_path = dir.join("settings.json");
    let settings = settings::load(&settings_path);
    AppState {
        settings_path,
        settings: Mutex::new(settings),
        vault_path: dir.join("vault.enc"),
        vault: Mutex::new(None),
        pending: Mutex::new(None),
        update_helper,
        update_busy: AtomicBool::new(false),
    }
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
            let helper = app.path().resource_dir()?.join(update::HELPER);
            app.manage(app_state(dir, helper));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            is_locked,
            create_vault,
            unlock,
            lock,
            change_password,
            list_entries,
            get_codes,
            hotp_next,
            entry_preview_uri,
            entry_preview_manual,
            entry_confirm,
            edit_entry,
            delete_entry,
            settings_get,
            settings_set,
            app_info,
            update_check,
            update_install
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// IPC contract (BRIEF §12): every command is classified, and every command
/// outside the allow-list refuses to run while the vault is locked.
#[cfg(test)]
mod contract_tests {
    use super::*;
    use tauri::async_runtime::block_on;
    use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};

    /// Commands that may run while locked.
    const OPEN: &[&str] = &[
        "vault_exists",
        "is_locked",
        "create_vault",
        "unlock",
        "lock",
        "settings_get",
        "app_info",
    ];
    /// Commands that must reject while locked (each exercised below).
    const GUARDED: &[&str] = &[
        "change_password",
        "list_entries",
        "get_codes",
        "hotp_next",
        "entry_preview_uri",
        "entry_preview_manual",
        "entry_confirm",
        "edit_entry",
        "delete_entry",
        "settings_set",
        "update_check",
        "update_install",
    ];
    const URI: &str = "otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP";

    fn app(dir: &std::path::Path) -> tauri::App<MockRuntime> {
        let app = mock_builder().build(mock_context(noop_assets())).unwrap();
        app.manage(app_state(dir.to_path_buf(), dir.join("no-helper.sh")));
        app
    }

    fn form() -> ManualForm {
        ManualForm {
            issuer: "Acme".into(),
            account: "me".into(),
            seed: "JBSWY3DPEHPK3PXP".into(),
            digits: None,
            period: None,
            algorithm: None,
            kind: None,
            counter: None,
        }
    }

    #[test]
    fn every_command_is_classified() {
        let build_rs = include_str!("../build.rs");
        let start = build_rs.find(".commands(&[").unwrap();
        let end = start + build_rs[start..].find("])").unwrap();
        let declared: Vec<&str> = build_rs[start..end]
            .split('"')
            .skip(1)
            .step_by(2)
            .collect();
        let mut classified: Vec<&str> = OPEN.iter().chain(GUARDED).copied().collect();
        let mut declared_sorted = declared.clone();
        classified.sort();
        declared_sorted.sort();
        assert_eq!(declared_sorted, classified, "build.rs commands vs OPEN + GUARDED");

        let caps = include_str!("../capabilities/default.json");
        for cmd in &declared {
            let perm = format!("\"allow-{}\"", cmd.replace('_', "-"));
            assert!(caps.contains(&perm), "{perm} missing from capabilities");
        }
    }

    #[test]
    fn guarded_commands_reject_while_locked() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(dir.path());
        let s = || app.state::<AppState>();
        fn locked<T>(name: &str, r: Result<T, String>) {
            assert_eq!(r.err().as_deref(), Some(LOCKED), "{name} ran while locked");
        }
        let pw = || "correct horse battery".to_string();

        locked("change_password", block_on(change_password(s(), pw(), pw())));
        locked("list_entries", list_entries(s()));
        locked("get_codes", get_codes(s()));
        locked("hotp_next", block_on(hotp_next(s(), "x".into())));
        locked("entry_preview_uri", entry_preview_uri(s(), URI.into()));
        locked("entry_preview_manual", entry_preview_manual(s(), form()));
        locked("entry_confirm", block_on(entry_confirm(s(), "t".into(), false)));
        locked(
            "edit_entry",
            block_on(edit_entry(s(), "x".into(), "a".into(), "b".into(), vec![])),
        );
        locked("delete_entry", block_on(delete_entry(s(), "x".into())));
        locked("settings_set", settings_set(s(), Settings::default()));
        locked("update_check", block_on(update_check(s())));
        locked("update_install", block_on(update_install(s(), pw())));
        assert_eq!(GUARDED.len(), 12, "exercise every GUARDED command above");
    }

    #[test]
    fn open_commands_work_while_locked() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(dir.path());
        let s = || app.state::<AppState>();
        assert!(is_locked(s()));
        assert!(!block_on(vault_exists(s())).unwrap());
        let _ = settings_get(s());
        let _ = app_info(app.handle().clone());
        lock(s());
    }

    #[test]
    fn add_flow_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(dir.path());
        let s = || app.state::<AppState>();
        // Fast KDF so the test doesn't pay for Argon2id at full strength.
        *s().vault.lock().unwrap() = Some(
            Vault::create(
                &dir.path().join("vault.enc"),
                "correct horse battery",
                KdfParams { m_kib: 64, t: 1, p: 1 },
            )
            .unwrap(),
        );

        let p = entry_preview_uri(s(), URI.into()).unwrap();
        assert_eq!((p.issuer.as_str(), p.account.as_str()), ("Acme", "me"));
        assert!(p.duplicate.is_none());
        assert!(block_on(entry_confirm(s(), "wrong-token".into(), false)).is_err());
        let id = block_on(entry_confirm(s(), p.token.clone(), false)).unwrap();
        assert!(
            block_on(entry_confirm(s(), p.token, false)).is_err(),
            "a token works once"
        );

        let listed = list_entries(s()).unwrap();
        assert_eq!(listed.len(), 1);
        let json = serde_json::to_string(&listed).unwrap();
        assert!(!json.contains("JBSWY3DP"), "no seed in list_entries");
        let codes = get_codes(s()).unwrap();
        assert_eq!(codes.len(), 1);
        assert_eq!(codes[0].code.len(), 6);
        assert!(!serde_json::to_string(&codes).unwrap().contains("JBSWY3DP"), "no seed in get_codes");

        // Same account again is flagged; confirming without replace is refused.
        let p2 = entry_preview_manual(s(), form()).unwrap();
        assert_eq!(p2.duplicate.as_ref().map(|d| d.id.as_str()), Some(id.as_str()));
        assert!(block_on(entry_confirm(s(), p2.token.clone(), false)).is_err());
        let p3 = entry_preview_manual(s(), form()).unwrap();
        block_on(entry_confirm(s(), p3.token, true)).unwrap();
        assert_eq!(list_entries(s()).unwrap().len(), 1);

        // Locking drops any pending preview.
        let p4 = entry_preview_uri(s(), URI.into()).unwrap();
        lock(s());
        assert!(s().pending.lock().unwrap().is_none());
        let _ = p4;
    }
}
