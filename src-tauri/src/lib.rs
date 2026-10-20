mod backoff;
mod clipboard;
mod otp;
mod panel;
mod qr;
mod secure_enclave;
mod settings;
mod system;
mod update;
mod vault;

use aes_gcm::aead::Generate;
use otp::{ManualForm, NewEntry};
use serde::Serialize;
use settings::Settings;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tauri::ipc::{InvokeBody, Request};
use tauri::{AppHandle, Manager, Runtime, State};
use vault::{Entry, EntryMeta, ImportSummary, KdfParams, Vault, VaultError};
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
    /// A backup file the user picked, waiting for its password. Encrypted,
    /// but cleared on lock all the same.
    pending_import: Mutex<Option<(String, Vec<u8>)>>,
    /// Shared by every master-password check (BRIEF §9, M6).
    backoff: Mutex<backoff::Backoff>,
    /// Our latest clipboard write, so locking can clear it if it's still there.
    last_copy: Mutex<Option<clipboard::Stamp>>,
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

fn token() -> String {
    <[u8; 16]>::generate().iter().map(|b| format!("{b:02x}")).collect()
}

/// File bytes sent as a raw invoke body (not JSON), e.g. `invoke(cmd, uint8Array)`.
fn raw_body(request: &Request<'_>) -> Result<Vec<u8>, String> {
    match request.body() {
        InvokeBody::Raw(bytes) => Ok(bytes.clone()),
        InvokeBody::Json(_) => Err("expected file contents".into()),
    }
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

#[derive(Serialize, Default, Debug)]
struct UnlockOutcome {
    unlocked: bool,
    /// Seconds before another password may be tried (backoff), 0 if none.
    retry_after_secs: u64,
    /// The vault file couldn't be opened for a reason other than the password.
    problem: Option<String>,
    /// `problem` is one that restoring vault.enc.bak may fix.
    can_restore: bool,
    /// Touch ID unlock didn't work (not shown for a cancelled prompt).
    touch_id_error: Option<String>,
}

const TOO_MANY: &str = "Too many wrong passwords.";

fn wait_message(wait: u64) -> String {
    format!("{TOO_MANY} Try again in {wait} s.")
}

/// Runs one password check under the shared backoff: refuses while waiting,
/// counts wrong passwords, resets on a right one.
fn guarded_check<T>(
    state: &AppState,
    check: impl FnOnce() -> Result<T, VaultError>,
) -> Result<Result<T, VaultError>, u64> {
    let wait = state.backoff.lock().unwrap().wait_secs(Instant::now());
    if wait > 0 {
        return Err(wait);
    }
    let result = check();
    let mut backoff = state.backoff.lock().unwrap();
    match &result {
        Ok(_) => backoff.record_success(),
        Err(VaultError::WrongPassword) => backoff.record_failure(Instant::now()),
        Err(_) => {}
    }
    Ok(result)
}

/// Checks the master password against the unlocked vault (export, update).
fn check_master(state: &AppState, vault: &Vault, password: &str) -> Result<(), String> {
    match guarded_check(state, || vault.verify_password(password)) {
        Err(wait) => Err(wait_message(wait)),
        Ok(Ok(())) => Ok(()),
        Ok(Err(VaultError::WrongPassword)) => Err("Wrong password.".into()),
        Ok(Err(e)) => Err(e.to_string()),
    }
}

/// A wrong password, a backoff wait and a damaged vault all come back as an
/// `UnlockOutcome`; `Err` is only for unexpected I/O failures.
#[tauri::command]
async fn unlock(state: State<'_, AppState>, password: String) -> Result<UnlockOutcome, String> {
    let password = Zeroizing::new(password);
    open_vault(&state, &state.vault_path, &password)
}

fn open_vault(
    state: &AppState,
    path: &std::path::Path,
    password: &str,
) -> Result<UnlockOutcome, String> {
    let result = match guarded_check(state, || Vault::unlock(path, password)) {
        Err(wait) => {
            return Ok(UnlockOutcome {
                retry_after_secs: wait,
                ..Default::default()
            });
        }
        Ok(result) => result,
    };
    match result {
        Ok(vault) => {
            *state.vault.lock().unwrap() = Some(vault);
            Ok(UnlockOutcome {
                unlocked: true,
                ..Default::default()
            })
        }
        Err(VaultError::WrongPassword) => Ok(UnlockOutcome {
            retry_after_secs: state.backoff.lock().unwrap().wait_secs(Instant::now()),
            ..Default::default()
        }),
        Err(e @ (VaultError::Tampered | VaultError::Corrupt(_))) => Ok(UnlockOutcome {
            problem: Some(e.to_string()),
            can_restore: vault::backup_path(&state.vault_path).exists(),
            ..Default::default()
        }),
        Err(e @ VaultError::UnsupportedVersion(_)) => Ok(UnlockOutcome {
            problem: Some(format!("{e}. This vault was saved by a newer lockbox; update the app.")),
            ..Default::default()
        }),
        Err(e) => Err(e.to_string()),
    }
}

/// Recovery when vault.enc is damaged (M6): opens vault.enc.bak with the
/// password and, if that works, keeps the damaged file aside as
/// vault.enc.damaged-<time> and promotes the backup. Allowed while locked;
/// shares the password backoff.
#[tauri::command]
async fn restore_backup(state: State<'_, AppState>, password: String) -> Result<UnlockOutcome, String> {
    let password = Zeroizing::new(password);
    let bak = vault::backup_path(&state.vault_path);
    if !bak.exists() {
        return Err("There's no previous version to restore.".into());
    }
    match guarded_check(&state, || Vault::unlock(&bak, &password).map(drop)) {
        Err(wait) => {
            return Ok(UnlockOutcome {
                retry_after_secs: wait,
                ..Default::default()
            });
        }
        Ok(Err(VaultError::WrongPassword)) => {
            return Ok(UnlockOutcome {
                retry_after_secs: state.backoff.lock().unwrap().wait_secs(Instant::now()),
                ..Default::default()
            });
        }
        Ok(Err(e)) => {
            return Ok(UnlockOutcome {
                problem: Some(format!("The previous version can't be opened either: {e}")),
                ..Default::default()
            });
        }
        Ok(Ok(())) => {}
    }
    let damaged = state
        .vault_path
        .with_file_name(format!("vault.enc.damaged-{}", now()));
    if state.vault_path.exists() {
        std::fs::rename(&state.vault_path, &damaged)
            .map_err(|e| format!("couldn't set the damaged vault aside: {e}"))?;
    }
    std::fs::copy(&bak, &state.vault_path).map_err(|e| format!("couldn't restore the backup: {e}"))?;
    open_vault(&state, &state.vault_path, &password)
}

/// Locks: drops the vault (zeroizing it), any pending add or import, and a
/// copied code still on the clipboard. Used by the Lock button, idle and
/// hide locking, system events and the panic hotkey.
fn do_lock(state: &AppState) {
    state.pending.lock().unwrap().take();
    state.pending_import.lock().unwrap().take();
    state.vault.lock().unwrap().take();
    if let Some(stamp) = state.last_copy.lock().unwrap().take() {
        clipboard::clear_if_unchanged(stamp);
    }
}

#[tauri::command]
fn lock(state: State<'_, AppState>) {
    do_lock(&state);
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
    let touch_id = vault.biometric_material();
    match guarded_check(&state, || vault.change_password(&old, &new)) {
        Err(wait) => Err(wait_message(wait)),
        Ok(Ok(())) => {
            // The re-key dropped the Touch ID wrap of the old vault key;
            // seal the new key to the same Secure Enclave key (no prompt).
            if let Some((se_key, se_public, _)) = touch_id {
                let rewrapped = secure_enclave::wrap_key(&se_public)
                    .map_err(|e| e.to_string())
                    .and_then(|(eph, wrap)| {
                        vault.set_biometric(&se_key, &se_public, &eph, &wrap).map_err(|e| e.to_string())
                    });
                if let Err(e) = rewrapped {
                    eprintln!("lockbox: Touch ID turned off after password change: {e}");
                }
            }
            Ok(true)
        }
        Ok(Err(VaultError::WrongPassword)) => Ok(false),
        Ok(Err(e)) => Err(e.to_string()),
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

#[derive(Serialize)]
struct Copied {
    code: String,
    wipe_seconds: u32,
}

/// Copies the account's current code (TOTP) or next code (HOTP; advances
/// the counter) to the clipboard, marked private, and schedules the wipe.
/// The webview has no clipboard access of its own.
#[tauri::command]
async fn copy_code(state: State<'_, AppState>, id: String) -> Result<Copied, String> {
    // Optional Touch ID gate (M6.1). The vault lock is released while the
    // prompt waits, so codes keep updating.
    let gate = state.settings.lock().unwrap().touch_id_to_copy;
    let material = with_vault(&state, |v| Ok(v.biometric_material()))?;
    if let (true, Some((se_key, _, ephemeral))) = (gate, material) {
        secure_enclave::unwrap_key(&se_key, &ephemeral, "copy a code").map_err(|e| e.to_string())?;
    }
    let t = now();
    let code = with_vault(&state, |v| {
        let e = v.entries().iter().find(|e| e.id == id).ok_or(VaultError::NoSuchEntry)?;
        if e.kind == otp::Kind::Totp {
            return e.totp_code(t).map_err(VaultError::Invalid);
        }
        v.next_hotp(&id)
    })?;
    let wipe_seconds = state.settings.lock().unwrap().clipboard_wipe_seconds;
    let stamp = clipboard::copy(&code);
    *state.last_copy.lock().unwrap() = Some(stamp);
    clipboard::schedule_wipe(stamp, std::time::Duration::from_secs(wipe_seconds.into()));
    Ok(Copied { code, wipe_seconds })
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
    let token = token();
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

/// Step 1 of adding from a QR screenshot: decode, parse and preview. The
/// image arrives as a raw body; the decoded link never leaves Rust.
#[tauri::command]
fn entry_preview_qr(state: State<'_, AppState>, request: Request<'_>) -> Result<Preview, String> {
    with_vault(&state, |_| Ok(()))?;
    preview_qr_bytes(&state, &raw_body(&request)?)
}

fn preview_qr_bytes(state: &AppState, bytes: &[u8]) -> Result<Preview, String> {
    with_vault(state, |_| Ok(()))?;
    let uri = qr::decode(bytes)?;
    stage(state, otp::parse_uri(&uri))
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

// ---- backups (BRIEF §7): master-password-encrypted, vault.enc format ----

#[derive(Serialize)]
struct Exported {
    path: String,
    accounts: usize,
}

/// Re-checks the master password, then asks where to save via the native
/// panel. `Ok(None)` if the user cancelled.
#[tauri::command]
async fn export_backup<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    password: String,
) -> Result<Option<Exported>, String> {
    let password = Zeroizing::new(password);
    // Take what we need and release the vault before the (modal) panel opens.
    let (bytes, accounts) = {
        let guard = state.vault.lock().unwrap();
        let vault = guard.as_ref().ok_or(LOCKED)?;
        check_master(&state, vault, &password)?;
        (vault.export_bytes().map_err(|e| e.to_string())?, vault.entries().len())
    };
    let name = format!("lockbox-backup-{}.lockbox", today());
    let Some(path) = panel::choose_save_path(&app, &name)? else {
        return Ok(None);
    };
    write_private(&path, &bytes).map_err(|e| format!("couldn't save the backup: {e}"))?;
    Ok(Some(Exported {
        path: path.display().to_string(),
        accounts,
    }))
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// `YYYY-MM-DD` in UTC, for the default backup file name.
fn today() -> String {
    // Howard Hinnant's days-to-civil algorithm.
    let z = (now() / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Step 1 of importing: hold the picked file until its password arrives.
#[tauri::command]
fn import_stage(state: State<'_, AppState>, request: Request<'_>) -> Result<String, String> {
    with_vault(&state, |_| Ok(()))?;
    stage_import_bytes(&state, raw_body(&request)?)
}

fn stage_import_bytes(state: &AppState, bytes: Vec<u8>) -> Result<String, String> {
    with_vault(state, |_| Ok(()))?;
    if bytes.len() > vault::MAX_BACKUP_BYTES {
        return Err("That file is too large to be a lockbox backup.".into());
    }
    let token = token();
    *state.pending_import.lock().unwrap() = Some((token.clone(), bytes));
    Ok(token)
}

/// Step 2: decrypt with the password the backup was made with and merge in
/// accounts that aren't already here. A wrong password keeps the file staged
/// so the user can try again.
#[tauri::command]
async fn import_confirm(
    state: State<'_, AppState>,
    token: String,
    password: String,
) -> Result<ImportSummary, String> {
    let password = Zeroizing::new(password);
    with_vault(&state, |_| Ok(()))?;
    let bytes = match &*state.pending_import.lock().unwrap() {
        Some((t, bytes)) if *t == token => bytes.clone(),
        _ => return Err("Pick the backup file again.".into()),
    };
    let entries = vault::read_backup(&bytes, &password).map_err(|e| match e {
        VaultError::WrongPassword => "Wrong password for this backup. Use the master password you had when you made it.".to_string(),
        VaultError::Tampered => "This backup failed its integrity check. It has been modified or damaged.".to_string(),
        VaultError::Corrupt(_) | VaultError::UnsupportedVersion(_) => "That file isn't a lockbox backup, or it's damaged.".to_string(),
        e => e.to_string(),
    })?;
    let summary = with_vault(&state, |v| v.import(entries))?;
    state.pending_import.lock().unwrap().take();
    Ok(summary)
}

// ---- Touch ID (M6.1, BRIEF §6.3) ----

#[derive(Serialize)]
struct TouchIdStatus {
    /// This Mac has a Secure Enclave and an enrolled fingerprint.
    available: bool,
    /// The vault on disk has Touch ID unlock set up.
    enabled: bool,
}

/// Allowed while locked: the lock screen decides whether to offer Touch ID.
#[tauri::command]
fn touch_id_status(state: State<'_, AppState>) -> TouchIdStatus {
    TouchIdStatus {
        available: secure_enclave::available(),
        enabled: Vault::has_biometric(&state.vault_path),
    }
}

/// Unlocks with a fingerprint: the Secure Enclave re-derives the key that
/// seals the vault key. The master password always works too. Touch ID
/// failures don't count towards the password backoff; macOS limits them.
#[tauri::command]
async fn unlock_touch_id(state: State<'_, AppState>) -> Result<UnlockOutcome, String> {
    let result = Vault::unlock_biometric(&state.vault_path, |se_key, ephemeral| {
        secure_enclave::unwrap_key(se_key, ephemeral, "unlock lockbox").map_err(|e| match e {
            secure_enclave::SeError::Cancelled => String::new(),
            e => e.to_string(),
        })
    });
    match result {
        Ok(vault) => {
            *state.vault.lock().unwrap() = Some(vault);
            state.backoff.lock().unwrap().record_success();
            Ok(UnlockOutcome {
                unlocked: true,
                ..Default::default()
            })
        }
        Err(VaultError::Biometric(msg)) => Ok(UnlockOutcome {
            touch_id_error: (!msg.is_empty()).then_some(msg),
            ..Default::default()
        }),
        // Damaged files are reported through the password path's recovery.
        Err(e) => Ok(UnlockOutcome {
            touch_id_error: Some(format!("{e}. Use your master password.")),
            ..Default::default()
        }),
    }
}

/// Turns on Touch ID unlock: re-checks the master password, creates a
/// fingerprint-gated Secure Enclave key, proves a fingerprint works with it,
/// then seals the vault key to it. Re-running replaces the previous setup.
#[tauri::command]
async fn touch_id_enable(state: State<'_, AppState>, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    {
        let guard = state.vault.lock().unwrap();
        let vault = guard.as_ref().ok_or(LOCKED)?;
        check_master(&state, vault, &password)?;
    }
    if !secure_enclave::available() {
        return Err(secure_enclave::SeError::Unavailable.to_string());
    }
    // Vault lock released while the prompt waits.
    let (se_key, se_public) = secure_enclave::create_key().map_err(|e| e.to_string())?;
    let (ephemeral, wrap) = secure_enclave::wrap_key(&se_public).map_err(|e| e.to_string())?;
    let proof = secure_enclave::unwrap_key(&se_key, &ephemeral, "turn on Touch ID for lockbox")
        .map_err(|e| match e {
            secure_enclave::SeError::Cancelled => "Touch ID wasn't turned on.".to_string(),
            e => e.to_string(),
        })?;
    if *proof != *wrap {
        return Err("Touch ID check didn't match. Touch ID wasn't turned on.".into());
    }
    with_vault(&state, |v| v.set_biometric(&se_key, &se_public, &ephemeral, &wrap))
}

/// Turns Touch ID unlock off (and with it the Touch ID copy gate).
#[tauri::command]
async fn touch_id_disable(state: State<'_, AppState>) -> Result<(), String> {
    with_vault(&state, |v| v.clear_biometric())?;
    let mut settings = state.settings.lock().unwrap();
    if settings.touch_id_to_copy {
        settings.touch_id_to_copy = false;
        settings::save(&state.settings_path, &settings).map_err(|e| format!("could not save settings: {e}"))?;
    }
    Ok(())
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
            check_master(state, vault, pw)?;
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
        pending_import: Mutex::new(None),
        backoff: Mutex::new(backoff::Backoff::default()),
        last_copy: Mutex::new(None),
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

            // M6 hardening hooks (src/system.rs).
            let handle = app.handle().clone();
            system::lock_on_system_events(move || do_lock(&handle.state::<AppState>()));
            let handle = app.handle().clone();
            if let Err(e) = system::register_panic_hotkey(move || do_lock(&handle.state::<AppState>())) {
                eprintln!("lockbox: panic hotkey unavailable: {e}");
            }
            if let Some(window) = app.get_webview_window("main") {
                system::hide_from_capture(&window)?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            is_locked,
            create_vault,
            unlock,
            restore_backup,
            touch_id_status,
            unlock_touch_id,
            touch_id_enable,
            touch_id_disable,
            lock,
            change_password,
            list_entries,
            get_codes,
            hotp_next,
            copy_code,
            entry_preview_uri,
            entry_preview_manual,
            entry_preview_qr,
            entry_confirm,
            edit_entry,
            delete_entry,
            export_backup,
            import_stage,
            import_confirm,
            settings_get,
            settings_set,
            app_info,
            update_check,
            update_install
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            // Quitting shouldn't leave a copied code behind (M6).
            if let tauri::RunEvent::Exit = event {
                if let Some(stamp) = app.state::<AppState>().last_copy.lock().unwrap().take() {
                    clipboard::clear_if_unchanged(stamp);
                }
            }
        });
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
        "restore_backup",
        "touch_id_status",
        "unlock_touch_id",
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
        "copy_code",
        "entry_preview_uri",
        "entry_preview_manual",
        "entry_preview_qr",
        "entry_confirm",
        "edit_entry",
        "delete_entry",
        "export_backup",
        "import_stage",
        "import_confirm",
        "touch_id_enable",
        "touch_id_disable",
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
        locked("copy_code", block_on(copy_code(s(), "x".into())));
        locked("entry_preview_uri", entry_preview_uri(s(), URI.into()));
        locked("entry_preview_manual", entry_preview_manual(s(), form()));
        // Raw-body commands can't be built outside a webview; their first step
        // is the same guarded helper exercised here.
        locked("entry_preview_qr", preview_qr_bytes(&s(), b"png"));
        locked("entry_confirm", block_on(entry_confirm(s(), "t".into(), false)));
        locked("export_backup", block_on(export_backup(app.handle().clone(), s(), pw())));
        locked("import_stage", stage_import_bytes(&s(), b"{}".to_vec()));
        locked("import_confirm", block_on(import_confirm(s(), "t".into(), pw())));
        locked("touch_id_enable", block_on(touch_id_enable(s(), pw())));
        locked("touch_id_disable", block_on(touch_id_disable(s())));
        locked(
            "edit_entry",
            block_on(edit_entry(s(), "x".into(), "a".into(), "b".into(), vec![])),
        );
        locked("delete_entry", block_on(delete_entry(s(), "x".into())));
        locked("settings_set", settings_set(s(), Settings::default()));
        locked("update_check", block_on(update_check(s())));
        locked("update_install", block_on(update_install(s(), pw())));
        assert_eq!(GUARDED.len(), 19, "exercise every GUARDED command above");
    }

    #[test]
    fn import_flow_end_to_end() {
        let fast = KdfParams { m_kib: 64, t: 1, p: 1 };
        // A backup from another vault, made with a different password.
        let other_dir = tempfile::tempdir().unwrap();
        let mut other = Vault::create(&other_dir.path().join("vault.enc"), "backup password", fast).unwrap();
        let entry = otp::parse_uri(URI).unwrap();
        other.add(&entry, None).unwrap();
        let backup = other.export_bytes().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let app = app(dir.path());
        let s = || app.state::<AppState>();
        *s().vault.lock().unwrap() =
            Some(Vault::create(&dir.path().join("vault.enc"), "correct horse battery", fast).unwrap());

        let token = stage_import_bytes(&s(), backup).unwrap();
        let err = block_on(import_confirm(s(), token.clone(), "nope".into())).unwrap_err();
        assert!(err.contains("Wrong password"), "{err}");
        // Still staged after a wrong password.
        let summary = block_on(import_confirm(s(), token.clone(), "backup password".into())).unwrap();
        assert_eq!((summary.added, summary.skipped), (1, 0));
        assert!(block_on(import_confirm(s(), token, "backup password".into())).is_err(), "used once");

        let token = stage_import_bytes(&s(), b"garbage".to_vec()).unwrap();
        let err = block_on(import_confirm(s(), token, "backup password".into())).unwrap_err();
        assert!(err.contains("isn't a lockbox backup"), "{err}");
        assert_eq!(list_entries(s()).unwrap().len(), 1);
    }

    const PW: &str = "correct horse battery";

    fn create(dir: &std::path::Path) -> Vault {
        Vault::create(&dir.join("vault.enc"), PW, KdfParams { m_kib: 64, t: 1, p: 1 }).unwrap()
    }

    #[test]
    fn wrong_passwords_back_off_across_every_check() {
        let dir = tempfile::tempdir().unwrap();
        create(dir.path());
        let app = app(dir.path());
        let s = || app.state::<AppState>();

        for _ in 0..backoff::FREE_ATTEMPTS {
            let o = block_on(unlock(s(), "nope".into())).unwrap();
            assert!(!o.unlocked);
            assert_eq!(o.retry_after_secs, 0, "free attempts");
        }
        let o = block_on(unlock(s(), "nope".into())).unwrap();
        assert_eq!(o.retry_after_secs, 1, "6th wrong password starts the wait");
        // Even the right password is refused while waiting.
        let o = block_on(unlock(s(), PW.into())).unwrap();
        assert!(!o.unlocked && o.retry_after_secs >= 1);

        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(block_on(unlock(s(), PW.into())).unwrap().unlocked, "right password resets");

        // Unlocked: export and change password share the same counter.
        for _ in 0..backoff::FREE_ATTEMPTS {
            let err = block_on(export_backup(app.handle().clone(), s(), "nope".into())).err().unwrap();
            assert_eq!(err, "Wrong password.");
        }
        assert_eq!(block_on(change_password(s(), "nope".into(), "another password".into())), Ok(false));
        let err = block_on(export_backup(app.handle().clone(), s(), PW.into())).err().unwrap();
        assert!(err.starts_with(TOO_MANY), "{err}");
        let err = block_on(change_password(s(), PW.into(), "another password".into())).unwrap_err();
        assert!(err.starts_with(TOO_MANY), "{err}");
    }

    #[test]
    fn damaged_vault_can_be_restored_from_backup() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = create(dir.path());
        v.add(&otp::parse_uri(URI).unwrap(), None).unwrap(); // second save → .bak exists
        drop(v);
        let path = dir.path().join("vault.enc");
        std::fs::write(&path, b"{ damaged").unwrap();

        let app = app(dir.path());
        let s = || app.state::<AppState>();
        let o = block_on(unlock(s(), PW.into())).unwrap();
        assert!(!o.unlocked && o.can_restore, "{o:?}");
        assert!(o.problem.unwrap().contains("unreadable"));

        let o = block_on(restore_backup(s(), "nope".into())).unwrap();
        assert!(!o.unlocked, "wrong password restores nothing");
        assert_eq!(std::fs::read(&path).unwrap(), b"{ damaged");

        let o = block_on(restore_backup(s(), PW.into())).unwrap();
        assert!(o.unlocked, "{o:?}");
        assert!(!is_locked(s()));
        // The backup was taken before the add, so the vault is empty again.
        assert_eq!(list_entries(s()).unwrap().len(), 0);
        let kept: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with("vault.enc.damaged-"))
            .collect();
        assert_eq!(kept.len(), 1, "damaged file kept aside");
        // And the restored vault opens normally afterwards.
        lock(s());
        assert!(block_on(unlock(s(), PW.into())).unwrap().unlocked);
    }

    #[test]
    fn lock_clears_pending_state() {
        let dir = tempfile::tempdir().unwrap();
        create(dir.path());
        let app = app(dir.path());
        let s = || app.state::<AppState>();
        assert!(block_on(unlock(s(), PW.into())).unwrap().unlocked);
        entry_preview_uri(s(), URI.into()).unwrap();
        stage_import_bytes(&s(), b"{}".to_vec()).unwrap();
        do_lock(&s());
        assert!(s().pending.lock().unwrap().is_none());
        assert!(s().pending_import.lock().unwrap().is_none());
        assert!(is_locked(s()));
    }

    #[test]
    fn today_formats_civil_date() {
        let d = today();
        assert_eq!(d.len(), 10);
        assert!(d.starts_with("20"), "{d}");
    }

    #[test]
    fn open_commands_work_while_locked() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(dir.path());
        let s = || app.state::<AppState>();
        assert!(is_locked(s()));
        assert!(!block_on(vault_exists(s())).unwrap());
        assert!(!touch_id_status(s()).enabled);
        let o = block_on(unlock_touch_id(s())).unwrap();
        assert!(!o.unlocked && o.touch_id_error.is_some(), "no vault, no Touch ID");
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
