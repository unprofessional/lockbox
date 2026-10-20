# Architecture

lockbox is a [Tauri v2](https://tauri.app) app. It has a Rust backend that holds all secrets, and a small vanilla-TypeScript UI rendered in the system webview (WKWebView on macOS). The UI is deliberately thin: it shows what Rust tells it and asks Rust to do everything else. Why that matters is covered in [security.md](security.md).

## Module map

**Rust** (`src-tauri/src/`):

| File | Responsibility |
| --- | --- |
| `lib.rs` | App state, every IPC command, app setup (system hooks, capture exclusion, quitting), and the IPC contract tests |
| `vault.rs` | Vault encryption and file format, accounts, atomic saves, backups and import, the Touch ID copy of the vault key |
| `otp.rs` | TOTP/HOTP code generation (totp-rs) and the `otpauth://` link parser |
| `qr.rs` | Reading `otpauth://` links from PNG and JPEG screenshots (rqrr) |
| `clipboard.rs` | Copying codes to NSPasteboard with privacy markers, and the delayed wipe |
| `system.rs` | macOS hooks: lock on sleep and screen lock, the ⌃⌥⌘L hotkey, hiding the window from capture |
| `secure_enclave.rs` | Rust side of the Touch ID bridge |
| `panel.rs` | The native save dialog for backups |
| `backoff.rs` | The shared password backoff |
| `settings.rs` | Plaintext preferences |
| `update.rs` | The in-app updater: the only module allowed to start another program |

**Swift** (`src-tauri/swift/secure_enclave.swift`): CryptoKit Secure Enclave calls behind five C functions. `build.rs` compiles it into a static library.

**TypeScript** (`src/`):

| File | Responsibility |
| --- | --- |
| `main.ts` | Screens (create, unlock, vault), the unlock flow, locking, Touch ID prompts, idle lock, the updater UI |
| `accounts.ts` | The tile grid, live codes, copying, the add/edit/delete dialogs, QR drop and paste |
| `settings.ts` | The settings sheet: preferences, Touch ID, backups, password change |
| `ui.ts` | Small shared helpers (toast, shake) |

**Scripts:** [`scripts/release.sh`](../scripts/release.sh) runs every check, then builds, installs and relaunches. [`scripts/check-surface.sh`](../scripts/check-surface.sh) holds the attack-surface rules. [`src-tauri/resources/update-helper.sh`](../src-tauri/resources/update-helper.sh) is the updater's helper, bundled inside the app.

## IPC surface

These are the only commands the UI can call. Each one is listed in [build.rs](../src-tauri/build.rs), granted in [capabilities/default.json](../src-tauri/capabilities/default.json) and classified in the contract tests. The app has no other permissions: no core permissions, no plugins.

| Command | Works while locked | Notes |
| --- | --- | --- |
| `vault_exists`, `is_locked` | yes | Choose between the first-run wizard and the lock screen |
| `create_vault(password)` | yes | |
| `unlock(password)` | yes | Returns the backoff wait, and whether a damaged vault can be restored |
| `restore_backup(password)` | yes | Recovery from `vault.enc.bak` |
| `touch_id_status`, `unlock_touch_id` | yes | |
| `lock` | yes | |
| `settings_get` | yes | The lock screen needs the theme |
| `app_info` | yes | Version and build commit only |
| `touch_id_enable(password)` | no | Re-checks the master password, then asks for one fingerprint |
| `touch_id_disable` | no | |
| `settings_set(settings)` | no | |
| `change_password(old, new)` | no | Re-seals the Touch ID copy automatically |
| `list_entries` | no | Account metadata only, never secrets |
| `get_codes` | no | All time-based codes, calculated at one instant; polled every second |
| `hotp_next(id)`, `copy_code(id)` | no | `copy_code` writes the clipboard in Rust; optional Touch ID check first |
| `entry_preview_uri`, `entry_preview_manual`, `entry_preview_qr` | no | Step 1 of adding: parse in Rust, return a preview and a one-time token |
| `entry_confirm(token, replace)` | no | Step 2 of adding |
| `edit_entry`, `delete_entry` | no | |
| `export_backup(password)` | no | Re-checks the master password, then opens the native save dialog |
| `import_stage(file)`, `import_confirm(token, password)` | no | |
| `update_check` | no | |
| `update_install(password)` | no | Re-checks the master password |

Images and backup files are sent as raw invoke bodies rather than JSON. Secrets go from the UI to Rust only when you type or paste them; nothing secret ever comes back.

## A few flows

**Adding an account.** The UI sends a link, a form or an image to an `entry_preview_*` command. Rust parses it, keeps the result (secret included) in memory under a one-time token, and returns only the issuer, account, format, and any duplicate it found. `entry_confirm` saves it. Locking discards anything pending.

**Live codes.** Every second, the UI calls `get_codes` and paints the tiles. When the vault has locked behind the UI's back (sleep, the hotkey), that call is refused, and the UI switches to the lock screen. This is how background locks reach the UI without any event permission.

**Touch ID prompts.** The UI asks for Touch ID at launch, and, if the setting is on, when you come back to a locked lockbox. "Coming back" means the window regains focus after losing it; lockbox's own Touch ID dialog doesn't count, so cancelling doesn't loop.

**The in-app updater.** `update_check` and `update_install` run the bundled `update-helper.sh` in one of two fixed modes, and the UI can't pass it arguments.

- **Paths it needs:** at build time, `build.rs` records the commit, the repo's path, and your shell's `PATH`. Apps launched from Finder get a bare `PATH`, without `cargo` or `npm`.
- **`check`:** fetches `master` over HTTPS with git and lists commits that aren't in the installed build, ignoring merge-only commits.
- **`install`:** updates a separate worktree at `~/Library/Caches/lockbox/release` to `origin/master`, then runs its `scripts/release.sh`. On success, the release script quits lockbox and opens the new build. On failure, the log is at `~/Library/Logs/lockbox/update.log`, and the last lines appear in the app.

## Build-time pieces

`src-tauri/build.rs` does three things:

1. **Allow-lists every command.** It declares them with Tauri's `AppManifest`, so each one needs an explicit `allow-*` permission.
2. **Records build information** for the updater: commit, uncommitted-changes flag, repo path, `PATH`.
3. **Compiles the Swift bridge** with `xcrun swiftc` into a static library, and links it against the system Swift runtime (`/usr/lib/swift`), CryptoKit, LocalAuthentication and Security.

Release builds are ad-hoc signed and not notarized, and target macOS 12 or later.
