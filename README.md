# lockbox

A local-only TOTP/HOTP authenticator for macOS, built to replace the discontinued Authy desktop app. One user, one machine, one encrypted vault file. No network code, no sync, no accounts.

Built with Tauri v2 and Rust. The webview only renders the UI: secrets never leave Rust (see [Architecture](#architecture)).

The full plan, scope and milestones are in [BRIEF.md](BRIEF.md).

## Status

| Milestone | What | State |
| --- | --- | --- |
| M1 | Skeleton: locked-down Tauri shell, settings store, lock screen | done |
| M2 | Vault core: Argon2id + AES-256-GCM, create/unlock/lock/change password | done |
| M3 | Codes: add entries (manual, `otpauth://` paste), TOTP/HOTP generation | done |
| M4 | UI parity: tile grid, copy with clipboard wipe, settings | done |
| M5 | QR image import, encrypted export/import | in review |
| M6 | Hardening: lock on sleep/screen lock, panic hotkey, capture exclusion, password backoff, recovery | done |
| M6.1 | Touch ID unlock (Secure Enclave), optional Touch ID to copy | in review |

Right now you can create a vault and add accounts from a screenshot of the QR code (drop, paste or pick it), by pasting an `otpauth://` link, or by typing the secret. Accounts show as a tile grid with live codes, for both time-based and counter-based accounts. Click a tile to copy its code. You can search, edit or delete accounts, and export or import encrypted backups. You can unlock with Touch ID. Settings cover Touch ID, the theme, lock after inactivity, how long copied codes stay on the clipboard, changing the master password, backups, and checking for updates.

Shortcuts: ⌘N add, ⌘F search, ⌘, settings, ⌘L lock, and ⌃⌥⌘L to lock from any app.

## Threat model

**Protects against:**

- A stolen laptop or lost disk: the vault is encrypted at rest.
- Shoulder-surfing: codes are hidden until you unlock. lockbox locks itself after a set time without activity, when your Mac sleeps or its screen locks, and when you press ⌃⌥⌘L from any app. Optionally it also locks when minimized or hidden.
- Clipboard snooping: copied codes are wiped after a timeout, kept out of clipboard-manager history, and never synced to other devices through Universal Clipboard.
- A compromised webview: no secret crosses IPC; the webview only gets codes for the current 30-second window.
- Leaked backups: backups are always encrypted with your master password; there is no plain-text export.
- Accidental network exfiltration: there is no networking code to exfiltrate with (see [Security surface](#security-surface)).

**Does not protect against:**

- Malware running as you while the vault is unlocked. It can read memory or take screenshots; the same is true of Authy, 1Password or any other app.
- Keyloggers.
- Being forced to type your password.
- Forgetting your password. **There is no recovery.** Lose the password and you lose the vault. Keep an encrypted backup (Settings → Backup) somewhere safe.

**Desktop automation agents.** AI agents that you grant Screen Recording and Accessibility permission can take screenshots of your desktop, read on-screen text through macOS accessibility, and click and type. Treat them like a tireless person looking over your shoulder.

- **Screenshots:** the window is excluded from screen capture, so screenshots, recordings and screen sharing show it blank. That includes your own screenshots of lockbox.
- **Password guessing:** after 5 wrong master passwords, each further attempt waits longer (1 s, 2 s, 4 s… up to 30 s). Every password prompt shares this counter: unlock, change password, export, update and restore. It resets when the app restarts and does nothing against an attacker who has a copy of `vault.enc`. Against that attacker, Argon2id and a strong password are what count.
- **Accessibility:** by default, codes on screen are readable through accessibility while the vault is unlocked, so VoiceOver works. **Settings → Hide codes from accessibility tools** removes them from the accessibility tree.
- **Copying:** an agent could click a tile to copy a code, unless **Settings → Require Touch ID to copy codes** is on. Then every copy needs a real fingerprint.
- **Touch ID** (M6.1): synthetic clicks and keystrokes can't fake a fingerprint, and the Secure Enclave enforces the fingerprint, not lockbox's code.
- **Your own control:** be deliberate about which apps hold Screen Recording and Accessibility permission.

**The in-app updater** lets an unlocked session build and install `master`. Installing requires re-entering the master password, so clicks alone can't install new code. Anyone who can push to `master` on GitHub can ship code to this laptop the next time you update, so treat push access to `master` like access to your vault.

## Requirements

- macOS 12 or later. Developed and tested on macOS 13.7.8 (Ventura).
- Rust stable (currently 1.99.1). Tauri 2.12 needs a newer Rust than 1.89, so run `rustup update stable` if a build complains about versions.
- Node 22+ and npm.
- Xcode command line tools, including `swiftc`. The Touch ID bridge is a small Swift file compiled by `build.rs`.
- `cargo-audit` and `cargo-deny` for the release checks: `cargo install cargo-audit cargo-deny --locked`.

## Develop

```bash
npm install
```

```bash
npm run tauri dev
```

Dev builds use `devCsp`, which additionally allows inline styles and the Vite HMR websocket. Release builds use the strict CSP.

## Test

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```

```bash
sh scripts/check-surface.sh
```

```bash
cargo audit --file src-tauri/Cargo.lock
```

```bash
cargo deny --manifest-path src-tauri/Cargo.toml check
```

[deny.toml](src-tauri/deny.toml) allows only crates.io sources and a fixed licence list (permissive licences plus MPL-2.0), and bans networking crates.

## Build and install

```bash
npm run release
```

This is the whole release loop, run on this Mac. [scripts/release.sh](scripts/release.sh) runs the Rust tests, the surface check, `cargo audit` and `cargo deny`. If they all pass, it builds the app, installs it to `/Applications/lockbox.app` (quitting the running copy first) and relaunches it. If any check fails, nothing is installed. Your vault isn't touched; it lives in `~/Library/Application Support/lockbox`.

Options:

- `npm run release -- --dmg` also keeps a `.dmg` in `src-tauri/target/release/bundle/dmg/`.
- `npm run release -- --no-launch` installs without relaunching.

### Updating from inside the app

In **Settings → About** (⌘,), **Check for updates** compares the installed build with `master` on GitHub and lists any new commits. **Update now** asks for your master password again, then builds `master` and installs it with the same checks as `npm run release`, and lockbox restarts. If the build or any check fails, nothing is installed and the error appears in the app. The full log is in `~/Library/Logs/lockbox/update.log`.

The app itself still has no network code. Both buttons run a single helper script bundled inside the app ([update-helper.sh](src-tauri/resources/update-helper.sh)), with fixed modes the webview can't change. git does the fetching. The helper builds in its own copy of the repo at `~/Library/Caches/lockbox/release` (a git worktree), so it never disturbs whatever branch you have checked out. The first update takes a few minutes; later ones reuse the build cache.

The app is ad-hoc signed and not notarized. It's built and installed on this machine only (see BRIEF §2). There's no CI server: a Jenkins agent on this laptop would let the build server run code as you on the machine that holds your vault.

## Where your data lives

Everything is in `~/Library/Application Support/lockbox/`. The directory is `0700` and the vault files are `0600`.

| File | What |
| --- | --- |
| `vault.enc` | The encrypted vault |
| `vault.enc.bak` | The previous version of the vault, kept for corruption recovery. It's a complete vault and opens with the same password it had when it was saved. |
| `settings.json` | Plaintext settings: auto-lock minutes, clipboard wipe seconds, theme. Nothing secret. |

To start over with a fresh vault, quit lockbox and delete the folder. **This destroys the vault.**

```bash
rm -rf ~/Library/Application\ Support/lockbox
```

To recover from a damaged `vault.enc`, quit lockbox and copy `vault.enc.bak` over it. Restoring from the backup isn't automatic yet.

## Architecture

**The webview never sees a secret.** Seeds are decrypted only inside Rust, only while the vault is unlocked. IPC commands return rendered codes and entry metadata, never seeds. Locking drops the in-memory vault, which zeroizes the vault key and every entry.

### Vault encryption

```
master password --Argon2id--> key-encryption key --AES-256-GCM--> vault key (random 256-bit) --AES-256-GCM--> payload
```

- **Argon2id:** 64 MiB memory, 3 iterations, 4 lanes, 16-byte random salt. These parameters are stored in the vault file, so they can be raised later without breaking existing vaults.
- **AES-256-GCM:** a fresh random 96-bit nonce for every encryption. The key-wrap layer and the payload layer each use their own associated-data label, so one can't be substituted for the other.
- **Why a separate vault key:** the password unlocks the vault key rather than encrypting the payload directly. Touch ID unlock (planned for v1.1) can then store a second, Keychain-protected copy of the vault key without changing the file format.
- **Changing the password** re-keys everything: a new vault key, a new salt and the current default parameters.

### Vault file format

```json
{
  "version": 1,
  "kdf": { "algo": "argon2id", "m_kib": 65536, "t": 3, "p": 4, "salt": "<b64>" },
  "key_wrap": { "algo": "aes-256-gcm", "nonce": "<b64>", "ciphertext": "<b64>" },
  "cipher": { "algo": "aes-256-gcm", "nonce": "<b64>" },
  "payload": "<b64 ciphertext of a JSON array of entries>",
  "created_at": 1760000000,
  "updated_at": 1760000000
}
```

Issuers, account names and seeds are all inside the encrypted payload. Timestamps are Unix seconds.

On unlock, lockbox refuses unknown versions and algorithms. It bounds-checks the KDF parameters before deriving, so a tampered file can't make it allocate gigabytes of memory. A wrong password and a tampered key wrap both report "wrong password"; a tampered payload reports an integrity failure.

Saves are atomic: write `vault.enc.tmp`, fsync, rename over `vault.enc`, fsync the directory. The previous file becomes `vault.enc.bak` first.

### Backups

**Settings → Backup → Export backup…** asks for your master password, then opens the standard macOS save dialog. The file (`lockbox-backup-YYYY-MM-DD.lockbox`) uses the same encrypted format as `vault.enc` and opens with the master password you had when you made it. Only you choose where it goes: the save dialog runs from Rust, and the webview never sees a file path.

**Import backup…** reads a backup you pick, asks for the password it was made with, and adds every account that isn't already in your vault (same issuer, account and secret). It never removes or overwrites anything, so importing the same backup twice is harmless. If you've changed your master password since, use the old one for older backups.

There is deliberately no plain-text export.

### Adding from a QR screenshot

On the **QR image** tab of **+ Add**, drop a screenshot, paste one with ⌘V, or choose a file. PNG and JPEG are supported, up to 20 MB and 8000 px per side. The image goes to Rust as raw bytes, where [qr.rs](src-tauri/src/qr.rs) decodes it with `rqrr`. Only the account preview comes back to the webview, never the decoded link.

### Touch ID (M6.1)

**Settings → Touch ID → Turn on Touch ID…** asks for your master password, then for one touch to prove it works. After that, the lock screen offers **Unlock with Touch ID**. It also prompts automatically whenever you come to lockbox while it's locked: at launch, and when you return after minimizing or hiding it, switching apps or desktops, waking the Mac, or using the panic hotkey from another app. Locking never prompts by itself; if you press ⌘L and stay, nothing pops up until you leave and come back. Your master password always works too.

How it works:

- **Secure Enclave key:** lockbox creates a key inside your Mac's Secure Enclave that can only be used after a current fingerprint. Adding or removing a fingerprint in System Settings disables it until you turn Touch ID on again. The key never leaves the chip; what lockbox stores is an opaque blob that only this Mac's Secure Enclave can use.
- **Second copy of the vault key:** the vault key is sealed a second time to that chip key and stored in `vault.enc` next to the password copy.
- **Backups never include it:** a backup always needs the master password.
- **Changing your password** re-seals the Touch ID copy for the new key automatically, with no fingerprint needed.
- **No keychain, no entitlements:** the Secure Enclave code is in [secure_enclave.swift](src-tauri/swift/secure_enclave.swift), because Apple's API for it is Swift-only, and Rust calls it through a C interface. Apple's keychain route for Touch ID needs developer entitlements an ad-hoc-signed app can't have; see BRIEF §6.3.
- **Require Touch ID to copy codes** (optional) asks for a fingerprint before every copy.

### Hardening (M6)

- **Locking:** lockbox locks when the Mac sleeps, its displays sleep, the screen locks, the screensaver starts, or another user takes over. [system.rs](src-tauri/src/system.rs) listens for these through macOS's own notifications. The UI notices within a second, because Rust starts refusing its requests for codes, so the webview needs no extra permission.
- **Panic hotkey:** ⌃⌥⌘L locks lockbox from any app. It uses macOS's built-in global hotkey API, which needs no Accessibility permission. If another app already uses the combination, lockbox logs that and carries on.
- **Hidden from capture:** screenshots, recordings and screen sharing show the window blank.
- **Password backoff:** see the threat model above.
- **Recovery:** if `vault.enc` is damaged but `vault.enc.bak` opens, the unlock screen offers **Restore previous version**. The damaged file is kept aside as `vault.enc.damaged-<time>`, not deleted.
- **On quit:** a copied code still on the clipboard is wiped.

### Copying codes

Clicking a tile asks Rust to copy its code (`copy_code`). Counter-based (HOTP) tiles get their next code. The webview never touches the clipboard and has no permission to.

- **Kept out of clipboard history:** Rust writes the code straight to the macOS clipboard ([clipboard.rs](src-tauri/src/clipboard.rs)) and tags it with the `org.nspasteboard.ConcealedType` and `TransientType` markers. Clipboard managers such as Raycast, Alfred, Paste and Maccy respect these and don't save the code.
- **Kept on this Mac:** copies are marked current-host-only, so Universal Clipboard (Handoff) doesn't send them to your iPhone or iPad, where lockbox's wipe couldn't reach them.
- **Wiped afterwards:** after the delay set in Settings (30 seconds by default), lockbox clears the code, but only if nothing else has been copied since. Locking the vault also clears a code that's still on the clipboard.
- **Auto-lock:** after the configured minutes with no mouse or keyboard activity, lockbox locks itself. Locking on sleep and when the window is hidden comes in M6.

### IPC surface

These are the only commands the webview can call. Each one is declared in [build.rs](src-tauri/build.rs) and granted in [capabilities/default.json](src-tauri/capabilities/default.json); the app has no other permissions.

| Command | Works while locked |
| --- | --- |
| `vault_exists` | yes |
| `is_locked` | yes |
| `create_vault(password)` | yes |
| `unlock(password)` | yes (returns the backoff wait and whether a damaged vault can be restored) |
| `restore_backup(password)` | yes (recovery from `vault.enc.bak`) |
| `touch_id_status`, `unlock_touch_id` | yes |
| `touch_id_enable(password)` | no, and it also re-checks the master password |
| `touch_id_disable` | no |
| `lock` | yes |
| `settings_get` | yes (the lock screen needs the theme) |
| `settings_set(settings)` | no |
| `change_password(old, new)` | no |
| `list_entries` | no (metadata only, never seeds) |
| `get_codes` | no |
| `hotp_next(id)` | no |
| `copy_code(id)` | no |
| `entry_preview_uri(uri)`, `entry_preview_manual(form)`, `entry_preview_qr(image)` | no |
| `entry_confirm(token, replace)` | no |
| `edit_entry(id, issuer, account, tags)` | no |
| `delete_entry(id)` | no |
| `export_backup(password)` | no, and it also re-checks the master password |
| `import_stage(file)`, `import_confirm(token, password)` | no |
| `app_info` | yes (version and build commit only) |
| `update_check` | no |
| `update_install(password)` | no, and it also re-checks the master password |

Adding an account takes two steps. The preview step parses the link or form in Rust and returns the details without the secret, plus a one-time token. The confirm step saves it. The parsed secret waits in Rust in the meantime and is dropped if you lock.

The IPC contract tests in [lib.rs](src-tauri/src/lib.rs) check that every command in `build.rs` is granted in the capabilities file and classified as allowed or refused while locked, and they call every command that should be refused to make sure it is.

## Security surface

Keeping the app's attack surface small is the whole point, so these rules are checked automatically by [scripts/check-surface.sh](scripts/check-surface.sh), which runs in CI:

- **No Tauri plugins at all.** The clipboard is written directly (see [Copying codes](#copying-codes)). Never `http`, `fs` or `shell`.
- **No networking crates** anywhere in the dependency tree (`reqwest`, `hyper`, `ureq`, websocket crates and so on).
- **No core or plugin permissions** in the capabilities file; only this app's own commands.
- **Process spawning only in `src/update.rs`,** which runs nothing but the bundled update helper.
- **A locked CSP:** `default-src 'none'`, with no remote origins. The only `connect-src` entries are Tauri's local IPC channel.
- **No devtools in release builds.**

Any change to the CSP in `tauri.conf.json` or to dependencies in `Cargo.toml` needs a human review (BRIEF §14).
