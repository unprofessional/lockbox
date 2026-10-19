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
| M4 | UI parity: tile grid, copy with clipboard wipe, settings | in review |
| M5 | QR image import, encrypted export/import | next |
| M6 | Hardening: auto-lock, panic hotkey, screen-capture exclusion | |

Right now you can create a vault and add accounts, either by pasting an `otpauth://` link or by typing the secret. Accounts show as a tile grid with live codes, for both time-based and counter-based accounts. Click a tile to copy its code. You can search, and edit or delete accounts. Settings cover the theme, lock after inactivity, how long copied codes stay on the clipboard, changing the master password, and checking for updates.

Shortcuts: ⌘N add, ⌘F search, ⌘, settings, ⌘L lock.

## Threat model

**Protects against:**

- A stolen laptop or lost disk: the vault is encrypted at rest.
- Shoulder-surfing: auto-lock (M6), and codes are hidden until you unlock.
- Clipboard sniffers: copied codes are wiped after a timeout (M4).
- A compromised webview: no secret crosses IPC; the webview only gets codes for the current 30-second window.
- Leaked backups: exports are encrypted by default (M5).
- Accidental network exfiltration: there is no networking code to exfiltrate with (see [Security surface](#security-surface)).

**Does not protect against:**

- Malware running as you while the vault is unlocked. It can read memory or take screenshots; the same is true of Authy, 1Password or any other app.
- Keyloggers.
- Being forced to type your password.
- Forgetting your password. **There is no recovery.** Lose the password and you lose the vault. Keep an encrypted export (M5) as your backup.

**Desktop automation agents.** AI agents that you grant Screen Recording and Accessibility permission can take screenshots of your desktop, read on-screen text through macOS accessibility, and click and type. Treat them like a tireless person looking over your shoulder.

- **Screenshots:** hiding the window from screen capture (M6) blanks lockbox in screenshots.
- **Unlock guessing:** a backoff on wrong passwords (M6) slows guessing through the unlock screen. It can't stop someone who quits and relaunches the app, and it does nothing against an attacker who has a copy of `vault.enc`. Against that attacker, Argon2id and a strong password are what count.
- **Not covered yet:**
  - Codes on screen are still readable through accessibility while the vault is unlocked.
  - An agent could click a tile to copy a code.
- **What would close the gap:** Touch ID (planned for v1.1). Synthetic clicks and keystrokes can't fake a fingerprint.
- **Your own control:** be deliberate about which apps hold Screen Recording and Accessibility permission.

**The in-app updater** lets an unlocked session build and install `master`. Installing requires re-entering the master password, so clicks alone can't install new code. Anyone who can push to `master` on GitHub can ship code to this laptop the next time you update, so treat push access to `master` like access to your vault.

## Requirements

- macOS 12 or later. Developed and tested on macOS 13.7.8 (Ventura).
- Rust stable (currently 1.99.1). Tauri 2.12 needs a newer Rust than 1.89, so run `rustup update stable` if a build complains about versions.
- Node 22+ and npm.
- Xcode command line tools.
- `cargo-audit` for the release checks: `cargo install cargo-audit --locked`.

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

## Build and install

```bash
npm run release
```

This is the whole release loop, run on this Mac. [scripts/release.sh](scripts/release.sh) runs the Rust tests, the surface check and `cargo audit`. If they all pass, it builds the app, installs it to `/Applications/lockbox.app` (quitting the running copy first) and relaunches it. If any check fails, nothing is installed. Your vault isn't touched; it lives in `~/Library/Application Support/lockbox`.

Options:

- `npm run release -- --dmg` also keeps a `.dmg` in `src-tauri/target/release/bundle/dmg/`.
- `npm run release -- --no-launch` installs without relaunching.

### Updating from inside the app

When the vault is unlocked, **Check for updates** compares the installed build with `master` on GitHub and lists any new commits. **Update now** asks for your master password again, then builds `master` and installs it with the same checks as `npm run release`, and lockbox restarts. If the build or any check fails, nothing is installed and the error appears in the app. The full log is in `~/Library/Logs/lockbox/update.log`.

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
| `unlock(password)` | yes |
| `lock` | yes |
| `settings_get` | yes (the lock screen needs the theme) |
| `settings_set(settings)` | no |
| `change_password(old, new)` | no |
| `list_entries` | no (metadata only, never seeds) |
| `get_codes` | no |
| `hotp_next(id)` | no |
| `copy_code(id)` | no |
| `entry_preview_uri(uri)`, `entry_preview_manual(form)` | no |
| `entry_confirm(token, replace)` | no |
| `edit_entry(id, issuer, account, tags)` | no |
| `delete_entry(id)` | no |
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
