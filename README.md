# lockbox

A local-only TOTP/HOTP authenticator for macOS, built to replace the discontinued Authy desktop app. One user, one machine, one encrypted vault file. No network code, no sync, no accounts.

Built with Tauri v2 and Rust. The webview only renders the UI: secrets never leave Rust (see [Architecture](#architecture)).

The full plan, scope and milestones are in [BRIEF.md](BRIEF.md).

## Status

| Milestone | What | State |
| --- | --- | --- |
| M1 | Skeleton: locked-down Tauri shell, settings store, lock screen | done |
| M2 | Vault core: Argon2id + AES-256-GCM, create/unlock/lock/change password | in review |
| M3 | Codes: add entries (manual, `otpauth://` paste), TOTP/HOTP generation | next |
| M4 | UI parity: tile grid, search, copy with clipboard wipe | |
| M5 | QR image import, encrypted export/import | |
| M6 | Hardening: auto-lock, panic hotkey, screen-capture exclusion | |

Right now you can create a vault, lock it and unlock it. There's no way to add accounts until M3.

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

## Requirements

- macOS 12 or later. Developed and tested on macOS 13.7.8 (Ventura).
- Rust stable (currently 1.99.1). Tauri 2.12 needs a newer Rust than 1.89, so run `rustup update stable` if a build complains about versions.
- Node 22+ and npm.
- Xcode command line tools.
- `cargo-audit` for the audit step: `cargo install cargo-audit --locked`.

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

## Build

```bash
CI=true npm run tauri build -- --bundles dmg
```

This produces `src-tauri/target/release/bundle/dmg/lockbox_<version>_aarch64.dmg`. The app is ad-hoc signed and not notarized; it's meant to be installed only on this machine (see BRIEF §2).

`CI=true` makes Tauri skip its Finder layout step for the disk image. Without it, the build times out unless the process has macOS Automation permission to control Finder.

The [Jenkinsfile](Jenkinsfile) runs the same steps on the `macbook` agent: `npm ci`, `cargo test`, the surface check and `cargo audit`, then the `.dmg` build. The job builds `master`.

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

More commands arrive with M3 (entries and codes); the full planned list is in BRIEF §8.

## Security surface

Keeping the app's attack surface small is the whole point, so these rules are checked automatically by [scripts/check-surface.sh](scripts/check-surface.sh), which runs in CI:

- **No Tauri plugins,** except the clipboard plugin (planned for M4). Never `http`, `fs` or `shell`.
- **No networking crates** anywhere in the dependency tree (`reqwest`, `hyper`, `ureq`, websocket crates and so on).
- **No core or plugin permissions** in the capabilities file; only this app's own commands.
- **A locked CSP:** `default-src 'none'`, with no remote origins. The only `connect-src` entries are Tauri's local IPC channel.
- **No devtools in release builds.**

Any change to the CSP in `tauri.conf.json` or to dependencies in `Cargo.toml` needs a human review (BRIEF §14).
