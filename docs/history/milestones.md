# How lockbox was built

lockbox was built in milestones from [the original brief](brief.md), all on 19–20 October 2026. Each milestone went through a pull request into `develop`, was hand-tested on the target MacBook, then went to `master`. The brief's own milestone list is in §11; below is what each one actually delivered.

| Milestone | Delivered | Pull request |
| --- | --- | --- |
| M1: skeleton | Tauri v2 + vanilla TypeScript app that opens to a lock screen. Zero plugins, `default-src 'none'` CSP, app commands allow-listed in `build.rs`, plaintext settings store, surface-check script. | [#1](https://github.com/unprofessional/lockbox/pull/1) |
| M2: vault core | Encrypted vault: Argon2id derives a key that wraps a random vault key, which encrypts the accounts (AES-256-GCM). Atomic saves with a rolling backup, private file permissions, first-run wizard. | [#3](https://github.com/unprofessional/lockbox/pull/3) |
| Release loop | `npm run release` (checks, build, install to `/Applications`, relaunch) replaced the Jenkins pipeline. In-app **Check for updates** through a bundled helper script, with the password re-checked before installing. | [#4](https://github.com/unprofessional/lockbox/pull/4) |
| M3: codes | TOTP and HOTP (RFC 6238 and 4226 test vectors), `otpauth://` link parsing, add with a preview step, edit, delete, duplicate detection, and contract tests for the IPC commands. | [#5](https://github.com/unprofessional/lockbox/pull/5) |
| M4: UI | Authy-style tile grid, click to copy (written directly to the macOS clipboard, kept out of clipboard history and off Universal Clipboard, wiped after a delay), settings, idle auto-lock. | [#7](https://github.com/unprofessional/lockbox/pull/7) |
| M5: QR and backups | Add accounts from QR screenshots (drop, paste or pick). Encrypted backup export through the native save dialog, and import that merges without overwriting. Fixed a flaky clipboard test. | [#9](https://github.com/unprofessional/lockbox/pull/9) |
| M6: hardening, v1.0.0 | Lock on sleep and screen lock, ⌃⌥⌘L panic hotkey, window hidden from screen capture, a password backoff shared by every password prompt, guided restore of a damaged vault, `cargo deny`. | [#10](https://github.com/unprofessional/lockbox/pull/10) |
| M6.1: Touch ID, v1.1.0 | Touch ID unlock through a Secure Enclave key, an optional Touch ID check before copying, and an optional prompt when you return to a locked lockbox. | [#11](https://github.com/unprofessional/lockbox/pull/11) |

`develop` was merged into `master` in [#2](https://github.com/unprofessional/lockbox/pull/2), [#6](https://github.com/unprofessional/lockbox/pull/6) and [#8](https://github.com/unprofessional/lockbox/pull/8).

## Decisions made along the way

These changed the original plan. Each is recorded in more detail in the brief or in the pull request.

- **No CI server (#4).** The brief's Jenkins pipeline needed a macOS build agent, and making the MacBook a Jenkins agent would let the build server run code on the machine that holds the vault. Builds happen locally instead.
- **In-app updater (#4).** The brief ruled out any update check. The app now has one, but still contains no network code: it runs one bundled helper script, which uses git. Installing needs the master password again.
- **No clipboard plugin (#7).** Writing to the clipboard directly from Rust means the webview needs no clipboard permission, and codes can be kept out of clipboard history and off Universal Clipboard. lockbox ships with zero Tauri plugins.
- **Backups use the master password only (#9).** There's no separate export password and no plain-text export.
- **Every password prompt shares one backoff (#10).** So an unlocked session can't be used to test password guesses.
- **Touch ID through the Secure Enclave, not the Keychain (#11).** A spike showed the Keychain route needs entitlements that an ad-hoc-signed app can't have. A CryptoKit Secure Enclave key works, and the chip itself enforces the fingerprint.
