# Project Brief: `lockbox` — a local-only TOTP authenticator for macOS (Authy-desktop-style)

- **Date:** 2026-10-10
- **Origin:** mads's idea after Authy killed its desktop app (EOL Mar 2024, no security reason given — cost/focus + post-2022-breach mobile-only pivot). He wants "as close to Authy desktop as possible" for his MacBook Pro, Ventura 13.7.8.
- **Owner/driver:** mads runs the sessions; this brief is written so Codex (or any coding agent) can execute it in slices. mads has shipped one Tauri app before (a diff checker), so scaffold familiarity is assumed.
- **Working name:** `lockbox` (rename freely — nothing here depends on the name).

## 1. Goal

A single-user, offline, local-only TOTP/HOTP authenticator desktop app for macOS that replaces the discontinued Authy desktop client. Encrypted vault at rest, fast code display, QR/URI import, click-to-copy. Built with Tauri v2 + Rust; webview is a dumb renderer.

## 2. Non-goals (hard scope boundaries)

- **No distribution.** No notarization, no Developer ID, no publishing anywhere. No autoupdater in the usual sense either: see the in-app updater note below. The app is built and installed on mads's MacBook only: `npm run release` runs every gate, builds an ad-hoc-signed `.app`, and installs it to `/Applications` as the production app (`--dmg` also keeps a `.dmg`). No CI server builds it — a Jenkins agent on the laptop would let the controller run code as mads on the machine holding the vault. Ad-hoc codesign if Gatekeeper ever complains.
- **No networking of any kind.** No HTTP plugin, no websocket, no telemetry, no update check. Enforced structurally (absent deps) and by CSP.
- **In-app updater (decided 2026-10-19).** The app still contains no network code. An unlocked session can press "Check for updates", which runs the one helper script bundled in the app (`update-helper.sh`, fixed modes `check`/`install`, no webview-supplied arguments). git does the fetch of `master`. "Update now" also requires re-entering the master password, then builds `master` in a dedicated worktree via `scripts/release.sh` and relaunches. `std::process` use is confined to `src/update.rs` by the surface check.
- **No cloud sync, no accounts, no multi-device.** One vault file on one machine.
- **No Steam Guard / vendor-specific extensions** in v1 (nice-to-have later; the `totp` crate ecosystem has support).
- **Not hardened against active local malware** (see §9 threat model). We make it _hard_, not magic.

## 3. Target platform

- macOS Ventura 13.7.8 (build + run on the MacBook Pro). Keep it arch-agnostic (`--target universal-apple-darwin` if needed; Tauri v2 MSRV is fine on Ventura — verify `tauri.conf.json` `macOS.minimumSystemVersion` = `12.0`).
- Rust stable. Node + Vite for the frontend (or plain static TS; no framework requirement — keep the JS side minimal on purpose).

## 4. Tech stack & crates

| Concern                      | Choice                                                            | Notes                                                        |
| ---------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------ |
| Shell                        | Tauri v2                                                          | capabilities/permissions system; disable devtools in release |
| TOTP/HOTP                    | `totp-rs` (with `otpauth` feature)                                | generation, countdown, otpauth:// parse                      |
| KDF                          | `argon2` (rust-argon2 / RustCrypto)                               | argon2id, params in §6                                       |
| Encryption                   | `aes-gcm` (RustCrypto)                                            | AES-256-GCM, 96-bit random nonce                             |
| QR decode                    | `rqrr` + image capture path                                       | see §7; fallback = manual URI paste is MANDATORY             |
| QR encode (for export/share) | `qrcode`                                                          | optional, v1.1                                               |
| Keychain (optional unlock)   | `security-framework` or Tauri `plugin-stronghold`-adjacent custom | see §6.3                                                     |
| Clipboard                    | NSPasteboard via `objc2-app-kit` (already in Tauri's tree) + timer wipe | 30s default; no plugin (decided M4, see §8)                  |
| Zeroization                  | `zeroize`                                                         | vault key, plaintext seed bytes, passwords                   |
| Serialization                | `serde` + `serde_json`                                            | vault entry metadata (secrets stay encrypted blob)           |
| Random                       | `rand` (OsRng)                                                    | nonces, salts, vault key                                     |
| Base32                       | via totp-rs                                                       | seed encoding                                                |

Frontend: vanilla TS or Svelte (mads's pick). The ONLY Tauri commands exposed to the webview should be the minimal set in §8 — no generic "eval" or filesystem command surface.

## 5. Architecture principle

**The webview never sees a secret.** TOTP seeds are decrypted only inside Rust, only while unlocked, and only long enough to produce the current code. Tauri commands return rendered strings (`"483920"`, `seconds_remaining: 17`) and entry metadata (issuer, account name, icon-color/initial). The seed bytes are `Zeroizing<_>` and wiped after each command invocation. If the webview is compromised (it shouldn't be able to be — nothing loads remote content), the attacker gets codes for the current 30s window, not the vault.

## 6. Vault & key management

### 6.1 File

`~/Library/Application Support/lockbox/vault.enc` — single JSON-envelope file:

```json
{
  "version": 1,
  "kdf": { "algo": "argon2id", "m_kib": 65536, "t": 3, "p": 4, "salt": "<b64>" },
  "cipher": { "algo": "aes-256-gcm", "nonce": "<b64>" },
  "payload": "<b64 of ciphertext: JSON array of entries>",
  "created_at": "...", "updated_at": "..."
}
```

Entry (inside decrypted payload): `{ id (uuid), issuer, account, seed_b32, digits, period, algorithm, kind: "totp"|"hotp", counter?, added_at, tags[] }`.

Writes are atomic: serialize → encrypt → write `vault.enc.tmp` → fsync → rename. Keep ONE rolling backup (`vault.enc.bak`, previous version) for corruption recovery.

### 6.2 Master password

- Argon2id (64 MiB, t=3, p=4 — tune if Ventura laptop feels slow; record final params in the envelope so they're forward-compatible) derives the 32-byte vault key from the master password.
- Password never persisted. Held in memory only while unlocked, `Zeroizing`.
- First run = vault-creation wizard: enter password twice, strength meter, scary-but-honest warning that **there is no recovery** — lose the password, lose the vault (offer encrypted export as the backup ritual).

### 6.3 Optional Touch ID unlock (v1.1, not v1)

- On first successful password unlock, generate a random 256-bit **vault key** VK; encrypt payload with VK.
- Wrap VK with a Keychain item (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, biometry-gated via `security-framework` / LocalAuthentication). Store wrapped VK in `vault.keychain` alongside the envelope; password-derived key also wraps VK inside the envelope → both unlock paths work, password remains recovery.
- Ship v1 with password-only; design the envelope in v1 so VK-wrapping slots in without a migration.

### 6.4 Auto-lock

- Lock on: window close-to-tray? (no tray in v1 — lock on app hide/minimize is optional setting), idle > N minutes (default 5, configurable), explicit lock button, system sleep (observe via tauri window events).
- Locked state shows only the unlock screen. Unlock re-derives the key (argon2id ~100-300ms is fine UX).

## 7. Import

1. **otpauth:// URI paste** (mandatory, day-1): text field → parse via `totp-rs` otpauth feature → preview (issuer/account/digits/period) → confirm.
2. **QR from image** (day-1 if cheap, else v1.1): file picker / paste-from-clipboard image → decode with `rqrr`. Covers "screenshot the QR on the enrollment page" — the dominant real-world flow on desktop.
3. **QR from webcam** (v1.1+, optional): needs camera entitlement + `Info.plist` string; only worth it if mads wants phone-screen scanning.
4. **Bulk import** (v1.1): Aegis encrypted/plain JSON export and 2FAS-style exports → mapped into entries. Also plain-text `otpauth-migration://` protobuf (Google Authenticator export) via `otpauth-migration` parsing — nice-to-have, put behind a flag.
5. Duplicate detection: same (issuer, account, seed) → warn and skip/replace choice.

**Export**: encrypted (`vault.enc`-compatible envelope, may use a separate export password) + optional plain otpauth:// text dump with a big red warning. Export is the backup ritual; document it in-app.

## 8. Tauri command surface (the whole IPC API)

```
unlock(password) -> bool
lock()
is_locked() -> bool
create_vault(password) -> bool
vault_exists() -> bool                    // first-run wizard vs unlock screen
list_entries() -> [{id, issuer, account, digits, period, algorithm, kind, tags}]   // NO seeds
get_codes() -> [{id, code, seconds_remaining, period}]   // all TOTP codes at one instant
hotp_next(id) -> code             // returns code for stored counter, then advances + saves it
entry_preview_uri(uri) -> preview{token, …, duplicate}   // step 1; nothing saved
entry_preview_manual(form) -> preview                    // step 1; nothing saved
entry_confirm(token, replace) -> id                      // step 2; duplicate refused unless replace
edit_entry(id, issuer, account, tags) -> ok   // metadata only; re-keying seed = delete+add in v1
delete_entry(id) -> ok            // UI asks for a second click
copy_code(id) -> {code, wipe_seconds}   // Rust writes clipboard (private markers) + schedules wipe; HOTP advances
change_password(old, new) -> ok   // re-encrypt payload
export_encrypted(path, password) / import_encrypted(path, password)
settings_get() / settings_set()   // auto-lock minutes, copy-wipe seconds, theme
app_info() -> {version, commit, dirty}          // allowed while locked
update_check() -> {status, latest, commits[]}   // unlocked only; runs bundled helper `check`
update_install(password)                        // unlocked + password re-check; runs helper `install`
```

M3 deviations from the original list, on purpose:

- `get_codes()` replaces per-entry `get_code(id)`: one call per second for the whole list, all codes from the same instant.
- Adding is always preview → confirm through a one-time token; the parsed seed waits in Rust (cleared on lock), never in the webview.
- `search(query)` was dropped: filtering issuer/account/tags happens in the webview, which already holds that metadata. Seeds aren't searchable anyway.
- `otpauth://` parsing is a small in-house parser (`src/otp.rs`) rather than totp-rs's `otpauth` feature, because that feature rejects HOTP links and pulls in the `url` crate. totp-rs (no default features; `std`, `zeroize`) does the code generation for both TOTP and HOTP.
- **M4: no clipboard plugin.** `src/clipboard.rs` writes NSPasteboard directly, so the webview gets no clipboard permission, copies carry the nspasteboard.org Concealed/Transient markers (clipboard managers skip them), are current-host-only (Universal Clipboard doesn't sync them to other Apple devices), and the wipe only clears if nothing else was copied since. Locking also clears a code still on the clipboard. lockbox ships with zero Tauri plugins.
- Secrets must decode to at least 80 bits. RFC 4226 asks for 128, but many real services still issue 80-bit seeds.

Nothing else. No `fs` plugin, no `shell` plugin, no `http` plugin in `Cargo.toml`/capabilities at all. `tauri.conf.json`: `"csp": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' asset:"`. Devtools disabled in release profile.

## 9. Threat model (honest version)

**Defends against:** laptop theft / lost disk (vault encrypted at rest), casual shoulder-surf (auto-lock, codes hidden until unlock), clipboard sniffers (timed wipe), a compromised webview layer (no secrets cross IPC), backup-file leakage (exports encrypted by default), accidental network exfil (structurally impossible — no networking code exists).

**Does NOT defend against:** active malware running as mads while unlocked (it can read memory or screenshot — same as Authy, 1Password, anything), keyloggers, coerced password entry, Time Machine snapshots of an _unlocked-in-memory_ state (at-rest file is still safe), and mads forgetting the password. State this in the README, not buried.

Paranoid extras (cheap, do them): `NSWindowSharingNone` so the window is excluded from screen capture APIs; zeroize on lock; optional "panic" hotkey that locks immediately.

**Desktop automation agents (future-proofing).** Assume AI agents with Screen Recording + Accessibility grants may drive this desktop: screenshot it, read UI text through the accessibility tree, click and type. They are a tireless shoulder-surfer. Mapping:

- Screenshots → `NSWindowSharingNone` (M6) blanks the window in capture APIs.
- Accessibility tree → **gap.** Webview text (codes, issuers) is exposed to AX clients even when capture is blocked. Rendering codes non-textually would hide them from agents *and* VoiceOver — decide in M6.
- Unlock guessing → Rust-side unlock backoff (M6). Matters more for agents than humans.
- Click-to-copy while unlocked → limited by auto-lock and clipboard wipe; only a presence check (Touch ID) actually stops it.
- Quit/relaunch to reset backoff → not enforceable by the app (any persisted counter is editable by the same user). Document, don't pretend.

In-app updater → an unlocked session can trigger a build of `master`; installing also requires re-entering the master password, so a desktop agent can't install code with clicks alone while the vault is unlocked. Whoever can push to `master` on GitHub can ship code to this laptop the next time mads updates, so treat push access to `master` as access to the vault.

Touch ID is the strongest control here: biometric presence is the one thing synthetic input can't produce. That raises the priority of §6.3 and of an optional "Touch ID to copy" setting.

## 10. UI spec (Authy-desktop-shaped)

- **Unlock screen:** password field, unlock button, subtle error shake. Nothing else.
- **Main view:** search bar top; grid of tiles (2-3 columns, responsive). Tile = issuer + account label, big monospace code with digit grouping (`483 920`), circular countdown ring, click tile = copy (toast: "copied, clipboard wipes in 30s").
- **Add flow:** `+` button → sheet with tabs: Paste URI / Upload QR image / Manual (issuer, account, base32 seed, digits, period, algo).
- **Settings:** auto-lock timeout, clipboard wipe timeout, change password, export/import, about (no analytics, no links home — because there is no home).
- Light/dark following system, plus a manual override. Keep it utilitarian-clean; the old Authy desktop aesthetic = dark, tile grid, countdown ring.

## 11. Milestones (each independently verifiable, sized for one Codex session)

1. **M1 — skeleton:** Tauri v2 scaffold, runs on Ventura, CSP locked, zero plugins, unlock-screen shell, settings store (plaintext JSON config is fine — no secrets in it). Gate: app opens, shows lock screen, `cargo audit` clean, no network capability present in build.
2. **M2 — vault core (Rust):** argon2id + AES-256-GCM envelope, create/unlock/lock/change-password, atomic writes + rolling backup, unit tests incl. wrong-password, tamper-detect (GCM auth failure), param round-trip. Gate: `cargo test` green; hand-test create→lock→unlock on device.
3. **M3 — codes:** entry CRUD (manual + URI paste), `totp-rs` generation, countdown, IPC surface from §8, zeroize discipline. Gate: add a known test vector entry (RFC 6238 vectors), code matches `oathtool` output.
4. **M4 — UI parity pass:** tile grid, search, copy + clipboard wipe, add-entry sheet, toasts, dark/light. Gate: side-by-side with Authy desktop screenshots feels familiar to mads.
5. **M5 — QR image import + encrypted export/import.** Gate: screenshot a real enrollment QR, import it, code matches phone authenticator; export → delete vault → import → identical entries.
6. **M6 — hardening & polish:** auto-lock timers, panic hotkey, NSWindowSharingNone, unlock backoff (enforced in Rust, in-memory, resets on success: 5 free attempts then 1s doubling to a ~30s cap; `unlock` returns the remaining wait; `change_password`'s old-password check shares it), decision on accessibility exposure of codes (§9 agents), first-run wizard copy, README with threat model. Gate: mads daily-drives it for a week with real (low-stakes first) tokens.

Suggested rollout for real tokens: start by importing a burner/low-stakes account, keep phone authenticator as fallback until trust is earned.

## 12. Testing & verification

- Rust unit tests: KDF params round-trip, GCM tamper rejection, vault migration/version guard, RFC 6238 test vectors for TOTP, HOTP counter persistence, otpauth:// parser edge cases (spaces, weird issuers, missing params).
- IPC contract tests: every command has a locked-state guard (all commands except unlock/create/is_locked must reject when locked).
- Manual test script (mads runs on the MacBook): create vault → add RFC vector → compare vs `oathtool --totp` → lock/idle auto-lock → wrong password → export → wipe → import → Touch ID unlock (M6+ if v1.1).
- `cargo audit` + `cargo deny` in the build script; zero high/critical findings gate for release.

## 13. Open questions for mads

1. App name? (`lockbox` is a placeholder — also a real product name, so pick something less collision-prone if he cares.)
2. Frontend flavor: vanilla TS or Svelte? (his diff-checker project may already have a preference)
3. Touch ID unlock: v1 or v1.1? (brief assumes v1.1; envelope designed for it either way)
4. Webcam QR scanning: wanted at all, or is screenshot/file import enough? (brief assumes file/image import suffices)
5. Repo location + visibility: private GitHub under which account (unprofessional? moldy-devcru?), or local-only git?
6. Desktop agents (§9): pull Touch ID unlock forward from v1.1? Add an optional "require Touch ID to copy a code" setting? Hide codes from the accessibility tree at the cost of VoiceOver support?

## 14. Dispatch notes (for whoever runs Codex)

- One milestone per session; each session starts from the merged state of the previous.
- Do NOT let the agent add tauri plugins (zero today; the clipboard is handled without one since M4). Stronghold/keychain only at M6 if Touch ID is greenlit. Plugin creep = network/filesystem surface creep; this app's whole selling point is structural paranoia.
- Any PR touching `tauri.conf.json` CSP or `Cargo.toml` deps gets human eyes, no exceptions.
- Target Ventura: pin `minimumSystemVersion: "12.0"` and test-build on the actual laptop, not CI assumptions.
- Release loop = `npm run release` on the MacBook (`scripts/release.sh`): `cargo test` → surface check → `cargo audit` → `tauri build` → install to `/Applications` → relaunch. Nothing installs unless every gate passes. Hand-testing a milestone means running that and using the installed app. (Jenkins was dropped: no Mac build agent, and making the laptop one conflicts with §9.)
