# Security design

How lockbox protects your 2FA secrets, and where its limits are. The short version, the lists of what lockbox does and doesn't protect against, is in the [README](../README.md#what-lockbox-protects-against). This page is the detail behind it.

## The core rule

**The webview never sees a secret.** lockbox has two halves: a Rust backend and a web-based UI shown in a system webview. Secrets (the "seeds" that generate your codes) are decrypted only in Rust, and only while the vault is unlocked. The UI only ever receives account names and the current 6–8 digit codes. A bug or compromise in the UI layer could expose codes for the current 30-second window, but not the secrets behind them.

Locking drops the decrypted vault from memory and overwrites the vault key and every secret with zeros (`zeroize`).

## Threat model

**Protects against:**

- **A stolen laptop or a copied disk.** The vault is encrypted at rest. Without your master password, an attacker has to brute-force Argon2id (see below).
- **Someone at your keyboard while you're away.** lockbox locks after a set idle time, when your Mac sleeps, its screen locks or the screensaver starts, when another user session takes over, and when you press ⌃⌥⌘L from any app. Optionally it also locks when minimized or hidden.
- **Screenshots, recordings and screen sharing.** The window is excluded from screen capture (`NSWindowSharingNone`).
- **Clipboard snooping.** Copied codes are wiped after a delay, marked so clipboard managers don't record them, and kept off Universal Clipboard.
- **Password guessing through the app.** After 5 wrong master passwords, every further attempt waits longer, up to 30 seconds.
- **A compromised UI layer.** No secret crosses from Rust to the webview.
- **Leaked backups.** Backups are always encrypted with your master password. There is no plain-text export.
- **Accidental data leaks over the network.** The app contains no networking code (enforced by automated checks; see [Attack surface](#attack-surface)).

**Does not protect against:**

- **Malware running as you while the vault is unlocked.** It can read lockbox's memory or the screen. The same is true of Authy, 1Password and any other app.
- **Keyloggers** capturing your master password.
- **Being forced** to unlock it.
- **Forgetting your master password.** There is no recovery. Keep an encrypted backup somewhere safe.
- **Someone with a copy of `vault.enc` and unlimited time.** The in-app backoff doesn't apply to them. Argon2id and the strength of your password are what count.

### Desktop automation agents

AI agents with Screen Recording and Accessibility permission can take screenshots, read on-screen text through macOS accessibility, and click and type. lockbox treats them like a tireless person looking over your shoulder:

| What an agent can do | What protects you |
| --- | --- |
| Take screenshots | The window is excluded from capture, so it shows blank. |
| Read text through accessibility | Optional: **Settings → Hide codes from accessibility tools.** Off by default, because it also hides codes from VoiceOver. |
| Guess your password through the UI | The password backoff. It resets when the app restarts. |
| Click a tile to copy a code | Optional: **Settings → Require Touch ID to copy codes.** Synthetic clicks can't produce a fingerprint. |
| Unlock lockbox | Your master password, or Touch ID. The Secure Enclave enforces the fingerprint, not lockbox's code. |

You control the rest: be deliberate about which apps hold Screen Recording and Accessibility permission.

### The in-app updater

**Settings → About → Update now** builds whatever is on `master` of the GitHub repository your copy was cloned from, then installs it. Anyone who can push to that `master` can therefore get code onto your Mac the next time you update. That code runs next to your secrets, so **using the updater means trusting whoever controls that repository.** Installing needs your master password again, so an unattended click can't trigger it.

## Vault encryption

```
master password --Argon2id--> key-encryption key --AES-256-GCM--> vault key (random, 256-bit) --AES-256-GCM--> accounts
```

- **Argon2id:** 64 MiB of memory, 3 iterations, 4 lanes, and a 16-byte random salt. The parameters are stored in the vault file, so they can be raised later without breaking existing vaults. On unlock they're bounds-checked before use, so a tampered file can't make lockbox allocate gigabytes of memory.
- **AES-256-GCM:** every encryption uses a fresh random 96-bit nonce. Each layer has its own associated-data label (`lockbox/v1/key-wrap`, `lockbox/v1/payload`, `lockbox/v1/touch-id`), so a ciphertext from one layer can't be substituted for another.
- **Why a separate vault key:** the password unlocks a random vault key rather than encrypting the accounts directly. That lets Touch ID hold a second copy of the vault key without a second copy of the data.
- **Changing the password** re-keys everything: a new vault key, a new salt and the current default parameters.
- **Error handling:** a wrong password and a tampered key wrap both report "wrong password". A tampered account payload reports an integrity failure. Unknown versions and algorithms are refused.

### Vault file format

`~/Library/Application Support/lockbox/vault.enc` is JSON:

```json
{
  "version": 1,
  "kdf": { "algo": "argon2id", "m_kib": 65536, "t": 3, "p": 4, "salt": "<base64>" },
  "key_wrap": { "algo": "aes-256-gcm", "nonce": "<base64>", "ciphertext": "<base64>" },
  "cipher": { "algo": "aes-256-gcm", "nonce": "<base64>" },
  "payload": "<base64 ciphertext of a JSON array of accounts>",
  "created_at": 1760000000,
  "updated_at": 1760000000,
  "biometric": { "algo": "secure-enclave-p256-ecdh-hkdf-sha256+aes-256-gcm", "se_key": "…", "se_public": "…", "ephemeral": "…", "nonce": "…", "ciphertext": "…" }
}
```

Issuers, account names and secrets are all inside the encrypted payload. `biometric` is present only while Touch ID is on. Older lockbox versions ignore it, and it's never written to backups.

### Files and saving

| File | What it is |
| --- | --- |
| `vault.enc` | The encrypted vault. |
| `vault.enc.bak` | The previous version, kept for recovery. It's a complete vault and opens with the password it had when it was saved. |
| `vault.enc.damaged-<time>` | Only exists if you used **Restore previous version**: the damaged file, kept aside rather than deleted. |
| `settings.json` | Plaintext preferences (theme, timeouts, toggles). Nothing secret. |

The folder is mode `0700` and the files `0600`, so only your user can read them. Saves are atomic: lockbox writes `vault.enc.tmp`, flushes it to disk, copies the old file to `vault.enc.bak`, renames the new file into place, then flushes the folder. A crash can't leave a half-written vault. Every change to your accounts saves immediately. If a save fails, the in-memory accounts roll back to match the file.

**Recovery:** if `vault.enc` is damaged but `vault.enc.bak` opens, the unlock screen offers **Restore previous version**.

## Touch ID

Turning Touch ID on asks for your master password, then for one fingerprint to prove that the chip and your finger both work. Only then is anything saved.

**How it's built:**

1. lockbox creates a P-256 key inside the Mac's **Secure Enclave** with the access control `[.privateKeyUsage, .biometryCurrentSet]`. The private key never leaves the chip. lockbox stores the key's `dataRepresentation`, an opaque blob only this Mac's Secure Enclave can use.
2. To seal the vault key, a fresh ephemeral P-256 key does ECDH with the Secure Enclave key's public half. HKDF-SHA256 (salted with the ephemeral public key, info `lockbox/v1/touch-id`) derives a 32-byte key, which seals the vault key with AES-256-GCM. **This step needs no fingerprint.**
3. To unlock, the Secure Enclave performs the same ECDH with its private half. **The chip itself demands a current fingerprint**, so lockbox's code can't skip the check.

**Properties that follow:**

- **Fingerprint changes:** adding or removing a fingerprint in System Settings permanently invalidates the key (`biometryCurrentSet`). Touch ID stops working until you turn it on again with your master password.
- **Password changes:** changing the master password drops the old Touch ID copy in the same save as the re-key, then re-seals the new vault key to the same chip key. No fingerprint is needed, because sealing uses only the public half. A crash between those two steps can leave Touch ID off, but can never leave it pointing at an old key.
- **Backups:** never contain the Touch ID copy. They open with the master password alone.
- **Lockouts:** Touch ID failures don't count towards lockbox's password backoff; macOS applies its own Touch ID lockout.

**Why not the Keychain?** A spike on the target MacBook, with lockbox ad-hoc signed, gave these results:

| Approach | Result |
| --- | --- |
| Data-protection keychain item with a fingerprint access control | Fails: `-34018 errSecMissingEntitlement`. It needs entitlements that only an Apple-issued signing certificate provides. |
| Legacy login keychain item | Works, but only lockbox's own code would enforce the fingerprint. Ad-hoc re-signing would also trigger a keychain password prompt after every update. |
| CryptoKit Secure Enclave key | Works, with the chip enforcing the fingerprint. **Chosen.** |

CryptoKit's Secure Enclave API is Swift-only. So [`secure_enclave.swift`](../src-tauri/swift/secure_enclave.swift), about 125 lines, is compiled by `build.rs` into a static library that Rust calls through five C functions.

## Password backoff

One counter covers every master-password prompt: unlock, change password, export, update install and restore. The first 5 wrong passwords are free. After that, each failure doubles the wait (1, 2, 4, 8, 16, then 30 seconds), and even the right password is refused until the wait ends. A correct password resets the counter. It lives in memory only, so it resets when lockbox restarts. It slows down someone at your keyboard and does nothing against someone holding a copy of the vault file.

## Locking

lockbox locks on:

- the **Lock** button or ⌘L
- the **⌃⌥⌘L panic hotkey**, from any app; registered with Carbon's `RegisterEventHotKey`, which needs no Accessibility permission
- the configured **idle time** with no mouse or keyboard activity
- **sleep, display sleep, screen lock, screensaver start, or a switch to another user** (macOS `NSWorkspace` and distributed notifications)
- optionally, being **minimized or hidden**

Every lock does the same four things:

1. drops the vault from memory, zeroizing it
2. discards a half-finished account add or backup import
3. clears a copied code that's still on the clipboard
4. switches the UI to the lock screen within a second

The UI learns about locks from the backend refusing its once-a-second request for codes, so the webview needs no event permission.

## Copying codes

Clicking a tile asks Rust to copy the code. The webview has no clipboard access of its own. [clipboard.rs](../src-tauri/src/clipboard.rs) writes straight to the macOS pasteboard:

- **Kept out of clipboard history:** codes are tagged `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType`. Clipboard managers that follow the nspasteboard.org convention (Raycast, Alfred, Paste, Maccy and others) skip them.
- **Kept on this Mac:** codes are written with `prepareForNewContentsWithOptions(.currentHostOnly)`, so Universal Clipboard doesn't send them to your iPhone or iPad.
- **Wiped after the delay set in Settings,** but only if nothing else has been copied since. lockbox also wipes a code when it locks and when you quit.

## Backups

**Export** re-checks the master password, then opens the native macOS save dialog from Rust, so the webview never chooses or sees a file path. The file uses the same format as `vault.enc`, without the Touch ID field, and gets mode `0600`.

**Import** reads a file you pick, asks for the password it was made with, and adds only the accounts you don't already have (same issuer, account and secret). It never removes or overwrites anything.

## Adding from QR screenshots

Images go to Rust as raw bytes. [qr.rs](../src-tauri/src/qr.rs) decodes only PNG and JPEG, refuses files over 20 MB or 8000 px per side before decoding them into memory, and returns only the account preview to the webview, never the decoded link.

## Attack surface

The point of lockbox is to have very little that could go wrong. These rules are enforced automatically every time it's built through `npm run release`:

- **[`check-surface.sh`](../scripts/check-surface.sh)**:
  - **No Tauri plugins** of any kind.
  - **No networking crates** anywhere in the dependency tree.
  - **No core or plugin permissions** in the capabilities file; only lockbox's own commands.
  - **Starting other programs is allowed only in `update.rs`,** which runs nothing but the bundled update helper.
  - **The Swift bridge** may import only Foundation, CryptoKit, LocalAuthentication and Security, and may use no networking APIs.
  - **The CSP stays locked** (`default-src 'none'`, no remote origins).
- **`cargo audit`:** no known vulnerabilities in dependencies.
- **`cargo deny`** ([deny.toml](../src-tauri/deny.toml)):
  - crates only from crates.io
  - licences only from an allow-list
  - networking crates banned
- **IPC contract tests** in [lib.rs](../src-tauri/src/lib.rs): every command is allow-listed, granted, and classified as allowed or refused while locked, and every command that should be refused is called to check that it is.
- **No devtools** in release builds.

Changes to the CSP in `tauri.conf.json`, or to dependencies in `Cargo.toml`, should always get a human review.
