# Plan: Windows

Target: Windows 11, and Windows 10 version 2004 or later (the minimum for capture exclusion). x64 first, ARM64 after. Not started. See [the porting overview](README.md) for the platform layer this builds on.

## Build and runtime

- **Toolchain:** Rust with the MSVC target, Visual Studio Build Tools (C++ workload), Node 22+.
- **Webview:** WebView2. It's preinstalled on Windows 11; on Windows 10, Tauri's installer can bootstrap it.
- **Native APIs:** the `windows` crate (Microsoft's official bindings). Tauri already depends on it on Windows, so prefer its existing version and features over new crates.
- **Bundles:** `tauri build --bundles nsis`, or a per-user install with no bundle at all; see Release.

## Platform pieces

| Piece | Plan |
| --- | --- |
| **Data folder** | `%LOCALAPPDATA%\lockbox`, **not** `%APPDATA%` (Roaming): domain profiles can sync Roaming folders to other machines. Set an owner-only DACL on the folder and files with `SetNamedSecurityInfoW`, the equivalent of 0700/0600. |
| **Clipboard** | `OpenClipboard`, `EmptyClipboard`, `SetClipboardData(CF_UNICODETEXT)`. Also register and set three formats: **`ExcludeClipboardContentFromMonitorProcessing`** (clipboard monitors skip it), **`CanIncludeInClipboardHistory` = 0** (kept out of Win+V history) and **`CanUploadToCloudClipboard` = 0** (no cross-device sync). Together these match macOS's concealed and current-host-only markers. |
| **Wipe only if unchanged** | Record `GetClipboardSequenceNumber()` after writing; clear only if it hasn't changed. Same logic as `changeCount`. |
| **Hide from capture** | `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` on the main window. Screenshots, the Snipping Tool, OBS and Teams sharing show it black or omit it. Needs Windows 10 2004+; fall back to `WDA_MONITOR` before that. |
| **Lock on screen lock and sleep** | `WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)` and handle `WM_WTSSESSION_CHANGE` with `WTS_SESSION_LOCK`, plus `WM_POWERBROADCAST` with `PBT_APMSUSPEND`. Both need a message-only window or a subclass of Tauri's window. |
| **Panic hotkey** | `RegisterHotKey`. Win+L is reserved for locking Windows, so use **Ctrl+Alt+Shift+L**. If it's taken, log it and carry on, as on macOS. |
| **Save dialog** | `IFileSaveDialog` through COM, run on the UI thread like `panel.rs`. |
| **Biometric unlock** | **Windows Hello** with `Windows.Security.Credentials.KeyCredentialManager`; see below. |
| **Idle lock, lock when minimized, accessibility** | Already in the UI. `visibilitychange` and `aria-hidden` work in WebView2. |

## Windows Hello

The macOS design (seal the vault key to a hardware key that needs a fingerprint) carries over, with one twist. Windows Hello keys are TPM-backed RSA keys that can **sign**, but can't do ECDH.

1. **Enable:** `KeyCredentialManager.RequestCreateAsync("lockbox", ReplaceExisting)` creates a TPM-backed key gated by Windows Hello (face, fingerprint or PIN).
2. **Derive a wrapping key:** sign a fixed, random challenge stored in the vault with `RequestSignAsync`. RSA PKCS#1 v1.5 signatures are deterministic, so the same key and challenge always give the same signature. HKDF-SHA256 over the signature gives the 32-byte key that seals the vault key, exactly like the macOS `biometric` field.
3. **Unlock:** Windows Hello prompts, the signature is reproduced, the key is re-derived, and the vault key is unsealed.

**Differences from macOS to document:**

- **Windows Hello includes a PIN fallback,** so it isn't strictly biometric.
- **No `biometryCurrentSet` equivalent:** adding a fingerprint doesn't invalidate the key.

The "require Windows Hello to copy" toggle can use `UserConsentVerifier.RequestVerificationAsync`, though that check is enforced by lockbox's code rather than by hardware.

**Unpackaged apps:** the WinRT APIs need COM apartment initialisation and have to run off the UI thread, as on macOS.

## Release and update

- **Install location:** `%LOCALAPPDATA%\Programs\lockbox\lockbox.exe`, per user, with no admin rights needed, plus a Start-menu shortcut.
- **Release script:** a PowerShell port of `release.sh`. It runs the same checks, builds, stops the running app (`Stop-Process -Name lockbox`), copies the new build into place and starts it.
- **Updater helper:** a PowerShell port of `update-helper.sh`. Same modes, the same worktree idea (`%LOCALAPPDATA%\lockbox\release`), and git for fetching. `update.rs` would start `powershell.exe -NoProfile -ExecutionPolicy Bypass -File <bundled script>`, still the only program the app can start.
- **SmartScreen:** builds made on your own PC don't carry the "Mark of the Web", so they run without a warning. A downloaded or shared `.exe` would trigger SmartScreen; the same "build it yourself" rule as on macOS applies.

## Gaps and risks

- **WebView2 is shared:** it's Edge's runtime, which updates on Microsoft's schedule.
- **Windows Hello's PIN fallback** weakens the "a desktop agent can't fake it" argument. The PIN is still a secret the agent doesn't know, but it isn't a fingerprint.
- **The capture exclusion is a request, not a guarantee:** screen readers and some drivers can still read the window.
- **`deny.toml`:** add `x86_64-pc-windows-msvc`, and review the `windows-*` crates' licences (MIT/Apache) and any advisories.
