# Porting plans

lockbox runs on macOS only. Tauri itself is cross-platform: the window, the webview, the IPC layer and the build all work on Windows and Linux. But much of what makes lockbox *safe* is written against macOS APIs, and each of those pieces needs a native equivalent, or an honest note that there isn't one.

This page maps every macOS-specific piece. The per-platform plans go into detail:

- [Windows](windows.md)
- [Linux (Debian first)](linux-debian.md)

Nothing here is implemented yet. These are plans.

## Step zero: a platform layer

Today `lib.rs` calls the macOS code (`clipboard`, `system`, `panel`, `secure_enclave`) directly, and those modules use `objc2`, Carbon and Swift, which are declared only for macOS in `Cargo.toml`. **lockbox won't compile on another OS until that's split.** The first change for any port:

```
src-tauri/src/platform/
  mod.rs       ← the interface lib.rs uses, chosen by #[cfg(target_os = …)]
  macos.rs     ← today's clipboard.rs, system.rs, panel.rs, secure_enclave.rs
  windows.rs
  linux.rs
```

The interface (roughly):

- **Clipboard:** `copy(code) -> Stamp`, `clear_if_unchanged(Stamp)`
- **Locking:** `lock_on_system_events(callback)`, `register_panic_hotkey(callback)`
- **Window:** `hide_from_capture(window)`
- **Files:** `choose_save_path(name)`, `data_dir()`
- **Biometric unlock:** `available()`, `create_key()`, `wrap_key(public)`, `unwrap_key(blob, ephemeral, reason)`, or a platform-specific scheme behind the same seal/unseal idea

`build.rs` should compile the Swift bridge only on macOS. On other platforms the biometric functions can return "unavailable" until they're implemented. Everything above the platform layer (vault, OTP, QR, backoff, settings, IPC, UI) is already portable.

## What's macOS-specific today

| Piece | macOS (today) | Windows | Linux (Debian) |
| --- | --- | --- | --- |
| Data folder | `~/Library/Application Support/lockbox`, modes 0700/0600 | `%LOCALAPPDATA%\lockbox` (not Roaming), owner-only ACL | `$XDG_DATA_HOME/lockbox` (`~/.local/share`), 0700/0600 |
| Clipboard write | NSPasteboard | Win32 clipboard | GTK/X11/Wayland clipboard |
| Keep out of clipboard history | `org.nspasteboard.ConcealedType` / `TransientType` | `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory = 0` | `x-kde-passwordManagerHint = secret` (KDE; others vary) ⚠️ |
| Keep off cross-device clipboard | `currentHostOnly` (Universal Clipboard) | `CanUploadToCloudClipboard = 0` | none needed (no system cross-device clipboard) |
| Wipe only if unchanged | NSPasteboard `changeCount` | `GetClipboardSequenceNumber` | compare contents (no counter) ⚠️ |
| Hide window from capture | `NSWindowSharingNone` | `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` | **no equivalent** ❌ |
| Lock on sleep/screen lock | NSWorkspace + distributed notifications | `WTSRegisterSessionNotification`, `WM_POWERBROADCAST` | logind `PrepareForSleep` and session `Lock` over D-Bus, ScreenSaver `ActiveChanged` |
| Global panic hotkey | Carbon `RegisterEventHotKey` | `RegisterHotKey` | X11 `XGrabKey`; Wayland: GlobalShortcuts portal where available ⚠️ |
| Save dialog for backups | NSSavePanel | `IFileSaveDialog` | xdg-desktop-portal FileChooser, or GTK `FileChooserNative` |
| Biometric unlock | Secure Enclave key (CryptoKit, via Swift) | Windows Hello (`KeyCredentialManager`, TPM-backed) | fprintd can only gate in app code; no hardware-bound key ⚠️ |
| Updater helper | `update-helper.sh` (sh, git) | PowerShell equivalent | `update-helper.sh` mostly reusable |
| Release/install | `release.sh`: `/Applications`, `ditto`, `pkill`, `open` | per-user install under `%LOCALAPPDATA%\Programs`, `taskkill`, `Start-Process` | `~/.local/opt/lockbox` + a `.desktop` file, no sudo |
| Build toolchain | Xcode command line tools (swiftc) | MSVC Build Tools, WebView2 runtime | `build-essential`, `libwebkit2gtk-4.1-dev` and friends |
| UI wording | ⌘ shortcuts, "Touch ID", "this Mac" | Ctrl shortcuts, "Windows Hello", "this PC" | Ctrl shortcuts, no biometric wording by default |

⚠️ means weaker than macOS or uneven across desktops. ❌ means not possible; it must be documented as a gap.

## Cross-cutting changes

- **`deny.toml`** checks only macOS targets today. Adding Windows and Linux targets brings their dependencies into scope, including the GTK and glib crates and advisories that are excluded now. Each needs a deliberate decision.
- **`check-surface.sh`:**
  - its Swift rules apply only to macOS
  - add equivalent rules for any new native code (for example, no `WinHTTP` or `WinINet` on Windows)
  - make sure local D-Bus use on Linux isn't confused with networking
- **The IPC contract tests** are portable as they are.
- **UI strings** need a small per-platform lookup: shortcut symbols, the biometric name, "Mac" or "PC".
- **README:** a section per platform, with its own "protects against" list wherever a protection is weaker.
