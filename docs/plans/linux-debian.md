# Plan: Linux (Debian first)

Target: Debian 13 (trixie), on GNOME and KDE, under both Wayland and X11. Other distributions should follow from the same code with different package names. Not started. See [the porting overview](README.md) for the platform layer this builds on.

**Linux is the weakest of the three platforms for lockbox's protections.** Several macOS guarantees have no Linux equivalent. Rather than paper over that, the Linux README section needs its own, shorter "protects against" list.

## Build and runtime

**Packages:**

```bash
sudo apt install build-essential curl git pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libssl-dev
```

**Webview:** WebKitGTK. This brings the GTK and glib crates into the build, and with them advisories that the macOS-only `deny.toml` ignores today (for example RUSTSEC-2024-0429 in `glib`). Review each one and either upgrade or record an explicit, justified exception.

**D-Bus:** use `zbus` (pure Rust) or `ashpd` (portal helpers built on zbus). D-Bus is local IPC over a Unix socket, not networking. Make sure `check-surface.sh` and the `deny.toml` bans can tell the two apart, and that nothing in the tree opens TCP.

## Platform pieces

| Piece | Plan |
| --- | --- |
| **Data folder** | `$XDG_DATA_HOME/lockbox`, defaulting to `~/.local/share/lockbox`, with modes 0700/0600. The existing code works as is. |
| **Clipboard** | Through GTK (already in the process) or the `arboard` crate. Set **`x-kde-passwordManagerHint` = `secret`**, which Klipper and some other managers honour. GNOME clipboard-history extensions vary, and there's no universal standard. ⚠️ |
| **Wipe only if unchanged** | No change counter: compare the current text with what lockbox wrote, and clear only on a match. A rare false match just clears a clipboard that already held the same code. |
| **Hide from capture** | **No equivalent.** ❌ On X11, any client can read the whole screen. On Wayland, capture goes through a portal that asks the user per session, but there's no per-window exclusion. Document it as a gap. |
| **Lock on sleep and screen lock** | logind over D-Bus: `org.freedesktop.login1.Manager.PrepareForSleep(true)`, and the session's `Lock` signal. Also `org.freedesktop.ScreenSaver` / `org.gnome.ScreenSaver` `ActiveChanged`. |
| **Panic hotkey** | X11: `XGrabKey` (via `x11rb`). Wayland: apps can't grab global keys. Use the **`org.freedesktop.portal.GlobalShortcuts`** portal where the desktop supports it (recent GNOME and KDE). Elsewhere, ship a `lockbox --lock` command the user binds in their desktop's keyboard settings, which tells the running app to lock through a Unix socket in `$XDG_RUNTIME_DIR`. ⚠️ |
| **Save dialog** | The xdg-desktop-portal `FileChooser` (`ashpd`), which works sandboxed and on any desktop, or GTK's `FileChooserNative`. |
| **Biometric unlock** | See below. |
| **Idle lock, lock when minimized, accessibility** | In the UI already. `aria-hidden` is honoured by AT-SPI, the Linux accessibility layer. |

## Biometric unlock

There's no Secure Enclave equivalent with built-in fingerprint gating:

- **fprintd** (D-Bus) can check a fingerprint, but only lockbox's own code would enforce it. Anything running as you could skip it and read whatever key lockbox stores. That's weaker than macOS, and the UI must not present it as equivalent.
- **TPM 2.0:** sealing the vault key to the TPM (`tss-esapi`) with a PIN policy would give a hardware-bound quick unlock, but with no fingerprint, and TPM availability varies.

**Recommendation:** ship Linux **without** biometric unlock at first, using the master password only. Revisit TPM-plus-PIN later as a separate milestone, and offer fprintd only as a clearly labelled convenience, if at all.

## Release and update

- **Install location:** `~/.local/opt/lockbox/`, with a `~/.local/share/applications/lockbox.desktop` launcher. No `sudo`, no `.deb` needed for personal use.
- **Release script:** `release.sh` mostly carries over. Replace `ditto` with `cp -a`, keep `pkill -x lockbox`, replace `open` with `setsid -f`, and swap the install paths.
- **Updater helper:** `update-helper.sh` is already POSIX sh. Only the paths change: the worktree goes to `$XDG_CACHE_HOME/lockbox/release`, the log to `$XDG_STATE_HOME/lockbox/update.log`.
- **Optional `.deb`:** for friends who prefer packages, `tauri build --bundles deb`, installed with `sudo apt install ./lockbox_*.deb`. But then updates need `sudo`, which the in-app updater shouldn't do. Keep the per-user install as the default.

## Gaps to state plainly on Linux

- **No screen-capture exclusion.**
- **Clipboard privacy depends on your clipboard manager.**
- **The panic hotkey may need manual setup on Wayland.**
- **No hardware-backed biometric unlock.**
- **On X11 there's no isolation between apps:** any app you run can read other windows' content and inject keystrokes. The desktop-agent protections in [security.md](../security.md) mostly don't hold there.
