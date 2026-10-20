# lockbox

A 2FA code app for your Mac that keeps everything on your Mac.

lockbox shows the six-digit sign-in codes ("TOTP" codes) that sites like GitHub, AWS or Discord ask for, like Authy or Google Authenticator do. It was built to replace Authy's discontinued desktop app. Your accounts live in one encrypted file on your Mac: no cloud, no account, no sync, and no networking code at all.

> **A personal project.** lockbox was built for one person's Mac (a MacBook Pro with Apple silicon, running macOS 13 Ventura) and is shared with friends as is. There's no download: you build it yourself, which takes about 20 minutes the first time. Read [Will it work on your Mac?](#will-it-work-on-your-mac) before you start.

## What lockbox protects against

**Protects against:**

- **A stolen or lost Mac.** Your accounts are encrypted with your master password.
- **Someone using your Mac while you're away.** lockbox locks itself after a few idle minutes, when your Mac sleeps or its screen locks, and instantly with ⌃⌥⌘L from any app.
- **Screenshots and screen sharing.** The lockbox window shows up blank in screenshots, recordings, Zoom and Meet.
- **Clipboard snooping.** Copied codes clear themselves after 30 seconds, stay out of clipboard-history apps, and don't sync to your iPhone.
- **Password guessing in the app.** After 5 wrong passwords, each try makes you wait longer.
- **Leaked backups.** Backups are always encrypted. There's no plain-text export.
- **Data leaking over the internet.** The app contains no networking code, and automated checks keep it that way.

**Does not protect against:**

- **Malware already running on your Mac** while lockbox is unlocked. No authenticator app can.
- **Keyloggers** recording your master password.
- **Someone forcing you** to unlock it.
- **Forgetting your master password. There is no recovery.** Lose it and your accounts are gone. Keep an encrypted backup somewhere safe, and keep your phone authenticator as a fallback.

The details, including how lockbox handles AI agents that can control your desktop, are in [docs/security.md](docs/security.md).

## Will it work on your Mac?

| | |
| --- | --- |
| ✅ **Tested** | MacBook Pro, Apple M2 Max, macOS 13.7.8 Ventura, with Touch ID. Everything works. |
| 🟡 **Should work, untested** | Other Apple-silicon Macs on macOS 12 Monterey to macOS 15 Sequoia. |
| ❓ **Unknown** | Intel Macs. On newer macOS versions: whether the window still shows blank to every kind of screen capture (verified on macOS 13 only), and whether macOS 26 Tahoe's Spotlight clipboard history respects lockbox's "don't record this" markers. |
| ❌ **Won't work** | Windows and Linux; plans are in [docs/plans/](docs/plans/). macOS 11 and earlier. |

**Features that depend on your setup:**

- **Touch ID unlock** needs a Mac with Touch ID, or a Magic Keyboard with Touch ID, and at least one fingerprint enrolled. Without it, the option simply doesn't appear, and you use your password.
- **Installing needs an administrator account,** because lockbox installs into `/Applications`.
- **The ⌃⌥⌘L panic hotkey** won't work if another app already uses that combination. lockbox still starts.
- **Clipboard-history apps** (Raycast, Alfred, Paste, Maccy and so on) skip lockbox's codes only if they follow the standard "concealed" marker. Most popular ones do.
- **You need the real repository, not a ZIP download.** The build and the in-app updater both need its git history.
- **Builds can't be shared.** A lockbox app copied from someone else's Mac will be blocked by macOS (it isn't notarized by Apple), and its updater won't work. Build your own.

## Before you install

- **Keep your current authenticator.** Treat lockbox as a second place for your codes until you trust it. Moving accounts in means re-enrolling them (see [Moving accounts from Authy](#moving-accounts-from-authy-or-a-phone-app)).
- **Updates come from this repository.** lockbox's **Check for updates** builds the latest version of *this* GitHub repository on your Mac. Using it means trusting whoever can change this repository, because that code will run next to your 2FA secrets. Prefer to review first? Update by hand instead (see [Updating](#updating)).
- **It isn't signed by Apple.** It's built and signed locally on your own Mac, which macOS allows for apps you build yourself.

## Install

This is a one-time setup of developer tools, then one command. Expect about 20 minutes, mostly waiting, and **at least 15 GB of free disk space** for build files. All commands go in **Terminal** (Applications → Utilities → Terminal).

**1. Check your Mac.** Choose Apple menu → **About This Mac** and confirm macOS 12 or later. In System Settings → Users & Groups, confirm your account is an **Admin**.

**2. Install Apple's command line tools.** These include `git` and the Swift compiler. A window pops up; click **Install**.

```bash
xcode-select --install
```

If it says they're already installed, move on.

**3. Install Rust.** Accept the defaults when asked, then **quit and reopen Terminal**.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**4. Install Node.js 22 or later.** Download the **LTS** installer from [nodejs.org](https://nodejs.org) and run it. If you use Homebrew, `brew install node` works too. Check it worked:

```bash
node --version
```

**5. Install the security-check tools.** lockbox won't build without passing these checks. This takes 5–10 minutes.

```bash
cargo install cargo-audit cargo-deny --locked
```

**6. Download lockbox.** This puts it in your home folder. **Leave the folder where it is afterwards**; the updater uses it. `--branch master` matters: `master` is the released version, while the repository's default branch has work in progress.

```bash
git clone --branch master https://github.com/unprofessional/lockbox.git ~/lockbox
```

**7. Build and install.**

```bash
cd ~/lockbox && npm ci && npm run release
```

The first build takes 5–15 minutes. It runs every test and security check, installs **lockbox** into Applications, and opens it.

**8. Create your vault.** Choose a strong master password you won't forget. Write it down somewhere safe if you need to: **it can't be recovered.**

**If the build fails:**

| Message | Fix |
| --- | --- |
| `xcrun: error` or `swiftc` not found | Run step 2 again. If you have full Xcode installed, also run `sudo xcodebuild -license accept`. |
| Complaints about the Rust or Tauri version | `rustup update stable`, then run step 7 again. |
| `cargo-audit` or `cargo-deny` not found | Run step 5, and make sure you reopened Terminal after step 3. |
| `Permission denied` while installing to `/Applications` | Your account isn't an administrator. |
| `No space left on device` | Free up disk space, then run step 7 again. |

## Using lockbox

### Adding accounts

Click **+ Add** (⌘N). There are three ways:

- **QR image** (easiest). When a site shows its 2FA QR code, take a screenshot of it, then drop it onto lockbox or paste it with ⌘V. Tip: ⇧⌘4, then hold **Control** while selecting, copies the screenshot straight to the clipboard.
- **Paste link.** Some sites offer an `otpauth://` link under "can't scan?".
- **Enter manually.** Type the secret key the site shows. The **Advanced** options are for unusual sites (8 digits, 60 seconds, and so on).

lockbox shows a preview before saving, and warns you if you already have that account.

### Moving accounts from Authy or a phone app

Authy (and most phone apps) won't let you export your secrets. For each account, go to the site's security settings and choose to set up or reset your authenticator app. When it shows the new QR code, add it to **both** lockbox and your phone app before you confirm. Then both stay in sync, and your phone remains a backup.

### Everyday use

- **Copy a code:** click its tile. It clears from the clipboard after 30 seconds.
- **Find an account:** type in the search box (⌘F). It matches the service, account name and tags.
- **Edit or delete:** click **⋯** on a tile. Deleting asks you to confirm.
- **Counter-based accounts** (rare, older hardware tokens): click the tile for the next code.

### Touch ID

Turn it on in **Settings → Touch ID**. It asks for your master password and one fingerprint. After that you can unlock with your finger; your password always works too. If you add or remove a fingerprint in System Settings, turn Touch ID on again. Optional settings:

- **Ask for Touch ID when you come back to lockbox:** on by default.
- **Require Touch ID to copy codes:** off by default.

### Backups

**Settings → Backup → Export backup…** saves an encrypted file. Keep it somewhere other than your Mac, such as a USB stick or cloud storage; it's useless without your password. **Import backup…** adds any accounts from a backup that you don't already have. A backup opens with the master password you had **when you made it**.

### Locking

lockbox locks:

- when you click **Lock** (⌘L)
- after a few idle minutes (set in Settings)
- when your Mac sleeps or its screen locks
- instantly with **⌃⌥⌘L** from any app
- optionally, when minimized or hidden

### Settings

⌘, opens **Settings**:

- theme
- lock timer
- clipboard timer
- Touch ID
- backups
- master password
- privacy options: lock when hidden, hide codes from screen readers
- **About** (version and updates)

### Keyboard shortcuts

| Shortcut | Does |
| --- | --- |
| ⌘N | Add an account |
| ⌘F | Search |
| ⌘, | Settings |
| ⌘L | Lock |
| ⌃⌥⌘L | Lock from any app |

## Updating

**From inside lockbox:** go to **Settings → About → Check for updates**. If there's something new, enter your master password and click **Update now**. lockbox rebuilds itself from this repository, which takes a few minutes, and restarts. Your accounts aren't touched. If anything fails, nothing changes and the error is shown. (Remember the [trust note](#before-you-install).)

**By hand:**

```bash
cd ~/lockbox && git checkout master && git pull && npm run release
```

## Your data

Everything lives in `~/Library/Application Support/lockbox/`, readable only by your user:

- **`vault.enc`:** your accounts, encrypted.
- **`vault.enc.bak`:** the previous version, kept automatically. If `vault.enc` is ever damaged, the unlock screen offers **Restore previous version**.
- **`settings.json`:** your preferences, nothing secret.

## Uninstall

Quit lockbox, then delete the app, its caches and its logs:

```bash
rm -rf /Applications/lockbox.app ~/Library/Caches/lockbox ~/Library/Logs/lockbox
```

To also delete your accounts, **which can't be undone** (export a backup first if you might want them):

```bash
rm -rf ~/Library/Application\ Support/lockbox
```

Then delete the `~/lockbox` folder.

## Learn more

- [docs/security.md](docs/security.md): how the encryption, Touch ID, clipboard and locking work, and the full threat model.
- [docs/architecture.md](docs/architecture.md): how the app is put together.
- [docs/development.md](docs/development.md): working on lockbox.
- [docs/plans/](docs/plans/): what it would take to run on Windows and Linux.
- [docs/history/](docs/history/): the original brief, and how lockbox was built milestone by milestone.
