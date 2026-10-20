# Development

For working on lockbox itself. To install and use it, see the [README](../README.md).

## Requirements

Everything from the README's install walkthrough, plus:

- **Rust stable,** kept current with `rustup update stable`. Tauri 2.12 needs a newer Rust than 1.89.
- **Node 22 or later,** and npm.
- **Xcode command line tools,** including `swiftc`. `build.rs` compiles the Touch ID bridge.
- **`cargo-audit` and `cargo-deny`:**

```bash
cargo install cargo-audit cargo-deny --locked
```

## Branches

- **Feature branches** go to `develop` through pull requests.
- **`develop` goes to `master`** when it's ready to ship.

**`master` is what users receive:** the in-app updater on anyone's copy builds and installs `master`. Treat merging to `master` as a release.

## Run in development

```bash
npm install
```

```bash
npm run tauri dev
```

Development builds use `devCsp`, which also allows inline styles and Vite's hot-reload websocket. Release builds use the strict CSP.

> **Warning:** development builds use the same data folder as the installed app, `~/Library/Application Support/lockbox`, so they work on your real vault. Back it up first (Settings → Backup), or move the folder aside while you experiment.

## Tests

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```

About 90 Rust tests. They cover:

- the RFC 6238 and 4226 test vectors
- `otpauth://` parsing
- vault encryption, tampering, backups and recovery
- the password backoff
- QR decoding from generated images
- the clipboard, on a private pasteboard so your real clipboard is never touched
- the updater helper against throwaway git repositories
- the IPC contract

One test needs a finger on the Touch ID sensor, so it only runs on request:

```bash
cargo test --manifest-path src-tauri/Cargo.toml -- --ignored touch_id_round_trip
```

**Testing the UI without real data:** the UI calls Rust through `window.__TAURI_INTERNALS__.invoke`. A throwaway HTML page that defines a fake `invoke` before loading `/src/main.ts`, served by `npm run dev`, lets you check any screen in a browser. lockbox's milestones were checked this way; those pages aren't committed.

## Release checks

```bash
npm run release
```

[scripts/release.sh](../scripts/release.sh) runs, in order:

1. the Rust tests
2. [check-surface.sh](../scripts/check-surface.sh)
3. `cargo audit`
4. `cargo deny` ([deny.toml](../src-tauri/deny.toml))

Then it builds, quits the running lockbox, installs to `/Applications/lockbox.app` and relaunches it. If any check fails, nothing is installed. `--dmg` also keeps a disk image; `--no-launch` skips the relaunch.

You can run each check on its own:

```bash
sh scripts/check-surface.sh
```

```bash
cargo audit --file src-tauri/Cargo.lock
```

```bash
cargo deny --manifest-path src-tauri/Cargo.toml check
```

## Adding an IPC command

1. **Write it** in `src-tauri/src/lib.rs` and add it to `generate_handler!`.
2. **List it** in `build.rs`, in `AppManifest::commands`.
3. **Grant it** in `capabilities/default.json` as `allow-<command-name>`.
4. **Classify it** in the contract tests, as `OPEN` (works while locked) or `GUARDED`. If it's guarded, call it in `guarded_commands_reject_while_locked`.

The contract test `every_command_is_classified` fails if you miss step 2, 3 or 4. **Never return a secret** from a command.

## Dependency rules

- **No Tauri plugins.** If a feature seems to need one, write it in Rust against the platform API instead, as the clipboard, save dialog and hotkey are.
- **No networking crates.** `check-surface.sh` and `cargo deny` both enforce this.
- **Prefer crates already in Tauri's dependency tree.** `objc2`, `objc2-app-kit`, `objc2-foundation` and `block2` cover most macOS work.
- **Review dependency changes:** any change to `Cargo.toml` dependencies, or to the CSP in `tauri.conf.json`, deserves a human review in its pull request.

## References in code comments

Comments such as "BRIEF §6.3" point to sections of [the original brief](history/brief.md), which is kept unchanged as a historical record. The current behaviour is described in [security.md](security.md) and [architecture.md](architecture.md).
