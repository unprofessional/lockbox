#!/bin/sh
# Build lockbox and install it as the production app in /Applications.
# Runs every gate first; nothing is installed unless all of them pass.
# Your vault lives in ~/Library/Application Support/lockbox and is never touched.
#
#   npm run release                 check, build, install, relaunch
#   npm run release -- --dmg        also keep a .dmg in src-tauri/target/release/bundle/dmg
#   npm run release -- --no-launch  install without relaunching
set -eu
cd "$(dirname "$0")/.."

dmg=0
launch=1
for arg in "$@"; do
  case "$arg" in
    --dmg) dmg=1 ;;
    --no-launch) launch=0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n==> %s\n' "$*"; }

app_src=src-tauri/target/release/bundle/macos/lockbox.app
app_dst=/Applications/lockbox.app

if [ ! -d node_modules ]; then
  step "Installing npm packages"
  npm ci
fi

step "Rust tests"
cargo test --manifest-path src-tauri/Cargo.toml --locked --quiet

step "Surface check"
sh scripts/check-surface.sh

step "cargo audit"
cargo audit --file src-tauri/Cargo.lock --quiet

step "Building release"
bundles=app
[ "$dmg" -eq 1 ] && bundles=app,dmg
# CI=true makes the dmg bundler skip its Finder AppleScript (needs Automation permission otherwise).
CI=true npm run tauri build -- --bundles "$bundles"

step "Installing to $app_dst"
if pgrep -x lockbox >/dev/null; then
  echo "Quitting running lockbox (it locks; nothing unsaved is lost)"
  pkill -x lockbox || true
  i=0
  while pgrep -x lockbox >/dev/null && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
  done
fi
# Stage next to the target, then swap, so a failed copy never leaves a half-installed app.
rm -rf "$app_dst.new"
ditto "$app_src" "$app_dst.new"
rm -rf "$app_dst"
mv "$app_dst.new" "$app_dst"

version=$(node -p 'require("./src-tauri/tauri.conf.json").version')
commit=$(git rev-parse --short HEAD)
dirty=$(git diff --quiet HEAD -- && echo "" || echo " +uncommitted changes")
echo "Installed lockbox $version ($commit$dirty)"
[ "$dmg" -eq 1 ] && ls src-tauri/target/release/bundle/dmg/*.dmg

if [ "$launch" -eq 1 ]; then
  open "$app_dst"
fi
