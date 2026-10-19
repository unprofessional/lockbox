#!/bin/sh
# Bundled inside lockbox.app. This is the only thing the app can run, and only
# with these fixed modes (see src/update.rs). The app itself has no network
# code; git does the fetching here.
#
#   update-helper.sh check   <repo> <installed-sha>
#   update-helper.sh install <repo>
#
# check prints machine-readable lines:
#   LATEST <sha>
#   STATUS up-to-date|available|unknown-installed
#   COMMIT <sha> <subject>        (newest first, at most 20)
#
# install updates a dedicated worktree to origin/master and runs its
# scripts/release.sh, which quits and relaunches lockbox on success.
set -eu

mode=${1:-}
repo=${2:-}
[ -n "$mode" ] && [ -d "$repo/.git" ] || {
  echo "lockbox repo not found at '$repo'" >&2
  exit 2
}

worktree="$HOME/Library/Caches/lockbox/release"
export GIT_TERMINAL_PROMPT=0
export GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=15"

fetch_master() {
  # The repo is public: fetch over HTTPS so no SSH agent or key is needed
  # (Finder-launched apps don't see the terminal's agent).
  origin=$(git -C "$repo" remote get-url origin)
  url=$(printf '%s' "$origin" | sed -E 's#^git@github\.com:#https://github.com/#')
  git -C "$repo" -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=20 \
    fetch --quiet "$url" "+refs/heads/master:refs/remotes/origin/master"
}

case "$mode" in
  check)
    installed=${3:-}
    fetch_master
    latest=$(git -C "$repo" rev-parse origin/master)
    echo "LATEST $latest"
    if [ -z "$installed" ] || ! git -C "$repo" cat-file -e "$installed^{commit}" 2>/dev/null; then
      echo "STATUS unknown-installed"
      range="origin/master"
    elif [ "$(git -C "$repo" rev-list --count "$installed..origin/master")" -eq 0 ]; then
      echo "STATUS up-to-date"
      exit 0
    else
      echo "STATUS available"
      range="$installed..origin/master"
    fi
    git -C "$repo" log --format='COMMIT %H %s' -n 20 "$range"
    ;;

  install)
    echo "==> Fetching master"
    fetch_master
    git -C "$repo" worktree prune
    if [ ! -e "$worktree/.git" ]; then
      echo "==> Creating release worktree at $worktree"
      mkdir -p "$(dirname "$worktree")"
      git -C "$repo" worktree add --detach "$worktree" origin/master
    else
      git -C "$worktree" checkout --quiet --force --detach origin/master
      git -C "$worktree" clean -fdq -e node_modules -e src-tauri/target
    fi
    cd "$worktree"
    echo "==> Building master @ $(git rev-parse --short HEAD)"
    [ -f scripts/release.sh ] || {
      echo "master has no scripts/release.sh yet; merge it to master first" >&2
      exit 1
    }
    # Reinstall npm packages only when the lockfile changed.
    if ! cmp -s package-lock.json node_modules/.lockbox-lock 2>/dev/null; then
      echo "==> Installing npm packages"
      npm ci
      cp package-lock.json node_modules/.lockbox-lock
    fi
    exec sh scripts/release.sh
    ;;

  *)
    echo "unknown mode: $mode" >&2
    exit 2
    ;;
esac
