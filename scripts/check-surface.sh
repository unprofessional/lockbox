#!/bin/sh
# Structural paranoia check (BRIEF §2, §8, §14). Fails if the build could
# gain network, filesystem or shell surface. Run from the repo root.
set -eu

fail=0
bad() { echo "FAIL: $*"; fail=1; }

# 1. No Tauri plugins at all (the clipboard is handled in src/clipboard.rs).
if grep -E '^tauri-plugin-' src-tauri/Cargo.toml ; then
  bad "tauri plugin in src-tauri/Cargo.toml"
fi
if grep -E '"@tauri-apps/plugin-' package.json ; then
  bad "tauri plugin in package.json"
fi

# 2. No devtools feature on tauri (devtools stay debug-only).
if grep -E '^tauri *=.*devtools' src-tauri/Cargo.toml ; then
  bad "tauri devtools feature enabled"
fi

# 3. No networking crates anywhere in the resolved dependency graph.
tree=$(cargo tree --manifest-path src-tauri/Cargo.toml -e normal --prefix none --format '{p}' | awk '{print $1}' | sort -u)
for crate in reqwest hyper ureq isahc curl tungstenite tokio-tungstenite websocket attohttpc surf; do
  if printf '%s\n' "$tree" | grep -qx "$crate"; then
    bad "networking crate '$crate' in dependency graph"
  fi
done

# 4. Capabilities grant only app commands (allow-*), no core/fs/http/shell.
if grep -hoE '"[a-z0-9-]+:[a-z0-9:-]+"' src-tauri/capabilities/*.json ; then
  bad "plugin/core permission granted in capabilities"
fi

# 5. Only the updater may spawn processes (it runs the bundled helper only).
if grep -lE 'std::process|Command::new|process::Command' src-tauri/src/*.rs | grep -vx 'src-tauri/src/update.rs' ; then
  bad "process spawning outside src-tauri/src/update.rs"
fi

# 6. CSP locked: default-src 'none', no remote origins beyond Tauri's IPC.
csp=$(node -e 'const c=require("./src-tauri/tauri.conf.json");process.stdout.write(c.app.security.csp||"")')
case "$csp" in
  *"default-src 'none'"*) ;;
  *) bad "CSP missing default-src 'none' (got: '$csp')" ;;
esac
if printf '%s' "$csp" | tr ' ;' '\n\n' | grep -E '^(https?|wss?):' | grep -vx 'http://ipc.localhost' ; then
  bad "CSP allows a remote origin"
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "PASS surface check: no plugins, no networking crates, process spawning only in update.rs, locked capabilities and CSP"
