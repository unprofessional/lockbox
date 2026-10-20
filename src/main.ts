import { invoke } from "@tauri-apps/api/core";
import { onLockedElsewhere, setupAccounts, startAccounts, stopAccounts } from "./accounts";
import { getSettings, loadSettings, openSettings, setupSettings } from "./settings";
import { $, errorText, shake, toast } from "./ui";

const MIN_PASSWORD_CHARS = 8; // mirrors vault::MIN_PASSWORD_CHARS

const screens = {
  create: $<HTMLFormElement>("#create-form"),
  unlock: $<HTMLFormElement>("#unlock-form"),
  vault: $<HTMLElement>("#vault-view"),
};

function show(name: keyof typeof screens) {
  for (const [key, el] of Object.entries(screens)) {
    el.hidden = key !== name;
  }
  const focus: Record<keyof typeof screens, string> = {
    create: "#new-password",
    unlock: "#password",
    vault: "#search",
  };
  if (name === "vault") {
    startAccounts();
  } else {
    stopAccounts();
  }
  $<HTMLElement>(focus[name]).focus();
}

/** Rough strength score 0–4. Guidance only; Rust enforces the minimum. */
function strength(pw: string): number {
  if ([...pw].length < MIN_PASSWORD_CHARS) return 0;
  let score = 1;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  if (classes >= 3) score++;
  if (/^(.)\1+$/.test(pw) || /^(password|12345678|qwerty)/i.test(pw)) score = 1;
  return Math.min(score, 4);
}

const STRENGTH_LABELS = [
  `At least ${MIN_PASSWORD_CHARS} characters`,
  "Weak",
  "Fair",
  "Good",
  "Strong",
];

function setupCreate() {
  const form = screens.create;
  const pw = $<HTMLInputElement>("#new-password");
  const confirm = $<HTMLInputElement>("#confirm-password");
  const ack = $<HTMLInputElement>("#ack");
  const btn = $<HTMLButtonElement>("#create-btn");
  const meter = $<HTMLElement>("#strength");
  const label = $<HTMLElement>("#strength-label");
  const msg = $<HTMLElement>("#create-msg");

  const update = () => {
    const score = strength(pw.value);
    meter.dataset.score = String(score);
    label.textContent = pw.value ? STRENGTH_LABELS[score] : STRENGTH_LABELS[0];
    btn.disabled = !(score > 0 && confirm.value === pw.value && ack.checked);
    msg.textContent =
      confirm.value && confirm.value !== pw.value ? "Passwords don't match." : "";
  };
  for (const el of [pw, confirm, ack]) el.addEventListener("input", update);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (btn.disabled) return;
    btn.disabled = true;
    btn.textContent = "Creating…";
    try {
      await invoke<boolean>("create_vault", { password: pw.value });
      pw.value = confirm.value = "";
      ack.checked = false;
      update();
      show("vault");
    } catch (err) {
      msg.textContent = errorText(err);
      shake(form);
    } finally {
      btn.textContent = "Create vault";
      update();
    }
  });
}

interface UnlockOutcome {
  unlocked: boolean;
  retry_after_secs: number;
  problem: string | null;
  can_restore: boolean;
  touch_id_error: string | null;
}

/** Shows "Unlock with Touch ID" when it's set up; `prompt` asks right away. */
async function offerTouchId(prompt: boolean) {
  const btn = $<HTMLButtonElement>("#touchid-btn");
  try {
    const s = await invoke<{ available: boolean; enabled: boolean }>("touch_id_status");
    btn.hidden = !(s.available && s.enabled);
  } catch {
    btn.hidden = true;
  }
  if (prompt && !btn.hidden) void unlockWithTouchId();
}

/** Touch ID on return (M6.1, on by default, a setting): coming back to
 * lockbox while it's locked asks for a fingerprint, just as launching does. Armed when the window loses
 * focus or is hidden on the lock screen; our own prompt doesn't arm it,
 * since the system Touch ID dialog takes focus too. */
let promptOnReturn = false;
let touchIdPromptOpen = false;

function setupTouchIdOnReturn() {
  const away = () => {
    if (!screens.unlock.hidden && !touchIdPromptOpen) promptOnReturn = true;
  };
  const back = () => {
    if (!promptOnReturn || screens.unlock.hidden || document.hidden || !document.hasFocus()) return;
    if (!getSettings().touch_id_on_return) return; // Settings → Touch ID
    promptOnReturn = false;
    void offerTouchId(true);
  };
  window.addEventListener("blur", away);
  window.addEventListener("focus", back);
  document.addEventListener("visibilitychange", () => (document.hidden ? away() : back()));
}

async function unlockWithTouchId() {
  const btn = $<HTMLButtonElement>("#touchid-btn");
  const msg = $<HTMLElement>("#unlock-msg");
  if (btn.disabled) return;
  btn.disabled = true;
  touchIdPromptOpen = true;
  msg.textContent = "";
  try {
    const o = await invoke<UnlockOutcome>("unlock_touch_id");
    if (o.unlocked) {
      show("vault");
    } else if (o.touch_id_error) {
      msg.textContent = o.touch_id_error;
    }
  } catch (err) {
    msg.textContent = errorText(err);
  } finally {
    btn.disabled = false;
    touchIdPromptOpen = false;
  }
}

let countdown: number | undefined;

/** Disables Unlock and counts down while the password backoff runs. */
function waitBeforeRetry(secs: number) {
  const btn = $<HTMLButtonElement>("#unlock-btn");
  const msg = $<HTMLElement>("#unlock-msg");
  window.clearInterval(countdown);
  let left = secs;
  const paint = () => {
    btn.disabled = left > 0;
    btn.textContent = left > 0 ? `Try again in ${left} s` : "Unlock";
    msg.textContent = left > 0 ? "Too many wrong passwords." : "";
  };
  paint();
  countdown = window.setInterval(() => {
    left -= 1;
    paint();
    if (left <= 0) {
      window.clearInterval(countdown);
      $<HTMLInputElement>("#password").focus();
    }
  }, 1000);
}

function setupUnlock() {
  const form = screens.unlock;
  const pw = $<HTMLInputElement>("#password");
  const btn = $<HTMLButtonElement>("#unlock-btn");
  const msg = $<HTMLElement>("#unlock-msg");
  const recovery = $<HTMLElement>("#recovery");

  /** Shared by Unlock and Restore previous version. */
  async function attempt(command: "unlock" | "restore_backup", busyLabel: string) {
    if (!pw.value || btn.disabled) return;
    btn.disabled = true;
    btn.textContent = busyLabel;
    msg.textContent = "";
    let outcome: UnlockOutcome;
    try {
      outcome = await invoke<UnlockOutcome>(command, { password: pw.value });
    } catch (err) {
      msg.textContent = errorText(err);
      shake(form);
      btn.disabled = false;
      btn.textContent = "Unlock";
      return;
    } finally {
      pw.value = "";
    }
    btn.disabled = false;
    btn.textContent = "Unlock";
    if (outcome.unlocked) {
      recovery.hidden = true;
      if (command === "restore_backup") toast("Restored the previous version of your vault");
      show("vault");
      return;
    }
    if (outcome.problem) {
      msg.textContent = "";
      $<HTMLElement>("#recovery-detail").textContent = `(${outcome.problem}.)`;
      $<HTMLElement>("#restore-btn").hidden = !outcome.can_restore;
      recovery.hidden = false;
      pw.focus();
      return;
    }
    shake(form);
    if (outcome.retry_after_secs > 0) {
      waitBeforeRetry(outcome.retry_after_secs);
    } else {
      msg.textContent = "Wrong password.";
      pw.focus();
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void attempt("unlock", "Unlocking…");
  });
  $<HTMLButtonElement>("#touchid-btn").addEventListener("click", () => void unlockWithTouchId());
  $<HTMLButtonElement>("#restore-btn").addEventListener("click", () => {
    if (!pw.value) {
      msg.textContent = "Enter your master password first.";
      return pw.focus();
    }
    void attempt("restore_backup", "Restoring…");
  });
}

interface AppInfo {
  version: string;
  commit: string;
  dirty: boolean;
}

interface UpdateCheck {
  status: "up-to-date" | "available" | "unknown-installed";
  installed: string;
  latest: string;
  commits: { sha: string; subject: string }[];
}

const short = (sha: string) => sha.slice(0, 7);

function resetUpdate() {
  $<HTMLElement>("#update-msg").textContent = "";
  $<HTMLElement>("#update-error").hidden = true;
  $<HTMLFormElement>("#update-form").hidden = true;
  $<HTMLInputElement>("#update-password").value = "";
}

function showUpdateError(text: string) {
  const pre = $<HTMLElement>("#update-error");
  pre.textContent = text;
  pre.title = text;
  pre.hidden = false;
}

async function lockNow() {
  await invoke("lock");
  showLocked("");
}

/** Shows the lock screen; `reason` explains a lock the user didn't click.
 * Locking never prompts by itself: Touch ID is asked for when the user comes
 * back (see setupTouchIdOnReturn), or right away if lockbox is in front. */
function showLocked(reason: string) {
  resetUpdate();
  $<HTMLElement>("#unlock-msg").textContent = reason;
  show("unlock");
  void offerTouchId(false);
  // Locked while away (sleep, hotkey from another app, hide): ask on return.
  promptOnReturn = document.hidden || !document.hasFocus();
}

/** Locks the UI follows: sleep, screen lock and the panic hotkey happen in
 * Rust; minimizing or hiding locks here when the setting is on. */
function setupBackgroundLocks() {
  onLockedElsewhere(() => showLocked("Locked."));
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && !screens.vault.hidden && getSettings().lock_on_hide) void lockNow();
  });
}

/** Locks after the configured minutes without keyboard or mouse activity. */
function setupIdleLock() {
  let last = Date.now();
  const touch = () => (last = Date.now());
  for (const ev of ["mousemove", "mousedown", "keydown", "wheel"]) {
    window.addEventListener(ev, touch, { passive: true, capture: true });
  }
  window.setInterval(() => {
    if (screens.vault.hidden) {
      last = Date.now();
      return;
    }
    if (Date.now() - last >= getSettings().auto_lock_minutes * 60_000) void lockNow();
  }, 5_000);
}

function setupVault() {
  $<HTMLButtonElement>("#lock-btn").addEventListener("click", lockNow);
  document.addEventListener("keydown", (e) => {
    if (screens.vault.hidden || !e.metaKey) return;
    if (e.key === "l") {
      e.preventDefault();
      void lockNow();
    } else if (e.key === ",") {
      e.preventDefault();
      openSettings();
    }
  });

  const checkBtn = $<HTMLButtonElement>("#update-check");
  const msg = $<HTMLElement>("#update-msg");
  const form = $<HTMLFormElement>("#update-form");
  const list = $<HTMLUListElement>("#update-commits");
  const pw = $<HTMLInputElement>("#update-password");
  const installBtn = $<HTMLButtonElement>("#update-install");

  checkBtn.addEventListener("click", async () => {
    resetUpdate();
    checkBtn.disabled = true;
    msg.textContent = "Checking master…";
    try {
      const r = await invoke<UpdateCheck>("update_check");
      if (r.status === "up-to-date") {
        msg.textContent = `Up to date with master (${short(r.latest)}).`;
        return;
      }
      msg.textContent =
        r.status === "available"
          ? `${r.commits.length === 20 ? "20+" : r.commits.length} new on master:`
          : "This build isn't from a known commit. Latest master:";
      list.replaceChildren(
        ...r.commits.map((c) => {
          const li = document.createElement("li");
          const code = document.createElement("code");
          code.textContent = short(c.sha);
          li.append(code, " ", c.subject);
          li.title = c.subject;
          return li;
        }),
      );
      form.hidden = false;
      pw.focus();
    } catch (err) {
      msg.textContent = "";
      showUpdateError(errorText(err));
    } finally {
      checkBtn.disabled = false;
    }
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!pw.value || installBtn.disabled) return;
    $<HTMLElement>("#update-error").hidden = true;
    installBtn.disabled = checkBtn.disabled = pw.disabled = true;
    installBtn.textContent = "Updating…";
    msg.textContent = "Building master. lockbox will restart when it's done.";
    try {
      // Only returns if the update failed; on success this app is replaced.
      await invoke("update_install", { password: pw.value });
    } catch (err) {
      const text = errorText(err);
      msg.textContent = "";
      if (text === "Wrong password.") {
        msg.textContent = text;
        shake(form);
      } else {
        showUpdateError(text);
      }
    } finally {
      pw.value = "";
      installBtn.disabled = checkBtn.disabled = pw.disabled = false;
      installBtn.textContent = "Update now";
    }
  });
}

async function showBuildInfo() {
  try {
    const info = await invoke<AppInfo>("app_info");
    $<HTMLElement>("#build-info").textContent =
      `lockbox ${info.version} · ${short(info.commit) || "unknown commit"}` +
      (info.dirty ? " + local changes" : "");
  } catch {
    // Not essential.
  }
}

window.addEventListener("DOMContentLoaded", async () => {
  setupCreate();
  setupUnlock();
  setupVault();
  setupAccounts();
  setupSettings();
  setupIdleLock();
  setupBackgroundLocks();
  setupTouchIdOnReturn();
  void showBuildInfo();
  await loadSettings();

  if (!(await invoke<boolean>("vault_exists"))) {
    show("create");
  } else if (await invoke<boolean>("is_locked")) {
    show("unlock");
    void offerTouchId(true); // at launch, ask right away
  } else {
    show("vault");
  }
});
