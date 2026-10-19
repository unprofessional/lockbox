import { invoke } from "@tauri-apps/api/core";

type Theme = "system" | "light" | "dark";

interface Settings {
  auto_lock_minutes: number;
  clipboard_wipe_seconds: number;
  theme: Theme;
}

const MIN_PASSWORD_CHARS = 8; // mirrors vault::MIN_PASSWORD_CHARS

const $ = <T extends HTMLElement>(sel: string) => document.querySelector<T>(sel)!;

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
    vault: "#lock-btn",
  };
  $<HTMLElement>(focus[name]).focus();
}

function applyTheme(theme: Theme) {
  if (theme === "system") {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = theme;
  }
}

function shake(el: HTMLElement) {
  el.classList.remove("shake");
  void el.offsetWidth; // restart the animation
  el.classList.add("shake");
}

function errorText(e: unknown): string {
  return typeof e === "string" ? e : "Something went wrong.";
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

function setupUnlock() {
  const form = screens.unlock;
  const pw = $<HTMLInputElement>("#password");
  const btn = $<HTMLButtonElement>("#unlock-btn");
  const msg = $<HTMLElement>("#unlock-msg");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!pw.value || btn.disabled) return;
    btn.disabled = true;
    btn.textContent = "Unlocking…";
    msg.textContent = "";
    try {
      const ok = await invoke<boolean>("unlock", { password: pw.value });
      pw.value = "";
      if (ok) {
        show("vault");
      } else {
        msg.textContent = "Wrong password.";
        shake(form);
        pw.focus();
      }
    } catch (err) {
      pw.value = "";
      msg.textContent = errorText(err);
      shake(form);
    } finally {
      btn.disabled = false;
      btn.textContent = "Unlock";
    }
  });
}

function setupVault() {
  $<HTMLButtonElement>("#lock-btn").addEventListener("click", async () => {
    await invoke("lock");
    $<HTMLElement>("#unlock-msg").textContent = "";
    show("unlock");
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  setupCreate();
  setupUnlock();
  setupVault();

  try {
    applyTheme((await invoke<Settings>("settings_get")).theme);
  } catch {
    // Defaults (follow system) are fine if settings can't be read.
  }

  if (!(await invoke<boolean>("vault_exists"))) {
    show("create");
  } else if (await invoke<boolean>("is_locked")) {
    show("unlock");
  } else {
    show("vault");
  }
});
