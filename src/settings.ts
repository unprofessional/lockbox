// Settings sheet (BRIEF §10): theme, auto-lock, clipboard wipe, master password.
import { invoke } from "@tauri-apps/api/core";
import { $, errorText, shake, toast } from "./ui";

export type Theme = "system" | "light" | "dark";

export interface Settings {
  auto_lock_minutes: number;
  clipboard_wipe_seconds: number;
  theme: Theme;
}

const MIN_PASSWORD_CHARS = 8; // mirrors vault::MIN_PASSWORD_CHARS

let current: Settings = { auto_lock_minutes: 5, clipboard_wipe_seconds: 30, theme: "system" };

export const getSettings = () => current;

export function applyTheme(theme: Theme) {
  if (theme === "system") {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = theme;
  }
}

/** Allowed while locked, so the lock screen gets the right theme. */
export async function loadSettings() {
  try {
    current = await invoke<Settings>("settings_get");
  } catch {
    // Defaults are fine if settings can't be read.
  }
  applyTheme(current.theme);
}

/** Selects a value, adding it as an option first if a hand-edited file holds an unusual one. */
function selectValue(sel: HTMLSelectElement, value: number | string, text: string) {
  const v = String(value);
  if (![...sel.options].some((o) => o.value === v)) sel.add(new Option(text, v));
  sel.value = v;
}

function populate() {
  $<HTMLSelectElement>("#s-theme").value = current.theme;
  selectValue($<HTMLSelectElement>("#s-autolock"), current.auto_lock_minutes, `${current.auto_lock_minutes} minutes`);
  selectValue($<HTMLSelectElement>("#s-wipe"), current.clipboard_wipe_seconds, `${current.clipboard_wipe_seconds} seconds`);
  $<HTMLElement>("#settings-msg").textContent = "";
}

async function save(patch: Partial<Settings>) {
  try {
    current = await invoke<Settings>("settings_set", { settings: { ...current, ...patch } });
    applyTheme(current.theme);
    $<HTMLElement>("#settings-msg").textContent = "";
  } catch (err) {
    $<HTMLElement>("#settings-msg").textContent = errorText(err);
    populate();
  }
}

function resetPasswordForm() {
  for (const id of ["#pw-old", "#pw-new", "#pw-confirm"]) $<HTMLInputElement>(id).value = "";
  $<HTMLElement>("#pw-msg").textContent = "";
}

export function openSettings() {
  populate();
  resetPasswordForm();
  $<HTMLDialogElement>("#settings-dialog").showModal();
  $<HTMLSelectElement>("#s-theme").focus();
}

export function setupSettings() {
  $<HTMLButtonElement>("#settings-btn").addEventListener("click", openSettings);
  $<HTMLSelectElement>("#s-theme").addEventListener("change", (e) =>
    save({ theme: (e.target as HTMLSelectElement).value as Theme }),
  );
  $<HTMLSelectElement>("#s-autolock").addEventListener("change", (e) =>
    save({ auto_lock_minutes: Number((e.target as HTMLSelectElement).value) }),
  );
  $<HTMLSelectElement>("#s-wipe").addEventListener("change", (e) =>
    save({ clipboard_wipe_seconds: Number((e.target as HTMLSelectElement).value) }),
  );

  const form = $<HTMLFormElement>("#pw-form");
  const btn = $<HTMLButtonElement>("#pw-btn");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const old = $<HTMLInputElement>("#pw-old").value;
    const next = $<HTMLInputElement>("#pw-new").value;
    const confirm = $<HTMLInputElement>("#pw-confirm").value;
    const msg = $<HTMLElement>("#pw-msg");
    if (!old) return;
    if ([...next].length < MIN_PASSWORD_CHARS) {
      msg.textContent = `New password must be at least ${MIN_PASSWORD_CHARS} characters.`;
      return shake(form);
    }
    if (next !== confirm) {
      msg.textContent = "New passwords don't match.";
      return shake(form);
    }
    btn.disabled = true;
    btn.textContent = "Changing…";
    msg.textContent = "";
    try {
      if (await invoke<boolean>("change_password", { old, new: next })) {
        resetPasswordForm();
        toast("Master password changed");
      } else {
        msg.textContent = "Current password is wrong.";
        shake(form);
      }
    } catch (err) {
      msg.textContent = errorText(err);
    } finally {
      btn.disabled = false;
      btn.textContent = "Change password";
    }
  });
}
