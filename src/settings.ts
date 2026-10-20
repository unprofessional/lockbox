// Settings sheet (BRIEF §10): theme, auto-lock, clipboard wipe, master password.
import { invoke } from "@tauri-apps/api/core";
import { refresh as refreshAccounts } from "./accounts";
import { $, errorText, shake, toast } from "./ui";

export type Theme = "system" | "light" | "dark";

export interface Settings {
  auto_lock_minutes: number;
  clipboard_wipe_seconds: number;
  theme: Theme;
  lock_on_hide: boolean;
  hide_codes_from_accessibility: boolean;
}

const MIN_PASSWORD_CHARS = 8; // mirrors vault::MIN_PASSWORD_CHARS

let current: Settings = {
  auto_lock_minutes: 5,
  clipboard_wipe_seconds: 30,
  theme: "system",
  lock_on_hide: false,
  hide_codes_from_accessibility: false,
};

/** Called after settings change, so the tiles can re-render. */
let onChange: () => void = () => {};
export const onSettingsChange = (f: () => void) => (onChange = f);

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
  $<HTMLInputElement>("#s-lockhide").checked = current.lock_on_hide;
  $<HTMLInputElement>("#s-a11y").checked = current.hide_codes_from_accessibility;
  $<HTMLElement>("#settings-msg").textContent = "";
}

async function save(patch: Partial<Settings>) {
  try {
    current = await invoke<Settings>("settings_set", { settings: { ...current, ...patch } });
    applyTheme(current.theme);
    onChange();
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

interface Exported {
  path: string;
  accounts: number;
}

interface ImportSummary {
  added: number;
  skipped: number;
}

let importToken: string | null = null;

function resetBackup() {
  importToken = null;
  $<HTMLInputElement>("#export-password").value = "";
  $<HTMLInputElement>("#import-password").value = "";
  $<HTMLInputElement>("#import-file").value = "";
  $<HTMLElement>("#import-step").hidden = true;
  $<HTMLElement>("#backup-msg").textContent = "";
}

function plural(n: number, word: string) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function setupBackup() {
  const msg = $<HTMLElement>("#backup-msg");

  const exportForm = $<HTMLFormElement>("#export-form");
  const exportBtn = $<HTMLButtonElement>("#export-btn");
  exportForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = $<HTMLInputElement>("#export-password");
    if (!pw.value) return pw.focus();
    exportBtn.disabled = true;
    msg.textContent = "";
    try {
      // Rust re-checks the password, then shows the native save panel.
      const r = await invoke<Exported | null>("export_backup", { password: pw.value });
      pw.value = "";
      if (r) {
        msg.textContent = `Saved ${plural(r.accounts, "account")} to ${r.path}`;
        toast("Backup saved");
      }
    } catch (err) {
      msg.textContent = errorText(err);
      shake(exportForm);
    } finally {
      exportBtn.disabled = false;
    }
  });

  const importForm = $<HTMLFormElement>("#import-form");
  const fileInput = $<HTMLInputElement>("#import-file");
  const importBtn = $<HTMLButtonElement>("#import-btn");
  $<HTMLButtonElement>("#import-pick").addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    msg.textContent = "";
    try {
      // Encrypted bytes go to Rust as a raw body and wait for the password.
      importToken = await invoke<string>("import_stage", new Uint8Array(await file.arrayBuffer()));
      $<HTMLElement>("#import-file-name").textContent = file.name;
      $<HTMLElement>("#import-step").hidden = false;
      $<HTMLInputElement>("#import-password").focus();
    } catch (err) {
      msg.textContent = errorText(err);
    } finally {
      fileInput.value = "";
    }
  });
  importForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = $<HTMLInputElement>("#import-password");
    if (!importToken || !pw.value) return;
    importBtn.disabled = true;
    msg.textContent = "";
    try {
      const r = await invoke<ImportSummary>("import_confirm", { token: importToken, password: pw.value });
      resetBackup();
      msg.textContent =
        `Added ${plural(r.added, "account")}` +
        (r.skipped ? ` · ${r.skipped} already in your vault` : "") + ".";
      toast(`Imported ${plural(r.added, "account")}`);
      await refreshAccounts();
    } catch (err) {
      msg.textContent = errorText(err);
      shake(importForm);
    } finally {
      pw.value = "";
      importBtn.disabled = false;
    }
  });
}

export function openSettings() {
  populate();
  resetPasswordForm();
  resetBackup();
  $<HTMLDialogElement>("#settings-dialog").showModal();
  $<HTMLSelectElement>("#s-theme").focus();
}

export function setupSettings() {
  setupBackup();
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
  $<HTMLInputElement>("#s-lockhide").addEventListener("change", (e) =>
    save({ lock_on_hide: (e.target as HTMLInputElement).checked }),
  );
  $<HTMLInputElement>("#s-a11y").addEventListener("change", (e) =>
    save({ hide_codes_from_accessibility: (e.target as HTMLInputElement).checked }),
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
