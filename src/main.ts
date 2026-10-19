import { invoke } from "@tauri-apps/api/core";

type Theme = "system" | "light" | "dark";

interface Settings {
  auto_lock_minutes: number;
  clipboard_wipe_seconds: number;
  theme: Theme;
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

window.addEventListener("DOMContentLoaded", async () => {
  const form = document.querySelector<HTMLFormElement>("#unlock-form")!;
  const password = document.querySelector<HTMLInputElement>("#password")!;
  const msg = document.querySelector<HTMLParagraphElement>("#unlock-msg")!;

  try {
    const settings = await invoke<Settings>("settings_get");
    applyTheme(settings.theme);
  } catch {
    // Defaults (follow system) are fine if settings can't be read.
  }

  // Always true until the vault lands in M2; the lock screen is the only view.
  await invoke<boolean>("is_locked");

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    password.value = "";
    msg.textContent = "No vault yet. Vault creation arrives in M2.";
    shake(form);
    password.focus();
  });
});
