export const $ = <T extends HTMLElement>(sel: string) => document.querySelector<T>(sel)!;

export function shake(el: HTMLElement) {
  el.classList.remove("shake");
  void el.offsetWidth; // restart the animation
  el.classList.add("shake");
}

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : "Something went wrong.";
}

let toastTimer: number | undefined;

/** A short message at the bottom of the window. */
export function toast(message: string, error = false) {
  const el = $<HTMLElement>("#toast");
  el.textContent = message;
  el.classList.toggle("error", error);
  el.hidden = false;
  el.classList.remove("show");
  void el.offsetWidth;
  el.classList.add("show");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    el.classList.remove("show");
    el.hidden = true;
  }, 2600);
}
