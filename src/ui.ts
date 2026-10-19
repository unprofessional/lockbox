export const $ = <T extends HTMLElement>(sel: string) => document.querySelector<T>(sel)!;

export function shake(el: HTMLElement) {
  el.classList.remove("shake");
  void el.offsetWidth; // restart the animation
  el.classList.add("shake");
}

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : "Something went wrong.";
}
