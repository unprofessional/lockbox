// Accounts list, live codes, add/edit/delete (BRIEF §7, §8, §10).
// Seeds never reach this file: Rust returns metadata and rendered codes only.
import { invoke } from "@tauri-apps/api/core";
import { $, errorText, shake, toast } from "./ui";

type Kind = "totp" | "hotp";

interface EntryMeta {
  id: string;
  issuer: string;
  account: string;
  digits: number;
  period: number;
  algorithm: "SHA1" | "SHA256" | "SHA512";
  kind: Kind;
  tags: string[];
}

interface CodeOut {
  id: string;
  code: string;
  seconds_remaining: number;
  period: number;
}

interface Preview {
  token: string;
  issuer: string;
  account: string;
  digits: number;
  period: number;
  algorithm: string;
  kind: Kind;
  counter: number | null;
  duplicate: EntryMeta | null;
}

const RING = 2 * Math.PI * 9; // circumference of the countdown ring (r=9)

let entries: EntryMeta[] = [];
let timer: number | undefined;
let pending: Preview | null = null;
let editing: EntryMeta | null = null;

/** "483920" → "483 920", "48392017" → "4839 2017", 7 digits → "483 9201". */
export function groupDigits(code: string): string {
  const cut = code.length === 8 ? 4 : 3;
  return `${code.slice(0, cut)} ${code.slice(cut)}`;
}

function label(e: { issuer: string; account: string }) {
  return e.issuer || e.account;
}

// ---- tile grid and codes ----

interface Copied {
  code: string;
  wipe_seconds: number;
}

/** A stable hue per issuer, so each account keeps its colour (Authy-style). */
function hue(name: string): number {
  let h = 0;
  for (const ch of name.toLowerCase()) h = (h * 31 + ch.codePointAt(0)!) % 360;
  return h;
}

async function copy(e: EntryMeta, tile: HTMLElement) {
  try {
    const r = await invoke<Copied>("copy_code", { id: e.id });
    if (e.kind === "hotp") tile.querySelector(".code")!.textContent = groupDigits(r.code);
    tile.classList.remove("copied");
    void tile.offsetWidth;
    tile.classList.add("copied");
    toast(`Copied ${label(e)} · clipboard clears in ${r.wipe_seconds}s`);
  } catch (err) {
    toast(errorText(err), true);
  }
}

function render() {
  const list = $<HTMLUListElement>("#entries");
  const q = $<HTMLInputElement>("#search").value.trim().toLowerCase();
  const shown = entries.filter(
    (e) =>
      !q ||
      e.issuer.toLowerCase().includes(q) ||
      e.account.toLowerCase().includes(q) ||
      e.tags.some((t) => t.toLowerCase().includes(q)),
  );
  $<HTMLElement>("#empty").hidden = entries.length > 0;
  $<HTMLElement>("#no-matches").hidden = entries.length === 0 || shown.length > 0;

  list.replaceChildren(
    ...shown.map((e) => {
      const li = document.createElement("li");
      li.className = "tile";
      li.dataset.id = e.id;
      li.tabIndex = 0;
      li.setAttribute("role", "button");
      li.setAttribute(
        "aria-label",
        e.kind === "hotp" ? `Copy next code for ${label(e)}` : `Copy code for ${label(e)}`,
      );
      li.style.setProperty("--hue", String(hue(label(e))));

      const head = document.createElement("div");
      head.className = "tile-head";
      const avatar = document.createElement("span");
      avatar.className = "avatar";
      avatar.textContent = (label(e)[0] ?? "?").toUpperCase();
      avatar.setAttribute("aria-hidden", "true");

      const names = document.createElement("div");
      names.className = "names";
      const issuer = document.createElement("span");
      issuer.className = "issuer";
      issuer.textContent = label(e);
      const account = document.createElement("span");
      account.className = "account";
      account.textContent = e.issuer ? e.account : "";
      names.append(issuer, account);

      const edit = document.createElement("button");
      edit.type = "button";
      edit.className = "icon";
      edit.textContent = "⋯";
      edit.title = `Edit ${label(e)}`;
      edit.setAttribute("aria-label", `Edit ${label(e)}`);
      edit.addEventListener("click", (ev) => {
        ev.stopPropagation();
        openEdit(e);
      });
      head.append(avatar, names, edit);

      const foot = document.createElement("div");
      foot.className = "tile-foot";
      const code = document.createElement("span");
      code.className = "code";
      foot.append(code);
      if (e.kind === "totp") {
        foot.insertAdjacentHTML(
          "beforeend",
          '<svg class="ring" viewBox="0 0 24 24" aria-hidden="true">' +
            '<circle class="ring-bg" cx="12" cy="12" r="9"/>' +
            '<circle class="ring-fg" cx="12" cy="12" r="9"/></svg>',
        );
        foot.querySelector(".ring-fg")!.setAttribute("stroke-dasharray", String(RING));
      } else {
        code.textContent = "––– –––";
        const hint = document.createElement("span");
        hint.className = "hotp-hint";
        hint.textContent = "Click for next code";
        foot.append(hint);
      }
      if (e.tags.length) {
        const tags = document.createElement("span");
        tags.className = "tags";
        tags.textContent = e.tags.join(" · ");
        li.append(head, foot, tags);
      } else {
        li.append(head, foot);
      }

      li.addEventListener("click", () => copy(e, li));
      li.addEventListener("keydown", (ev) => {
        if (ev.target === li && (ev.key === "Enter" || ev.key === " ")) {
          ev.preventDefault();
          void copy(e, li);
        }
      });
      return li;
    }),
  );
  void tick();
}

export async function refresh() {
  entries = await invoke<EntryMeta[]>("list_entries");
  entries.sort((a, b) => label(a).localeCompare(label(b), undefined, { sensitivity: "base" }));
  render();
}

async function tick() {
  let codes: CodeOut[];
  try {
    codes = await invoke<CodeOut[]>("get_codes");
  } catch {
    return; // locked mid-tick; stopAccounts() cleans up
  }
  for (const c of codes) {
    const li = document.querySelector<HTMLElement>(`.tile[data-id="${c.id}"]`);
    if (!li) continue;
    const code = li.querySelector<HTMLElement>(".code")!;
    const grouped = groupDigits(c.code);
    if (code.textContent !== grouped) code.textContent = grouped;
    li.classList.toggle("expiring", c.seconds_remaining <= 5);
    const fg = li.querySelector(".ring-fg");
    fg?.setAttribute("stroke-dashoffset", String(RING * (1 - c.seconds_remaining / c.period)));
  }
}

export function startAccounts() {
  void refresh();
  window.clearInterval(timer);
  timer = window.setInterval(tick, 1000);
}

export function stopAccounts() {
  window.clearInterval(timer);
  timer = undefined;
  entries = [];
  pending = null;
  editing = null;
  $<HTMLUListElement>("#entries").replaceChildren();
  $<HTMLInputElement>("#search").value = "";
  for (const d of document.querySelectorAll<HTMLDialogElement>("dialog")) d.close();
}

// ---- add ----

type Tab = "qr" | "uri" | "manual";
const FOCUS: Record<Tab, string> = { qr: "#dropzone", uri: "#uri", manual: "#m-issuer" };

function setTab(tab: Tab) {
  for (const t of ["qr", "uri", "manual"] as Tab[]) {
    $<HTMLElement>(`#tab-${t}`).setAttribute("aria-selected", String(t === tab));
    $<HTMLElement>(`#pane-${t}`).hidden = t !== tab;
  }
  $<HTMLElement>(FOCUS[tab]).focus();
}

function activeTab(): Tab {
  return (["qr", "uri", "manual"] as Tab[]).find((t) => !$<HTMLElement>(`#pane-${t}`).hidden)!;
}

function clearAddForm() {
  for (const sel of ["#uri", "#m-issuer", "#m-account", "#m-seed"]) {
    $<HTMLInputElement>(sel).value = "";
  }
  $<HTMLSelectElement>("#m-kind").value = "totp";
  $<HTMLSelectElement>("#m-digits").value = "6";
  $<HTMLSelectElement>("#m-algo").value = "SHA1";
  $<HTMLInputElement>("#m-period").value = "30";
  $<HTMLInputElement>("#m-counter").value = "0";
  syncKindFields();
  $<HTMLElement>("#add-error").textContent = "";
  $<HTMLElement>("#confirm-error").textContent = "";
}

function syncKindFields() {
  const hotp = $<HTMLSelectElement>("#m-kind").value === "hotp";
  $<HTMLElement>("#m-period-field").hidden = hotp;
  $<HTMLElement>("#m-counter-field").hidden = !hotp;
}

function showAddStep(preview: boolean) {
  $<HTMLElement>("#add-input").hidden = preview;
  $<HTMLElement>("#add-preview").hidden = !preview;
}

function openAdd() {
  pending = null;
  clearAddForm();
  showAddStep(false);
  $<HTMLDialogElement>("#add-dialog").showModal();
  setTab("qr");
}

function describe(p: Preview): string {
  const kind = p.kind === "totp" ? `every ${p.period}s` : `counter ${p.counter ?? 0}`;
  return `${p.digits} digits, ${kind}, ${p.algorithm}`;
}

async function submitAddInput(e: SubmitEvent) {
  e.preventDefault();
  const err = $<HTMLElement>("#add-error");
  err.textContent = "";
  const tab = activeTab();
  if (tab === "qr") {
    $<HTMLInputElement>("#qr-file").click();
    return;
  }
  try {
    if (tab === "manual") {
      const kind = $<HTMLSelectElement>("#m-kind").value as Kind;
      pending = await invoke<Preview>("entry_preview_manual", {
        form: {
          issuer: $<HTMLInputElement>("#m-issuer").value,
          account: $<HTMLInputElement>("#m-account").value,
          seed: $<HTMLInputElement>("#m-seed").value,
          digits: Number($<HTMLSelectElement>("#m-digits").value),
          algorithm: $<HTMLSelectElement>("#m-algo").value,
          kind,
          period: kind === "totp" ? Number($<HTMLInputElement>("#m-period").value) : null,
          counter: kind === "hotp" ? Number($<HTMLInputElement>("#m-counter").value) : null,
        },
      });
    } else {
      pending = await invoke<Preview>("entry_preview_uri", {
        uri: $<HTMLTextAreaElement>("#uri").value,
      });
    }
  } catch (ex) {
    err.textContent = errorText(ex);
    shake($<HTMLElement>("#add-input"));
    return;
  }
  // The secret has been handed to Rust; don't keep it in the DOM.
  $<HTMLTextAreaElement>("#uri").value = "";
  $<HTMLInputElement>("#m-seed").value = "";
  showPreview(pending);
}

/** The QR screenshot goes to Rust as raw bytes; only the preview comes back. */
async function previewImage(file: Blob | null) {
  const err = $<HTMLElement>("#add-error");
  err.textContent = "";
  if (!file) return;
  if (!/^image\/(png|jpeg)$/.test(file.type)) {
    err.textContent = "Use a PNG or JPEG image (screenshots are PNG).";
    shake($<HTMLElement>("#add-input"));
    return;
  }
  const zone = $<HTMLElement>("#dropzone");
  zone.classList.add("busy");
  try {
    pending = await invoke<Preview>("entry_preview_qr", new Uint8Array(await file.arrayBuffer()));
  } catch (ex) {
    err.textContent = errorText(ex);
    shake($<HTMLElement>("#add-input"));
    return;
  } finally {
    zone.classList.remove("busy", "over");
    $<HTMLInputElement>("#qr-file").value = "";
  }
  showPreview(pending);
}

function showPreview(pending: Preview) {
  $<HTMLElement>("#p-issuer").textContent = pending.issuer || "—";
  $<HTMLElement>("#p-account").textContent = pending.account || "—";
  $<HTMLElement>("#p-format").textContent = describe(pending);
  const dup = $<HTMLElement>("#p-duplicate");
  dup.hidden = !pending.duplicate;
  dup.textContent = pending.duplicate
    ? `You already have this account (${label(pending.duplicate)}) with the same secret. Adding it again will replace it.`
    : "";
  $<HTMLButtonElement>("#confirm-btn").textContent = pending.duplicate ? "Replace" : "Add account";
  $<HTMLElement>("#confirm-error").textContent = "";
  showAddStep(true);
  $<HTMLButtonElement>("#confirm-btn").focus();
}

async function submitConfirm(e: SubmitEvent) {
  e.preventDefault();
  if (!pending) return;
  try {
    await invoke<string>("entry_confirm", {
      token: pending.token,
      replace: pending.duplicate !== null,
    });
  } catch (ex) {
    $<HTMLElement>("#confirm-error").textContent = errorText(ex);
    return;
  }
  pending = null;
  $<HTMLDialogElement>("#add-dialog").close();
  await refresh();
}

// ---- edit / delete ----

function openEdit(e: EntryMeta) {
  editing = e;
  $<HTMLInputElement>("#e-issuer").value = e.issuer;
  $<HTMLInputElement>("#e-account").value = e.account;
  $<HTMLInputElement>("#e-tags").value = e.tags.join(", ");
  $<HTMLElement>("#edit-error").textContent = "";
  showDeleteStep(false);
  $<HTMLDialogElement>("#edit-dialog").showModal();
  $<HTMLInputElement>("#e-issuer").focus();
}

async function submitEdit(ev: SubmitEvent) {
  ev.preventDefault();
  if (!editing) return;
  const tags = $<HTMLInputElement>("#e-tags")
    .value.split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  try {
    await invoke("edit_entry", {
      id: editing.id,
      issuer: $<HTMLInputElement>("#e-issuer").value,
      account: $<HTMLInputElement>("#e-account").value,
      tags,
    });
  } catch (ex) {
    $<HTMLElement>("#edit-error").textContent = errorText(ex);
    shake($<HTMLElement>("#edit-form"));
    return;
  }
  $<HTMLDialogElement>("#edit-dialog").close();
  await refresh();
}

/** Swaps the edit form for a separate confirmation step (and back). */
function showDeleteStep(confirming: boolean) {
  $<HTMLElement>("#edit-form").hidden = confirming;
  $<HTMLElement>("#delete-confirm").hidden = !confirming;
  $<HTMLElement>("#delete-error").textContent = "";
  if (confirming && editing) {
    $<HTMLElement>("#delete-title").textContent = `Delete ${label(editing)}?`;
    $<HTMLElement>("#delete-name").textContent = label(editing);
    // The safe choice has focus, so Enter or a stray double-click keeps it.
    $<HTMLButtonElement>("#delete-cancel").focus();
  }
}

async function confirmDelete(ev: SubmitEvent) {
  ev.preventDefault();
  if (!editing) return;
  try {
    await invoke("delete_entry", { id: editing.id });
  } catch (ex) {
    $<HTMLElement>("#delete-error").textContent = errorText(ex);
    return;
  }
  const name = label(editing);
  $<HTMLDialogElement>("#edit-dialog").close();
  await refresh();
  toast(`Deleted ${name}`);
}

export function setupAccounts() {
  $<HTMLInputElement>("#search").addEventListener("input", render);
  $<HTMLButtonElement>("#add-btn").addEventListener("click", openAdd);
  for (const t of ["qr", "uri", "manual"] as Tab[]) {
    $<HTMLButtonElement>(`#tab-${t}`).addEventListener("click", () => setTab(t));
  }

  // QR screenshots: choose, drop or paste.
  const zone = $<HTMLElement>("#dropzone");
  const fileInput = $<HTMLInputElement>("#qr-file");
  // The whole zone (including its button) opens the picker.
  zone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => previewImage(fileInput.files?.[0] ?? null));
  zone.addEventListener("keydown", (e) => {
    if (e.target === zone && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault();
      fileInput.click();
    }
  });
  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("over");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    void previewImage(e.dataTransfer?.files[0] ?? null);
  });
  // Dropping anywhere else in the window shouldn't navigate away.
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());
  document.addEventListener("paste", (e) => {
    const dialog = $<HTMLDialogElement>("#add-dialog");
    if (!dialog.open || !$<HTMLElement>("#add-preview").hidden) return;
    const item = [...(e.clipboardData?.items ?? [])].find((i) => i.type.startsWith("image/"));
    if (!item) return; // ordinary text paste into the link or manual fields
    e.preventDefault();
    setTab("qr");
    void previewImage(item.getAsFile());
  });
  $<HTMLSelectElement>("#m-kind").addEventListener("change", syncKindFields);
  $<HTMLFormElement>("#add-input").addEventListener("submit", submitAddInput);
  $<HTMLFormElement>("#add-preview").addEventListener("submit", submitConfirm);
  $<HTMLButtonElement>("#preview-back").addEventListener("click", () => {
    pending = null;
    showAddStep(false);
  });
  $<HTMLFormElement>("#edit-form").addEventListener("submit", submitEdit);
  $<HTMLButtonElement>("#delete-btn").addEventListener("click", () => showDeleteStep(true));
  $<HTMLButtonElement>("#delete-cancel").addEventListener("click", () => {
    showDeleteStep(false);
    $<HTMLButtonElement>("#delete-btn").focus();
  });
  $<HTMLFormElement>("#delete-confirm").addEventListener("submit", confirmDelete);
  for (const d of document.querySelectorAll<HTMLDialogElement>("dialog")) {
    d.querySelectorAll("[data-close]").forEach((b) =>
      b.addEventListener("click", () => d.close()),
    );
    d.addEventListener("close", () => {
      showDeleteStep(false);
      clearAddForm();
    });
  }
  // ⌘N / ⌘F shortcuts while the vault is open.
  document.addEventListener("keydown", (e) => {
    if ($<HTMLElement>("#vault-view").hidden || !e.metaKey) return;
    if (e.key === "n") {
      e.preventDefault();
      openAdd();
    } else if (e.key === "f") {
      e.preventDefault();
      $<HTMLInputElement>("#search").focus();
    }
  });
}
