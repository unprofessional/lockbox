// Accounts list, live codes, add/edit/delete (BRIEF §7, §8, §10).
// Seeds never reach this file: Rust returns metadata and rendered codes only.
import { invoke } from "@tauri-apps/api/core";
import { $, errorText, shake } from "./ui";

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

// ---- list and codes ----

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
      li.className = "entry";
      li.dataset.id = e.id;

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
      if (e.tags.length) {
        const tags = document.createElement("span");
        tags.className = "tags";
        tags.textContent = e.tags.join(" · ");
        names.append(tags);
      }

      const code = document.createElement("span");
      code.className = "code";
      code.textContent = e.kind === "hotp" ? "––– –––" : "";
      code.title = "Select and press ⌘C to copy (one-click copy arrives in M4)";

      const side = document.createElement("div");
      side.className = "side";
      if (e.kind === "totp") {
        side.innerHTML =
          '<svg class="ring" viewBox="0 0 24 24" aria-hidden="true">' +
          '<circle class="ring-bg" cx="12" cy="12" r="9"/>' +
          '<circle class="ring-fg" cx="12" cy="12" r="9"/></svg>';
        side.querySelector(".ring-fg")!.setAttribute("stroke-dasharray", String(RING));
      } else {
        const next = document.createElement("button");
        next.type = "button";
        next.className = "secondary small";
        next.textContent = "Next code";
        next.addEventListener("click", () => nextHotp(e.id, code));
        side.append(next);
      }

      const edit = document.createElement("button");
      edit.type = "button";
      edit.className = "icon";
      edit.textContent = "⋯";
      edit.title = `Edit ${label(e)}`;
      edit.setAttribute("aria-label", `Edit ${label(e)}`);
      edit.addEventListener("click", () => openEdit(e));

      li.append(avatar, names, code, side, edit);
      return li;
    }),
  );
  void tick();
}

async function refresh() {
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
    const li = document.querySelector<HTMLElement>(`.entry[data-id="${c.id}"]`);
    if (!li) continue;
    const code = li.querySelector<HTMLElement>(".code")!;
    const grouped = groupDigits(c.code);
    if (code.textContent !== grouped) code.textContent = grouped;
    li.classList.toggle("expiring", c.seconds_remaining <= 5);
    const fg = li.querySelector(".ring-fg");
    fg?.setAttribute("stroke-dashoffset", String(RING * (1 - c.seconds_remaining / c.period)));
  }
}

async function nextHotp(id: string, codeEl: HTMLElement) {
  try {
    codeEl.textContent = groupDigits(await invoke<string>("hotp_next", { id }));
  } catch (err) {
    codeEl.textContent = "error";
    codeEl.title = errorText(err);
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

function setTab(manual: boolean) {
  $<HTMLElement>("#tab-uri").setAttribute("aria-selected", String(!manual));
  $<HTMLElement>("#tab-manual").setAttribute("aria-selected", String(manual));
  $<HTMLElement>("#pane-uri").hidden = manual;
  $<HTMLElement>("#pane-manual").hidden = !manual;
  $<HTMLElement>(manual ? "#m-issuer" : "#uri").focus();
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
  setTab(false);
}

function describe(p: Preview): string {
  const kind = p.kind === "totp" ? `every ${p.period}s` : `counter ${p.counter ?? 0}`;
  return `${p.digits} digits, ${kind}, ${p.algorithm}`;
}

async function submitAddInput(e: SubmitEvent) {
  e.preventDefault();
  const err = $<HTMLElement>("#add-error");
  err.textContent = "";
  const manual = !$<HTMLElement>("#pane-manual").hidden;
  try {
    if (manual) {
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
  $<HTMLButtonElement>("#delete-btn").textContent = "Delete…";
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

/** Two clicks: the first arms the button, the second deletes. */
async function clickDelete() {
  if (!editing) return;
  const btn = $<HTMLButtonElement>("#delete-btn");
  if (btn.dataset.armed !== "true") {
    btn.dataset.armed = "true";
    btn.textContent = `Delete ${label(editing)} for good`;
    return;
  }
  try {
    await invoke("delete_entry", { id: editing.id });
  } catch (ex) {
    $<HTMLElement>("#edit-error").textContent = errorText(ex);
    return;
  }
  $<HTMLDialogElement>("#edit-dialog").close();
  await refresh();
}

export function setupAccounts() {
  $<HTMLInputElement>("#search").addEventListener("input", render);
  $<HTMLButtonElement>("#add-btn").addEventListener("click", openAdd);
  $<HTMLButtonElement>("#tab-uri").addEventListener("click", () => setTab(false));
  $<HTMLButtonElement>("#tab-manual").addEventListener("click", () => setTab(true));
  $<HTMLSelectElement>("#m-kind").addEventListener("change", syncKindFields);
  $<HTMLFormElement>("#add-input").addEventListener("submit", submitAddInput);
  $<HTMLFormElement>("#add-preview").addEventListener("submit", submitConfirm);
  $<HTMLButtonElement>("#preview-back").addEventListener("click", () => {
    pending = null;
    showAddStep(false);
  });
  $<HTMLFormElement>("#edit-form").addEventListener("submit", submitEdit);
  $<HTMLButtonElement>("#delete-btn").addEventListener("click", clickDelete);
  for (const d of document.querySelectorAll<HTMLDialogElement>("dialog")) {
    d.querySelectorAll("[data-close]").forEach((b) =>
      b.addEventListener("click", () => d.close()),
    );
    d.addEventListener("close", () => {
      delete $<HTMLButtonElement>("#delete-btn").dataset.armed;
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
