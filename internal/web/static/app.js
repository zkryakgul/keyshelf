// keyshelf web UI. Plain JavaScript, no dependencies. Every piece of data reaches the page through
// textContent or element properties, never innerHTML.
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const CLEAR_AFTER_MS = 30000;

let csrf = "";
let folders = [];
let current = { folder: null, recursive: true, query: "" }; // folder null = all entries
let selected = null; // entry path
let tab = "fields";

// ---- helpers ----

function el(tag, props = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
    else if (k in n) n[k] = v;
    else n.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c != null) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return n;
}

const SVG = "http://www.w3.org/2000/svg";
function icon(name) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG, "use");
  use.setAttribute("href", "#i-" + name);
  svg.append(use);
  return svg;
}
const KINDS = ["login", "api-key", "url", "note"];
function kindBadge(kind, big) {
  const k = KINDS.includes(kind) ? kind : "note";
  return el("span", { class: "kind " + k + (big ? " big" : ""), title: k }, icon(k));
}
function iconButton(name, label, onClick, cls = "") {
  return el("button", { type: "button", class: cls, title: label, "aria-label": label, on: { click: onClick } }, icon(name));
}

// busy disables a form's buttons while fn runs (unseal and login take a moment: Argon2id).
async function busy(form, fn) {
  const buttons = [...form.querySelectorAll("button")];
  buttons.forEach((b) => (b.disabled = true));
  try { return await fn(); } finally { buttons.forEach((b) => (b.disabled = false)); }
}

function show(screen) {
  for (const s of document.querySelectorAll(".screen")) s.hidden = s.id !== "screen-" + screen;
  const f = $("#screen-" + screen + " [autofocus]");
  if (f) f.focus();
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 2500);
}

class APIError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}

async function api(method, path, { json, raw, query } = {}) {
  let url = "/api/v1/" + path;
  if (query) url += "?" + new URLSearchParams(query);
  const opt = { method, headers: {}, credentials: "same-origin", cache: "no-store" };
  if (method !== "GET" && csrf) opt.headers["X-CSRF-Token"] = csrf;
  if (json !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(json); }
  if (raw !== undefined) { opt.headers["Content-Type"] = "application/octet-stream"; opt.body = raw; }
  const r = await fetch(url, opt);
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).error || msg; } catch (_) { /* not JSON */ }
    if (r.status === 503 && /sealed/.test(msg)) { show("unseal"); }
    else if (r.status === 401 && path !== "login" && !/login password/.test(msg)) { csrf = ""; show("login"); }
    throw new APIError(r.status, msg);
  }
  if (r.status === 204) return null;
  const ct = r.headers.get("Content-Type") || "";
  return ct.includes("application/json") ? r.json() : new Uint8Array(await r.arrayBuffer());
}

function formError(form, err) {
  const p = $("[data-error]", form);
  if (p) p.textContent = err ? err.message || String(err) : "";
  if (err && form.classList.contains("auth")) {
    form.classList.remove("shake");
    void form.offsetWidth; // restart the animation
    form.classList.add("shake");
  }
}

// Show/hide buttons next to password inputs.
document.addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-peek]");
  if (!b) return;
  const input = b.parentElement.querySelector("input");
  const showing = input.type === "text";
  input.type = showing ? "password" : "text";
  b.replaceChildren(icon(showing ? "eye" : "eye-off"));
  b.setAttribute("aria-label", showing ? "Show" : "Hide");
});

function fmt(ts) {
  if (!ts) return "–";
  return new Date(ts).toLocaleString();
}

function generate(n = 32) {
  const set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!@#%^&*+=";
  const out = [];
  const buf = new Uint8Array(1);
  const limit = 256 - (256 % set.length); // rejection sampling: no modulo bias
  while (out.length < n) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) out.push(set[buf[0] % set.length]);
  }
  return out.join("");
}

async function copyText(text) {
  await navigator.clipboard.writeText(text);
  toast("Copied; the clipboard is cleared in 30 s");
  setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), CLEAR_AFTER_MS);
}

const decoder = new TextDecoder("utf-8", { fatal: true });
function asText(bytes) {
  try { return decoder.decode(bytes); } catch (_) { return null; }
}

function joinPath(folder, name) { return folder ? folder + "/" + name : name; }

// ---- boot and auth ----

async function boot() {
  let st;
  try { st = await api("GET", "status"); } catch (e) { $("#screen-loading p").textContent = "Cannot reach keyshelf: " + e.message; return; }
  if (!st.initialized) return show("uninit");
  if (st.sealed) return show("unseal");
  try {
    const s = await api("GET", "session");
    csrf = s.csrf;
    await enterApp();
  } catch (e) {
    if (!(e instanceof APIError)) throw e;
  }
}

$("#form-unseal").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  formError(f);
  try {
    await busy(f, () => api("POST", "unseal", { json: { passphrase: f.passphrase.value } }));
    f.reset();
    boot();
  } catch (e) { formError(f, e); f.passphrase.select(); }
});

$("#btn-recover").addEventListener("click", async () => {
  const f = $("#form-unseal");
  formError(f);
  try {
    await busy(f, () => api("POST", "recover", { json: { recovery_code: f.recovery.value, new_passphrase: f.newpass.value } }));
    f.reset();
    boot();
  } catch (e) { formError(f, e); }
});

$("#form-login").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  formError(f);
  try {
    const r = await busy(f, () => api("POST", "login", { json: { password: f.password.value, totp: f.totp.value.trim(), cookie: true } }));
    csrf = r.csrf;
    f.reset();
    await enterApp();
  } catch (e) { formError(f, e); }
});

$("#btn-logout").addEventListener("click", async () => {
  try { await api("POST", "logout"); } catch (_) { /* already gone */ }
  csrf = "";
  show("login");
});

$("#btn-seal").addEventListener("click", async () => {
  await api("POST", "seal");
  csrf = "";
  show("unseal");
});

// ---- theme ----

function applyTheme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
}
try { applyTheme(localStorage.getItem("ks-theme")); } catch (_) { /* storage blocked */ }
$("#btn-theme").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem("ks-theme", next); } catch (_) { /* ignore */ }
});

// ---- main view ----

async function enterApp() {
  show("app");
  if (!selected) renderEmptyDetail();
  await refresh();
}

async function refresh() {
  folders = await api("GET", "folders");
  renderTree();
  await loadEntries();
  if (selected) await showEntry(selected).catch(() => { selected = null; renderEmptyDetail(); });
}

function renderTree() {
  const root = { children: new Map(), path: "" };
  for (const f of folders) {
    if (!f.path) continue;
    let node = root;
    for (const seg of f.path.split("/")) {
      if (!node.children.has(seg)) node.children.set(seg, { children: new Map(), path: joinPath(node.path, seg), name: seg });
      node = node.children.get(seg);
    }
  }
  const build = (node) => el("ul", {}, [...node.children.values()].sort((a, b) => a.name.localeCompare(b.name)).map((c) =>
    el("li", {},
      el("a", { class: current.folder === c.path ? "active" : "", title: c.path, on: { click: () => selectFolder(c.path) } }, icon("folder"), c.name),
      c.children.size ? build(c) : null)));
  $("#tree-nav").replaceChildren(
    el("ul", {}, el("li", {}, el("a", { class: current.folder === null ? "active" : "", on: { click: () => selectFolder(null) } }, icon("all"), "All entries"))),
    root.children.size ? el("div", { class: "tree-label" }, "Folders") : null,
    build(root));
}

function selectFolder(path) {
  current = { folder: path, recursive: path === null, query: "" };
  $("#search").value = "";
  $("#tree").classList.remove("open");
  renderTree();
  loadEntries();
}

async function loadEntries() {
  let list, title;
  if (current.query) {
    list = await api("GET", "entries", { query: { q: current.query } });
    title = "Search: " + current.query;
  } else if (current.folder === null) {
    list = await api("GET", "entries", { query: { recursive: "1" } });
    title = "All entries";
  } else {
    list = await api("GET", "entries", { query: { folder: current.folder } });
    title = current.folder || "(root)";
  }
  $("#list-title").textContent = title;
  $("#list-count").textContent = list.length ? String(list.length) : "";
  $("#list-empty").hidden = list.length > 0;
  $("#entries").replaceChildren(...list.map((e, i) => {
    const path = joinPath(e.folder, e.name);
    const sub = [current.folder === e.folder ? "" : e.folder, e.username, e.url].filter(Boolean).join(" · ");
    const li = el("li", { class: path === selected ? "active" : "", on: { click: () => showEntry(path) } },
      kindBadge(e.kind),
      el("div", { class: "text" }, el("div", { class: "name" }, e.name), el("div", { class: "sub" }, sub || e.kind)),
      icon("chevron"));
    li.lastChild.classList.add("chev");
    li.style.setProperty("--i", String(Math.min(i, 20)));
    return li;
  }));
}

let searchTimer;
$("#search").addEventListener("input", (ev) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { current.query = ev.target.value.trim(); loadEntries(); }, 200);
});
$("#btn-menu").addEventListener("click", () => $("#tree").classList.toggle("open"));
$("#scrim").addEventListener("click", () => $("#tree").classList.remove("open"));
document.addEventListener("keydown", (ev) => {
  if (ev.key !== "/" || $("#screen-app").hidden || document.querySelector("dialog[open]")) return;
  if (/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) return;
  ev.preventDefault();
  $("#search").focus();
});

function renderEmptyDetail() {
  $("#detail").replaceChildren(el("div", { class: "empty" },
    el("img", { src: "logo.svg", alt: "", width: 48, height: 48 }),
    el("p", {}, "Select an entry"),
    el("p", { class: "muted" }, "Values stay hidden until you reveal or copy them, and every read is logged.")));
}

// ---- entry detail ----

async function showEntry(path) {
  const e = await api("GET", "entries/" + path);
  selected = path;
  for (const li of document.querySelectorAll("#entries li")) li.classList.toggle("active", li.querySelector(".name").textContent === e.name);
  const meta = el("dl", {},
    e.url ? [el("dt", {}, "URL"), el("dd", {}, /^https?:\/\//i.test(e.url) ? el("a", { href: e.url, target: "_blank", rel: "noopener noreferrer" }, e.url) : e.url)] : null,
    e.username ? [el("dt", {}, "Username"), el("dd", {}, e.username, el("button", { type: "button", on: { click: () => copyText(e.username) } }, icon("copy"), "Copy"))] : null,
    e.tags && e.tags.length ? [el("dt", {}, "Tags"), el("dd", { class: "tags" }, e.tags.map((t) => el("span", {}, t)))] : null,
    el("dt", {}, "Updated"), el("dd", {}, fmt(e.updated_at), " by ", e.updated_by));
  const tabs = el("div", { class: "tabs" },
    el("button", { class: tab === "fields" ? "active" : "", on: { click: () => { tab = "fields"; showEntry(path); } } }, "Secrets"),
    el("button", { class: tab === "audit" ? "active" : "", on: { click: () => { tab = "audit"; showEntry(path); } } }, "Audit"));
  const body = tab === "audit" ? await auditView(path) : fieldsView(path, e);
  $("#detail").replaceChildren(
    el("div", { class: "detail-head" }, kindBadge(e.kind, true),
      el("div", {}, el("h2", {}, e.name), el("div", { class: "crumb" }, path))),
    meta,
    el("div", { class: "row" },
      el("button", { type: "button", on: { click: () => openEntryDialog(e) } }, icon("edit"), "Edit"),
      el("button", { type: "button", on: { click: () => openFieldDialog(path) } }, icon("plus"), "Add secret field"),
      el("button", { type: "button", class: "danger", on: { click: () => deleteEntry(path) } }, icon("trash"), "Delete")),
    tabs, body);
  $("#detail").scrollTop = 0;
}

function fieldsView(path, e) {
  const rows = e.fields.map((f) => fieldRow(path, f, f));
  if (e.secret_notes) rows.push(fieldRow(path, "_notes", "notes (secret)"));
  const box = el("div", {}, rows.length ? rows : el("p", { class: "muted" }, "No secret fields yet."));
  if (e.notes && !e.secret_notes) box.append(el("h3", {}, "Notes"), el("pre", { class: "notes" }, e.notes));
  return box;
}

function fieldRow(path, field, label) {
  const value = el("span", { class: "fvalue muted" }, "••••••••");
  let hideTimer;
  const fetchValue = async () => {
    const bytes = await api("GET", "values/" + path, { query: { field } });
    return bytes;
  };
  const hide = () => {
    value.textContent = "••••••••";
    value.classList.add("muted");
    value.classList.remove("revealed");
    reveal.replaceChildren(icon("eye"));
    reveal.title = "Reveal";
  };
  const reveal = iconButton("eye", "Reveal", async () => {
    if (value.classList.contains("revealed")) { clearTimeout(hideTimer); return hide(); }
    const bytes = await fetchValue();
    const text = asText(bytes);
    value.textContent = text === null ? `(binary, ${bytes.length} bytes)` : text;
    value.classList.remove("muted");
    value.classList.add("revealed");
    reveal.replaceChildren(icon("eye-off"));
    reveal.title = "Hide";
    clearTimeout(hideTimer);
    hideTimer = setTimeout(hide, CLEAR_AFTER_MS);
  });
  return el("div", { class: "field" },
    el("span", { class: "fname", title: label }, label),
    value,
    el("div", { class: "row" },
      reveal,
      iconButton("copy", "Copy", async () => {
        const text = asText(await fetchValue());
        if (text === null) return toast("Binary value: use ks get --to-file");
        await copyText(text);
      }),
      field === "_notes" ? null : iconButton("edit", "Change", () => openFieldDialog(path, field)),
      field === "_notes" ? null : iconButton("trash", "Remove", async () => {
        if (!confirmInline(`Remove field ${field}? Earlier versions are kept.`)) return;
        await api("DELETE", "values/" + path, { query: { field } });
        showEntry(path);
      }, "danger")));
}

// confirm() is a modal browser dialog; a plain one is fine for a destructive click.
function confirmInline(msg) { return window.confirm(msg); }

async function auditView(path) {
  let events;
  try { events = await api("GET", "audit", { query: { target: path, limit: "100" } }); } catch (e) { return el("p", { class: "error" }, e.message); }
  if (!events.length) return el("p", { class: "muted" }, "No events.");
  return el("table", { class: "audit" }, el("tbody", {}, events.map((ev) =>
    el("tr", {}, el("td", {}, fmt(ev.at)), el("td", {}, ev.actor), el("td", {}, ev.action), el("td", {}, ev.target.includes("#") ? ev.target.split("#")[1] : "")))));
}

async function deleteEntry(path) {
  if (!confirmInline(`Delete ${path}?`)) return;
  await api("DELETE", "entries/" + path);
  selected = null;
  renderEmptyDetail();
  await refresh();
}

// ---- dialogs ----

const dlgEntry = $("#dlg-entry");
let editing = null;

function openEntryDialog(e) {
  editing = e || null;
  const f = $("#form-entry");
  f.reset();
  formError(f);
  $("[data-title]", f).textContent = e ? "Edit " + e.name : "New entry";
  $("[data-newonly]", f).hidden = !!e;
  f.path.readOnly = !!e;
  if (e) {
    f.path.value = joinPath(e.folder, e.name);
    f.kind.value = e.kind; f.url.value = e.url; f.username.value = e.username;
    f.tags.value = (e.tags || []).join(", "); f.notes.value = e.notes; f.secret_notes.checked = e.secret_notes;
    if (e.secret_notes) f.notes.placeholder = "Secret notes are not shown here; typing replaces them";
  } else {
    f.path.value = current.folder ? current.folder + "/" : "";
  }
  dlgEntry.showModal();
}

$("[data-generate]", dlgEntry).addEventListener("click", () => { const f = $("#form-entry"); f.value.value = generate(); f.value.type = "text"; });

$("[data-save]", dlgEntry).addEventListener("click", async (ev) => {
  ev.preventDefault();
  const f = $("#form-entry");
  if (!f.reportValidity()) return;
  formError(f);
  const path = f.path.value.trim().replace(/^\/+|\/+$/g, "");
  const input = {
    kind: f.kind.value, url: f.url.value.trim(), username: f.username.value.trim(),
    tags: f.tags.value.split(",").map((t) => t.trim()).filter(Boolean),
    notes: f.notes.value, secret_notes: f.secret_notes.checked,
  };
  try {
    if (editing && editing.secret_notes && input.secret_notes && input.notes === "") {
      // Keep the stored secret notes: send them back unchanged.
      const old = asText(await api("GET", "values/" + path, { query: { field: "_notes" } }));
      input.notes = old || "";
    }
    await api("PUT", "entries/" + path, { json: input });
    if (!editing && f.value.value) await api("PUT", "values/" + path, { query: { field: f.field.value.trim() || "password" }, raw: f.value.value });
    dlgEntry.close();
    selected = path;
    await refresh();
  } catch (e) { formError(f, e); }
});

$("#btn-new").addEventListener("click", () => openEntryDialog(null));

const dlgField = $("#dlg-field");
let fieldPath = "";
function openFieldDialog(path, field) {
  fieldPath = path;
  const f = $("#form-field");
  f.reset();
  formError(f);
  f.value.type = "password";
  f.field.value = field || "";
  f.field.readOnly = !!field;
  dlgField.showModal();
}
$("[data-generate]", dlgField).addEventListener("click", () => { const f = $("#form-field"); f.value.value = generate(); f.value.type = "text"; });
$("[data-save]", dlgField).addEventListener("click", async (ev) => {
  ev.preventDefault();
  const f = $("#form-field");
  if (!f.reportValidity()) return;
  try {
    await api("PUT", "values/" + fieldPath, { query: { field: f.field.value.trim() }, raw: f.value.value });
    dlgField.close();
    showEntry(fieldPath);
  } catch (e) { formError(f, e); }
});

// ---- tokens ----

const dlgTokens = $("#dlg-tokens");
async function loadTokens() {
  const list = await api("GET", "tokens");
  $("[data-rows]", dlgTokens).replaceChildren(...list.map((t) => el("tr", {},
    el("td", {}, t.name),
    el("td", {}, t.scopes.map((s) => el("div", {}, (s.folder || "(everything)") + ": " + s.perms.join(", ")))),
    el("td", {}, fmt(t.expires_at)),
    el("td", {}, fmt(t.last_used_at)),
    el("td", {}, el("button", { class: "danger", on: { click: async () => {
      if (!confirmInline(`Revoke token ${t.name}? Agents using it stop working at once.`)) return;
      await api("DELETE", "tokens/" + t.id);
      loadTokens();
    } } }, "Revoke")))));
  if (!list.length) $("[data-rows]", dlgTokens).append(el("tr", {}, el("td", { colSpan: 5, class: "muted" }, "No tokens yet.")));
}

$("#btn-tokens").addEventListener("click", async () => {
  const f = $("#form-token");
  f.reset();
  formError(f);
  $("[data-newtoken]", f).hidden = true;
  await loadTokens();
  dlgTokens.showModal();
});

$("[data-create]", dlgTokens).addEventListener("click", async () => {
  const f = $("#form-token");
  formError(f);
  try {
    const scopes = f.scopes.value.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => {
      const i = l.lastIndexOf(":");
      if (i < 0) throw new Error(`Scope "${l}" needs FOLDER:perms`);
      return { folder: l.slice(0, i).replace(/^\/+|\/+$/g, ""), perms: l.slice(i + 1).split(",").map((p) => p.trim()).filter(Boolean) };
    });
    const days = parseInt(f.days.value, 10);
    const r = await api("POST", "tokens", { json: { name: f.name.value.trim(), scopes, ttl_seconds: days > 0 ? days * 86400 : 0, password: f.password.value } });
    $("[data-secret]", f).textContent = r.token;
    $("[data-newtoken]", f).hidden = false;
    f.name.value = ""; f.scopes.value = ""; f.days.value = ""; f.password.value = "";
    loadTokens();
  } catch (e) { formError(f, e); }
});

$("[data-copy]", dlgTokens).addEventListener("click", () => copyText($("[data-secret]", dlgTokens).textContent));
dlgTokens.addEventListener("close", () => { $("[data-secret]", dlgTokens).textContent = ""; });

// ---- go ----

window.addEventListener("unhandledrejection", (ev) => {
  if (ev.reason instanceof APIError && (ev.reason.status === 401 || ev.reason.status === 503)) return;
  toast(ev.reason && ev.reason.message ? ev.reason.message : "Something went wrong");
});
boot();
