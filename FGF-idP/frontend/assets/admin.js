"use strict";

// The page is served under a strict CSP (default-src 'none'; script-src 'self').
// That means no inline handlers and no inline styles: every listener is attached
// here, and rows are cloned from <template> with textContent only, never
// innerHTML — usernames, client names and redirect URIs are attacker-controlled.

const ROLES = [
  { value: 0, label: "訪客 (0)" },
  { value: 1, label: "一般 (1)" },
  { value: 4, label: "管理員 (4)" },
  { value: 6, label: "Root (6)" },
];
const ROOT_ROLE = 6;
const PAGE_SIZE = 20;

const el = (id) => document.getElementById(id);
const signin = el("signin");
const signinForm = el("signin-form");
const signinFields = el("signin-fields");
const signinFeedback = el("signin-feedback");
const signinLabel = el("signin-label");
const consolePanel = el("console");
const feedback = el("feedback");
const whoami = el("whoami");
const logout = el("logout");
const clientsTab = document.querySelector('[data-tab="clients"]');

let me = null;
const users = { rows: el("user-rows"), page: 1, hasMore: false, query: "" };
const clients = { rows: el("client-rows"), page: 1, hasMore: false, query: "" };

// --- transport ---------------------------------------------------------------

async function api(path, options) {
  const init = {
    credentials: "same-origin",
    redirect: "error",
    signal: AbortSignal.timeout(20000),
    ...options,
  };
  if (init.body !== undefined) {
    init.headers = { "Content-Type": "application/json", Accept: "application/json" };
    init.body = JSON.stringify(init.body);
  }
  const response = await fetch(path, init);
  const body = response.status === 204 ? {} : await response.json().catch(() => ({}));
  return { status: response.status, ok: response.ok, body };
}

const MESSAGES = {
  forbidden_self: "無法對自己的帳號執行這個操作。",
  forbidden_root: "Root 帳號無法透過後台修改或刪除。",
  forbidden_peer: "無法變更權限相同或更高的帳號。",
  forbidden_grant: "無法授予等於或高於自己的權限等級。",
  invalid_role: "權限等級無效。",
  invalid_user_profile: "請確認帳號格式、Email 與顯示名稱長度。",
  invalid_password: "密碼至少需 12 字元；建議使用 12–56 個英文字母、數字或符號。",
  user_exists: "帳號或 Email 已被使用，請改用其他資料。",
  user_changed: "使用者資料已被其他操作更新，請重新開啟編輯。",
  invalid_scope: "Scope 無效，只接受 openid、profile、email。",
  invalid_redirect_uri: "Redirect URI 無效：必須是絕對網址、不得含片段或萬用字元。",
  invalid_client_id: "Client ID 格式無效（3-64 字，限英數與 . _ ~ -）。",
  client_exists: "這個 Client ID 已經被使用。",
  not_found: "找不到目標，可能已被刪除。",
};

function describe(result) {
  if (MESSAGES[result.body.error]) return MESSAGES[result.body.error];
  if (result.status === 403) return "沒有執行這個操作的權限。";
  if (result.status === 400) return "請確認輸入內容，再試一次。";
  if (result.status === 429) return "操作次數較多，請稍候再試。";
  return "服務暫時無法使用，請稍後再試。";
}

// The console reports both outcomes through one banner, so the tone has to be
// explicit: a success shown in the error style reads as a failure.
function notify(message, isError) {
  feedback.textContent = message;
  feedback.classList.toggle("error", Boolean(isError));
  feedback.hidden = !message;
}

// Any 401 mid-session means the cookie expired or was revoked.
function handled(result) {
  if (result.status === 401) {
    showSignin("登入已過期，請重新登入。");
    return true;
  }
  return false;
}

// --- shell -------------------------------------------------------------------

function showSignin(message) {
  me = null;
  el("user-form").reset();
  el("user-editor").hidden = true;
  consolePanel.hidden = true;
  whoami.hidden = true;
  logout.hidden = true;
  signin.hidden = false;
  signinFeedback.textContent = message || "";
  signinFeedback.hidden = !message;
  el("password").value = "";
}

function showConsole() {
  signin.hidden = true;
  consolePanel.hidden = false;
  whoami.textContent = (me.display_name?.trim() || me.username) + " · " + me.role;
  whoami.hidden = false;
  logout.hidden = false;
  clientsTab.hidden = me.role < ROOT_ROLE;
}

async function start() {
  let result;
  try {
    result = await api("/x/admin/me");
  } catch {
    showSignin("目前無法連線，請確認網路後重新整理。");
    return;
  }
  if (result.status === 401) {
    showSignin("");
    return;
  }
  if (result.status === 403) {
    showSignin("此帳號沒有管理權限。");
    return;
  }
  if (!result.ok) {
    showSignin("服務暫時無法使用，請稍後再試。");
    return;
  }
  me = result.body;
  showConsole();
  loadUsers();
}

signinForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (signinFields.disabled || !signinForm.reportValidity()) return;
  signinFields.disabled = true;
  signinLabel.textContent = "正在登入…";
  signinFeedback.hidden = true;
  signinFeedback.classList.remove("notice");
  try {
    const result = await api("/x/admin/login", {
      method: "POST",
      body: { account: el("account").value.trim(), password: el("password").value },
    });
    if (result.status === 203) {
      const email = String(result.body.email || "");
      const separator = email.indexOf("@");
      const masked = separator > 0 ? email[0] + "•••" + email.slice(separator) : "你的信箱";
      signinFeedback.classList.add("notice");
      signinFeedback.textContent = "這是沒見過的裝置。驗證連結已寄到 " + masked + "，請使用同一瀏覽器開啟信件連結，完成後會回到後台。";
      return;
    }
    if (result.ok) {
      el("password").value = "";
      me = result.body;
      showConsole();
      loadUsers();
      return;
    }
    signinFeedback.textContent =
      result.status === 401 ? "帳號、密碼不正確，或此帳號沒有管理權限。" : describe(result);
  } catch {
    signinFeedback.textContent = "目前無法連線。請確認網路，稍後再試。";
  } finally {
    el("password").value = "";
    signinFields.disabled = false;
    signinLabel.textContent = "登入";
    signinFeedback.hidden = !signinFeedback.textContent;
  }
});

logout.addEventListener("click", async () => {
  try {
    await api("/x/logout", { method: "POST" });
  } catch {
    /* the cookie is cleared server-side or already gone; fall through */
  }
  showSignin("已登出。");
});

// --- tabs --------------------------------------------------------------------

document.querySelector(".tabs").addEventListener("click", (event) => {
  const tab = event.target.closest("[data-tab]");
  if (!tab || tab.hidden) return;
  for (const other of document.querySelectorAll("[data-tab]")) {
    other.setAttribute("aria-selected", String(other === tab));
  }
  const showClients = tab.dataset.tab === "clients";
  el("panel-users").hidden = showClients;
  el("panel-clients").hidden = !showClients;
  notify("");
  if (showClients) loadClients();
});

// --- users -------------------------------------------------------------------

async function loadUsers() {
  let result;
  try {
    result = await api(query("/x/admin/users", users));
  } catch {
    notify("目前無法連線，請稍後再試。", true);
    return;
  }
  if (handled(result)) return;
  if (!result.ok) {
    notify(describe(result), true);
    return;
  }
  users.hasMore = Boolean(result.body.has_more);
  renderUsers(result.body.users || []);
  el("user-page").textContent = "第 " + users.page + " 頁";
}

function renderUsers(rows) {
  const template = el("user-row");
  users.rows.replaceChildren();
  for (const user of rows) {
    const node = template.content.cloneNode(true);
    const tr = node.querySelector("tr");
    tr.dataset.id = String(user.id);
    tr.dataset.role = String(user.role);
    node.querySelector('[data-cell="id"]').textContent = user.id;
    node.querySelector('[data-cell="username"]').textContent = user.username;
    node.querySelector('[data-cell="email"]').textContent = user.email;
    node.querySelector('[data-cell="display_name"]').textContent = user.display_name || "—";
    // Client-side locking is an affordance only; the server enforces the same
    // rules in controller.guardTarget.
    const locked = user.id === me.id || user.role >= ROOT_ROLE || user.role >= me.role;
    const select = node.querySelector('[data-action="role"]');
    for (const role of ROLES) {
      if (!locked && role.value >= me.role) continue;
      const option = document.createElement("option");
      option.value = String(role.value);
      option.textContent = role.label;
      select.append(option);
    }
    select.value = String(user.role);
    select.disabled = locked;
    node.querySelector('[data-action="delete"]').disabled = locked;
    node.querySelector('[data-action="edit"]').disabled = locked;
    if (locked) tr.dataset.locked = "1";
    users.rows.append(node);
  }
  el("user-empty").hidden = rows.length > 0;
}

users.rows.addEventListener("change", async (event) => {
  const select = event.target.closest('[data-action="role"]');
  if (!select) return;
  const tr = select.closest("tr");
  const result = await send("PATCH", "/x/admin/users/" + tr.dataset.id + "/role", {
    role: Number(select.value),
  });
  if (!result || !result.ok) {
    select.value = tr.dataset.role; // reject the change visually too
    return;
  }
  tr.dataset.role = select.value;
  notify("已更新權限。");
});

users.rows.addEventListener("click", async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button || button.disabled) return;
  const tr = button.closest("tr");
  if (button.dataset.action === "edit") {
    button.disabled = true;
    const result = await send("GET", "/x/admin/users/" + tr.dataset.id);
    button.disabled = false;
    if (result && result.ok) openUserEditor(result.body);
    return;
  }
  if (!window.confirm("確定要刪除這個使用者嗎？")) return;
  const result = await send("DELETE", "/x/admin/users/" + tr.dataset.id);
  if (result && result.ok) {
    notify("已刪除使用者。");
    loadUsers();
  }
});

// One form handles create and profile edit; credentials are never loaded back.
function openUserEditor(user) {
  const form = el("user-form");
  form.reset();
  form.dataset.userId = user ? String(user.id) : "";
  el("user-editor-title").textContent = user ? "編輯使用者" : "新增使用者";
  el("user-save").textContent = user ? "儲存變更" : "建立使用者";
  el("user-username").value = user ? user.username : "";
  el("user-display-name").value = user ? user.display_name : "";
  el("user-email").value = user ? user.email : "";
  el("user-password-field").hidden = Boolean(user);
  el("user-password").required = !user;
  el("user-password").disabled = Boolean(user);
  el("user-role-field").hidden = Boolean(user);
  el("user-edit-note").hidden = !user;
  const roles = el("user-role");
  roles.replaceChildren();
  for (const role of ROLES.filter(role => role.value < me.role)) {
    const option = document.createElement("option");
    option.value = String(role.value);
    option.textContent = role.label;
    roles.append(option);
  }
  roles.value = "1";
  el("user-editor").hidden = false;
  el("user-username").focus();
}

function closeUserEditor() {
  el("user-form").reset();
  el("user-form").dataset.userId = "";
  el("user-editor").hidden = true;
  el("create-user").focus();
}

el("create-user").addEventListener("click", () => openUserEditor(null));
el("user-cancel").addEventListener("click", closeUserEditor);
el("user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = el("user-fields");
  if (fields.disabled || !event.target.reportValidity()) return;
  const id = event.target.dataset.userId;
  const body = {
    username: el("user-username").value.trim(),
    display_name: el("user-display-name").value.trim(),
    email: el("user-email").value.trim(),
  };
  if (!id) {
    body.password = el("user-password").value;
    body.role = Number(el("user-role").value);
  }
  fields.disabled = true;
  el("user-save").textContent = "正在儲存…";
  const result = await send(id ? "PATCH" : "POST", "/x/admin/users" + (id ? "/" + id : ""), body);
  el("user-password").value = "";
  fields.disabled = false;
  el("user-save").textContent = id ? "儲存變更" : "建立使用者";
  if (result && result.ok) {
    closeUserEditor();
    notify(id ? "已更新使用者。" : "已建立使用者。");
    users.query = result.body.username;
    users.page = 1;
    el("user-search").value = users.query;
    await loadUsers();
  }
});

// --- services ----------------------------------------------------------------

async function loadClients() {
  let result;
  try {
    result = await api(query("/x/admin/clients", clients));
  } catch {
    notify("目前無法連線，請稍後再試。", true);
    return;
  }
  if (handled(result)) return;
  if (!result.ok) {
    notify(describe(result), true);
    return;
  }
  clients.hasMore = Boolean(result.body.has_more);
  renderClients(result.body.clients || []);
  el("client-page").textContent = "第 " + clients.page + " 頁";
}

function renderClients(rows) {
  const template = el("client-row");
  clients.rows.replaceChildren();
  for (const client of rows) {
    const node = template.content.cloneNode(true);
    node.querySelector("tr").dataset.id = client.client_id;
    node.querySelector('[data-cell="client_id"]').textContent = client.client_id;
    node.querySelector('[data-cell="name"]').textContent = client.name;
    node.querySelector('[data-cell="redirect_uris"]').textContent =
      (client.redirect_uris || []).join("\n");
    node.querySelector('[data-cell="scope"]').textContent = client.scope;
    clients.rows.append(node);
  }
  el("client-empty").hidden = rows.length > 0;
}

clients.rows.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action]");
  if (!button || button.disabled) return;
  const clientID = button.closest("tr").dataset.id;
  const path = "/x/admin/clients/" + encodeURIComponent(clientID);
  if (button.dataset.action === "rotate") {
    if (!window.confirm("輪替後舊密鑰立即失效，確定要繼續嗎？")) return;
    const result = await send("POST", path + "/secret");
    if (result && result.ok) {
      revealSecret(result.body.client_secret);
      notify("已輪替密鑰。");
    }
    return;
  }
  if (!window.confirm("刪除後此服務將無法再登入，確定嗎？")) return;
  const result = await send("DELETE", path);
  if (result && result.ok) {
    notify("已刪除服務。");
    loadClients();
  }
});

el("client-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = el("client-fields");
  if (fields.disabled || !event.target.reportValidity()) return;
  fields.disabled = true;
  el("client-label").textContent = "正在建立…";
  const result = await send("POST", "/x/admin/clients", {
    client_id: el("client-id").value.trim(),
    name: el("client-name").value.trim(),
    scope: el("client-scope").value.trim(),
    redirect_uris: el("client-uris").value.split("\n").map((s) => s.trim()).filter(Boolean),
  });
  fields.disabled = false;
  el("client-label").textContent = "建立服務";
  if (result && result.ok) {
    revealSecret(result.body.client_secret);
    notify("已建立服務。");
    el("client-id").value = "";
    el("client-name").value = "";
    el("client-uris").value = "";
    el("create-client").open = false;
    loadClients();
  }
});

// The plaintext secret exists only in this DOM node: it is never stored, never
// logged, and the server cannot return it again.
function revealSecret(secret) {
  if (!secret) return;
  const field = el("secret-value");
  field.value = secret;
  el("secret-box").hidden = false;
  field.focus();
  field.select();
}

// --- shared ------------------------------------------------------------------

function query(path, state) {
  const params = new URLSearchParams({ page: String(state.page), size: String(PAGE_SIZE) });
  if (state.query) params.set("q", state.query);
  return path + "?" + params.toString();
}

async function send(method, path, body) {
  notify("");
  try {
    const result = await api(path, body === undefined ? { method } : { method, body });
    if (handled(result)) return null;
    if (!result.ok) notify(describe(result), true);
    return result;
  } catch {
    notify("目前無法連線，請稍後再試。", true);
    return null;
  }
}

function debounce(fn) {
  let timer = 0;
  return () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(fn, 250);
  };
}

el("user-search").addEventListener("input", debounce(() => {
  users.query = el("user-search").value.trim();
  users.page = 1;
  loadUsers();
}));

el("client-search").addEventListener("input", debounce(() => {
  clients.query = el("client-search").value.trim();
  clients.page = 1;
  loadClients();
}));

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-page]");
  if (!button) return;
  const [table, direction] = button.dataset.page.split("-");
  const state = table === "users" ? users : clients;
  if (direction === "next" && !state.hasMore) return;
  if (direction === "prev" && state.page === 1) return;
  state.page += direction === "next" ? 1 : -1;
  if (table === "users") loadUsers();
  else loadClients();
});

start();
