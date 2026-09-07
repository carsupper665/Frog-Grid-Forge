const $ = (id) => document.getElementById(id);

const ui = {
  backendOrigin: $("backend-origin"),
  clientId: $("client-id"),
  clientSecret: $("client-secret"),
  redirectUri: $("redirect-uri"),
  scope: $("scope"),
  state: $("state"),
  nonce: $("nonce"),
  codeVerifier: $("code-verifier"),
  username: $("username"),
  email: $("email"),
  password: $("password"),
  reqId: $("req-id"),
  verifyToken: $("verify-token"),
  authCode: $("auth-code"),
  didValue: $("did-cookie-value"),
  didServer: $("did-cookie-server"),
  status: $("flow-status"),
  cookieStatus: $("cookie-status"),
  log: $("log"),
  btnFillDefault: $("btn-fill-default"),
  btnAuth: $("btn-auth"),
  btnLogin: $("btn-login"),
  btnVerify: $("btn-verify"),
  btnToken: $("btn-token"),
  btnCookieSync: $("btn-cookie-sync"),
  btnCookieSet: $("btn-cookie-set"),
  btnCookieClear: $("btn-cookie-clear"),
  btnClearLog: $("btn-clear-log"),
};

function now() {
  return new Date().toISOString();
}

function appendLog(line) {
  ui.log.textContent += `${line}\n`;
  ui.log.scrollTop = ui.log.scrollHeight;
}

function setStatus(message, tone = "normal") {
  ui.status.textContent = message;
  applyStatusTone(ui.status, tone);
}

function setCookieStatus(message, tone = "normal") {
  ui.cookieStatus.textContent = message;
  applyStatusTone(ui.cookieStatus, tone);
}

function applyStatusTone(element, tone = "normal") {
  if (tone === "ok") {
    element.style.background = "#ecfff2";
    element.style.color = "#205f2f";
    return;
  }
  if (tone === "error") {
    element.style.background = "#fff0f0";
    element.style.color = "#6f2626";
    return;
  }
  element.style.background = "#fffaef";
  element.style.color = "#684f25";
}

function randomTag(prefix) {
  const short = Math.random().toString(36).slice(2, 10);
  return `${prefix}-${short}`;
}

function getFormSnapshot() {
  return {
    backend_origin: ui.backendOrigin.value.trim(),
    client_id: ui.clientId.value.trim(),
    redirect_uri: ui.redirectUri.value.trim(),
    scope: ui.scope.value.trim(),
    state: ui.state.value.trim(),
    nonce: ui.nonce.value.trim(),
    code_verifier: ui.codeVerifier.value.trim(),
  };
}

function headersToObject(headers) {
  const data = {};
  headers.forEach((value, key) => {
    data[key] = value;
  });
  return data;
}

function parseReqIdFromLocation(location) {
  if (!location) {
    return "";
  }
  try {
    const u = new URL(location, window.location.origin);
    return u.searchParams.get("req_id") || "";
  } catch {
    return "";
  }
}

function parseCodeFromLocation(location) {
  if (!location) {
    return "";
  }
  try {
    const u = new URL(location, window.location.origin);
    return u.searchParams.get("code") || "";
  } catch {
    return "";
  }
}

function extractVerifyToken(value) {
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }
  try {
    const parsed = new URL(trimmed);
    return parsed.searchParams.get("t") || "";
  } catch {
    if (trimmed.includes("t=")) {
      try {
        const q = new URLSearchParams(trimmed.split("?")[1] || trimmed);
        return q.get("t") || trimmed;
      } catch {
        return trimmed;
      }
    }
    return trimmed;
  }
}

async function pkceChallengeS256(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  let text = "";
  for (const b of bytes) {
    text += String.fromCharCode(b);
  }
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function callApi(path, options = {}) {
  const method = options.method || "GET";
  const headers = new Headers(options.headers || {});
  const backendOrigin = ui.backendOrigin.value.trim() || "http://localhost:15515";
  headers.set("x-backend-origin", backendOrigin);

  appendLog(`[${now()}] -> ${method} /api${path}`);
  appendLog(`  backend: ${backendOrigin}`);
  const requestHeaders = headersToObject(headers);
  appendLog(`  req headers: ${JSON.stringify(requestHeaders)}`);
  if (typeof options.body !== "undefined") {
    appendLog(`  req body: ${typeof options.body === "string" ? options.body : "<binary>"}`);
  }

  const response = await fetch(`/api${path}`, {
    method,
    headers,
    body: options.body,
    credentials: "include",
    redirect: options.redirect || "manual",
  });

  const responseHeaders = headersToObject(response.headers);
  const rawText = await response.text();
  const upstreamStatus = Number(responseHeaders["x-upstream-status"] || response.status);
  const upstreamLocation = responseHeaders["x-upstream-location"] || responseHeaders.location || "";
  appendLog(`[${now()}] <- ${upstreamStatus} ${method} /api${path}`);
  if (response.status !== upstreamStatus) {
    appendLog(`  proxy status: ${response.status}`);
  }
  appendLog(`  res headers: ${JSON.stringify(responseHeaders)}`);
  appendLog(`  res body: ${rawText || "<empty>"}`);
  appendLog("");

  let json = null;
  const contentType = (responseHeaders["content-type"] || "").toLowerCase();
  if (contentType.includes("application/json") && rawText) {
    try {
      json = JSON.parse(rawText);
    } catch {
      json = null;
    }
  }

  return { response, status: upstreamStatus, location: upstreamLocation, headers: responseHeaders, rawText, json };
}

async function callLocal(path, options = {}) {
  const method = options.method || "GET";
  const headers = new Headers(options.headers || {});
  appendLog(`[${now()}] -> ${method} ${path}`);
  const response = await fetch(path, {
    method,
    headers,
    body: options.body,
    credentials: "include",
  });
  const rawText = await response.text();
  appendLog(`[${now()}] <- ${response.status} ${path}`);
  appendLog(`  body: ${rawText || "<empty>"}`);
  appendLog("");
  let json = null;
  if (rawText) {
    try {
      json = JSON.parse(rawText);
    } catch {
      json = null;
    }
  }
  return { response, json, rawText };
}

async function startAuthStep() {
  const state = getFormSnapshot();
  if (!state.client_id || !state.redirect_uri || !state.scope) {
    setStatus("Step A 失敗：請先填 client_id / redirect_uri / scope", "error");
    return;
  }
  const params = new URLSearchParams({
    response_type: "code",
    client_id: state.client_id,
    redirect_uri: state.redirect_uri,
    scope: state.scope,
    state: state.state,
    nonce: state.nonce,
  });

  if (state.code_verifier) {
    try {
      const challenge = await pkceChallengeS256(state.code_verifier);
      params.set("code_challenge", challenge);
      params.set("code_challenge_method", "S256");
    } catch (err) {
      appendLog(`[warn] PKCE challenge generate failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  const { status, location } = await callApi(`/x/auth?${params.toString()}`, { method: "GET", redirect: "manual" });
  const reqId = parseReqIdFromLocation(location);
  if (reqId) {
    ui.reqId.value = reqId;
    setStatus(`Step A 成功：取得 req_id=${reqId}`, "ok");
    return;
  }
  if (status === 302) {
    setStatus("Step A 收到 302 但無法解析 req_id，請看 Log", "error");
    return;
  }
  setStatus(`Step A 非預期狀態：${status}`, "error");
}

async function loginStep() {
  const reqId = ui.reqId.value.trim();
  const password = ui.password.value;
  const username = ui.username.value.trim();
  const email = ui.email.value.trim();
  if (!reqId || !password || (!username && !email)) {
    setStatus("Step B 失敗：需提供 req_id、password、username/email", "error");
    return;
  }
  const payload = { password, req_id: reqId };
  if (email) {
    payload.email = email;
  } else {
    payload.username = username;
  }

  const { status, location, json } = await callApi("/x/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    redirect: "manual",
  });

  if (status === 302) {
    const code = parseCodeFromLocation(location);
    if (code) {
      ui.authCode.value = code;
      setStatus("Step B 成功：登入後拿到 auth code", "ok");
      return;
    }
    setStatus("Step B 收到 302，但 Location 沒有 code", "error");
    return;
  }
  if (status === 203) {
    const msg = json?.message || "new_device_detected";
    setStatus(`Step B: ${msg}，請走 Step C`, "normal");
    return;
  }
  if (status >= 400) {
    setStatus(`Step B 失敗：${status} ${json?.error || ""}`.trim(), "error");
    return;
  }
  setStatus(`Step B 狀態：${status}`, "normal");
}

async function verifyStep() {
  const token = extractVerifyToken(ui.verifyToken.value);
  if (!token) {
    setStatus("Step C 失敗：請輸入 verify token 或完整 verify URL", "error");
    return;
  }
  const { status, location, json } = await callApi(`/x/verify?t=${encodeURIComponent(token)}`, {
    method: "GET",
    redirect: "manual",
  });
  if (status === 302) {
    const code = parseCodeFromLocation(location);
    if (code) {
      ui.authCode.value = code;
      setStatus("Step C 成功：verify 後拿到 auth code", "ok");
      return;
    }
    setStatus("Step C 收到 302，但 Location 沒有 code", "error");
    return;
  }
  setStatus(`Step C 失敗：${status} ${json?.error || ""}`.trim(), "error");
}

async function tokenStep() {
  const code = ui.authCode.value.trim();
  if (!code) {
    setStatus("Step D 失敗：請先取得 auth code", "error");
    return;
  }
  const params = new URLSearchParams();
  params.set("grant_type", "authorization_code");
  params.set("code", code);
  params.set("redirect_uri", ui.redirectUri.value.trim());
  params.set("client_id", ui.clientId.value.trim());
  params.set("client_secret", ui.clientSecret.value);
  const verifier = ui.codeVerifier.value.trim();
  if (verifier) {
    params.set("code_verifier", verifier);
  }

  const { status, json } = await callApi("/x/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded;charset=UTF-8" },
    body: params.toString(),
  });
  if (status === 200 && json?.access_token) {
    setStatus("Step D 成功：token 已取得，請查看 Log", "ok");
    return;
  }
  setStatus(`Step D 失敗：${status} ${json?.error || ""}`.trim(), "error");
}

async function syncDid() {
  const { response, json } = await callLocal("/cookie/did");
  if (response.status !== 200 || !json) {
    setCookieStatus("did 同步失敗", "error");
    return;
  }
  ui.didServer.value = json.value || "";
  if (!ui.didValue.value && json.value) {
    ui.didValue.value = json.value;
  }
  setCookieStatus(json.present ? "did 已存在" : "did 不存在", json.present ? "ok" : "normal");
}

async function setDid() {
  const value = ui.didValue.value.trim();
  if (!value) {
    setCookieStatus("請輸入 did cookie value", "error");
    return;
  }
  const { response } = await callLocal("/cookie/did/set", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ value }),
  });
  if (response.status === 200) {
    await syncDid();
    setCookieStatus("did 已設置", "ok");
    return;
  }
  setCookieStatus("did 設置失敗", "error");
}

async function clearDid() {
  const { response } = await callLocal("/cookie/did/clear", { method: "POST" });
  if (response.status === 200) {
    ui.didValue.value = "";
    ui.didServer.value = "";
    setCookieStatus("did 已清除", "ok");
    return;
  }
  setCookieStatus("did 清除失敗", "error");
}

function fillDefaults() {
  ui.backendOrigin.value = "http://localhost:15515";
  ui.clientId.value = "fgf-mc-panel";
  ui.redirectUri.value = "http://localhost:3000/callback";
  ui.scope.value = "openid profile email";
  ui.state.value = randomTag("state");
  ui.nonce.value = randomTag("nonce");
  ui.codeVerifier.value = "";
  setStatus("已填入預設值", "ok");
}

function applyLoginQuery() {
  const params = new URLSearchParams(window.location.search);
  const reqId = params.get("req_id") || "";
  const reason = params.get("reason") || "";
  if (reqId) {
    ui.reqId.value = reqId;
  }
  if (reason === "device_verification_required") {
    setStatus("需要重新登入並完成裝置驗證", "normal");
    return;
  }
  if (reqId) {
    setStatus(`已從 login redirect 帶入 req_id=${reqId}`, "ok");
  }
}

function wireEvents() {
  ui.btnFillDefault.addEventListener("click", fillDefaults);
  ui.btnAuth.addEventListener("click", () => startAuthStep().catch((err) => setStatus(`Step A exception: ${err.message}`, "error")));
  ui.btnLogin.addEventListener("click", () => loginStep().catch((err) => setStatus(`Step B exception: ${err.message}`, "error")));
  ui.btnVerify.addEventListener("click", () => verifyStep().catch((err) => setStatus(`Step C exception: ${err.message}`, "error")));
  ui.btnToken.addEventListener("click", () => tokenStep().catch((err) => setStatus(`Step D exception: ${err.message}`, "error")));
  ui.btnCookieSync.addEventListener("click", () => syncDid().catch((err) => setStatus(`Cookie sync exception: ${err.message}`, "error")));
  ui.btnCookieSet.addEventListener("click", () => setDid().catch((err) => setStatus(`Cookie set exception: ${err.message}`, "error")));
  ui.btnCookieClear.addEventListener("click", () => clearDid().catch((err) => setStatus(`Cookie clear exception: ${err.message}`, "error")));
  ui.btnClearLog.addEventListener("click", () => {
    ui.log.textContent = "";
    appendLog(`[${now()}] log cleared`);
  });
}

function init() {
  wireEvents();
  appendLog(`[${now()}] OIDC tester initialized`);
  fillDefaults();
  applyLoginQuery();
  syncDid().catch((err) => appendLog(`[warn] initial cookie sync failed: ${err.message}`));
}

init();
