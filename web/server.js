const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { URL } = require("node:url");

const WEB_ROOT = __dirname;
const WEB_PORT = Number(process.env.WEB_PORT || 15517);
const WEB_HOST = process.env.WEB_HOST || "127.0.0.1";
const DEFAULT_BACKEND_ORIGIN = process.env.BACKEND_ORIGIN || "http://localhost:15515";
const ALLOW_REMOTE_BACKEND_ORIGIN = process.env.ALLOW_REMOTE_BACKEND_ORIGIN === "true";
const API_PREFIX = "/api";

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".ico": "image/x-icon",
};

function sendJson(res, statusCode, payload, headers = {}) {
  const data = Buffer.from(JSON.stringify(payload, null, 2), "utf8");
  res.writeHead(statusCode, {
    ...headers,
    "content-type": "application/json; charset=utf-8",
    "content-length": data.length,
  });
  res.end(data);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function parseCookies(cookieHeader) {
  const map = new Map();
  if (!cookieHeader) {
    return map;
  }
  const pairs = cookieHeader.split(";");
  for (const pair of pairs) {
    const idx = pair.indexOf("=");
    if (idx < 0) {
      continue;
    }
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    map.set(k, decodeURIComponent(v));
  }
  return map;
}

function resolveBackendOrigin(headerValue) {
  if (!headerValue) {
    return DEFAULT_BACKEND_ORIGIN;
  }
  let parsed;
  try {
    parsed = new URL(headerValue);
  } catch {
    return DEFAULT_BACKEND_ORIGIN;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return DEFAULT_BACKEND_ORIGIN;
  }
  if (!ALLOW_REMOTE_BACKEND_ORIGIN && !isLoopbackHostname(parsed.hostname)) {
    return DEFAULT_BACKEND_ORIGIN;
  }
  return parsed.origin;
}

function isLoopbackHostname(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1") {
    return true;
  }
  const parts = host.split(".").map((part) => Number(part));
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) && parts[0] === 127;
}

function safePathFromUrlPathname(urlPathname) {
  const spaPath = urlPathname === "/" || urlPathname === "/login" ? "/index.html" : urlPathname;
  const cleaned = decodeURIComponent(spaPath);
  const normalized = path.normalize(cleaned).replace(/^(\.\.[/\\])+/, "");
  const fullPath = path.join(WEB_ROOT, normalized);
  if (!fullPath.startsWith(WEB_ROOT)) {
    return null;
  }
  return fullPath;
}

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || "/"}`);
  if (typeof opts.maxAge === "number") {
    parts.push(`Max-Age=${opts.maxAge}`);
  }
  if (opts.httpOnly !== false) {
    parts.push("HttpOnly");
  }
  if (opts.sameSite) {
    parts.push(`SameSite=${opts.sameSite}`);
  }
  if (opts.secure) {
    parts.push("Secure");
  }
  res.setHeader("set-cookie", parts.join("; "));
}

async function handleCookieRoutes(req, res, pathname) {
  if (pathname === "/cookie/did" && req.method === "GET") {
    const cookies = parseCookies(req.headers.cookie);
    const did = cookies.get("did") || null;
    sendJson(res, 200, {
      present: Boolean(did),
      value: did,
      note: "did cookie is HttpOnly when set by backend; this endpoint reads it server-side.",
    });
    return true;
  }

  if (pathname === "/cookie/did/clear" && req.method === "POST") {
    setCookie(res, "did", "", { maxAge: 0, httpOnly: true, sameSite: "Lax" });
    sendJson(res, 200, { ok: true, message: "did cookie cleared" });
    return true;
  }

  if (pathname === "/cookie/did/set" && req.method === "POST") {
    let body = {};
    try {
      const raw = await readRawBody(req);
      body = raw.length > 0 ? JSON.parse(raw.toString("utf8")) : {};
    } catch {
      sendJson(res, 400, { ok: false, error: "invalid_json" });
      return true;
    }
    const value = String(body.value || "").trim();
    if (!value) {
      sendJson(res, 400, { ok: false, error: "missing_value" });
      return true;
    }
    setCookie(res, "did", value, {
      maxAge: 360 * 24 * 60 * 60,
      httpOnly: true,
      sameSite: "Lax",
    });
    sendJson(res, 200, { ok: true, message: "did cookie set", value });
    return true;
  }

  return false;
}

async function handleProxy(req, res, parsedUrl) {
  const backendOrigin = resolveBackendOrigin(req.headers["x-backend-origin"]);
  const targetPath = parsedUrl.pathname.slice(API_PREFIX.length) || "/";
  const targetUrl = new URL(`${targetPath}${parsedUrl.search || ""}`, backendOrigin);
  const requestBody = req.method === "GET" || req.method === "HEAD" ? undefined : await readRawBody(req);

  const outboundHeaders = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === "undefined") {
      continue;
    }
    const lower = key.toLowerCase();
    if (lower === "host" || lower === "content-length" || lower === "connection" || lower === "x-backend-origin") {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        outboundHeaders.append(key, item);
      }
    } else {
      outboundHeaders.set(key, value);
    }
  }

  let upstream;
  try {
    upstream = await fetch(targetUrl, {
      method: req.method,
      headers: outboundHeaders,
      body: requestBody,
      redirect: "manual",
    });
  } catch (err) {
    sendJson(res, 502, {
      error: "proxy_error",
      message: err instanceof Error ? err.message : String(err),
      target: targetUrl.toString(),
    });
    return;
  }

  const resHeaders = {};
  upstream.headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (
      lower === "set-cookie" ||
      lower === "content-encoding" ||
      lower === "content-length" ||
      lower === "transfer-encoding" ||
      lower === "connection"
    ) {
      return;
    }
    resHeaders[key] = value;
  });
  resHeaders["x-proxy-target"] = targetUrl.origin;
  resHeaders["x-upstream-status"] = String(upstream.status);

  const setCookies = typeof upstream.headers.getSetCookie === "function" ? upstream.headers.getSetCookie() : [];
  if (setCookies.length > 0) {
    resHeaders["set-cookie"] = setCookies;
  }

  if (upstream.status >= 300 && upstream.status < 400) {
    const location = upstream.headers.get("location") || "";
    if (location) {
      resHeaders["x-upstream-location"] = location;
    }
    sendJson(res, 200, {
      redirected: true,
      status: upstream.status,
      location,
      target: targetUrl.toString(),
    }, resHeaders);
    return;
  }

  res.writeHead(upstream.status, resHeaders);
  if (req.method === "HEAD") {
    res.end();
    return;
  }

  const payload = Buffer.from(await upstream.arrayBuffer());
  res.end(payload);
}

function serveStatic(res, parsedUrl) {
  const filePath = safePathFromUrlPathname(parsedUrl.pathname);
  if (!filePath) {
    sendJson(res, 403, { error: "forbidden" });
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      if (err.code === "ENOENT") {
        sendJson(res, 404, { error: "not_found", path: parsedUrl.pathname });
        return;
      }
      sendJson(res, 500, { error: "read_error", message: err.message });
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { "content-type": MIME_TYPES[ext] || "application/octet-stream" });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (parsedUrl.pathname === "/health" && req.method === "GET") {
    sendJson(res, 200, {
      ok: true,
      app: "oidc-login-flow-tester",
      now: new Date().toISOString(),
      backendDefault: DEFAULT_BACKEND_ORIGIN,
    });
    return;
  }

  if (await handleCookieRoutes(req, res, parsedUrl.pathname)) {
    return;
  }

  if (parsedUrl.pathname.startsWith(API_PREFIX + "/") || parsedUrl.pathname === API_PREFIX) {
    await handleProxy(req, res, parsedUrl);
    return;
  }

  serveStatic(res, parsedUrl);
});

server.listen(WEB_PORT, WEB_HOST, () => {
  // eslint-disable-next-line no-console
  console.log(`[web] OIDC tester running at http://${WEB_HOST}:${WEB_PORT}`);
  // eslint-disable-next-line no-console
  console.log(`[web] default backend origin: ${DEFAULT_BACKEND_ORIGIN}`);
});
