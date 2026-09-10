const { chromium } = require("@playwright/test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { once } = require("node:events");
const root = path.resolve(__dirname, "../..");
const base = "http://127.0.0.1:15519";
const output = path.join(root, "output/playwright");
fs.mkdirSync(output, { recursive: true });
const server = spawn("go", ["test", "./controller", "-run", "^TestLoginBrowserServer$", "-count=1", "-timeout=16m", "-v"], {
  cwd: path.join(root, "FGF-idP"), env: { ...process.env, FGF_BROWSER_TEST_ADDR: "127.0.0.1:15519" }, windowsHide: true,
});
let logs = "";
server.stdout.on("data", b => logs += b);
server.stderr.on("data", b => logs += b);
const stopped = once(server, "exit");
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let browser;
async function test(name, fn, options = {}) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ...options });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", e => errors.push(e.message));
  try { await fn(page, context); assert.deepEqual(errors, []); console.log("PASS", name); }
  finally { await context.close(); }
}
async function fill(page) {
  await page.getByLabel("帳號 / Email").fill("root-user");
  await page.getByLabel("密碼", { exact: true }).fill("correct-horse-battery-staple");
}
async function expectText(page, selector, text) {
  await page.locator(selector).filter({ hasText: text }).waitFor({ state: "visible" });
}
(async () => {
  try {
    for (let i = 0; !logs.includes("LOGIN_BROWSER_READY"); i++) {
      if (i > 240 || server.exitCode !== null) throw new Error("Fixture startup failed: " + logs);
      await pause(250);
    }
    const candidates = [process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE, "C:/Program Files/Google/Chrome/Application/chrome.exe", chromium.executablePath()].filter(Boolean);
    const executablePath = candidates.find(p => fs.existsSync(p));
    browser = await chromium.launch({ headless: true, executablePath });
    await test("missing request and safe query rendering", async page => {
      await page.goto(base + "/login");
      await expectText(page, "h2", "請從服務開始登入");
      assert.equal(await page.locator("form").isVisible(), false);
      await page.goto(base + "/login?error=" + encodeURIComponent("<img src=x onerror=alert(1)>"));
      await expectText(page, "h2", "驗證連結已失效");
      assert.equal(await page.locator("img").count(), 0);
    });
    await test("desktop visual and local assets", async page => {
      const assets = [];
      page.on("request", request => assets.push(request.url()));
      await page.goto(base + "/test/start", { waitUntil: "networkidle" });
      await page.evaluate(() => document.fonts.ready);
      assert.equal(await page.getByLabel("帳號 / Email").inputValue(), "");
      assert.equal(await page.getByLabel("密碼", { exact: true }).inputValue(), "");
      // Installed antivirus injects its own requests into local HTTP pages on Windows.
      // These are outside the shipped page; do not modify the user's security software.
      const productRequests = assets.filter(url => !new URL(url).hostname.endsWith(".kaspersky-labs.com"));
      assert(productRequests.every(url => url.startsWith(base)), JSON.stringify(productRequests));
      const copy = await page.locator("body").innerText();
      assert(!/req_id|scope|client_secret|忘記密碼|重新寄送/.test(copy));
      await page.screenshot({ path: path.join(output, "login-desktop.png"), fullPage: true });
    });
    await test("mobile layout and visible keyboard focus", async page => {
      await page.goto(base + "/test/start", { waitUntil: "networkidle" });
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await page.getByLabel("帳號 / Email").focus();
      await page.keyboard.press("Tab");
      assert.equal(await page.evaluate(() => document.activeElement.id), "password");
      await page.screenshot({ path: path.join(output, "login-mobile.png"), fullPage: true });
    }, { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
    await test("real login via keyboard navigates to callback", async (page, context) => {
      await context.addCookies([{ name: "did", value: "known-device-id", url: base }]);
      await page.route("http://127.0.0.1:3210/**", route => route.fulfill({ contentType: "text/html", body: "<h1>Callback received</h1>" }));
      await page.goto(base + "/test/start");
      await fill(page);
      await page.getByLabel("密碼", { exact: true }).press("Enter");
      await page.waitForURL("http://127.0.0.1:3210/callback?**");
      const callback = new URL(page.url());
      assert(callback.searchParams.get("code"));
      assert.equal(callback.searchParams.get("state"), "browser-state");
    });
    await test("real credential error, retry and email verification", async page => {
      await page.goto(base + "/test/start");
      await fill(page);
      await page.getByLabel("密碼", { exact: true }).fill("wrong-password");
      await page.getByRole("button", { name: "登入並繼續" }).click();
      await expectText(page, "#feedback", "帳號或密碼不正確");
      assert.equal(await page.getByLabel("密碼", { exact: true }).inputValue(), "");
      await page.getByLabel("密碼", { exact: true }).fill("correct-horse-battery-staple");
      await page.getByRole("button", { name: "登入並繼續" }).click();
      await expectText(page, "h2", "信在路上");
      assert.match(await page.locator("#card-description").innerText(), /r•••@example.com/);
      assert.equal(await page.locator("form").isVisible(), false);
      assert.equal(await page.locator("#password").inputValue(), "");
      await page.screenshot({ path: path.join(output, "login-verification.png"), fullPage: true });
    });
    await test("double-submit guard and non-JSON rate limit", async page => {
      let requests = 0;
      let release;
      const gate = new Promise(resolve => release = resolve);
      await page.route("**/x/login", async route => { requests++; await gate; await route.fulfill({ status: 429, contentType: "text/plain", body: "rate limited" }); });
      await page.goto(base + "/test/start");
      await fill(page);
      await page.getByRole("button", { name: "登入並繼續" }).click();
      assert.equal(await page.getByRole("button").isDisabled(), true);
      await page.locator("form").dispatchEvent("submit");
      release();
      await expectText(page, "#feedback", "嘗試次數較多");
      assert.equal(requests, 1);
    });
    await test("expired request, device reason and connection failure", async page => {
      await page.goto(base + "/login?req_id=expired&reason=device_verification_required");
      await expectText(page, "h2", "再確認一次是你");
      await fill(page);
      await page.getByRole("button", { name: "登入並繼續" }).click();
      await expectText(page, "h2", "登入請求已失效");
      await page.goto(base + "/test/start");
      await page.route("**/x/login", route => route.abort());
      await fill(page);
      await page.getByRole("button", { name: "登入並繼續" }).click();
      await expectText(page, "#feedback", "目前無法連線");
      assert.equal(await page.getByRole("button").isEnabled(), true);
    });
    await test("browser verification error and no password storage", async page => {
      await page.goto(base + "/x/verify?t=invalid");
      await expectText(page, "h2", "請使用原本的瀏覽器");
      assert(!page.url().includes("t=invalid"));
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    });
  } finally {
    if (browser) await browser.close();
    await fetch(base + "/test/stop", { method: "POST" }).catch(() => {});
    if (server.exitCode === null) await Promise.race([stopped, pause(5000).then(() => { if(server.exitCode === null) server.kill(); })]);
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
