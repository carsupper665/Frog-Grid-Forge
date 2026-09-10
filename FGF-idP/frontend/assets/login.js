"use strict";
const form = document.getElementById("login-form");
const credentials = document.getElementById("credentials");
const account = document.getElementById("account");
const password = document.getElementById("password");
const title = document.getElementById("card-title");
const description = document.getElementById("card-description");
const feedback = document.getElementById("feedback");
const submitLabel = document.getElementById("submit-label");
const params = new URLSearchParams(window.location.search);
const requestID = params.get("req_id");
let busy = false;

function showState(heading, message) {
  form.hidden = true;
  feedback.hidden = true;
  document.getElementById("card-note").hidden = true;
  password.value = "";
  title.textContent = heading;
  description.textContent = message;
  title.tabIndex = -1;
  title.focus();
}

const verificationError = params.get("error");
if (verificationError) {
  if (["missing_device_cookie", "invalid_device"].includes(verificationError)) {
    showState("請使用原本的瀏覽器", "請回到開始登入的瀏覽器，開啟信件中的驗證連結，以確認這台裝置。");
  } else if (verificationError === "server_error") {
    showState("暫時無法完成驗證", "服務暫時無法使用，請稍後從原服務重新開始登入。");
  } else {
    showState("驗證連結已失效", "連結可能已過期或使用過。請回到原服務重新開始登入。");
  }
} else if (!requestID) {
  showState("請從服務開始登入", "請回到你要使用的服務，選擇以 Grid Forge 登入，再回到這裡完成驗證。");
} else {
  credentials.disabled = false;
  if (params.get("reason") === "device_verification_required") {
    title.textContent = "再確認一次是你";
    description.textContent = "這台裝置尚未受信任。請輸入帳號與密碼，再透過信箱完成驗證。";
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy || !requestID || !form.reportValidity()) return;
  const identifier = account.value.trim();
  if (!identifier) { account.focus(); return; }
  busy = true;
  credentials.disabled = true;
  form.setAttribute("aria-busy", "true");
  feedback.hidden = true;
  feedback.textContent = "";
  submitLabel.textContent = "正在驗證…";
  const payload = { req_id: requestID, password: password.value };
  payload[identifier.includes("@") ? "email" : "username"] = identifier;
  try {
    const response = await fetch("/x/login", {
      method: "POST", credentials: "same-origin", redirect: "error",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload), signal: AbortSignal.timeout(20000),
    });
    const result = await response.json().catch(() => ({}));
    if (response.status === 200) {
      const destination = new URL(result.redirect_to);
      if (!["http:", "https:"].includes(destination.protocol)) throw new Error("invalid redirect");
      showState("登入完成", "正在帶你回到服務…");
      window.location.assign(destination.href);
      return;
    }
    if (response.status === 203) {
      const email = typeof result.email === "string" ? result.email : "";
      const separator = email.lastIndexOf("@");
      const masked = separator > 0 ? email[0] + "•••" + email.slice(separator) : "你的信箱";
      showState("信在路上", "驗證連結已寄到 " + masked + "。請使用同一瀏覽器開啟信件連結，完成後將在該分頁回到服務。");
      return;
    }
    if (result.error === "invalid_req_id") {
      showState("登入請求已失效", "這次登入可能已過期或完成。請回到原服務重新開始登入。");
      return;
    }
    feedback.textContent = response.status === 401 ? "帳號或密碼不正確，請再試一次。"
      : response.status === 429 ? "嘗試次數較多，請稍候再試。"
      : response.status === 400 ? "請確認帳號與密碼的格式，再試一次。"
      : "服務暫時無法使用，請稍後再試。";
  } catch {
    feedback.textContent = "目前無法連線。請確認網路，稍後再試。";
  } finally {
    delete payload.password;
    password.value = "";
    busy = false;
    credentials.disabled = false;
    form.removeAttribute("aria-busy");
    if (!form.hidden) {
      submitLabel.textContent = "登入並繼續";
      feedback.hidden = !feedback.textContent;
      if (!feedback.hidden) password.focus();
    }
  }
});
