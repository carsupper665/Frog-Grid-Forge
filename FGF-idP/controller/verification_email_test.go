package controller

import (
	"FGF-idP/common"
	"FGF-idP/model"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The email states the link and device lifetimes from the same constants the
// server enforces, so a configuration change cannot make it lie.
func TestVerificationEmailStatesRealLifetimes(t *testing.T) {
	t.Setenv("BACKEND_BASE_URL", "https://id.example.test/")
	user := model.User{Email: "owner@example.test", DisplayName: "Owner"}
	body := buildVerificationEmail(user, "tok&en", "FGF MC Panel", "Mozilla/5.0 (Windows NT 10.0) Chrome/128.0 Safari/537.36", "203.0.113.9", time.Date(2026, 9, 12, 14, 32, 0, 0, time.FixedZone("TST", 8*3600)))
	for _, want := range []string{
		`href="https://id.example.test/x/verify?t=tok%26en"`,
		"連結 " + strconv.Itoa(int(common.EmailTokenTTL/time.Minute)) + " 分鐘後失效",
		"記住 " + strconv.Itoa(common.DeviceCookieExpireSeconds/86400) + " 天",
		"Chrome · Windows",
		"203.0.113.9",
		"2026-09-12 14:32 +08:00",
		"FGF MC Panel",
		"寄給 owner@example.test",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("email is missing %q", want)
		}
	}
}

// User-Agent and client name reach HTML and are attacker-influenced.
func TestVerificationEmailEscapesUntrustedFields(t *testing.T) {
	body := buildVerificationEmail(model.User{Email: "o@example.test"}, "t", `<b>app</b>`, `<script>alert(1)</script>`, "::1", time.Now())
	if strings.Contains(body, "<script>") || strings.Contains(body, "<b>app</b>") {
		t.Fatal("untrusted field interpolated unescaped")
	}
	if !strings.Contains(body, "未知瀏覽器 · 未知系統") {
		t.Fatal("unrecognised user agent should still render a device row")
	}
}
