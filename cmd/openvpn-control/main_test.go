package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"
	"testing"
)

func TestPassword(t *testing.T) {
	h := hashPassword("long correct example password")
	if !checkPassword("long correct example password", h) {
		t.Fatal("correct password rejected")
	}
	if checkPassword("wrong", h) {
		t.Fatal("bad password accepted")
	}
	if strings.Contains(h, "correct example") {
		t.Fatal("plain text leaked")
	}
}
func TestName(t *testing.T) {
	for _, s := range []string{"alice", "test-01", "CLIENT_2"} {
		if !validName(s) {
			t.Errorf("expected valid: %q", s)
		}
	}
	for _, s := range []string{"", "../foo", "-bad", "a b", "a;touch /tmp/file", strings.Repeat("a", 49)} {
		if validName(s) {
			t.Errorf("expected invalid: %q", s)
		}
	}
}
func TestHumanBytes(t *testing.T) {
	if humanBytes(2048) != "2.0 KiB" {
		t.Fatal(humanBytes(2048))
	}
}

func TestLoginCSRFWithoutCookiesOverHTTPS(t *testing.T) {
    tpl, err := template.New("pages").ParseFS(webFS, "web/login.html")
    if err != nil { t.Fatal(err) }
    a := &App{cfg: Config{AdminHash: hashPassword("test-correct-password")}, t: tpl,
        sessions: make(map[string]Session), tries: make(map[string]Attempt), loginTokens: make(map[string]time.Time)}
    page := httptest.NewRecorder()
    a.loginPage(page, httptest.NewRequest(http.MethodGet, "https://192.168.40.10:8989/login", nil))
    if page.Code != http.StatusOK { t.Fatalf("GET login: %d", page.Code) }
    if len(page.Result().Cookies()) != 0 { t.Fatal("unexpected pre-login cookie") }
    var nonce string
    for token := range a.loginTokens { nonce = token }
    if nonce == "" || !strings.Contains(page.Body.String(), "value=\"" + nonce + "\"") { t.Fatal("form token missing") }
    form := url.Values{"csrf": {nonce}, "user": {"admin"}, "password": {"test-correct-password"}}
    req := httptest.NewRequest(http.MethodPost, "https://192.168.40.10:8989/login", strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("Origin", "https://192.168.40.10:8989")
    response := httptest.NewRecorder()
    a.login(response, req)
    if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" { t.Fatalf("login failed: %d %s", response.Code, response.Body.String()) }
    found := false
    for _, cookie := range response.Result().Cookies() { if cookie.Name == "oc_session" && cookie.Secure && cookie.HttpOnly { found = true } }
    if !found { t.Fatal("missing secure session after login") }
    if a.consumeLoginToken(nonce) { t.Fatal("login token replay allowed") }
}

func TestLoginCSRFRejectedAndRecoverable(t *testing.T) {
	a := &App{cfg: Config{AdminHash: hashPassword("test-correct-password")}, sessions: make(map[string]Session), tries: make(map[string]Attempt)}
	form := url.Values{"csrf": {"bogus"}, "user": {"admin"}, "password": {"test-correct-password"}}
	req := httptest.NewRequest(http.MethodPost, "https://192.168.40.10:8989/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://192.168.40.10:8989")
	response := httptest.NewRecorder()
	a.login(response, req)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login?error=csrf" { t.Fatalf("unexpected missing CSRF behavior: %d", response.Code) }
	if len(a.sessions) != 0 { t.Fatal("invalid CSRF permitted authentication") }
}

func TestLoginCSRFRejectsCrossOriginAndExpiredToken(t *testing.T) {
    a := &App{cfg: Config{AdminHash: hashPassword("test-correct-password")},
        sessions: make(map[string]Session), tries: make(map[string]Attempt), loginTokens: map[string]time.Time{}}
    csrf := randomString(32)
    a.loginTokens[csrf] = time.Now().Add(10 * time.Minute)
    form := url.Values{"csrf": {csrf}, "user": {"admin"}, "password": {"test-correct-password"}}
    for _, origin := range []string{"https://evil.example", "http://192.168.40.10:8989", ""} {
        req := httptest.NewRequest(http.MethodPost, "https://192.168.40.10:8989/login", strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        if origin != "" { req.Header.Set("Origin", origin) }
        response := httptest.NewRecorder()
        a.login(response, req)
        if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login?error=csrf" { t.Fatalf("cross-origin login allowed for %q", origin) }
    }
    expired := randomString(32)
    a.loginTokens[expired] = time.Now().Add(-1 * time.Second)
    if a.consumeLoginToken(expired) { t.Fatal("expired token accepted") }
}
