package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestLoginCSRFOverHTTPS(t *testing.T) {
	tpl, err := template.New("pages").ParseFS(webFS, "web/login.html")
	if err != nil { t.Fatal(err) }
	a := &App{cfg: Config{AdminHash: hashPassword("test-correct-password")}, t: tpl,
		sessions: make(map[string]Session), tries: make(map[string]Attempt)}
	page := httptest.NewRecorder()
	a.loginPage(page, httptest.NewRequest(http.MethodGet, "https://192.168.40.10:8989/login", nil))
	if page.Code != http.StatusOK { t.Fatalf("GET login: %d", page.Code) }
	var csrfCookie *http.Cookie
	for _, cookie := range page.Result().Cookies() { if cookie.Name == "login_csrf" { csrfCookie = cookie; break } }
	if csrfCookie == nil { t.Fatal("missing login csrf cookie") }
	if !csrfCookie.Secure || !csrfCookie.HttpOnly || csrfCookie.SameSite != http.SameSiteLaxMode { t.Fatal("unexpected csrf cookie security attributes") }
	if !strings.Contains(page.Body.String(), "value=\"" + csrfCookie.Value + "\"") { t.Fatal("csrf cookie and form token differ") }
	form := url.Values{"csrf": {csrfCookie.Value}, "user": {"admin"}, "password": {"test-correct-password"}}
	req := httptest.NewRequest(http.MethodPost, "https://192.168.40.10:8989/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	response := httptest.NewRecorder()
	a.login(response, req)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" { t.Fatalf("login failed: %d %s", response.Code, response.Body.String()) }
	found := false
	for _, cookie := range response.Result().Cookies() { if cookie.Name == "oc_session" { found = true } }
	if !found { t.Fatal("missing session after successful login") }
}

func TestLoginCSRFRejectedAndRecoverable(t *testing.T) {
	a := &App{cfg: Config{AdminHash: hashPassword("test-correct-password")}, sessions: make(map[string]Session), tries: make(map[string]Attempt)}
	form := url.Values{"csrf": {"bogus"}, "user": {"admin"}, "password": {"test-correct-password"}}
	req := httptest.NewRequest(http.MethodPost, "https://192.168.40.10:8989/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	a.login(response, req)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login?error=csrf" { t.Fatalf("unexpected missing CSRF behavior: %d", response.Code) }
	if len(a.sessions) != 0 { t.Fatal("invalid CSRF permitted authentication") }
}
