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
    for _, origin := range []string{"https://evil.example", "http://192.168.40.10:8989"} {
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

func TestLoginCSRFWorksWithoutOriginAndFetchMetadata(t *testing.T) {
    a := &App{cfg: Config{AdminHash: hashPassword("test-correct-password")},
        sessions: make(map[string]Session), tries: make(map[string]Attempt), loginTokens: map[string]time.Time{}}
    csrf := randomString(32)
    a.loginTokens[csrf] = time.Now().Add(10 * time.Minute)
    form := url.Values{"csrf": {csrf}, "user": {"admin"}, "password": {"test-correct-password"}}
    request := httptest.NewRequest(http.MethodPost, "https://192.168.40.10:8989/login", strings.NewReader(form.Encode()))
    request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    response := httptest.NewRecorder()
    a.login(response, request)
    if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" {
        t.Fatalf("valid no-origin browser submission failed: %d %s", response.Code, response.Header().Get("Location"))
    }
}
func TestLoginCSRFRejectsExplicitCrossSiteFetchMetadata(t *testing.T) {
    a := &App{cfg: Config{AdminHash: hashPassword("test-correct-password")},
        sessions: make(map[string]Session), tries: make(map[string]Attempt), loginTokens: map[string]time.Time{}}
    csrf := randomString(32)
    a.loginTokens[csrf] = time.Now().Add(10 * time.Minute)
    form := url.Values{"csrf": {csrf}, "user": {"admin"}, "password": {"test-correct-password"}}
    request := httptest.NewRequest(http.MethodPost, "https://192.168.40.10:8989/login", strings.NewReader(form.Encode()))
    request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    request.Header.Set("Sec-Fetch-Site", "cross-site")
    response := httptest.NewRecorder()
    a.login(response, request)
    if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login?error=csrf" {
        t.Fatal("explicit cross-site metadata bypassed CSRF")
    }
    if !a.consumeLoginToken(csrf) { t.Fatal("wrongly consumed token on blocked origin") }
}

func TestProfileTemplateDefaults(t *testing.T) {
    settings := defaultProfile(1194)
    if err := validateProfileTemplate(settings.Template); err != nil { t.Fatal(err) }
    if settings.ExternalPort != 1194 { t.Fatal("unexpected default port") }
    if !strings.Contains(settings.Template, "verb 0") { t.Fatal("default profile verbosity should be 0") }
    header, err := buildProfileHeader(settings, "vpn.example.net", "udp")
    if err != nil { t.Fatal(err) }
    if !strings.Contains(header, "remote vpn.example.net 1194\n") { t.Fatal("default port missing from generated file") }
    if !strings.Contains(header, "proto udp\n") { t.Fatal("UDP protocol missing") }
    if strings.Contains(header, "{{") { t.Fatal("unexpanded placeholder") }
}
func TestProfileTemplateWANPortForwarding(t *testing.T) {
    // User forwards public TCP/2253 to OpenVPN daemon TCP/1194.
    settings := defaultProfile(1194)
    settings.ExternalPort = 2253
    settings.Template = strings.Replace(settings.Template, "verb 0", "verb 0\nconnect-retry-max 3", 1)
    header, err := buildProfileHeader(settings, "vpn.example.net", "tcp")
    if err != nil { t.Fatal(err) }
    if !strings.Contains(header, "proto tcp-client\nremote vpn.example.net 2253\n") {
        t.Fatalf("generated .ovpn does not use public port 2253: %s", header)
    }
    if strings.Contains(header, "vpn.example.net 1194") { t.Fatal("server-side listening port leaked into client profile") }
}
func TestProfileTemplateValidation(t *testing.T) {
    valid := defaultProfileTemplate
    tests := []struct{name, template string}{
        {"missing_tls_check", strings.Replace(valid, "remote-cert-tls server\n", "", 1)},
        {"missing_split_tunnel", strings.Replace(valid, "pull-filter ignore \"redirect-gateway\"\n", "", 1)},
        {"missing_port_variable", strings.Replace(valid, "{{PORT}}", "1194", 1)},
        {"credential_block", valid + "<key>\nSECRET\n</key>\n"},
        {"script_exec", valid + "script-security 2\n"},
        {"invalid_var", valid + "# {{BAD}}\n"},
        {"nul", valid + "\x00"},
    }
    for _, tc := range tests {
        if err := validateProfileTemplate(tc.template); err == nil {
            t.Errorf("%s: unsafe or malformed template accepted", tc.name)
        }
    }
    settings := defaultProfile(1194)
    for _, port := range []int{0, 65536} {
        settings.ExternalPort = port
        if _, err := buildProfileHeader(settings, "vpn.example.net", "tcp"); err == nil { t.Errorf("invalid port %d accepted", port) }
    }
}
