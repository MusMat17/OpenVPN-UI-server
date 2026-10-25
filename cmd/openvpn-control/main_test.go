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

func TestBentoDashboardRendersWithRealClients(t *testing.T) {
    tpl, err := template.New("pages").Funcs(template.FuncMap{"size": humanBytes}).ParseFS(webFS, "web/*.html")
    if err != nil { t.Fatalf("parse HTML dashboard: %v", err) }
    sample := View{
        CSRF: "csrf-test", VPNProto: "TCP", VPNPort: "1194", BindIP: "192.168.40.10",
        ClientProto: "tcp-client", LAN: "192.168.40.0/24", ExternalHost: "vpn.example.net",
        ExternalPort: 2253, Verb: 0, Active: 1, Total: 1,
        Rows: []Row{{Client: Client{Name: "laptop-01", Comment: "Notebook", Days: 365,
            ExpiresAt: time.Now().Add(365*24*time.Hour)}}},
    }
    var out strings.Builder
    if err := tpl.ExecuteTemplate(&out, "dashboard.html", sample); err != nil {
        t.Fatalf("render dashboard: %v", err)
    }
    for _, expected := range []string{
        "vpn.example.net", "2253", "1194", "csrf-test", "laptop-01",
        "/clients/laptop-01/download", "/clients/laptop-01/disable",
        "/clients/laptop-01/delete", "/clients/laptop-01/comment",
        "name=\"external_host\"", "name=\"external_port\"", "name=\"verb\"",
    } {
        if !strings.Contains(out.String(), expected) { t.Errorf("dashboard missing %q", expected) }
    }
}
func TestServerControlledClientProfile(t *testing.T) {
    config, err := generateClientHeader("vpn.example.net", 2253, 0, "tcp")
    if err != nil { t.Fatal(err) }
    for _, piece := range []string{
        "proto tcp-client", "remote vpn.example.net 2253", "verb 0",
        "remote-cert-tls server", "pull-filter ignore \"redirect-gateway\"",
    } {
        if !strings.Contains(config, piece) { t.Errorf("profile missing %q", piece) }
    }
    for _, host := range []string{"foo bar", "host\nredirect-gateway", "https://host", "", "-bad.example"} {
        if _, err := generateClientHeader(host, 2253, 0, "tcp"); err == nil {
            t.Errorf("unsafe host %q accepted", host)
        }
    }
    for _, p := range []int{0, -10, 65536} {
        if _, err := generateClientHeader("vpn.example.net", p, 0, "udp"); err == nil {
            t.Errorf("invalid port %d accepted", p)
        }
    }
    for _, v := range []int{-1, 12} {
        if _, err := generateClientHeader("vpn.example.net", 2253, v, "udp"); err == nil {
            t.Errorf("invalid verb %d accepted", v)
        }
    }
}
