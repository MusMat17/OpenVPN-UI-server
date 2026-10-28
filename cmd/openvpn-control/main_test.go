package main

import (
	"html/template"
	"fmt"
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

func TestManagementStatusAndPersistentConnectionTime(t *testing.T) {
    started := time.Now().Add(-45*time.Minute).UTC().Truncate(time.Second)
    status := fmt.Sprintf("SUCCESS: password is correct\nTITLE,OpenVPN 2.6\nTIME,2026-10-29,1793230000\nHEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher\nCLIENT_LIST,laptop-01,198.51.100.44:1000,10.40.0.2,,2457,5894,2026-10-29,%d,UNDEF,1,1,AES-256-GCM\nEND\n", started.Unix())
    online, err := parseManagementStatus(status)
    if err != nil { t.Fatal(err) }
    got, ok := online["laptop-01"]
    if !ok { t.Fatal("active connection missing") }
    if !got.Since.Equal(started) || got.VirtualIP != "10.40.0.2" || got.In != 2457 {
        t.Fatalf("unexpected status data: %#v", got)
    }
    clients := map[string]Client{"laptop-01": {Name:"laptop-01"}}
    if !updateLastConnected(clients, online) { t.Fatal("first session should update persisted metadata") }
    if !clients["laptop-01"].LastConnectedAt.Equal(started) { t.Fatal("timestamp not preserved") }
    if updateLastConnected(clients, online) { t.Fatal("unchanged session should not write metadata again") }
    if updateLastConnected(clients, map[string]Live{}) { t.Fatal("disconnect must not reset timestamp") }
    if !clients["laptop-01"].LastConnectedAt.Equal(started) { t.Fatal("timestamp lost on disconnect") }
    newer := started.Add(10*time.Minute)
    if !updateLastConnected(clients, map[string]Live{"laptop-01": {Since:newer}}) { t.Fatal("reconnect time not saved") }
    if !clients["laptop-01"].LastConnectedAt.Equal(newer) { t.Fatal("latest connection not retained") }
    if updateLastConnected(clients, map[string]Live{"laptop-01": {Since:started}}) { t.Fatal("older timestamp must not overwrite newer one") }
}
func TestManagementStatusRejectsPartialOrBadTime(t *testing.T) {
    for _, status := range []string{"", "SUCCESS: password is correct", "CLIENT_LIST,a,b,c", "ERROR: bad password", "HEADER,CLIENT_LIST,Common Name\nCLIENT_LIST,bad\n"} {
        if _, err := parseManagementStatus(status); err == nil { t.Fatalf("accepted incomplete management status: %q", status) }
    }
}
func TestLastConnectedColumnRendered(t *testing.T) {
    tpl, err := template.New("pages").Funcs(template.FuncMap{"size": humanBytes}).ParseFS(webFS, "web/*.html")
    if err != nil { t.Fatal(err) }
    started := time.Date(2026, 10, 29, 11, 32, 0, 0, time.UTC)
    v := View{CSRF: "csrf", Total: 2, Rows: []Row{
        {Client: Client{Name:"known", LastConnectedAt:started}},
        {Client: Client{Name:"never"}},
    }}
    var buf strings.Builder
    if err := tpl.ExecuteTemplate(&buf, "dashboard.html", v); err != nil { t.Fatal(err) }
    for _, expected := range []string{"ПОСЛЕДНЕЕ ПОДКЛЮЧЕНИЕ", "2026-10-29T11:32:00Z", "Нет данных", "Source Sans 3", "IBM Plex Sans", "Inter"} {
        if !strings.Contains(buf.String(), expected) { t.Errorf("missing %q",expected) }
    }
}

func TestSageStylesAndVersionedAssets(t *testing.T) {
    if len(assetVersion) != 16 {
        t.Fatalf("asset hash must change with CSS/JS; got %q", assetVersion)
    }
    style, err := webFS.ReadFile("web/style.css")
    if err != nil { t.Fatal(err) }
    css := string(style)
    for _, selector := range []string{
        "body.sage-ui", "body.sage-login", ".login-stage",
        "OC Source Sans 3", "OC IBM Plex Sans", "OC Inter",
        "html[data-ui-font=\"plex\"]",
    } {
        if !strings.Contains(css, selector) {
            t.Errorf("Sage CSS missing %q", selector)
        }
    }
    if strings.Contains(css, ".hero-card{") {
        t.Fatal("legacy style was not cleared")
    }
    pages, err := template.New("pages").Funcs(template.FuncMap{"size":humanBytes}).ParseFS(webFS, "web/*.html")
    if err != nil { t.Fatal(err) }
    login := struct { AssetVersion, CSRF string; Error, CSRFError bool }{
        assetVersion, "test-csrf", false, false,
    }
    var out strings.Builder
    if err := pages.ExecuteTemplate(&out, "login.html", login); err != nil { t.Fatal(err) }
    for _, expected := range []string{
        "style.css?v="+assetVersion, "app.js?v="+assetVersion,
        "name=\"csrf\"", "sage-login", "Вход в панель",
    } {
        if !strings.Contains(out.String(), expected) {
            t.Errorf("login page missing %q", expected)
        }
    }
    out.Reset()
    if err := pages.ExecuteTemplate(&out, "dashboard.html", View{AssetVersion:assetVersion}); err != nil { t.Fatal(err) }
    for _, expected := range []string{
        "style.css?v="+assetVersion, "app.js?v="+assetVersion, "sage-ui",
    } {
        if !strings.Contains(out.String(), expected) {
            t.Errorf("dashboard page missing %q", expected)
        }
    }
}


func TestSelectableSageAndMistColorPalettes(t *testing.T) {
    style, err := webFS.ReadFile("web/style.css")
    if err != nil { t.Fatal(err) }
    css := string(style)
    for _, required := range []string{
        "html[data-ui-theme=\"mist\"]",
        "--bg:#f1f3f8",
        "--ink:#293248",
        "--mist-primary:#5d5aaa",
        "html[data-ui-theme=\"mist\"] .kpi:nth-child(1)",
        "html[data-ui-theme=\"mist\"] .table th",
        "html[data-ui-theme=\"mist\"] .newform input",
        "html[data-ui-theme=\"mist\"] .login-stage",
        "html[data-ui-theme=\"mist\"] .login-aside",
    } {
        if !strings.Contains(css, required) { t.Errorf("Missing Mist palette rule %q", required) }
    }
    app, err := webFS.ReadFile("web/app.js")
    if err != nil { t.Fatal(err) }
    javascript := string(app)
    for _, required := range []string{
        "theme-choice",
        "openvpn-control-theme",
        "document.documentElement.dataset.uiTheme",
        "localStorage.setItem('openvpn-control-theme'",
        "new Set(['sage', 'mist'])",
    } {
        if !strings.Contains(javascript, required) { t.Errorf("Theme switcher missing %q", required) }
    }
    pages, err := template.New("pages").Funcs(template.FuncMap{"size":humanBytes}).ParseFS(webFS, "web/*.html")
    if err != nil { t.Fatal(err) }
    var dashboard strings.Builder
    if err := pages.ExecuteTemplate(&dashboard, "dashboard.html", View{AssetVersion:assetVersion}); err != nil { t.Fatal(err) }
    for _, required := range []string{
        "id=\"theme-choice\"", "Тема", "Sage · шалфей", "Mist · лаванда",
        "id=\"font-choice\"", "data-ui-theme=\"sage\"",
    } {
        if !strings.Contains(dashboard.String(), required) { t.Errorf("Dashboard missing %q", required) }
    }
    var login strings.Builder
    v := struct { AssetVersion, CSRF string; Error, CSRFError bool }{assetVersion, "test", false, false}
    if err := pages.ExecuteTemplate(&login, "login.html", v); err != nil { t.Fatal(err) }
    if !strings.Contains(login.String(), "data-ui-theme=\"sage\"") {
        t.Fatal("Login lacks fallback color theme before JS applies saved preference")
    }
}
