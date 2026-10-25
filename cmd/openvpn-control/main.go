package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFS embed.FS

const (
	defaultConf  = "/etc/openvpn-control/config.json"
	statePath    = "/var/lib/openvpn-control"
	easyrsaDir   = "/etc/openvpn-control/easy-rsa"
	vpnServerDir = "/etc/openvpn/server"
)

var cnPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$`)

type Config struct {
	BindIP    string `json:"bind_ip"`
	Port      int    `json:"port"`
	VPNPort   int    `json:"vpn_port"`
	VPNProto  string `json:"vpn_proto"`
	VPNHost   string `json:"vpn_host"`
	LAN       string `json:"lan"`
	VPNNet    string `json:"vpn_net"`
	AdminHash string `json:"admin_hash"`
	CertFile  string `json:"cert_file"`
	KeyFile   string `json:"key_file"`
}
type Client struct {
	Name      string    `json:"name"`
	Comment   string    `json:"comment"`
	Days      int       `json:"days"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Disabled  bool      `json:"disabled"`
	Deleted   bool      `json:"deleted"`
	Revoked   bool      `json:"revoked"`
}
type App struct {
	mu       sync.Mutex
	cfg      Config
	clients  map[string]Client
	sessions map[string]Session
	tries    map[string]Attempt
	t        *template.Template
}
type Session struct {
	CSRF    string
	Expires time.Time
}
type Attempt struct {
	Count int
	Until time.Time
}
type Row struct {
	Client
	Online    bool
	VirtualIP string
	RealIP    string
	BytesIn   string
	BytesOut  string
}
type View struct {
	Rows                                           []Row
	CSRF, Message, VPNPort, VPNProto, LAN, VPNHost string
	Active                                         int
	Total                                          int
	Now                                            string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			log.Fatal(err)
		}
		s := strings.TrimRight(string(b), "\r\n")
		if len(s) < 12 {
			log.Fatal("password must be at least 12 characters")
		}
		fmt.Println(hashPassword(s))
		return
	}
	path := defaultConf
	if len(os.Args) > 1 && os.Args[1] == "-config" && len(os.Args) == 3 {
		path = os.Args[2]
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var cfg Config
	if err = json.Unmarshal(b, &cfg); err != nil {
		log.Fatal(err)
	}
	if cfg.Port < 1 || cfg.Port > 65535 || net.ParseIP(cfg.BindIP) == nil || cfg.AdminHash == "" {
		log.Fatal("invalid configuration")
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		log.Fatal("HTTPS certificate and key required")
	}
	t, err := template.New("pages").Funcs(template.FuncMap{"size": humanBytes}).ParseFS(webFS, "web/*.html")
	if err != nil {
		log.Fatal(err)
	}
	a := &App{cfg: cfg, t: t, clients: map[string]Client{}, sessions: map[string]Session{}, tries: map[string]Attempt{}}
	if err := a.load(); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("POST /login", a.login)
	mux.HandleFunc("POST /logout", a.auth(a.logout))
	mux.HandleFunc("GET /", a.auth(a.dashboard))
	mux.HandleFunc("POST /clients", a.auth(a.createClient))
	mux.HandleFunc("POST /clients/{name}/disable", a.auth(a.disableClient))
	mux.HandleFunc("POST /clients/{name}/enable", a.auth(a.enableClient))
	mux.HandleFunc("POST /clients/{name}/delete", a.auth(a.deleteClient))
	mux.HandleFunc("POST /clients/{name}/comment", a.auth(a.editComment))
	mux.HandleFunc("GET /clients/{name}/download", a.auth(a.downloadClient))
	mux.HandleFunc("GET /assets/style.css", func(w http.ResponseWriter, r *http.Request) {
		serveAsset(w, "web/style.css", "text/css; charset=utf-8")
	})
	mux.HandleFunc("GET /assets/app.js", func(w http.ResponseWriter, r *http.Request) {
		serveAsset(w, "web/app.js", "application/javascript; charset=utf-8")
	})
	server := &http.Server{Addr: net.JoinHostPort(cfg.BindIP, strconv.Itoa(cfg.Port)), Handler: security(mux), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16384}
	log.Printf("OpenVPN Control serving HTTPS at %s", server.Addr)
	log.Fatal(server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile))
}
func serveAsset(w http.ResponseWriter, path, ct string) {
	b, e := webFS.ReadFile(path)
	if e != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(b)
}
func security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if r.ContentLength > 64<<10 {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func pbkdf2(password string, salt []byte, iter int) []byte { // PBKDF2-HMAC-SHA256, block 1
	s := append(append([]byte{}, salt...), 0, 0, 0, 1)
	h := hmac.New(sha256.New, []byte(password))
	h.Write(s)
	u := h.Sum(nil)
	out := append([]byte{}, u...)
	for i := 1; i < iter; i++ {
		h = hmac.New(sha256.New, []byte(password))
		h.Write(u)
		u = h.Sum(nil)
		for k := range out {
			out[k] ^= u[k]
		}
	}
	return out
}
func hashPassword(s string) string {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		panic(e)
	}
	const iterations = 310000
	return fmt.Sprintf("pbkdf2-sha256:%d:%s:%s", iterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(pbkdf2(s, salt, iterations)))
}
func checkPassword(password, hash string) bool {
	parts := strings.Split(hash, ":")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, e := strconv.Atoi(parts[1])
	if e != nil || iter < 100000 || iter > 2000000 {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(parts[2])
	if e != nil {
		return false
	}
	want, e := base64.RawStdEncoding.DecodeString(parts[3])
	if e != nil || len(want) != 32 {
		return false
	}
	got := pbkdf2(password, salt, iter)
	return subtle.ConstantTimeCompare(got, want) == 1
}
func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	csrf := randomString(24)
	http.SetCookie(w, &http.Cookie{Name: "login_csrf", Value: csrf, Path: "/login", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 1800})
	a.t.ExecuteTemplate(w, "login.html", struct {
		CSRF  string
		Error bool
		CSRFError bool
	}{csrf, r.URL.Query().Get("error") == "1", r.URL.Query().Get("error") == "csrf"})
}
func ipOf(r *http.Request) string {
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return r.RemoteAddr
	}
	return ip
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip := ipOf(r)
	a.mu.Lock()
	at := a.tries[ip]
	locked := at.Count >= 5 && time.Now().Before(at.Until)
	a.mu.Unlock()
	if locked {
		http.Error(w, "Too many attempts; retry later", 429)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	c, err := r.Cookie("login_csrf")
	if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.FormValue("csrf"))) != 1 {
		// Reject a stale/blocked login cookie while allowing a fresh login attempt.
		http.Redirect(w, r, "/login?error=csrf", http.StatusSeeOther)
		return
	}
	valid := r.FormValue("user") == "admin" && checkPassword(r.FormValue("password"), a.cfg.AdminHash)
	a.mu.Lock()
	defer a.mu.Unlock()
	if !valid {
		at = a.tries[ip]
		if time.Now().After(at.Until) {
			at.Count = 0
		}
		at.Count++
		at.Until = time.Now().Add(5 * time.Minute)
		a.tries[ip] = at
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}
	delete(a.tries, ip)
	sid := randomString(32)
	a.sessions[sid] = Session{CSRF: randomString(32), Expires: time.Now().Add(8 * time.Hour)}
	http.SetCookie(w, &http.Cookie{Name: "oc_session", Value: sid, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *App) session(r *http.Request) (string, Session, bool) {
	c, e := r.Cookie("oc_session")
	if e != nil {
		return "", Session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok || time.Now().After(s.Expires) {
		delete(a.sessions, c.Value)
		return "", Session{}, false
	}
	return c.Value, s, true
}
func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, s, ok := a.session(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil || subtle.ConstantTimeCompare([]byte(s.CSRF), []byte(r.FormValue("csrf"))) != 1 {
				http.Error(w, "CSRF mismatch", 403)
				return
			}
		}
		next(w, r)
	}
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	id, _, _ := a.session(r)
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "oc_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	_, s, _ := a.session(r)
	online := readOnline()
	a.mu.Lock()
	rows := make([]Row, 0, len(a.clients))
	for _, c := range a.clients {
		if c.Deleted {
			continue
		}
		o, ok := online[c.Name]
		rows = append(rows, Row{Client: c, Online: ok, VirtualIP: o.VirtualIP, RealIP: o.RealIP, BytesIn: humanBytes(o.In), BytesOut: humanBytes(o.Out)})
	}
	a.mu.Unlock()
	sortRows(rows)
	active := 0
	for _, c := range rows {
		if c.Online {
			active++
		}
	}
	v := View{Rows: rows, Active: active, Total: len(rows), CSRF: s.CSRF, Message: r.URL.Query().Get("msg"), VPNPort: strconv.Itoa(a.cfg.VPNPort), VPNProto: strings.ToUpper(a.cfg.VPNProto), LAN: a.cfg.LAN, VPNHost: a.cfg.VPNHost, Now: time.Now().Format("02.01.2006 15:04")}
	if e := a.t.ExecuteTemplate(w, "dashboard.html", v); e != nil {
		log.Print(e)
	}
}
func validName(n string) bool { return cnPattern.MatchString(n) }
func (a *App) createClient(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	comment := strings.TrimSpace(r.FormValue("comment"))
	days, e := strconv.Atoi(r.FormValue("days"))
	if !validName(name) || e != nil || days < 1 || days > 3650 || len([]rune(comment)) > 256 {
		http.Error(w, "invalid client name, days or comment", 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.clients[name]; ok {
		http.Error(w, "client name already used", 409)
		return
	}
	if _, e := os.Stat(filepath.Join(easyrsaDir, "pki/issued", name+".crt")); e == nil {
		http.Error(w, "certificate exists", 409)
		return
	}
	env := append(os.Environ(), "EASYRSA_BATCH=1", "EASYRSA_PKI="+filepath.Join(easyrsaDir, "pki"), "EASYRSA_CERT_EXPIRE="+strconv.Itoa(days))
	if err := runEasy(env, "build-client-full", name, "nopass"); err != nil {
		log.Printf("create client failed: %v", err)
		http.Error(w, "EasyRSA error (see server logs)", 500)
		return
	}
	now := time.Now()
	expiry := now.Add(time.Duration(days) * 24 * time.Hour)
	if b, err := os.ReadFile(filepath.Join(easyrsaDir, "pki/issued", name+".crt")); err == nil {
		if block, _ := pem.Decode(b); block != nil {
			if x, e := x509.ParseCertificate(block.Bytes); e == nil {
				expiry = x.NotAfter
			}
		}
	}
	cert := Client{Name: name, Comment: comment, Days: days, CreatedAt: now, ExpiresAt: expiry}
	a.clients[name] = cert
	if e := a.save(); e != nil {
		log.Printf("save failed: %v", e)
		http.Error(w, "metadata save failure", 500)
		return
	}
	audit("create", name)
	http.Redirect(w, r, "/?msg=created", 303)
}
func (a *App) disableClient(w http.ResponseWriter, r *http.Request) { a.toggle(w, r, true) }
func (a *App) enableClient(w http.ResponseWriter, r *http.Request)  { a.toggle(w, r, false) }
func (a *App) toggle(w http.ResponseWriter, r *http.Request, disabled bool) {
	name := r.PathValue("name")
	if !validName(name) {
		http.Error(w, "bad name", 400)
		return
	}
	a.mu.Lock()
	c, ok := a.clients[name]
	if !ok || c.Deleted || c.Revoked {
		a.mu.Unlock()
		http.Error(w, "not found", 404)
		return
	}
	prev := c.Disabled
	c.Disabled = disabled
	a.clients[name] = c
	if err := a.saveDisabled(); err != nil {
		c.Disabled = prev
		a.clients[name] = c
		a.mu.Unlock()
		http.Error(w, "disable-list update failed", 500)
		return
	}
	if err := a.save(); err != nil {
		a.mu.Unlock()
		http.Error(w, "save failed", 500)
		return
	}
	a.mu.Unlock()
	if disabled {
		if err := disconnect(name); err != nil {
			log.Printf("disconnect %s: %v", name, err)
		}
	}
	if disabled {
		audit("disable", name)
	} else {
		audit("enable", name)
	}
	http.Redirect(w, r, "/?msg=updated", 303)
}
func (a *App) deleteClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName(name) {
		http.Error(w, "bad name", 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.clients[name]
	if !ok || c.Deleted {
		http.Error(w, "not found", 404)
		return
	}
	// First revoke; always regenerate and deploy CRL, including on retry.
	env := append(os.Environ(), "EASYRSA_BATCH=1", "EASYRSA_PKI="+filepath.Join(easyrsaDir, "pki"))
	if !c.Revoked {
		if err := runEasy(env, "revoke", name); err != nil {
			log.Printf("revoke %s: %v", name, err)
			http.Error(w, "revoke failed", 500)
			return
		}
		c.Revoked = true
		a.clients[name] = c
		if err := a.save(); err != nil {
			http.Error(w, "revocation metadata save failed", 500)
			return
		}
	}
	if err := runEasy(env, "gen-crl"); err != nil {
		log.Printf("gen-crl %s: %v", name, err)
		http.Error(w, "CRL generation failed; retry deletion", 500)
		return
	}
	if err := copyFileAtomic(filepath.Join(easyrsaDir, "pki/crl.pem"), filepath.Join(vpnServerDir, "crl.pem"), 0644); err != nil {
		log.Printf("CRL copy: %v", err)
		http.Error(w, "CRL update failed; retry deletion", 500)
		return
	}
	c.Revoked = true
	c.Deleted = true
	c.Disabled = true
	a.clients[name] = c
	if err := a.saveDisabled(); err != nil {
		http.Error(w, "block-list update failed", 500)
		return
	}
	if err := a.save(); err != nil {
		http.Error(w, "metadata save failed", 500)
		return
	}
	_ = os.Remove(filepath.Join(easyrsaDir, "pki/private", name+".key"))
	_ = disconnect(name)
	audit("revoke-delete", name)
	http.Redirect(w, r, "/?msg=deleted", 303)
}
func (a *App) editComment(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	comment := strings.TrimSpace(r.FormValue("comment"))
	if !validName(name) || len([]rune(comment)) > 256 {
		http.Error(w, "invalid input", 400)
		return
	}
	a.mu.Lock()
	c, ok := a.clients[name]
	if !ok || c.Deleted {
		a.mu.Unlock()
		http.Error(w, "not found", 404)
		return
	}
	c.Comment = comment
	a.clients[name] = c
	if err := a.save(); err != nil {
		a.mu.Unlock()
		http.Error(w, "save failed", 500)
		return
	}
	a.mu.Unlock()
	audit("comment-updated", name)
	http.Redirect(w, r, "/?msg=updated", 303)
}
func (a *App) downloadClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName(name) {
		http.Error(w, "bad name", 400)
		return
	}
	a.mu.Lock()
	c, ok := a.clients[name]
	a.mu.Unlock()
	if !ok || c.Deleted || c.Revoked {
		http.Error(w, "not found", 404)
		return
	}
	pieces := []struct{ path, begin, end string }{
		{filepath.Join(easyrsaDir, "pki/ca.crt"), "<ca>", "</ca>"},
		{filepath.Join(easyrsaDir, "pki/issued", name+".crt"), "<cert>", "</cert>"},
		{filepath.Join(easyrsaDir, "pki/private", name+".key"), "<key>", "</key>"},
		{filepath.Join(vpnServerDir, "ta.key"), "<tls-crypt>", "</tls-crypt>"},
	}
	var sb strings.Builder
	proto := "udp"
	if a.cfg.VPNProto == "tcp" {
		proto = "tcp-client"
	}
	fmt.Fprintf(&sb, "client\ndev tun\nproto %s\nremote %s %d\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\nauth-nocache\npull-filter ignore \"redirect-gateway\"\nverb 3\n", proto, a.cfg.VPNHost, a.cfg.VPNPort)
	for _, p := range pieces {
		b, e := os.ReadFile(p.path)
		if e != nil {
			log.Printf("read profile: %v", e)
			http.Error(w, "profile unavailable", 500)
			return
		}
		fmt.Fprintf(&sb, "%s\n%s\n%s\n", p.begin, strings.TrimSpace(string(b)), p.end)
	}
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.ovpn"`, name))
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(sb.String()))
}
func runEasy(env []string, args ...string) error {
	cmd := exec.Command(filepath.Join(easyrsaDir, "easyrsa"), args...)
	cmd.Dir = easyrsaDir
	cmd.Env = env
	b, e := cmd.CombinedOutput()
	if e != nil {
		return fmt.Errorf("%w: %s", e, strings.TrimSpace(string(b)))
	}
	return nil
}
func (a *App) load() error {
	b, e := os.ReadFile(filepath.Join(statePath, "clients.json"))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	return json.Unmarshal(b, &a.clients)
}
func atomicWrite(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".new"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Chmod(tmp, mode); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func copyFileAtomic(src, dst string, mode os.FileMode) error {
	b, e := os.ReadFile(src)
	if e != nil {
		return e
	}
	return atomicWrite(dst, b, mode)
}
func (a *App) save() error {
	b, e := json.MarshalIndent(a.clients, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(filepath.Join(statePath, "clients.json"), b, 0600)
}
func (a *App) saveDisabled() error {
	var names []string
	for n, c := range a.clients {
		if c.Disabled {
			names = append(names, n)
		}
	}
	sortStrings(names)
	return atomicWrite(filepath.Join(statePath, "disabled.list"), []byte(strings.Join(names, "\n")+"\n"), 0644)
}
func audit(op, name string) {
	f, e := os.OpenFile(filepath.Join(statePath, "audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		log.Print(e)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s %s\n", time.Now().UTC().Format(time.RFC3339), op, name)
}

type Live struct {
	VirtualIP, RealIP string
	In, Out           uint64
}

func readOnline() map[string]Live {
	out := map[string]Live{}
	b, e := os.ReadFile("/run/openvpn-server/status-server.log")
	if e != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		v := strings.Split(line, ",")
		if len(v) < 7 || v[0] != "CLIENT_LIST" {
			continue
		}
		in, _ := strconv.ParseUint(v[5], 10, 64)
		sent, _ := strconv.ParseUint(v[6], 10, 64)
		out[v[1]] = Live{VirtualIP: v[3], RealIP: v[2], In: in, Out: sent}
	}
	return out
}
func humanBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	for _, u := range []string{"KiB", "MiB", "GiB", "TiB"} {
		v /= 1024
		if v < 1024 {
			return fmt.Sprintf("%.1f %s", v, u)
		}
	}
	return fmt.Sprintf("%.1f PiB", v/1024)
}
func disconnect(name string) error {
	if !validName(name) {
		return errors.New("bad name")
	}
	password, err := os.ReadFile("/etc/openvpn-control/management.pass")
	if err != nil {
		return err
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:2080", 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return err
	}
	var b [4096]byte
	_, _ = c.Read(b[:]) // banner / password request
	if _, err = io.WriteString(c, strings.TrimSpace(string(password))+"\n"); err != nil {
		return err
	}
	_, _ = c.Read(b[:]) // authentication confirmation / prompt
	if _, err = io.WriteString(c, "kill "+name+"\nquit\n"); err != nil {
		return err
	}
	return nil
}
func sortRows(a []Row) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j].Name < a[j-1].Name; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
