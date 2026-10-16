package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type envUpstream struct {
	Name    string
	BaseURL string
	APIKey  string
	Models  []string
}

type config struct {
	listen     string
	upstreams  []envUpstream
	adminToken string
	dataDir    string
}

type upstream struct {
	ID, Name, BaseURL, APIKey string
	Models                    []string
	ModelList                 string
	IsDefault                 bool
	URL                       *url.URL
}

type upstreamCtx struct{}

type windowCount struct {
	minute int64
	count  int
}

type server struct {
	cfg    config
	db     *sql.DB
	proxy  *httputil.ReverseProxy
	limMu  sync.Mutex
	limits map[string]*windowCount
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	db, err := openDB(cfg.dataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := syncEnvUpstreams(db, cfg); err != nil {
		log.Fatal(err)
	}
	s := &server{cfg: cfg, db: db, proxy: newProxy(), limits: map[string]*windowCount{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /signup", s.signupPage)
	mux.HandleFunc("POST /signup", s.signupSubmit)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("GET /admin/login", s.loginPage)
	mux.HandleFunc("POST /admin/login", s.loginSubmit)
	mux.HandleFunc("POST /admin/logout", s.logout)
	mux.HandleFunc("GET /admin", s.adminPage)
	mux.HandleFunc("POST /admin/keys", s.createKey)
	mux.HandleFunc("POST /admin/keys/rpm", s.setRPM)
	mux.HandleFunc("POST /admin/keys/revoke", s.revokeKey)
	mux.HandleFunc("POST /admin/upstreams", s.createUpstream)
	mux.HandleFunc("POST /admin/upstreams/delete", s.deleteUpstream)
	mux.HandleFunc("GET /v1/models", s.listModels)
	mux.HandleFunc("GET /v1/models/{id}", s.getModel)
	mux.HandleFunc("GET /models", s.listModels)
	mux.HandleFunc("GET /models/{id}", s.getModel)
	mux.HandleFunc("/", s.forward)

	log.Printf("listening on %s", cfg.listen)
	if err := http.ListenAndServe(cfg.listen, mux); err != nil {
		log.Fatal(err)
	}
}

func loadConfig() (config, error) {
	base := strings.TrimSpace(os.Getenv("UPSTREAM_BASE_URL"))
	key := strings.TrimSpace(os.Getenv("UPSTREAM_API_KEY"))
	admin := strings.TrimSpace(os.Getenv("ADMIN_TOKEN"))
	if base == "" || key == "" || admin == "" {
		return config{}, errors.New("UPSTREAM_BASE_URL, UPSTREAM_API_KEY, and ADMIN_TOKEN are required")
	}
	name := strings.TrimSpace(os.Getenv("UPSTREAM_NAME"))
	if name == "" {
		name = "primary"
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return config{}, errors.New("UPSTREAM_BASE_URL must be an absolute URL, for example https://api.example.com")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "/data"
	}
	ups := []envUpstream{{
		Name: name, BaseURL: u.String(), APIKey: key, Models: splitModels(os.Getenv("UPSTREAM_MODELS")),
	}}
	second, err := optionalUpstream("UPSTREAM_2")
	if err != nil {
		return config{}, err
	}
	if second != nil {
		ups = append(ups, *second)
	}
	return config{listen: listen, upstreams: ups, adminToken: admin, dataDir: dataDir}, nil
}

func optionalUpstream(prefix string) (*envUpstream, error) {
	base := strings.TrimSpace(os.Getenv(prefix + "_BASE_URL"))
	key := strings.TrimSpace(os.Getenv(prefix + "_API_KEY"))
	models := strings.TrimSpace(os.Getenv(prefix + "_MODELS"))
	name := strings.TrimSpace(os.Getenv(prefix + "_NAME"))
	if base == "" && key == "" && models == "" {
		return nil, nil
	}
	if base == "" || key == "" || models == "" {
		return nil, errors.New(prefix + "_BASE_URL, " + prefix + "_API_KEY, and " + prefix + "_MODELS are required together")
	}
	if name == "" {
		name = strings.ToLower(prefix)
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New(prefix + "_BASE_URL must be an absolute URL")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return &envUpstream{Name: name, BaseURL: u.String(), APIKey: key, Models: splitModels(models)}, nil
}

func splitModels(raw string) []string {
	raw = strings.ReplaceAll(raw, "\n", ",")
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		m := strings.TrimSpace(part)
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

func openDB(dir string) (*sql.DB, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dir+"/keys.db")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS api_keys (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		key_hash TEXT NOT NULL UNIQUE,
		key_prefix TEXT NOT NULL,
		created_at TEXT NOT NULL,
		revoked INTEGER NOT NULL DEFAULT 0,
		last_used_at TEXT,
		rpm INTEGER NOT NULL DEFAULT 0,
		key_secret TEXT NOT NULL DEFAULT ''
	)`)
	if err != nil {
		return nil, err
	}
	_, _ = db.Exec(`ALTER TABLE api_keys ADD COLUMN rpm INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE api_keys ADD COLUMN key_secret TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE api_keys ADD COLUMN email TEXT NOT NULL DEFAULT ''`)
	if _, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS api_keys_email_active ON api_keys(email) WHERE revoked = 0 AND email != ''`); err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS upstreams (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		base_url TEXT NOT NULL,
		api_key TEXT NOT NULL,
		models TEXT NOT NULL DEFAULT '',
		is_default INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL
	)`)
	return db, err
}

func syncEnvUpstreams(db *sql.DB, cfg config) error {
	if len(cfg.upstreams) == 0 {
		return nil
	}
	_, _ = db.Exec(`UPDATE upstreams SET is_default = 0`)
	now := time.Now().UTC().Format(time.RFC3339)
	for i, u := range cfg.upstreams {
		models := strings.Join(u.Models, ", ")
		def := 0
		if i == 0 {
			def = 1
		}
		var id string
		err := db.QueryRow(`SELECT id FROM upstreams WHERE name = ?`, u.Name).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			id, err = randomToken(8)
			if err != nil {
				return err
			}
			_, err = db.Exec(
				`INSERT INTO upstreams (id, name, base_url, api_key, models, is_default, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				id, u.Name, u.BaseURL, u.APIKey, models, def, now,
			)
		} else if err != nil {
			return err
		} else {
			_, err = db.Exec(
				`UPDATE upstreams SET base_url = ?, api_key = ?, models = ?, is_default = ? WHERE id = ?`,
				u.BaseURL, u.APIKey, models, def, id,
			)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func newProxy() *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			up := r.In.Context().Value(upstreamCtx{}).(*upstream)
			r.SetURL(up.URL)
			r.Out.Host = up.URL.Host
			path := upstreamPath(up.URL.Path, r.In.URL.Path)
			r.Out.URL.Path = path
			r.Out.URL.RawPath = path
			r.Out.URL.RawQuery = r.In.URL.RawQuery
			r.Out.Header.Del("Authorization")
			r.Out.Header.Del("X-Api-Key")
			r.Out.Header.Set("Authorization", "Bearer "+up.APIKey)
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream request failed: " + err.Error()})
		},
	}
	return proxy
}

// upstreamPath joins the upstream base with the client path. Clients call
// /v1/responses while Azure bases already end in /openai/v1, so a second /v1
// is dropped.
func upstreamPath(base, path string) string {
	path = "/" + strings.TrimLeft(path, "/")
	if strings.HasSuffix(strings.TrimRight(base, "/"), "/v1") && (path == "/v1" || strings.HasPrefix(path, "/v1/")) {
		path = strings.TrimPrefix(path, "/v1")
		if path == "" {
			path = "/"
		}
	}
	return singleJoining(base, path)
}

func singleJoining(base, path string) string {
	if base == "" {
		if path == "" {
			return "/"
		}
		return path
	}
	return base + "/" + strings.TrimLeft(path, "/")
}

func (s *server) forward(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/admin") {
		http.NotFound(w, r)
		return
	}
	raw := clientKey(r)
	if raw == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing api key"})
		return
	}
	id, rpm, ok, err := s.touchKey(raw)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key lookup failed"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
		return
	}
	if !s.allow(id, rpm) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "rate limit exceeded",
			"rpm":   rpm,
		})
		return
	}
	model, err := modelFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not read request body"})
		return
	}
	up, err := s.pickUpstream(model)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), upstreamCtx{}, up)))
}

func modelFromRequest(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Del("Transfer-Encoding")
	if len(bytes.TrimSpace(body)) == 0 {
		return "", nil
	}
	var probe struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return "", nil
	}
	return strings.TrimSpace(probe.Model), nil
}

func (s *server) loadUpstreams() ([]*upstream, error) {
	rows, err := s.db.Query(`SELECT id, name, base_url, api_key, models, is_default FROM upstreams ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*upstream
	for rows.Next() {
		var u upstream
		var def int
		if err := rows.Scan(&u.ID, &u.Name, &u.BaseURL, &u.APIKey, &u.ModelList, &def); err != nil {
			return nil, err
		}
		parsed, err := url.Parse(u.BaseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		parsed.Path = strings.TrimRight(parsed.Path, "/")
		u.URL = parsed
		u.Models = splitModels(u.ModelList)
		u.IsDefault = def == 1
		out = append(out, &u)
	}
	return out, rows.Err()
}

func (s *server) pickUpstream(model string) (*upstream, error) {
	list, err := s.loadUpstreams()
	if err != nil {
		return nil, errors.New("could not load upstreams")
	}
	if len(list) == 0 {
		return nil, errors.New("no upstreams configured")
	}
	var fallback *upstream
	for _, u := range list {
		if u.IsDefault {
			fallback = u
		}
		if model == "" {
			continue
		}
		for _, m := range u.Models {
			if m == model {
				return u, nil
			}
		}
	}
	if model != "" {
		return nil, errors.New("no upstream owns model " + model)
	}
	if fallback == nil {
		fallback = list[0]
	}
	return fallback, nil
}

func clientKey(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		const p = "bearer "
		if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
			return strings.TrimSpace(h[len(p):])
		}
	}
	if k := strings.TrimSpace(r.Header.Get("X-Api-Key")); k != "" {
		return k
	}
	return strings.TrimSpace(r.URL.Query().Get("api_key"))
}

func (s *server) touchKey(raw string) (string, int, bool, error) {
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	var id string
	var rpm int
	err := s.db.QueryRow(
		`UPDATE api_keys SET last_used_at = ? WHERE key_hash = ? AND revoked = 0 RETURNING id, rpm`,
		time.Now().UTC().Format(time.RFC3339), hash,
	).Scan(&id, &rpm)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	return id, rpm, true, nil
}

func (s *server) keyExists(raw string) (bool, error) {
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE key_hash = ? AND revoked = 0`, hash).Scan(&n)
	return n == 1, err
}

func (s *server) allow(id string, rpm int) bool {
	if rpm <= 0 {
		return true
	}
	minute := time.Now().Unix() / 60
	s.limMu.Lock()
	defer s.limMu.Unlock()
	w := s.limits[id]
	if w == nil || w.minute != minute {
		w = &windowCount{minute: minute}
		s.limits[id] = w
	}
	if w.count >= rpm {
		return false
	}
	w.count++
	return true
}

type keyRow struct {
	ID         string
	Name       string
	Prefix     string
	CreatedAt  string
	Revoked    bool
	LastUsedAt string
	RPM        int
	Secret     string
	Email      string
}

func (s *server) listKeys() ([]keyRow, error) {
	rows, err := s.db.Query(`SELECT id, name, key_prefix, created_at, revoked, COALESCE(last_used_at, ''), rpm, COALESCE(key_secret, ''), COALESCE(email, '') FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keyRow
	for rows.Next() {
		var k keyRow
		var revoked int
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.CreatedAt, &revoked, &k.LastUsedAt, &k.RPM, &k.Secret, &k.Email); err != nil {
			return nil, err
		}
		k.Revoked = revoked == 1
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *server) createKey(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "key"
	}
	if len(name) > 80 {
		name = name[:80]
	}
	secret, err := randomToken(24)
	if err != nil {
		http.Error(w, "could not create key", http.StatusInternalServerError)
		return
	}
	full := "sk-" + secret
	sum := sha256.Sum256([]byte(full))
	id, err := randomToken(8)
	if err != nil {
		http.Error(w, "could not create key", http.StatusInternalServerError)
		return
	}
	rpm := parseRPM(r.FormValue("rpm"))
	prefix := full[:7] + "…" + full[len(full)-4:]
	_, err = s.db.Exec(
		`INSERT INTO api_keys (id, name, key_hash, key_prefix, created_at, rpm, key_secret) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, name, hex.EncodeToString(sum[:]), prefix, time.Now().UTC().Format(time.RFC3339), rpm, full,
	)
	if err != nil {
		http.Error(w, "could not store key", http.StatusInternalServerError)
		return
	}
	s.renderAdmin(w, r, full)
}

func parseRPM(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 {
		return 0
	}
	if n > 1_000_000 {
		return 1_000_000
	}
	return n
}

func (s *server) setRPM(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if id != "" {
		_, _ = s.db.Exec(`UPDATE api_keys SET rpm = ? WHERE id = ?`, parseRPM(r.FormValue("rpm")), id)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) revokeKey(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if id != "" {
		_, _ = s.db.Exec(`UPDATE api_keys SET revoked = 1 WHERE id = ?`, id)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) createUpstream(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	base := strings.TrimSpace(r.FormValue("base_url"))
	key := strings.TrimSpace(r.FormValue("api_key"))
	models := splitModels(r.FormValue("models"))
	if name == "" || base == "" || key == "" || len(models) == 0 {
		http.Error(w, "name, base url, api key, and at least one model are required", http.StatusBadRequest)
		return
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		http.Error(w, "base url must be absolute", http.StatusBadRequest)
		return
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	existing, err := s.loadUpstreams()
	if err != nil {
		http.Error(w, "could not load upstreams", http.StatusInternalServerError)
		return
	}
	owned := map[string]string{}
	for _, u := range existing {
		for _, m := range u.Models {
			owned[m] = u.Name
		}
	}
	for _, m := range models {
		if owner, ok := owned[m]; ok {
			http.Error(w, "model "+m+" is already on "+owner, http.StatusConflict)
			return
		}
	}
	id, err := randomToken(8)
	if err != nil {
		http.Error(w, "could not create upstream", http.StatusInternalServerError)
		return
	}
	def := 0
	if r.FormValue("is_default") == "on" || len(existing) == 0 {
		def = 1
		_, _ = s.db.Exec(`UPDATE upstreams SET is_default = 0`)
	}
	_, err = s.db.Exec(
		`INSERT INTO upstreams (id, name, base_url, api_key, models, is_default, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, name, parsed.String(), key, strings.Join(models, ", "), def, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		http.Error(w, "could not store upstream", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) deleteUpstream(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if id != "" {
		_, _ = s.db.Exec(`DELETE FROM upstreams WHERE id = ?`, id)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) adminPage(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.renderAdmin(w, r, "")
}

func (s *server) renderAdmin(w http.ResponseWriter, r *http.Request, fresh string) {
	keys, err := s.listKeys()
	if err != nil {
		http.Error(w, "could not list keys", http.StatusInternalServerError)
		return
	}
	ups, err := s.loadUpstreams()
	if err != nil {
		http.Error(w, "could not list upstreams", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = adminTmpl.Execute(w, map[string]any{
		"Keys":      keys,
		"Upstreams": ups,
		"Fresh":     fresh,
		"Host":      r.Host,
	})
}

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.adminOK(r) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(loginHTML))
}

func (s *server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.adminToken)) != 1 {
		http.Error(w, "invalid admin token", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "admin",
		Value:    token,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   60 * 60 * 24 * 7,
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "admin", Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.adminOK(r) {
		return true
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") || r.Header.Get("Accept") == "" {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return false
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin auth required"})
	return false
}

func (s *server) adminOK(r *http.Request) bool {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		token := strings.TrimSpace(h[7:])
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.adminToken)) == 1 {
			return true
		}
	}
	c, err := r.Cookie("admin")
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.cfg.adminToken)) == 1
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

const pageCSS = `
  :root {
    color-scheme: light;
    --ink: #1c1915;
    --ink-soft: #5c5348;
    --paper: #f3efe6;
    --sheet: #fffdf8;
    --line: #e2d9cc;
    --accent: #1f6b45;
    --accent-ink: #f4fff8;
    --danger: #8c2f2f;
    --danger-bg: #f8e8e4;
    --focus: #1f6b45;
  }
  * { box-sizing: border-box; }
  html { background: var(--paper); }
  body {
    margin: 0;
    min-height: 100vh;
    color: var(--ink);
    font: 15px/1.45 "Segoe UI", system-ui, sans-serif;
    background:
      radial-gradient(1200px 400px at 10% -10%, #efe6d4 0%, transparent 55%),
      var(--paper);
  }
  ::selection { background: #d7ecdf; color: var(--ink); }
  :focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
  main { width: min(1080px, calc(100% - 32px)); margin: 0 auto; padding: 36px 0 72px; }
  header { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; margin-bottom: 28px; }
  h1, h2 { font-family: Georgia, "Iowan Old Style", serif; font-weight: 500; letter-spacing: -0.03em; margin: 0; }
  h1 { font-size: 40px; line-height: 1; }
  h2 { font-size: 28px; margin-top: 48px; }
  .sub { margin: 8px 0 0; color: var(--ink-soft); max-width: 62ch; }
  button, input { font: inherit; }
  input {
    padding: 9px 11px;
    border-radius: 8px;
    border: 1px solid var(--line);
    background: var(--sheet);
    color: var(--ink);
  }
  input::placeholder { color: #8a7f72; }
  button {
    padding: 9px 14px;
    border: 0;
    border-radius: 999px;
    background: var(--accent);
    color: var(--accent-ink);
    font-weight: 650;
    cursor: pointer;
  }
  button:hover { filter: brightness(1.08); }
  button.ghost { background: transparent; color: var(--ink); border: 1px solid var(--line); }
  button.danger { background: var(--danger-bg); color: var(--danger); }
  button.copy { background: var(--sheet); color: var(--ink); border: 1px solid var(--line); padding: 6px 10px; }
  button.copy.done { background: var(--accent); color: var(--accent-ink); border-color: transparent; }
  .create {
    display: flex; flex-wrap: wrap; gap: 10px; align-items: end;
    padding-bottom: 22px; margin-bottom: 8px;
    border-bottom: 1px solid var(--line);
  }
  label { display: grid; gap: 4px; color: var(--ink-soft); font-size: 13px; }
  label input[name="name"] { width: min(280px, 70vw); }
  label input[name="rpm"] { width: 110px; }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  th { text-align: left; font-size: 12px; letter-spacing: 0.04em; text-transform: uppercase; color: var(--ink-soft); font-weight: 650; padding: 12px 8px; }
  td { padding: 14px 8px; border-top: 1px solid var(--line); vertical-align: middle; }
  .name { font-weight: 650; }
  .revoked { color: var(--ink-soft); font-weight: 500; }
  .keycell { display: flex; gap: 8px; align-items: center; }
  code {
    font-family: ui-monospace, "Cascadia Code", monospace;
    font-size: 13px;
    background: #efe8dc;
    padding: 6px 8px;
    border-radius: 6px;
    word-break: break-all;
  }
  .rpm { display: flex; gap: 6px; align-items: center; }
  .rpm input { width: 84px; }
  .when { color: var(--ink-soft); font-variant-numeric: tabular-nums; white-space: nowrap; }
  .empty { padding: 28px 0; color: var(--ink-soft); }
  .login {
    min-height: 100vh; display: grid; place-items: center; padding: 24px;
  }
  .login form {
    width: min(400px, 100%);
    display: grid; gap: 14px;
    background: var(--sheet);
    padding: 28px;
    border-radius: 16px;
    box-shadow: 0 18px 40px -24px rgba(28, 25, 21, 0.45);
  }
  .login h1 { font-size: 32px; }
  @media (max-width: 720px) {
    h1 { font-size: 32px; }
    table, thead, tbody, tr, td, th { display: block; }
    thead { display: none; }
    tr { padding: 12px 0; border-top: 1px solid var(--line); }
    td { border: 0; padding: 6px 0; }
    .keycell { flex-wrap: wrap; }
  }
`

const loginHTML = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>` + pageCSS + `</style>
<body class="login">
<form method="post" action="/admin/login">
  <h1>Keys</h1>
  <label>Admin token<input type="password" name="token" autofocus required></label>
  <button type="submit">Sign in</button>
</form>
`

var adminTmpl = template.Must(template.New("admin").Parse(`<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Keys</title>
<style>` + pageCSS + `</style>
<main>
  <header>
    <div>
      <h1>Keys</h1>
      <p class="sub">Clients use one key on this proxy. The <code>model</code> in the body picks which upstream base URL and API key to send. RPM 0 is unlimited. A request with no model uses the default upstream.</p>
    </div>
    <form method="post" action="/admin/logout"><button class="ghost" type="submit">Log out</button></form>
  </header>
  <form class="create" method="post" action="/admin/keys">
    <label>Name<input name="name" placeholder="laptop" required></label>
    <label>RPM<input name="rpm" type="number" min="0" step="1" value="60"></label>
    <button type="submit">Create key</button>
  </form>
  <table>
    <thead><tr><th>Name</th><th>Email</th><th>Key</th><th>RPM</th><th>Last used</th><th></th></tr></thead>
    <tbody>
    {{range .Keys}}
      <tr>
        <td class="name">{{.Name}}{{if .Revoked}} <span class="revoked">revoked</span>{{end}}</td>
        <td>{{if .Email}}{{.Email}}{{else}}<span class="when">—</span>{{end}}</td>
        <td>
          {{if .Secret}}
          <div class="keycell">
            <code>{{.Secret}}</code>
            <button type="button" class="copy" data-copy="{{.Secret}}">Copy</button>
          </div>
          {{else}}<span class="when">Not stored. Create a new key.</span>{{end}}
        </td>
        <td>
          {{if not .Revoked}}
          <form class="rpm" method="post" action="/admin/keys/rpm">
            <input type="hidden" name="id" value="{{.ID}}">
            <input name="rpm" type="number" min="0" step="1" value="{{.RPM}}">
            <button class="ghost" type="submit">Save</button>
          </form>
          {{else}}{{.RPM}}{{end}}
        </td>
        <td class="when">{{if .LastUsedAt}}{{.LastUsedAt}}{{else}}Never{{end}}</td>
        <td>
          {{if not .Revoked}}
          <form method="post" action="/admin/keys/revoke">
            <input type="hidden" name="id" value="{{.ID}}">
            <button class="danger" type="submit">Revoke</button>
          </form>
          {{end}}
        </td>
      </tr>
    {{else}}
      <tr><td class="empty" colspan="6">No keys yet. Name one above.</td></tr>
    {{end}}
    </tbody>
  </table>
  <h2>Upstreams</h2>
  <p class="sub">One row per API. Put every model id that API serves, separated by commas. The same model cannot sit on two upstreams.</p>
  <form class="create" method="post" action="/admin/upstreams">
    <label>Name<input name="name" placeholder="azure-other" required></label>
    <label>Base URL<input name="base_url" placeholder="https://example.openai.azure.com/openai/v1" required style="width:min(360px,80vw)"></label>
    <label>API key<input name="api_key" required style="width:min(280px,70vw)"></label>
    <label>Model ids<input name="models" placeholder="model-a, model-b" required></label>
    <label>Default<input type="checkbox" name="is_default"></label>
    <button type="submit">Add upstream</button>
  </form>
  <table>
    <thead><tr><th>Name</th><th>Base URL</th><th>Models</th><th></th></tr></thead>
    <tbody>
    {{range .Upstreams}}
      <tr>
        <td class="name">{{.Name}}{{if .IsDefault}} <span class="revoked">default</span>{{end}}</td>
        <td><code>{{.BaseURL}}</code></td>
        <td>{{if .ModelList}}{{.ModelList}}{{else}}<span class="when">any request without a model</span>{{end}}</td>
        <td>
          <form method="post" action="/admin/upstreams/delete">
            <input type="hidden" name="id" value="{{.ID}}">
            <button class="danger" type="submit">Remove</button>
          </form>
        </td>
      </tr>
    {{else}}
      <tr><td class="empty" colspan="4">No upstreams yet.</td></tr>
    {{end}}
    </tbody>
  </table>
</main>
<script>
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('button.copy');
  if (!btn) return;
  try {
    await navigator.clipboard.writeText(btn.dataset.copy);
    btn.textContent = 'Copied';
    btn.classList.add('done');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('done'); }, 1200);
  } catch {
    btn.textContent = 'Select the key';
  }
});
</script>
`))
