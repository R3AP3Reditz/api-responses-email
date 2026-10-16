package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

const signupRPM = 30

func normalizeEmail(raw string) (string, bool) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || len(email) > 254 || strings.ContainsAny(email, " \t\r\n") {
		return "", false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || !strings.Contains(email, "@") {
		return "", false
	}
	return email, true
}

func (s *server) signupPage(w http.ResponseWriter, r *http.Request) {
	s.renderSignup(w, http.StatusOK, signupView{})
}

func (s *server) signupSubmit(w http.ResponseWriter, r *http.Request) {
	email, ok := normalizeEmail(r.FormValue("email"))
	if !ok {
		s.renderSignup(w, http.StatusBadRequest, signupView{Error: "Enter a valid email address."})
		return
	}
	secret, existed, err := s.issueEmailKey(email)
	if err != nil {
		s.renderSignup(w, http.StatusInternalServerError, signupView{Error: "Could not create a key. Try again."})
		return
	}
	s.renderSignup(w, http.StatusOK, signupView{
		Email:   email,
		Key:     secret,
		Existed: existed,
		Host:    r.Host,
	})
}

type signupView struct {
	Error   string
	Email   string
	Key     string
	Existed bool
	Host    string
}

func (s *server) renderSignup(w http.ResponseWriter, code int, view signupView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = signupTmpl.Execute(w, view)
}

func (s *server) issueEmailKey(email string) (secret string, existed bool, err error) {
	err = s.db.QueryRow(
		`SELECT COALESCE(key_secret, '') FROM api_keys WHERE email = ? AND revoked = 0`,
		email,
	).Scan(&secret)
	if err == nil {
		if secret == "" {
			return "", true, errors.New("stored key is empty")
		}
		return secret, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}
	token, err := randomToken(24)
	if err != nil {
		return "", false, err
	}
	secret = "sk-" + token
	sum := sha256.Sum256([]byte(secret))
	id, err := randomToken(8)
	if err != nil {
		return "", false, err
	}
	prefix := secret[:7] + "…" + secret[len(secret)-4:]
	_, err = s.db.Exec(
		`INSERT INTO api_keys (id, name, key_hash, key_prefix, created_at, rpm, key_secret, email) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, email, hex.EncodeToString(sum[:]), prefix, time.Now().UTC().Format(time.RFC3339), signupRPM, secret, email,
	)
	if err != nil {
		var again string
		qerr := s.db.QueryRow(
			`SELECT COALESCE(key_secret, '') FROM api_keys WHERE email = ? AND revoked = 0`,
			email,
		).Scan(&again)
		if qerr == nil && again != "" {
			return again, true, nil
		}
		return "", false, err
	}
	return secret, false, nil
}

var signupTmpl = template.Must(template.New("signup").Parse(`<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Get an API key</title>
<style>` + pageCSS + `
  body.gate { min-height: 100vh; }
  .gate main { width: min(720px, calc(100% - 32px)); padding-top: 64px; }
  .gate h1 { font-size: clamp(36px, 6vw, 52px); letter-spacing: -0.03em; text-wrap: balance; }
  .gate .lead { margin: 14px 0 0; max-width: 58ch; color: var(--ink-soft); font-size: 17px; }
  .gate .sub code { background: transparent; padding: 0; font-size: 0.95em; }
  .sheet {
    margin-top: 32px;
    background: var(--sheet);
    border-radius: 16px;
    box-shadow: 0 22px 40px -28px rgba(28, 25, 21, 0.55);
    padding: 22px;
  }
  .sheet form { display: grid; gap: 14px; }
  .ask { display: flex; gap: 10px; align-items: end; }
  .ask label { flex: 1; }
  .ask input { width: 100%; }
  .ask button { height: 42px; }
  .alert {
    margin: 0 0 14px;
    padding: 10px 12px;
    border-radius: 10px;
    background: var(--danger-bg);
    color: var(--danger);
  }
  .result { display: grid; gap: 16px; }
  .result h2 { margin: 0; font-size: 28px; }
  .secret {
    display: flex; gap: 8px; align-items: center;
    padding: 10px;
    border-radius: 12px;
    background: #efe8dc;
  }
  .secret code {
    flex: 1;
    background: transparent;
    padding: 4px 6px;
    font-size: 14px;
  }
  .facts { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 0; }
  .facts div { display: grid; gap: 4px; }
  .facts dt { font-size: 12px; letter-spacing: 0.04em; text-transform: uppercase; color: var(--ink-soft); }
  .facts dd { margin: 0; }
  .facts code { display: inline-block; word-break: break-all; }
  .sample {
    margin: 0;
    padding: 14px;
    border-radius: 12px;
    background: #1c1915;
    color: #f4fff8;
    overflow: auto;
    font-family: ui-monospace, "Cascadia Code", monospace;
    font-size: 13px;
    line-height: 1.5;
  }
  ::selection { background: #d7ecdf; }
  .sample ::selection, .sample::selection { background: #1f6b45; color: #f4fff8; }
  @media (max-width: 640px) {
    .ask, .facts { display: grid; grid-template-columns: 1fr; }
    .secret { flex-wrap: wrap; }
  }
</style>
<body class="gate">
<main>
  <h1>Get an API key</h1>
  <p class="lead">One email, one key, 30 requests a minute. Submit the same email again to see the active key.</p>
  <section class="sheet">
    <form method="post" action="/signup">
      {{if .Error}}<p class="alert" role="alert">{{.Error}}</p>{{end}}
      <div class="ask">
        <label>Email
          <input type="email" name="email" value="{{.Email}}" autocomplete="email" placeholder="you@example.com" autofocus required>
        </label>
        <button type="submit">Get key</button>
      </div>
    </form>
  </section>
  {{if .Key}}
  <section class="sheet result">
    <div>
      <h2>{{if .Existed}}Your existing key{{else}}Your key is ready{{end}}</h2>
      <p class="sub">Send it as <code>Authorization: Bearer</code>. Store it somewhere you can find again. This page will show it when you enter the same email.</p>
    </div>
    <div class="secret">
      <code id="key">{{.Key}}</code>
      <button type="button" class="copy" data-copy="{{.Key}}">Copy</button>
    </div>
    <dl class="facts">
      <div>
        <dt>Base URL</dt>
        <dd><code>https://{{.Host}}/v1</code></dd>
      </div>
      <div>
        <dt>Limit</dt>
        <dd>30 requests / minute</dd>
      </div>
    </dl>
    <pre class="sample">curl https://{{.Host}}/v1/models \
  -H "Authorization: Bearer {{.Key}}"</pre>
  </section>
  {{end}}
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
