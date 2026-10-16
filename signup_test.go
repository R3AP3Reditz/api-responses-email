package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestUpstreamPathDropsDuplicateV1(t *testing.T) {
	got := upstreamPath("/openai/v1", "/v1/responses")
	if got != "/openai/v1/responses" {
		t.Fatalf("got %s", got)
	}
	if got := upstreamPath("/openai/v1", "/responses"); got != "/openai/v1/responses" {
		t.Fatalf("bare path %s", got)
	}
}

func TestSignupIssuesThirtyRPMAndReusesEmail(t *testing.T) {
	db, err := openDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := &server{db: db}

	body := url.Values{"email": {"Ada@Example.com"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.signupSubmit(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "sk-") {
		t.Fatalf("missing key: %s", rec.Body.String())
	}

	var rpm int
	var email string
	if err := db.QueryRow(`SELECT rpm, email FROM api_keys`).Scan(&rpm, &email); err != nil {
		t.Fatal(err)
	}
	if rpm != 30 || email != "ada@example.com" {
		t.Fatalf("rpm=%d email=%s", rpm, email)
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.signupSubmit(rec2, req2)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_keys`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("keys = %d", n)
	}
	keys, err := s.listKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Email != "ada@example.com" || keys[0].RPM != 30 {
		t.Fatalf("admin list %+v", keys)
	}
}
