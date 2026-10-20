package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHeaderIngressSelectsTunnelPortByToken(t *testing.T) {
	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) || r.Header.Get("X-Target-URL") != "https://business.example/api/status" {
			t.Error("headers changed")
		}
		raw, _ := io.ReadAll(r.Body)
		w.Write(raw)
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	port := 0
	fmtSscanf(u.Host, &port)
	grants := []TunnelAccess{{Domain: "entry.example", ListenPort: port, Token: strings.Repeat("a", 64), HeaderURL: true}}
	wrong, _ := url.Parse("http://127.0.0.1:1")
	handler := newHeaderIngress(wrong, func() []TunnelAccess { return grants }, 1)
	r := httptest.NewRequest("POST", "/", strings.NewReader("binary body"))
	r.Host = "entry.example"
	r.Header.Set("Authorization", "Bearer "+grants[0].Token)
	r.Header.Set("X-Target-URL", "https://business.example/api/status")
	w := httptest.NewRecorder()
	if !handler(w, r) || w.Code != 200 || w.Body.String() != "binary body" {
		t.Fatal("did not use selected tunnel port", w.Code, w.Body.String())
	}
	grants = nil
	w = httptest.NewRecorder()
	if handler(w, r) {
		t.Fatal("revoked grant was accepted")
	}
	if calls != 1 {
		t.Fatal("bad call reached tunnel")
	}
}
