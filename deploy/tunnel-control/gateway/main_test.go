package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOriginScopeAndStreamingIntegrity(t *testing.T) {
	token := strings.Repeat("a", 64)
	h, err := newHandler(Endpoint{Mode: "origin", Token: token, Target: "http://127.0.0.1:5081", Node: "isolated-origin"})
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0, 255, 128, 17}, 512*1024)
	r := httptest.NewRequest("POST", "/__test/echo", bytes.NewReader(payload))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var result struct {
		Bytes  int
		SHA256 string
		Origin string
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	sum := sha256.Sum256(payload)
	if w.Code != 200 || result.Bytes != len(payload) || result.SHA256 != hex.EncodeToString(sum[:]) || result.Origin != "isolated-origin" {
		t.Fatal("body integrity or origin mismatch")
	}
	for _, path := range []string{"/tunnel/api/state", "/api/sync/settings", "/__test/echo?target=http://169.254.169.254", "/%61pi/sync/status", "/api/../sync/status"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("path escaped scope: %s %d", path, w.Code)
		}
	}
	r = httptest.NewRequest("POST", "/__test/echo", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("unauthenticated request allowed")
	}
	r = httptest.NewRequest("POST", "/__test/echo", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.ContentLength = maxBody + 1
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatal("oversized body allowed")
	}
}
func TestFixedForwardingReplacesIdentityAndPreservesBody(t *testing.T) {
	token := strings.Repeat("b", 64)
	next := strings.Repeat("c", 64)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+next || r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-For") != "" || r.URL.Path != "/__test/echo" {
			t.Error("credential or routing boundary failed")
		}
		if r.Header.Get("X-Sync-Token") != "business-secret" {
			t.Error("business authentication lost")
		}
		w.Header().Set("Set-Cookie", "internal=session")
		w.Write([]byte("streamed response"))
	}))
	defer upstream.Close()
	h, err := newHandler(Endpoint{Mode: "forward", Token: token, Target: upstream.URL, NextToken: next})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/__test/echo", strings.NewReader("payload"))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Cookie", "private=cookie")
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	r.Header.Set("X-Sync-Token", "business-secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "streamed response" || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("response handling failed")
	}
}
func TestHTTPSIdentityAndTargetValidation(t *testing.T) {
	for _, target := range []string{"http://example.com", "http://169.254.169.254", "https://user:password@example.com", "https://example.com?target=x", "https://example.com/path"} {
		if _, err := fixedTarget(Endpoint{Target: target}); err == nil {
			t.Fatal("unsafe target accepted", target)
		}
	}
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted origin was reached") }))
	defer tlsOrigin.Close()
	token := strings.Repeat("d", 64)
	h, err := newHandler(Endpoint{Mode: "forward", Token: token, Target: tlsOrigin.URL})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/sync/status", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 502 {
		t.Fatal("TLS validation did not fail closed")
	}
}
func TestSyncQueriesStayWithinBusinessScope(t *testing.T) {
	for _,path:=range []string{"/api/sync/events?after=0&limit=100","/api/sync/bangumi/cover?file=0123456789abcdef01234567.webp"}{
	 r:=httptest.NewRequest("GET",path,nil);if !allowedPath(r,true)||allowedPath(r,false){t.Fatal("sync scope flag failed",path)}
	}
	for _,path:=range []string{"/api/sync/events?target=http://127.0.0.1","/api/sync/events?after=-1","/api/sync/events?limit=10000","/api/sync/events?after=1&after=2","/api/sync/bangumi/cover?file=../../secret","/api/sync/run","/tunnel/api/state"}{
	 if allowedPath(httptest.NewRequest("GET",path,nil),true){t.Fatal("query scope escaped",path)}
	}
}
