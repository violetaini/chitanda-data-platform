package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDownloadWhitelistUsesSocketAddressAndFailsClosed(t *testing.T) {
	for _, v := range []struct {
		ip      string
		allowed []string
		want    bool
	}{{"203.0.113.8:1234", []string{"203.0.113.8"}, true}, {"203.0.113.9:12", []string{"203.0.113.8"}, false}, {"[2001:db8::2]:1234", []string{"2001:db8::/64"}, true}, {"[::ffff:203.0.113.8]:1234", []string{"203.0.113.8"}, true}, {"203.0.113.8:1234", nil, false}, {"bad", []string{"0.0.0.0/0"}, false}} {
		if got := downloadAddressAllowed(v.ip, v.allowed); got != v.want {
			t.Errorf("%s got %v", v.ip, got)
		}
	}
}
func TestDownloadGatewayIsolationRevocationAndStreaming(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:5000")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 1)
	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"} {
			if r.Header.Get(h) != "" {
				t.Errorf("forwarding header escaped: %s", h)
			}
		}
		seen <- r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte{0, 255, 1, 2})
	})}
	go backend.Serve(listener)
	defer backend.Close()
	e := &Engine{cfg: Config{DownloadBackendEnabled: true, Path: "/bridge", DownloadAccess: &DownloadAccessConfig{Domain: "downloads.example", Enabled: true, Allowed: []string{"203.0.113.8"}, Revision: 1}}}
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	handler := e.downloadHandler(fallback)
	request := func(remote, host, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://"+host+path, nil)
		r.RemoteAddr = remote
		r.TLS = &tls.ConnectionState{ServerName: "downloads.example"}
		r.Header.Set("CF-Connecting-IP", "203.0.113.8")
		r.Header.Set("X-Forwarded-For", "203.0.113.8")
		r.Header.Set("Forwarded", "for=203.0.113.8")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if got := request("198.51.100.1:1", "downloads.example", "/v2/").Code; got != 403 {
		t.Fatal(got)
	}
	if got := request("203.0.113.8:1", "other.example", "/v2/").Code; got != 421 {
		t.Fatal(got)
	}
	w := request("203.0.113.8:1", "downloads.example", "/https://example.com/a?x=1")
	if w.Code != 200 || string(w.Body.Bytes()) != string([]byte{0, 255, 1, 2}) {
		t.Fatal(w.Code, w.Body.Bytes())
	}
	if got := <-seen; got != "/https://example.com/a?x=1" {
		t.Fatal(got)
	}
	e.mu.Lock()
	e.cfg.DownloadAccess.Enabled = false
	e.mu.Unlock()
	if request("203.0.113.8:1", "downloads.example", "/v2/").Code != 403 {
		t.Fatal("pause not applied")
	}
	e.mu.Lock()
	e.cfg.DownloadAccess = nil
	e.mu.Unlock()
	if request("203.0.113.8:1", "downloads.example", "/v2/").Code != 404 {
		t.Fatal("removed policy still exposed")
	}
	r := httptest.NewRequest("GET", "https://downloads.example/bridge", strings.NewReader("x"))
	r.TLS = &tls.ConnectionState{ServerName: "downloads.example"}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	io.Copy(io.Discard, w.Body)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestDownloadCredentialRevocationClearsPolicy(t *testing.T) {
	e := testEngine(t)
	e.cfg.DownloadBackendEnabled = true
	e.cfg.DownloadAccess = &DownloadAccessConfig{Domain: "downloads.example", Enabled: true, Allowed: []string{"203.0.113.8"}, Revision: 1}
	e.revoke()
	if e.config().DownloadAccess != nil {
		t.Fatal("revoked node kept download permissions")
	}
}
