package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/server"
)

func TestBusinessSNIRoutesOnlyExactTunnelPath(t *testing.T) {
	cfg := &DataGatewayConfig{Domain: "business.example", AllowedSources: []string{"192.0.2.1"}}
	ingress := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	protocol := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) })
	app := gatewayMux(cfg, "/private-protocol", ingress, protocol)
	for _, tc := range []struct {
		path, host, remote string
		want               int
	}{
		{"/private-protocol", "business.example", "192.0.2.200:1234", 202},
		{"/private-protocol/other", "business.example", "192.0.2.200:1234", 403},
		{"/api/sync/status", "business.example", "192.0.2.200:1234", 403},
		{"/api/sync/status", "business.example", "192.0.2.1:1234", 204},
		{"/api/sync/status", "wrong.example", "192.0.2.1:1234", 421},
	} {
		r := httptest.NewRequest("POST", "https://"+tc.host+tc.path, nil)
		r.RemoteAddr = tc.remote
		r.TLS = &tls.ConnectionState{ServerName: cfg.Domain}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: got %d, want %d", tc.path, w.Code, tc.want)
		}
	}
}

func TestBusinessSNIUnauthenticatedTunnelStillRejected(t *testing.T) {
	replays, err := auth.OpenReplayCache(filepath.Join(t.TempDir(), "replay"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer replays.Close()
	protocol := server.NewServer("/private-protocol", []byte(strings.Repeat("s", 32)), replays, http.NotFoundHandler(), 0)
	app := gatewayMux(&DataGatewayConfig{Domain: "business.example"}, "/private-protocol", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("tunnel request reached business adapter") }), protocol)
	r := httptest.NewRequest("POST", "https://business.example/private-protocol", nil)
	r.ProtoMajor = 2
	r.TLS = &tls.ConnectionState{ServerName: "business.example"}
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("unauthenticated tunnel status %d", w.Code)
	}
}
