package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestManagedTunnelTokenScopeAndTranslation(t *testing.T) {
	wire := strings.Repeat("w", 64)
	token := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+wire || r.Header.Get("X-Sync-Token") != "" {
			t.Error("caller credentials leaked to next hop")
		}
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	port := 0
	fmtSscanf(upstream.Listener.Addr().String(), &port)
	grants := []TunnelAccess{{TunnelID: "one", RouteID: "r", Domain: "one.example", ListenPort: port, Token: token}, {TunnelID: "two", Domain: "two.example", ListenPort: port + 1, Token: other}}
	ep := Endpoint{Mode: "forward", Token: strings.Repeat("l", 64), ManagedAuth: true, Sync: true, Target: upstream.URL, NextToken: wire}
	h, err := newHandlerWithAccess(ep, func() []TunnelAccess { return grants })
	if err != nil {
		t.Fatal(err)
	}
	request := func(host, secret string) int {
		r := httptest.NewRequest("GET", "/api/sync/status", nil)
		r.Host = host
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("X-Sync-Token", "spoofed")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if request("one.example", token) != 204 {
		t.Fatal("valid tunnel token rejected")
	}
	for _, pair := range [][2]string{{"one.example", other}, {"other.example", token}, {"one.example", ep.Token}, {"two.example", other}, {"one.example", ""}} {
		if request(pair[0], pair[1]) != 401 {
			t.Fatal("wrong domain, port or credential accepted")
		}
	}
	grants[0].Token = other
	if request("one.example", token) != 401 || request("one.example", other) != 204 {
		t.Fatal("token reset did not revoke old credential and activate new credential")
	}
	grants = nil
	if request("one.example", token) != 401 {
		t.Fatal("paused/deleted grants still accepted")
	}
	ep.ManagedAuth = false
	ep.SyncToken = "server-only-business-secret"
	ep.Mode = "origin"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Sync-Token") != ep.SyncToken {
			t.Error("server-side business secret not injected")
		}
		w.WriteHeader(204)
	}))
	defer origin.Close()
	ep.Target = origin.URL
	h, err = newHandler(ep)
	if err != nil {
		t.Fatal(err)
	}
	if request("one.example", ep.Token) != 204 {
		t.Fatal("origin adapter failed")
	}
}
func fmtSscanf(address string, port *int) {
	_, p, _ := net.SplitHostPort(address)
	*port, _ = strconv.Atoi(p)
}
func TestManagedGrantFileFailsClosed(t *testing.T) {
	file := filepath.Join(t.TempDir(), "grants.json")
	token := strings.Repeat("f", 64)
	grant := TunnelAccess{Domain: "file.example", ListenPort: 15082, Token: token}
	raw, _ := json.Marshal([]TunnelAccess{grant})
	os.WriteFile(file, raw, 0600)
	req := httptest.NewRequest("GET", "https://file.example/api/sync/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if !tunnelAccessAllowed(req, readTunnelAccess(file), 15082) {
		t.Fatal("valid file not read")
	}
	os.WriteFile(file, []byte("broken"), 0600)
	if tunnelAccessAllowed(req, readTunnelAccess(file), 15082) {
		t.Fatal("invalid file accepted")
	}
	os.Remove(file)
	if tunnelAccessAllowed(req, readTunnelAccess(file), 15082) {
		t.Fatal("missing file accepted")
	}
}
