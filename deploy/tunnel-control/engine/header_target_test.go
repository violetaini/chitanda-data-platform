package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestHeaderTargetHTTPSBodyScopeAndRotation(t *testing.T) {
	token := strings.Repeat("h", 64)
	body := bytes.Repeat([]byte{0, 1, 255, 2}, 65536)
	calls := 0
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Host != "business.example" || r.URL.RequestURI() != "/api/items?q=hello%20world" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-Target-URL") != "" || r.Header.Get("X-Sync-Token") != "" || r.Header.Get("X-Real-IP") != "" {
			t.Errorf("request was not preserved or sanitized: %s %s", r.Method, r.URL)
		}
		raw, _ := io.ReadAll(r.Body)
		if !bytes.Equal(raw, body) {
			t.Error("body changed")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(raw)
	}))
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	factory := func(HTTPDestination) *http.Transport {
		return &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", origin.Listener.Addr().String())
		}}
	}
	policy := &HTTPRouteAccess{Token: token, Targets: []HTTPDestination{{BaseURL: "https://business.example/api/"}}}
	h := newHeaderTargetHandler(func() *HTTPRouteAccess { return policy }, 0, factory)
	request := func(target, key string, method string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("X-Target-URL", target)
		r.Header.Set("X-Sync-Token", "spoofed")
		r.Header.Set("X-Real-IP", "spoofed")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	url := "https://business.example/api/items?q=hello%20world"
	w := request(url, token, "POST")
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), body) {
		t.Fatalf("HTTPS call failed: %d %s", w.Code, w.Body.String())
	}
	for _, bad := range []string{"https://other.example/api/items", "http://business.example/api/items", "https://business.example/admin", "https://business.example/api2/items", "https://business.example/api/%2e%2e/admin", "https://business.example/api/%252e%252e/admin", "https://user:pass@business.example/api/items", "https://127.0.0.1/api/items", "https://business.example/api%2fitems"} {
		if request(bad, token, "POST").Code < 400 {
			t.Fatal("unsafe target accepted", bad)
		}
	}
	if calls != 1 {
		t.Fatal("denied request reached upstream")
	}
	policy = &HTTPRouteAccess{Token: strings.Repeat("z", 64), Targets: policy.Targets}
	if request(url, token, "POST").Code != 401 {
		t.Fatal("reset token not revoked")
	}
	policy = nil
	if request(url, token, "POST").Code != 403 {
		t.Fatal("disabled policy accepted")
	}
}
func TestHeaderRedirectAndPrivateAddresses(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "168.63.129.16", "::1", "::ffff:127.0.0.1", "fc00::1", "198.18.0.1", "64:ff9b::a00:1"} {
		if publicDestination(netip.MustParseAddr(ip)) {
			t.Fatal("private address accepted", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "168.138.209.1", "2606:4700:4700::1111"} {
		if !publicDestination(netip.MustParseAddr(ip)) {
			t.Fatal("public address rejected", ip)
		}
	}
}
func TestHeaderBrokerDoesNotNeedLocalOriginAdapter(t *testing.T) {
	token := strings.Repeat("t", 64)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("native HTTPS origin")) }))
	defer origin.Close()
	e := testEngine(t)
	e.cfg.ID = "international"
	e.cfg.Routes[0].HTTPAccess = &HTTPRouteAccess{Token: token, Targets: []HTTPDestination{{BaseURL: "https://business.example/api/"}}}
	e.cfg.Routes[0].TargetPort = 1
	e.httpTransport = func(HTTPDestination) *http.Transport {
		tr := origin.Client().Transport.(*http.Transport).Clone()
		tr.DialContext = func(ctx context.Context, n, a string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", origin.Listener.Addr().String())
		}
		tr.TLSClientConfig.ServerName = "example.com"
		return tr
	}
	for i := 0; i < 10; i++ {
		c := connectTest(t, e)
		send(c, Hello{Kind: "dial", Node: "mainland", Token: e.cfg.Nodes[0].Token, Route: "test-route"})
		ack, err := receive(c)
		if err != nil || !ack.OK {
			t.Fatal("broker did not enter HTTP handler", err, ack)
		}
		req, _ := http.NewRequest("GET", "http://entry.example/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Target-URL", "https://business.example/api/status")
		req.Write(c)
		resp, err := http.ReadResponse(bufio.NewReader(c), req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		c.Close()
		if resp.StatusCode != 200 || string(raw) != "native HTTPS origin" {
			t.Fatal("direct business call failed", resp.StatusCode, string(raw))
		}
	}
}

type flushBeforeCloseConn struct {
	net.Conn
	flushed bool
	closed  bool
	bad     bool
}

func (c *flushBeforeCloseConn) CloseWrite() error                { c.flushed = true; return nil }
func (c *flushBeforeCloseConn) SetReadDeadline(time.Time) error  { return nil }
func (c *flushBeforeCloseConn) SetWriteDeadline(time.Time) error { return nil }
func (c *flushBeforeCloseConn) Read([]byte) (int, error) {
	if !c.flushed {
		c.bad = true
	}
	return 0, io.EOF
}
func (c *flushBeforeCloseConn) Close() error {
	if !c.flushed {
		c.bad = true
	}
	c.closed = true
	return nil
}
func TestHTTPResponseFlushesBeforeFramedStreamCancellation(t *testing.T) {
	raw := &flushBeforeCloseConn{}
	wrapped := &oneHTTPConn{Conn: raw, done: make(chan struct{})}
	wrapped.Close()
	wrapped.Close()
	if raw.bad || !raw.closed || !raw.flushed {
		t.Fatal("HTTP response was cancelled before queued data could drain")
	}
}
func TestHeaderConditionalResponseAndRedirectPolicy(t *testing.T) {
	token := strings.Repeat("v", 64)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/redirect" {
			w.Header().Set("Location", "https://other.example/")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(304)
	}))
	defer origin.Close()
	factory := func(HTTPDestination) *http.Transport {
		tr := origin.Client().Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.ServerName = "example.com"
		tr.DialContext = func(ctx context.Context, n, a string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", origin.Listener.Addr().String())
		}
		return tr
	}
	policy := &HTTPRouteAccess{Token: token, Targets: []HTTPDestination{{BaseURL: "https://business.example/api/"}}}
	h := newHeaderTargetHandler(func() *HTTPRouteAccess { return policy }, 0, factory)
	for _, tc := range []struct {
		path   string
		status int
	}{{"redirect", 502}, {"unchanged", 304}} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-Target-URL", "https://business.example/api/"+tc.path)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal(tc.path, w.Code)
		}
	}
}
