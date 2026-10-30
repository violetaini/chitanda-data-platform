// Isolated data ingress and fixed origin adapters. Never serves control APIs.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const gatewayMaxBody = 16 << 20

type GatewayEndpoint struct {
	ManagedAuth      bool   `json:"managedAuth,omitempty"`
	AllowLegacyToken bool   `json:"allowLegacyToken,omitempty"`
	TunnelAccessFile string `json:"tunnelAccessFile,omitempty"`
	SyncToken        string `json:"syncToken,omitempty"`
	Sync             bool   `json:"sync,omitempty"`
	Listen           string `json:"listen"`
	Mode             string `json:"mode"`
	Token            string `json:"token"`
	Target           string `json:"target"`
	ConnectAddress   string `json:"connectAddress,omitempty"`
	NextToken        string `json:"nextToken,omitempty"`
	Node             string `json:"node,omitempty"`
}

func gatewayAllowedPath(r *http.Request, syncEnabled bool) bool {
	if r.URL.IsAbs() || r.URL.RawPath != "" || r.Header.Get("Upgrade") != "" {
		return false
	}
	if r.URL.RawQuery != "" {
		if !syncEnabled || r.Method != "GET" {
			return false
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return false
		}
		if r.URL.Path == "/api/sync/events" {
			for key, vs := range q {
				if (key != "after" && key != "limit") || len(vs) != 1 || len(vs[0]) > 16 {
					return false
				}
				n, err := strconv.ParseUint(vs[0], 10, 53)
				if err != nil || (key == "limit" && (n < 1 || n > 500)) {
					return false
				}
			}
			return true
		}
		if r.URL.Path == "/api/sync/bangumi/cover" && len(q) == 1 && len(q["file"]) == 1 {
			file := q.Get("file")
			if len(file) != 29 || !strings.HasSuffix(file, ".webp") {
				return false
			}
			_, err := hex.DecodeString(file[:24])
			return err == nil
		}
		return false
	}
	if (r.Method == "GET" && r.URL.Path == "/api/sync/status") || (r.Method == "POST" && r.URL.Path == "/__test/echo") {
		return true
	}
	if !syncEnabled {
		return false
	}
	if r.Method == "GET" {
		return r.URL.Path == "/api/sync/events" || r.URL.Path == "/api/sync/bangumi/cache"
	}
	if r.Method != "POST" {
		return false
	}
	switch r.URL.Path {
	case "/api/sync/events", "/api/sync/settings", "/api/sync/files/prepare", "/api/sync/files/chunk", "/api/sync/files/complete":
		return true
	}
	return false
}

func gatewayFixedTarget(ep GatewayEndpoint) (*url.URL, error) {
	u, err := url.Parse(ep.Target)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid fixed target")
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("plaintext target must be loopback")
		}
	} else if u.Scheme != "https" {
		return nil, errors.New("target must use HTTP or HTTPS")
	}
	if ep.ConnectAddress != "" {
		host, _, err := net.SplitHostPort(ep.ConnectAddress)
		if err != nil || net.ParseIP(host) == nil || u.Scheme != "https" {
			return nil, errors.New("invalid HTTPS connect address")
		}
	}
	return u, nil
}
func newGatewayHandler(ep GatewayEndpoint) (http.Handler, error) {
	return newGatewayHandlerWithAccess(ep, nil)
}
func newGatewayHandlerWithAccess(ep GatewayEndpoint, access func() []TunnelAccess, failover ...func(string) http.RoundTripper) (http.Handler, error) {
	if ep.TunnelAccessFile != "" {
		ep.ManagedAuth = true
		access = func() []TunnelAccess { return readTunnelAccess(ep.TunnelAccessFile) }
	}
	accessPort := 0
	if ep.ManagedAuth {
		u, err := url.Parse(ep.Target)
		if err != nil || u.Scheme != "http" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() {
			return nil, errors.New("managed ingress requires a fixed loopback target")
		}
		accessPort, _ = strconv.Atoi(u.Port())
		if accessPort < 1 {
			return nil, errors.New("invalid managed ingress port")
		}
	}

	if len(ep.Token) < 32 {
		return nil, errors.New("endpoint token too short")
	}
	if ep.Mode != "origin" && ep.Mode != "forward" {
		return nil, errors.New("invalid endpoint mode")
	}
	target, err := gatewayFixedTarget(ep)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: target.Hostname()}, DisableKeepAlives: true, MaxConnsPerHost: 16, ResponseHeaderTimeout: 240 * time.Second, TLSHandshakeTimeout: 8 * time.Second, ExpectContinueTimeout: time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if ep.ConnectAddress != "" {
			address = ep.ConnectAddress
		}
		return (&net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
	}
	proxy := &httputil.ReverseProxy{Transport: transport, FlushInterval: -1, Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		pr.Out.Host = target.Host
		// Replace caller identity with the independently scoped next-hop credential.
		for _, h := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Node-ID", "X-CSRF-Token"} {
			pr.Out.Header.Del(h)
		}
		if ep.ManagedAuth {
			pr.Out.Header.Del("X-Sync-Token")
		}
		if ep.SyncToken != "" {
			pr.Out.Header.Set("X-Sync-Token", ep.SyncToken)
		}
		if ep.NextToken != "" {
			pr.Out.Header.Set("Authorization", "Bearer "+ep.NextToken)
		}
	}, ModifyResponse: func(resp *http.Response) error {
		for _, h := range []string{"Set-Cookie", "Server", "X-Powered-By"} {
			resp.Header.Del(h)
		}
		resp.Header.Set("Cache-Control", "no-store")
		return nil
	}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("fixed upstream request failed: %v", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}, ErrorLog: log.New(io.Discard, "", 0)}
	headerIngress := newHeaderIngress(target, access, accessPort, failover...)
	slots := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if ep.ManagedAuth && headerIngress(w, r) {
			return
		}
		legacyOK := subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+ep.Token)) == 1
		authorized := legacyOK
		if ep.ManagedAuth {
			authorized = false
			if access != nil {
				authorized = tunnelAccessAllowed(r, access(), accessPort)
			}
			if ep.AllowLegacyToken && legacyOK {
				authorized = true
			}
		}
		if !authorized {
			http.Error(w, "authentication required", 401)
			return
		}
		if !gatewayAllowedPath(r, ep.Sync) {
			http.Error(w, "service not permitted", 403)
			return
		}
		if r.ContentLength > gatewayMaxBody {
			http.Error(w, "body too large", 413)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "busy", 429)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, gatewayMaxBody)
		if ep.Mode == "origin" && r.URL.Path == "/__test/echo" {
			hash := sha256.New()
			size, err := io.Copy(hash, r.Body)
			if err != nil {
				http.Error(w, "body too large or incomplete", 413)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"origin": ep.Node, "bytes": size, "sha256": hex.EncodeToString(hash.Sum(nil))})
			return
		}
		proxy.ServeHTTP(w, r)
	}), nil
}

// Public HTTPS ingress and local egress share the relay executable.
type DataGatewayConfig struct {
	Domain         string          `json:"domain"`
	Certificate    string          `json:"certificate"`
	Key            string          `json:"key"`
	AllowedSources []string        `json:"allowedSources"`
	Ingress        GatewayEndpoint `json:"ingress"`
	Egress         GatewayEndpoint `json:"egress"`
}

func (e *Engine) dataGatewayHandler(fallback http.Handler) (http.Handler, *tls.Certificate, error) {
	nodeConfig := e.config()
	cfg := nodeConfig.DataGateway
	if cfg == nil {
		return fallback, nil, nil
	}
	if !strings.Contains(cfg.Domain, ".") || cfg.Ingress.Mode != "forward" || cfg.Egress.Mode != "forward" {
		return nil, nil, errors.New("invalid public gateway configuration")
	}
	certificate, err := tls.LoadX509KeyPair(cfg.Certificate, cfg.Key)
	if current := e.publicCert.Load(); current != nil {
		certificate = *current
		err = nil
	}
	if err != nil {
		return nil, nil, err
	}
	if err := certificate.Leaf.VerifyHostname(cfg.Domain); err != nil {
		return nil, nil, err
	}
	ingress, err := newGatewayHandlerWithAccess(cfg.Ingress, func() []TunnelAccess { return e.config().TunnelAccess }, e.failoverHTTPTransport)
	if err != nil {
		return nil, nil, err
	}
	egress, err := newGatewayHandler(cfg.Egress)
	if err != nil {
		return nil, nil, err
	}
	host, _, err := net.SplitHostPort(cfg.Egress.Listen)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		return nil, nil, errors.New("gateway egress must be loopback")
	}
	listener, err := net.Listen("tcp", cfg.Egress.Listen)
	if err != nil {
		return nil, nil, err
	}
	local := &http.Server{Handler: egress, ReadHeaderTimeout: 8 * time.Second, ReadTimeout: 300 * time.Second, WriteTimeout: 300 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10}
	go local.Serve(listener)
	return gatewayMux(cfg, nodeConfig.Path, ingress, fallback), &certificate, nil
}

// A business SNI may also carry the authenticated tunnel protocol. Only its
// exact reserved path is delegated; PSK/replay/node checks remain in fallback.
func gatewayMux(cfg *DataGatewayConfig, protocolPath string, ingress, fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if protocolPath != "" && r.URL.Path == protocolPath {
			fallback.ServeHTTP(w, r)
			return
		}
		if r.TLS == nil || r.TLS.ServerName != cfg.Domain {
			fallback.ServeHTTP(w, r)
			return
		}
		hostname := r.Host
		if h, _, err := net.SplitHostPort(hostname); err == nil {
			hostname = h
		}
		if hostname != cfg.Domain {
			http.Error(w, "host mismatch", 421)
			return
		}
		remote, _, err := net.SplitHostPort(r.RemoteAddr)
		permitted := false
		if err == nil {
			for _, allowed := range cfg.AllowedSources {
				if remote == allowed {
					permitted = true
					break
				}
			}
		}
		if !permitted {
			http.Error(w, "access denied", 403)
			return
		}
		ingress.ServeHTTP(w, r)
	})
}
