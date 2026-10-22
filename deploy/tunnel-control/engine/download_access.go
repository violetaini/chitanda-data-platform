package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

// The backend address and opt-in are local bootstrap settings, not controller input.
// Forwarding headers are never an authorization source on this direct-origin service.
type DownloadAccessConfig struct {
	ID       string   `json:"id"`
	Domain   string   `json:"domain"`
	Enabled  bool     `json:"enabled"`
	Revision int      `json:"revision"`
	Allowed  []string `json:"allowed"`
}

func downloadAddressAllowed(remote string, allowed []string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	for _, value := range allowed {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			if prefix.Contains(ip) {
				return true
			}
		} else if candidate, err := netip.ParseAddr(value); err == nil && candidate.Unmap() == ip {
			return true
		}
	}
	return false
}
func (e *Engine) downloadReportLocked() any {
	p := e.cfg.DownloadAccess
	if !e.cfg.DownloadBackendEnabled {
		return map[string]any{"supported": false, "revision": 0, "ready": false}
	}
	ready := false
	if p != nil {
		c, err := net.DialTimeout("tcp", "127.0.0.1:5000", 300*time.Millisecond)
		if err == nil {
			c.Close()
			cert := e.publicCert.Load()
			ready = cert != nil && cert.Leaf != nil && cert.Leaf.VerifyHostname(p.Domain) == nil && time.Now().Before(cert.Leaf.NotAfter) && !time.Now().Before(cert.Leaf.NotBefore)
		}
	}
	revision := 0
	if p != nil {
		revision = p.Revision
	}
	return map[string]any{"supported": true, "revision": revision, "ready": ready}
}
func (e *Engine) downloadHandler(fallback http.Handler) http.Handler {
	if !e.config().DownloadBackendEnabled {
		return fallback
	}
	target, _ := url.Parse("http://127.0.0.1:5000")
	slots := make(chan struct{}, 64)
	proxy := &httputil.ReverseProxy{Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(target)
		p.Out.Host = p.In.Host
		for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP", "X-Original-URL", "X-Rewrite-URL"} {
			p.Out.Header.Del(h)
		}
		p.Out.Header.Set("X-Forwarded-Proto", "https")
	}, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 64, MaxIdleConnsPerHost: 32, MaxConnsPerHost: 64, IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: 90 * time.Second, DialContext: (&net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}).DialContext}, FlushInterval: -1, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "download service unavailable", 502)
	}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := e.config()
		p := cfg.DownloadAccess
		if p == nil || r.TLS == nil || !strings.EqualFold(r.TLS.ServerName, p.Domain) || r.URL.Path == cfg.Path {
			fallback.ServeHTTP(w, r)
			return
		}
		host := r.Host
		if v, _, err := net.SplitHostPort(host); err == nil {
			host = v
		}
		if !strings.EqualFold(host, p.Domain) {
			http.Error(w, "host mismatch", 421)
			return
		}
		if !p.Enabled || !downloadAddressAllowed(r.RemoteAddr, p.Allowed) {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "access denied", 403)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "5")
			http.Error(w, "too many active requests", 429)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}
func (e *Engine) downloadCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, bool) {
	cfg := e.config()
	p := cfg.DownloadAccess
	if !cfg.DownloadBackendEnabled || p == nil || !strings.EqualFold(hello.ServerName, p.Domain) {
		return nil, false
	}
	current := e.publicCert.Load()
	if current == nil || current.Leaf == nil || current.Leaf.VerifyHostname(p.Domain) != nil {
		return nil, true
	}
	return current, true
}

func downloadPolicyChanged(a, b *DownloadAccessConfig) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) != string(y)
}

// A revoked identity must not resurrect its download whitelist from an offline cache.
func (e *Engine) persistRevokedDownloadPolicy() {
	raw, err := json.Marshal(e.config())
	if err != nil {
		return
	}
	const file = "/var/lib/chitanda-transit/runtime.json"
	if err = os.WriteFile(file+".tmp", raw, 0600); err == nil {
		if os.Rename(file+".tmp", file) == nil {
			return
		}
	}
	// Removing the old cache is safer than restoring a revoked permission on restart.
	_ = os.Remove(file)
}
