package main

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func headerTargetURL(r *http.Request) (*url.URL, error) {
	values := r.Header.Values("X-Target-URL")
	if len(values) != 1 || len(values[0]) > 4096 {
		return nil, errors.New("one X-Target-URL is required")
	}
	u, err := url.Parse(values[0])
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || net.ParseIP(u.Hostname()) != nil || u.User != nil || u.Fragment != "" || strings.ContainsAny(values[0], "\r\n\\") {
		return nil, errors.New("target must be an HTTPS business URL")
	}
	for _, p := range strings.Split(u.Path, "/") {
		if p == "." || p == ".." || strings.Contains(p, "%") || strings.Contains(p, "\\") {
			return nil, errors.New("non-canonical target path")
		}
	}
	raw := strings.ToLower(u.RawPath)
	if strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") {
		return nil, errors.New("encoded separator not permitted")
	}
	return u, nil
}
func newHeaderIngress(target *url.URL, access func() []TunnelAccess, port int) func(http.ResponseWriter, *http.Request) bool {
	slots := make(chan struct{}, 8)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 240 * time.Second, MaxConnsPerHost: 16}
	template := &httputil.ReverseProxy{Transport: transport, FlushInterval: -1, Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(target)
		p.Out.Host = p.In.Host
		for _, h := range []string{"X-Sync-Token", "Proxy-Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Node-ID", "X-CSRF-Token"} {
			p.Out.Header.Del(h)
		}
	}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) { http.Error(w, "channel unavailable", 502) }}
	return func(w http.ResponseWriter, r *http.Request) bool {
		if access == nil {
			return false
		}
		var matched *TunnelAccess
		for _, g := range access() {
			if g.HeaderURL && tunnelAccessAllowed(r, []TunnelAccess{g}, g.ListenPort) {
				v := g
				matched = &v
				break
			}
		}
		if matched == nil {
			return false
		}
		if !matched.HeaderURL {
			if r.Header.Get("X-Target-URL") != "" {
				http.Error(w, "URL access is not enabled", 403)
				return true
			}
			return false
		}
		if matched.Legacy && r.Header.Get("X-Target-URL") == "" {
			return false
		}
		if _, err := headerTargetURL(r); err != nil {
			http.Error(w, err.Error(), 400)
			return true
		}
		if r.Method == "CONNECT" || r.Method == "TRACE" || r.Header.Get("Upgrade") != "" || r.URL.IsAbs() {
			http.Error(w, "request not permitted", 403)
			return true
		}
		if r.ContentLength > 16<<20 {
			http.Error(w, "body too large", 413)
			return true
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", 429)
			return true
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
		selected, _ := url.Parse("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(matched.ListenPort)))
		proxy := *template
		proxy.Rewrite = func(p *httputil.ProxyRequest) {
			template.Rewrite(p)
			p.Out.URL.Scheme = selected.Scheme
			p.Out.URL.Host = selected.Host
		}
		proxy.ServeHTTP(w, r)
		return true
	}
}
func tunnelBearer(r *http.Request, token string) bool {
	return len(token) == 64 && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) == 1
}
