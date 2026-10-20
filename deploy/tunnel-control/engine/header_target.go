package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HTTPDestination struct {
	BaseURL        string `json:"baseURL"`
	ConnectAddress string `json:"connectAddress"`
}
type HTTPRouteAccess struct {
	Token   string            `json:"token"`
	Legacy  bool              `json:"legacy"`
	Targets []HTTPDestination `json:"targets"`
}

func selectHTTPDestination(u *url.URL, targets []HTTPDestination) (HTTPDestination, bool) {
	for _, t := range targets {
		base, err := url.Parse(t.BaseURL)
		if err != nil || base.Scheme != "https" {
			continue
		}
		port := func(u *url.URL) string {
			if u.Port() == "" {
				return "443"
			}
			return u.Port()
		}
		prefix := strings.TrimSuffix(base.Path, "/")
		if strings.EqualFold(base.Hostname(), u.Hostname()) && port(base) == port(u) && (prefix == "" || u.Path == prefix || strings.HasPrefix(u.Path, prefix+"/")) {
			return t, true
		}
	}
	return HTTPDestination{}, false
}
func publicDestination(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32", "64:ff9b::/96", "2002::/16"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}
func secureHTTPTransport(destination HTTPDestination) *http.Transport {
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, DisableKeepAlives: true, ResponseHeaderTimeout: 240 * time.Second, TLSHandshakeTimeout: 8 * time.Second, MaxConnsPerHost: 8}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if destination.ConnectAddress != "" {
			address = destination.ConnectAddress
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("no business address")
		}
		for _, ip := range ips {
			if !publicDestination(ip) {
				return nil, errors.New("business address not public")
			}
		}
		var last error
		for _, ip := range ips {
			c, err := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}
	return tr
}
func newHeaderTargetHandler(policy func() *HTTPRouteAccess, legacyPort int, factory func(HTTPDestination) *http.Transport) http.Handler {
	if factory == nil {
		factory = secureHTTPTransport
	}
	slots := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		p := policy()
		if p == nil {
			http.Error(w, "URL access disabled", 403)
			return
		}
		if p.Legacy && r.Header.Get("X-Target-URL") == "" {
			target, _ := url.Parse("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(legacyPort)))
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.ServeHTTP(w, r)
			return
		}
		if !tunnelBearer(r, p.Token) {
			http.Error(w, "authentication required", 401)
			return
		}
		u, err := headerTargetURL(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		destination, ok := selectHTTPDestination(u, p.Targets)
		if !ok {
			http.Error(w, "business target not permitted", 403)
			return
		}
		if r.Method == "CONNECT" || r.Method == "TRACE" || r.Header.Get("Upgrade") != "" {
			http.Error(w, "request not permitted", 403)
			return
		}
		if r.ContentLength > 16<<20 {
			http.Error(w, "body too large", 413)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", 429)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
		tr := factory(destination)
		defer tr.CloseIdleConnections()
		proxy := &httputil.ReverseProxy{Transport: tr, FlushInterval: -1, Rewrite: func(pr *httputil.ProxyRequest) {
			*pr.Out.URL = *u
			pr.Out.Host = u.Host
			pr.Out.RequestURI = ""
			if auth := pr.In.Header.Get("X-Target-Authorization"); auth != "" {
				pr.Out.Header.Set("Authorization", auth)
			}
			pr.Out.Header.Del("X-Target-Authorization")
			for _, h := range []string{"X-Target-URL", "X-Sync-Token", "Proxy-Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Node-ID", "X-CSRF-Token"} {
				pr.Out.Header.Del(h)
			}
		}, ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.StatusCode != http.StatusNotModified {
				return errors.New("business redirects are not followed")
			}
			resp.Header.Del("Set-Cookie")
			resp.Header.Set("Cache-Control", "no-store")
			return nil
		}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) { http.Error(w, "business unavailable", 502) }}
		proxy.ServeHTTP(w, r)
	})
}

type oneHTTPConn struct {
	engine *Engine
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *oneHTTPConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.engine != nil {
		c.engine.rx.Add(int64(n))
	}
	return n, err
}
func (c *oneHTTPConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if c.engine != nil {
		c.engine.tx.Add(int64(n))
	}
	return n, err
}
func (c *oneHTTPConn) Close() error {
	c.once.Do(func() {
		// Framed H2/H3 writes must finish before Close cancels the underlying request.
		// The peer closes after consuming the HTTP response, which completes the drain.
		if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
			_ = c.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_ = half.CloseWrite()
			_ = c.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			_, _ = io.Copy(io.Discard, c.Conn)
		}
		_ = c.Conn.Close()
		close(c.done)
	})
	return nil
}

type oneHTTPListener struct {
	c        *oneHTTPConn
	accepted bool
}

func (l *oneHTTPListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.c, nil
	}
	<-l.c.done
	return nil, net.ErrClosed
}
func (l *oneHTTPListener) Close() error   { return l.c.Close() }
func (l *oneHTTPListener) Addr() net.Addr { return l.c.LocalAddr() }
func (e *Engine) serveHeaderHTTP(c net.Conn, routeID string) {
	policy := func() *HTTPRouteAccess {
		for _, r := range e.config().Routes {
			if r.ID == routeID && r.Enabled && r.Target == e.config().ID {
				return r.HTTPAccess
			}
		}
		return nil
	}
	port := 0
	for _, r := range e.config().Routes {
		if r.ID == routeID {
			port = r.TargetPort
		}
	}
	e.active.Add(1)
	e.connects.Add(1)
	defer e.active.Add(-1)
	wrapped := &oneHTTPConn{engine: e, Conn: c, done: make(chan struct{})}
	server := &http.Server{Handler: newHeaderTargetHandler(policy, port, e.httpTransport), ReadHeaderTimeout: 8 * time.Second, ReadTimeout: 300 * time.Second, WriteTimeout: 300 * time.Second, MaxHeaderBytes: 16 << 10}
	server.SetKeepAlivesEnabled(false)
	_ = server.Serve(&oneHTTPListener{c: wrapped})
}
