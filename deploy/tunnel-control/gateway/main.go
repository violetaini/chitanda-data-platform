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
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxBody = 16 << 20

type Endpoint struct {
	Sync           bool   `json:"sync,omitempty"`
	Listen         string `json:"listen"`
	Mode           string `json:"mode"`
	Token          string `json:"token"`
	Target         string `json:"target"`
	ConnectAddress string `json:"connectAddress,omitempty"`
	NextToken      string `json:"nextToken,omitempty"`
	Node           string `json:"node,omitempty"`
}
type Configuration struct {
	Endpoints []Endpoint `json:"endpoints"`
}

func allowedPath(r *http.Request, syncEnabled bool) bool {
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

func fixedTarget(ep Endpoint) (*url.URL, error) {
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
func newHandler(ep Endpoint) (http.Handler, error) {
	if len(ep.Token) < 32 {
		return nil, errors.New("endpoint token too short")
	}
	if ep.Mode != "origin" && ep.Mode != "forward" {
		return nil, errors.New("invalid endpoint mode")
	}
	target, err := fixedTarget(ep)
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
	slots := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+ep.Token)) != 1 {
			http.Error(w, "authentication required", 401)
			return
		}
		if !allowedPath(r, ep.Sync) {
			http.Error(w, "service not permitted", 403)
			return
		}
		if r.ContentLength > maxBody {
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
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
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
func main() {
	path := flag.String("config", "/etc/chitanda-data-test/config.json", "configuration file")
	flag.Parse()
	raw, err := os.ReadFile(*path)
	if err != nil {
		log.Fatal("configuration unavailable")
	}
	var cfg Configuration
	if json.Unmarshal(raw, &cfg) != nil || len(cfg.Endpoints) == 0 || len(cfg.Endpoints) > 4 {
		log.Fatal("invalid configuration")
	}
	var servers []*http.Server
	var listeners []net.Listener
	for _, ep := range cfg.Endpoints {
		host, _, err := net.SplitHostPort(ep.Listen)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() {
			log.Fatal("listener must be loopback")
		}
		handler, err := newHandler(ep)
		if err != nil {
			log.Fatal(err)
		}
		ln, err := net.Listen("tcp", ep.Listen)
		if err != nil {
			log.Fatal("listener unavailable")
		}
		servers = append(servers, &http.Server{Handler: handler, ReadHeaderTimeout: 8 * time.Second, ReadTimeout: 300 * time.Second, WriteTimeout: 300 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)})
		listeners = append(listeners, ln)
	}
	for i, s := range servers {
		go func(s *http.Server, ln net.Listener) {
			if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatal("listener stopped")
			}
		}(s, listeners[i])
	}
	log.Printf("data test gateway ready: %d loopback endpoints", len(servers))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var group sync.WaitGroup
	for _, s := range servers {
		group.Add(1)
		go func(s *http.Server) { defer group.Done(); s.Shutdown(ctx) }(s)
	}
	group.Wait()
}
