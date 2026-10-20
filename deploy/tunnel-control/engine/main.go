// Chitanda Transit: one small binary for relay and endpoint agents.
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/server"
)

const version = "2.10.0"

type Route struct {
	RelayIDs   []string `json:"relayIds,omitempty"`
	RelayID    string   `json:"relayId"`
	Transport  string   `json:"transport"`
	ServerName string   `json:"serverName"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	ListenPort int      `json:"listenPort"`
	TargetPort int      `json:"targetPort"`
	Enabled    bool     `json:"enabled"`
}
type Node struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}
type Relay struct {
	StreamPort  int    `json:"streamPort,omitempty"`
	BrokerToken string `json:"brokerToken,omitempty"`
	ID          string `json:"id"`
	CertPEM     string `json:"certPEM"`
	KeyPEM      string `json:"keyPEM"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	ServerName  string `json:"serverName"`
	Path        string `json:"path"`
	PSK         string `json:"psk"`
	CA          string `json:"ca"`
}
type Config struct {
	BusinessAccessFile string              `json:"businessAccessFile,omitempty"`
	TunnelAccess       []TunnelAccess      `json:"tunnelAccess"`
	HTTPSIngress       *HTTPSIngressConfig `json:"httpsIngress,omitempty"`
	HTTPSCertificate   *ManagedCertificate `json:"httpsCertificate,omitempty"`
	Checks             []RouteCheckTask    `json:"checks,omitempty"`
	DataGateway        *DataGatewayConfig  `json:"dataGateway,omitempty"`
	CredentialVersion  string              `json:"credentialVersion"`
	CA                 string              `json:"ca"`
	Relays             []Relay             `json:"relays"`
	SelfRelay          *Relay              `json:"selfRelay,omitempty"`
	Controller         string              `json:"controller"`
	ControllerAddress  string              `json:"controllerAddress"`
	ID                 string              `json:"id"`
	Token              string              `json:"token"`
	Role               string              `json:"role"`
	Revision           int                 `json:"revision"`
	Listen             string              `json:"listen"`
	Cert               string              `json:"cert"`
	Key                string              `json:"key"`
	PSK                string              `json:"psk"`
	Path               string              `json:"path"`
	Nodes              []Node              `json:"nodes"`
	Routes             []Route             `json:"routes"`
	Relay              Relay               `json:"relay"`
}
type Hello struct {
	Transport  string `json:"transport,omitempty"`
	ServerName string `json:"serverName,omitempty"`
	Kind       string `json:"kind"`
	Node       string `json:"node,omitempty"`
	Token      string `json:"token,omitempty"`
	Route      string `json:"route,omitempty"`
	OK         bool   `json:"ok,omitempty"`
	Error      string `json:"error,omitempty"`
}
type Engine struct {
	endpointMu       sync.Mutex
	endpointStop     chan struct{}
	endpointStopping bool
	syncMu           sync.Mutex
	checkMu          sync.Mutex
	checkBusy        bool
	checkResults     map[string]RouteCheckResult
	links            map[string]*Link
	cert             atomic.Pointer[tls.Certificate]
	publicCert       atomic.Pointer[tls.Certificate]
	serverTLS        atomic.Pointer[tls.Config]
	transports       []string
	connections      map[*slotConn]Hello
	mu               sync.RWMutex
	cfg              Config
	started          time.Time
	rx               atomic.Int64
	tx               atomic.Int64
	active           atomic.Int64
	connects         atomic.Int64
	latency          atomic.Int64
	lastError        string
	pools            map[string]chan net.Conn
	listeners        map[string]net.Listener
	listenerErrors   map[string]string
	listenerMu       sync.Mutex
	outbound         chan struct{}
	slots            chan struct{}
	brokerAddress    string
	clientMu         sync.Mutex
	cli              *client.Client
}

func safeEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func send(c net.Conn, v Hello) error {
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	e := json.NewEncoder(c).Encode(v)
	c.SetWriteDeadline(time.Time{})
	return e
}

// Read exactly one bounded JSON line; do not prefetch bytes from the following stream.
func receive(c net.Conn) (Hello, error) {
	var h Hello
	b := make([]byte, 0, 256)
	var one [1]byte
	for len(b) < 4096 {
		if _, e := io.ReadFull(c, one[:]); e != nil {
			return h, e
		}
		if one[0] == '\n' {
			return h, json.Unmarshal(b, &h)
		}
		b = append(b, one[0])
	}
	return h, errors.New("protocol header too large")
}
func (e *Engine) config() Config { e.mu.RLock(); defer e.mu.RUnlock(); return e.cfg }
func (e *Engine) err(err error) {
	if err != nil {
		e.mu.Lock()
		e.lastError = err.Error()
		e.mu.Unlock()
	}
}
func (e *Engine) report() map[string]any {
	ports := collectPorts()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memory := m.Sys
	if raw, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) > 1 {
			pages, _ := strconv.ParseUint(fields[1], 10, 64)
			memory = pages * uint64(os.Getpagesize())
		}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	ls := []string{}
	for id := range e.listeners {
		ls = append(ls, id)
	}
	listenerErrors := map[string]string{}
	for id, value := range e.listenerErrors {
		listenerErrors[id] = value
	}
	linkReports := map[string]any{}
	for key, l := range e.links {
		l.mu.RLock()
		linkReports[key] = map[string]any{"relayId": l.relay.ID, "transport": l.transport, "serverName": l.serverName, "connected": l.connected, "latency": float64(l.latency) / 1e6, "error": l.lastError}
		l.mu.RUnlock()
	}
	protocols := append([]string{}, e.transports...)
	if len(protocols) == 0 {
		seen := map[string]bool{}
		for _, l := range e.links {
			if !seen[l.transport] {
				seen[l.transport] = true
				protocols = append(protocols, l.transport)
			}
		}
	}
	return map[string]any{"ports": ports, "listenerErrors": listenerErrors, "routeChecks": e.checkReports(), "capabilities": map[string]any{"routeProbe": 1, "relayChain": 1, "directEndpoint": 1, "transports": protocols, "tlsServer": e.serverTLS.Load() != nil, "tlsClient": len(e.links) > 0}, "ingress": e.ingressReportLocked(), "tls": e.tlsReportLocked(), "version": version, "uptime": int64(time.Since(e.started).Seconds()), "memory": memory, "goroutines": runtime.NumGoroutine(), "rx": e.rx.Load(), "tx": e.tx.Load(), "active": e.active.Load(), "connections": e.connects.Load(), "latency": float64(e.latency.Load()) / 1e6, "revision": e.cfg.Revision, "errors": e.lastError, "listeners": ls, "links": linkReports}
}
func (e *Engine) syncConfig() error {
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	cfg := e.config()
	raw, _ := json.Marshal(e.report())
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(cfg.Controller, "/")+"/transit-node/sync", strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("X-Node-ID", cfg.ID)
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if cfg.ControllerAddress != "" {
			address = cfg.ControllerAddress
		}
		return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		if resp.StatusCode == 401 {
			e.revoke()
		}
		return fmt.Errorf("controller returned %d", resp.StatusCode)
	}
	var update Config
	if err = json.NewDecoder(io.LimitReader(resp.Body, 131072)).Decode(&update); err != nil {
		return err
	}
	if update.SelfRelay != nil {
		certificate, err := tls.X509KeyPair([]byte(update.SelfRelay.CertPEM), []byte(update.SelfRelay.KeyPEM))
		if err != nil {
			return fmt.Errorf("relay certificate invalid: %w", err)
		}
		e.cert.Store(&certificate)
	}
	if err := e.applyHTTPSCertificate(update.HTTPSCertificate); err != nil {
		return fmt.Errorf("HTTPS certificate update failed: %w", err)
	}
	if err := writeTunnelAccess(cfg.BusinessAccessFile, update.TunnelAccess); err != nil {
		return fmt.Errorf("business access update failed: %w", err)
	}
	e.mu.Lock()
	e.cfg.TunnelAccess = update.TunnelAccess
	e.cfg.HTTPSCertificate = update.HTTPSCertificate
	e.cfg.CredentialVersion = update.CredentialVersion
	e.cfg.CA = update.CA
	e.cfg.Relays = update.Relays
	e.cfg.SelfRelay = update.SelfRelay
	if update.SelfRelay != nil {
		e.cfg.PSK = update.SelfRelay.PSK
		e.cfg.Path = update.SelfRelay.Path
		if e.cfg.Listen == "" || cfg.Role == "agent" {
			e.cfg.Listen = fmt.Sprintf(":%d", update.SelfRelay.Port)
		}
	}
	e.cfg.Revision = update.Revision
	e.cfg.Nodes = update.Nodes
	e.cfg.Routes = update.Routes
	if update.Relay.Host != "" {
		e.cfg.Relay = update.Relay
	}
	e.mu.Unlock()
	if cfg.Revision != update.Revision || cfg.CredentialVersion != update.CredentialVersion || !slices.Equal(cfg.TunnelAccess, update.TunnelAccess) {
		runtimeCfg, _ := json.Marshal(e.config())
		if err := os.WriteFile("/var/lib/chitanda-transit/runtime.json.tmp", runtimeCfg, 0600); err == nil {
			os.Rename("/var/lib/chitanda-transit/runtime.json.tmp", "/var/lib/chitanda-transit/runtime.json")
		}
	}
	if cfg.Role == "agent" {
		e.reconcileLinks()
		e.reconcileListeners()
	} else {
		e.pruneRevoked()
		e.reconcileLinks()
		e.reconcileListeners()
	}
	e.pruneRevoked()
	e.reconcileEndpointServer()
	e.startChecks(update.Checks)
	return nil
}
func (e *Engine) controlLoop() {
	for {
		err := e.syncConfig()
		if err != nil {
			log.Printf("control: %v", err)
			// Keep existing data paths recoverable even while control is unreachable.
			e.reconcileLinks()
			e.reconcileListeners()
			e.reconcileEndpointServer()
		}
		time.Sleep(15 * time.Second)
	}
}

type countedWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (w countedWriter) Write(b []byte) (int, error) {
	n, err := w.w.Write(b)
	w.n.Add(int64(n))
	return n, err
}
func halfClose(c net.Conn) {
	if h, ok := c.(interface{ CloseWrite() error }); ok {
		h.CloseWrite()
	}
}
func (e *Engine) bridge(a, b net.Conn) {
	e.active.Add(1)
	defer e.active.Add(-1)
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn, n *atomic.Int64) {
		buf := make([]byte, 32*1024)
		io.CopyBuffer(countedWriter{dst, n}, src, buf)
		halfClose(dst)
		done <- struct{}{}
	}
	go copyOne(b, a, &e.rx)
	go copyOne(a, b, &e.tx)
	<-done
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
}
func (e *Engine) nodeAllowed(id, token string) bool {
	for _, n := range e.config().Nodes {
		if n.ID == id && safeEqual(n.Token, token) {
			return true
		}
	}
	return false
}
func (e *Engine) pool(id string) chan net.Conn {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.pools[id]
	if p == nil {
		p = make(chan net.Conn, 4)
		e.pools[id] = p
	}
	return p
}
func (e *Engine) handleBroker(c net.Conn) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	h, err := receive(c)
	if err != nil || !e.nodeAllowed(h.Node, h.Token) {
		return
	}
	e.mu.Lock()
	if e.connections == nil {
		e.connections = map[*slotConn]Hello{}
	}
	if s, ok := c.(*slotConn); ok {
		e.connections[s] = h
		defer func() { e.mu.Lock(); delete(e.connections, s); e.mu.Unlock() }()
	}
	e.mu.Unlock()
	c.SetReadDeadline(time.Time{})
	if h.Kind == "ping" {
		send(c, Hello{OK: true})
		return
	}
	if h.Kind == "accept" {
		p := e.pool(h.Node + "|" + h.Transport + "|" + h.ServerName)
		owned := c.(*slotConn)
		select {
		case p <- c:
		case <-time.After(time.Second):
			return
		}
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-owned.taken:
				<-owned.done
				return
			case <-ticker.C:
				owned.writeMu.Lock()
				select {
				case <-owned.taken:
					owned.writeMu.Unlock()
					continue
				default:
				}
				err := send(owned.Conn, Hello{Kind: "keepalive"})
				owned.writeMu.Unlock()
				if err != nil {
					return
				}
			}
		}
	}
	if h.Kind != "dial" && h.Kind != "probe" {
		return
	}
	var route *Route
	cfg := e.config()
	for _, r := range cfg.Routes {
		if r.ID == h.Route && r.Enabled && r.brokerSource(cfg.ID) == h.Node && r.Transport == h.Transport && r.ServerName == h.ServerName {
			copy := r
			route = &copy
			break
		}
	}
	if route == nil {
		send(c, Hello{Error: "route not permitted"})
		return
	}
	// Only the configured next relay is addressable; clients cannot supply a host or hop.
	if next := route.nextRelay(cfg.ID); next != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		cli, hello, dialErr := e.forwardClient(*route, next, h.Kind)
		if dialErr != nil {
			send(c, Hello{Error: "channel unavailable"})
			return
		}
		dest, dialErr := e.dialContext(ctx, cli, hello)
		if dialErr != nil {
			send(c, Hello{Error: "channel unavailable"})
			return
		}
		defer dest.Close()
		dest.SetReadDeadline(time.Now().Add(12 * time.Second))
		ack, readErr := receive(dest)
		dest.SetReadDeadline(time.Time{})
		if readErr != nil {
			send(c, Hello{Error: "channel unavailable"})
			return
		}
		if !ack.OK {
			send(c, Hello{Error: ack.Error})
			return
		}
		if send(c, Hello{OK: true}) != nil || h.Kind == "probe" {
			return
		}
		e.connects.Add(1)
		e.bridge(c, dest)
		return
	}
	// A relay may also be the endpoint. The service remains a fixed local port.
	if route.Target == cfg.ID {
		if route.TargetPort < 1 || route.TargetPort > 65535 || route.TargetPort == 5092 {
			send(c, Hello{Error: "service not permitted"})
			return
		}
		dest, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(route.TargetPort)), 8*time.Second)
		if dialErr != nil {
			send(c, Hello{Error: "target service unavailable"})
			return
		}
		defer dest.Close()
		if send(c, Hello{OK: true}) != nil {
			return
		}
		if h.Kind == "probe" {
			return
		}
		e.connects.Add(1)
		e.bridge(c, dest)
		return
	}
	p := e.pool(route.Target + "|" + route.Transport + "|" + route.ServerName)
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case dest := <-p:
			s, ok := dest.(*slotConn)
			if !ok {
				dest.Close()
				continue
			}
			select {
			case <-s.closed:
				continue
			default:
			}
			close(s.taken)
			e.mu.Lock()
			metadata := e.connections[s]
			metadata.Route = route.ID
			e.connections[s] = metadata
			e.mu.Unlock()
			s.writeMu.Lock()
			kind := "open"
			if h.Kind == "probe" {
				kind = "probe"
			}
			err = send(s.Conn, Hello{Kind: kind, Route: route.ID})
			s.writeMu.Unlock()
			if err != nil {
				close(s.done)
				s.Close()
				continue
			}
			s.SetReadDeadline(time.Now().Add(10 * time.Second))
			ack, readErr := receive(s)
			s.SetReadDeadline(time.Time{})
			if readErr != nil || !ack.OK {
				close(s.done)
				s.Close()
				send(c, Hello{Error: "target service unavailable"})
				return
			}
			if err = send(c, Hello{OK: true}); err != nil {
				close(s.done)
				s.Close()
				return
			}
			if h.Kind == "probe" {
				send(s, Hello{Kind: "probe-received"})
				close(s.done)
				s.Close()
				return
			}
			e.connects.Add(1)
			e.bridge(c, s)
			close(s.done)
			return
		case <-timer.C:
			send(c, Hello{Error: "target node is offline or busy"})
			return
		}
	}
}

type slotConn struct {
	net.Conn
	taken   chan struct{}
	done    chan struct{}
	closed  chan struct{}
	once    sync.Once
	writeMu sync.Mutex
}

func (s *slotConn) Close() error { s.once.Do(func() { close(s.closed) }); return s.Conn.Close() }
func (s *slotConn) CloseWrite() error {
	if c, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return nil
}
func (e *Engine) localBrokerAddress() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.brokerAddress
}
func (e *Engine) brokerConnection(ctx context.Context, address string) (net.Conn, error) {
	if address != "bridge.internal:1" {
		return nil, errors.New("target denied")
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", e.localBrokerAddress())
}
func (e *Engine) serveBroker(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case e.slots <- struct{}{}:
			s := &slotConn{Conn: c, taken: make(chan struct{}), done: make(chan struct{}), closed: make(chan struct{})}
			go func() { defer func() { <-e.slots }(); e.handleBroker(s) }()
		default:
			c.Close()
		}
	}
}
func (e *Engine) runRelay() error { return e.runRelayUntil(nil) }
func (e *Engine) runRelayUntil(stop <-chan struct{}) error {
	cfg := e.config()
	psk, err := base64.StdEncoding.DecodeString(cfg.PSK)
	if err != nil || len(psk) < 32 {
		return errors.New("invalid relay PSK")
	}
	replays, err := auth.OpenReplayCache("/var/lib/chitanda-transit/replay.db", time.Now())
	if err != nil {
		return err
	}
	defer replays.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	e.mu.Lock()
	e.brokerAddress = ln.Addr().String()
	e.mu.Unlock()
	go e.serveBroker(ln)
	protocolHandler := server.NewServer(cfg.Path, psk, replays, http.NotFoundHandler(), 0)
	protocolHandler.SetDialTargetForTest(e.brokerConnection)
	app, publicCertificate, err := e.dataGatewayHandler(protocolHandler)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if publicCertificate != nil && hello.ServerName == cfg.DataGateway.Domain {
			if current := e.publicCert.Load(); current != nil {
				return current, nil
			}
			return publicCertificate, nil
		}
		c := e.cert.Load()
		if c == nil {
			return nil, errors.New("certificate not available")
		}
		if hello.ServerName == "" || c.Leaf == nil || c.Leaf.VerifyHostname(hello.ServerName) != nil {
			return nil, errors.New("SNI does not match managed certificate")
		}
		return c, nil
	}}
	e.mu.Lock()
	e.transports = []string{"h2", "h3"}
	e.mu.Unlock()
	e.serverTLS.Store(tlsConfig)
	defer func() { e.serverTLS.Store(nil); e.mu.Lock(); e.transports = nil; e.mu.Unlock() }()
	if publicCertificate != nil {
		e.publicCert.Store(publicCertificate)
	}

	srv := &http.Server{Addr: cfg.Listen, Handler: app, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, TLSConfig: tlsConfig.Clone()}
	h3 := server.NewHTTP3Server(app, tlsConfig.Clone(), 1252)
	h3.Addr = cfg.Listen
	h3.QUICConfig.MaxIncomingStreams = 96
	h3.QUICConfig.InitialStreamReceiveWindow = 128 << 10
	h3.QUICConfig.MaxStreamReceiveWindow = 512 << 10
	h3.QUICConfig.InitialConnectionReceiveWindow = 512 << 10
	h3.QUICConfig.MaxConnectionReceiveWindow = 2 << 20
	h3.QUICConfig.Allow0RTT = false
	errCh := make(chan error, 3)
	streamPort := 11323
	if cfg.SelfRelay != nil && cfg.SelfRelay.StreamPort > 0 {
		streamPort = cfg.SelfRelay.StreamPort
	}
	streamListener, err := net.Listen("tcp", fmt.Sprintf(":%d", streamPort))
	if err != nil {
		return err
	}
	defer streamListener.Close()
	stream := server.NewStreamServer(psk, cfg.ID, replays, func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("TCP only")
		}
		return e.brokerConnection(ctx, address)
	})
	stream.SetMaxConns(96)
	stream.SetHandshakeLimit(16)
	defer stream.Close()
	e.mu.Lock()
	e.transports = append(e.transports, "stream")
	e.mu.Unlock()
	go func() { errCh <- stream.Serve(streamListener) }()
	go func() { errCh <- h3.ListenAndServe() }()
	go func() { errCh <- srv.ListenAndServeTLS("", "") }()
	e.reconcileLinks()
	e.reconcileListeners()
	log.Printf("relay listening %s (H2 TCP + H3 UDP / TLS 1.3)", cfg.Listen)
	select {
	case err = <-errCh:
	case <-stop:
		err = nil
	}
	h3.Close()
	srv.Close()
	return err
}
func (e *Engine) dial(cli *client.Client, h Hello) (net.Conn, error) {
	if len(h.Token) < 32 {
		return nil, errors.New("broker credential missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return e.dialContext(ctx, cli, h)
}
func (e *Engine) dialContext(ctx context.Context, cli *client.Client, h Hello) (net.Conn, error) {
	if len(h.Token) < 32 {
		return nil, errors.New("broker credential missing")
	}
	c, err := cli.DialContext(ctx, "tcp", "bridge.internal:1")
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	cfg := e.config()
	h.Node = cfg.ID
	if err = send(c, h); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
func (e *Engine) reconcileListeners() {
	e.listenerMu.Lock()
	defer e.listenerMu.Unlock()
	cfg := e.config()
	desired := map[string]Route{}
	for _, r := range cfg.Routes {
		if r.Enabled && r.Source == cfg.ID {
			desired[r.ID] = r
		}
	}
	e.mu.Lock()
	for id, ln := range e.listeners {
		r, ok := desired[id]
		if !ok || ln.Addr().String() != net.JoinHostPort("127.0.0.1", fmt.Sprint(r.ListenPort)) {
			ln.Close()
			delete(e.listeners, id)
		}
	}
	e.mu.Unlock()
	e.mu.Lock()
	if e.listenerErrors == nil {
		e.listenerErrors = map[string]string{}
	}
	for id := range e.listenerErrors {
		if _, ok := desired[id]; !ok {
			delete(e.listenerErrors, id)
		}
	}
	e.mu.Unlock()
	for id, r := range desired {
		e.mu.RLock()
		_, ok := e.listeners[id]
		e.mu.RUnlock()
		if ok {
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(r.ListenPort)))
		if err != nil {
			e.err(err)
			e.mu.Lock()
			if strings.Contains(strings.ToLower(err.Error()), "address already in use") {
				e.listenerErrors[id] = "port-in-use"
			} else {
				e.listenerErrors[id] = "listen-failed"
			}
			e.mu.Unlock()
			continue
		}
		e.mu.Lock()
		delete(e.listenerErrors, id)
		e.listeners[id] = ln
		e.mu.Unlock()
		go e.serveListener(ln, r.ID)
	}
}
func (e *Engine) serveListener(ln net.Listener, id string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case e.outbound <- struct{}{}:
			go func() {
				defer func() { <-e.outbound }()
				defer c.Close()
				peer, err := e.openRoute(id)
				if err != nil {
					e.err(err)
					return
				}
				defer peer.Close()
				peer.SetReadDeadline(time.Now().Add(15 * time.Second))
				h, err := receive(peer)
				peer.SetReadDeadline(time.Time{})
				if err != nil || !h.OK {
					if err == nil {
						err = errors.New(h.Error)
					}
					e.err(err)
					return
				}
				e.connects.Add(1)
				e.bridge(c, peer)
			}()
		default:
			c.Close()
		}
	}
}
func compatibleCache(current, cached Config) bool {
	return cached.CA != "" && cached.ID == current.ID && cached.Token == current.Token && cached.Controller == current.Controller && cached.CredentialVersion == current.CredentialVersion && cached.Revision >= current.Revision
}
func main() {
	cfgPath := flag.String("config", "/etc/chitanda-transit/config.json", "configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	var cfg Config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		log.Fatal(err)
	}
	if cfg.ID == "" || len(cfg.Token) < 32 || !strings.HasPrefix(cfg.Controller, "https://") {
		log.Fatal("invalid node configuration")
	}
	rootCA := cfg.CA
	if rootCA == "" {
		rootCA = cfg.Relay.CA
	}
	if rootCA != "" {
		caPath := "/var/lib/chitanda-transit/relay-ca.pem"
		if err := os.WriteFile(caPath, []byte(rootCA), 0600); err != nil {
			log.Fatal(err)
		}
		os.Setenv("SSL_CERT_FILE", caPath)
	}
	if raw, err := os.ReadFile("/var/lib/chitanda-transit/runtime.json"); err == nil {
		var cached Config
		if json.Unmarshal(raw, &cached) == nil && compatibleCache(cfg, cached) {
			gateway, ingress, accessFile := cfg.DataGateway, cfg.HTTPSIngress, cfg.BusinessAccessFile
			cfg = cached
			cfg.DataGateway, cfg.HTTPSIngress, cfg.BusinessAccessFile = gateway, ingress, accessFile
		}
	}
	e := &Engine{cfg: cfg, started: time.Now(), pools: map[string]chan net.Conn{}, listeners: map[string]net.Listener{}, outbound: make(chan struct{}, 32), slots: make(chan struct{}, 96), links: map[string]*Link{}, connections: map[*slotConn]Hello{}}
	if err := e.applyHTTPSCertificate(cfg.HTTPSCertificate); err != nil {
		log.Fatal(err)
	}
	if cfg.SelfRelay != nil {
		certificate, err := tls.X509KeyPair([]byte(cfg.SelfRelay.CertPEM), []byte(cfg.SelfRelay.KeyPEM))
		if err == nil {
			e.cert.Store(&certificate)
		}
	}
	if cfg.Role == "relay" {
		if err = e.syncConfig(); err != nil {
			if len(cfg.Nodes) == 0 {
				log.Fatal(err)
			}
			log.Printf("control unavailable, using persisted configuration: %v", err)
		}
		go e.controlLoop()
		err = e.runRelay()
	} else {
		err = e.runMultiAgent()
	}
	if err != nil {
		log.Fatal(err)
	}
}
