package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/violetaini/chitanda/pkg/client"
	"net"
	"sync"
	"time"
)

type Link struct {
	mu             sync.RWMutex
	relay          Relay
	transport      string
	serverName     string
	signature      string
	client         *client.Client
	ctx            context.Context
	cancel         context.CancelFunc
	connected      bool
	latency        int64
	lastError      string
	tlsObservation *TLSInfo
}

func routeKey(r Route) string { return r.RelayID + "|" + r.Transport + "|" + r.ServerName }
func (e *Engine) reconcileLinks() {
	cfg := e.config()
	desired := map[string]Route{}
	for _, r := range cfg.Routes {
		if r.Enabled && (r.Source == cfg.ID || r.Target == cfg.ID) {
			desired[routeKey(r)] = r
		}
	}
	relays := map[string]Relay{}
	for _, r := range cfg.Relays {
		relays[r.ID] = r
	}
	e.mu.Lock()
	if e.links == nil {
		e.links = map[string]*Link{}
	}
	e.mu.Unlock()
	for key, r := range desired {
		relay, ok := relays[r.RelayID]
		if !ok || relay.Host == "" {
			continue
		}
		raw, _ := json.Marshal(relay)
		signature := string(raw) + r.Transport + r.ServerName
		e.mu.RLock()
		existing := e.links[key]
		e.mu.RUnlock()
		if existing != nil && existing.signature == signature {
			continue
		}
		psk, err := base64.StdEncoding.DecodeString(relay.PSK)
		if err != nil {
			e.err(err)
			continue
		}
		port := relay.Port
		if r.Transport == "stream" {
			port = relay.StreamPort
			if port == 0 {
				port = 11323
			}
		}
		l := &Link{relay: relay, transport: r.Transport, serverName: r.ServerName, signature: signature}
		cli, err := client.New(client.Config{Server: net.JoinHostPort(relay.Host, fmt.Sprint(port)), ServerID: relay.ID, ServerName: r.ServerName, Path: relay.Path, PSK: psk, TCPTransport: r.Transport, TCPPoolSize: 1, UDPPoolSize: 1, QUICInitialPacketSize: 1252, TLSObserver: l.observeTLS})
		if err != nil {
			e.err(err)
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		l.client, l.ctx, l.cancel = cli, ctx, cancel
		e.mu.Lock()
		old := e.links[key]
		e.links[key] = l
		e.mu.Unlock()
		if old != nil {
			old.cancel()
			old.client.Close()
		}
		for i := 0; i < 2; i++ {
			go e.acceptOnLink(l)
		}
		go e.pingLink(l)
	}
	e.mu.Lock()
	removed := []*Link{}
	for key, l := range e.links {
		if _, ok := desired[key]; !ok {
			delete(e.links, key)
			removed = append(removed, l)
		} else if _, ok := relays[l.relay.ID]; !ok {
			delete(e.links, key)
			removed = append(removed, l)
		}
	}
	e.mu.Unlock()
	for _, l := range removed {
		l.cancel()
		l.client.Close()
	}
}
func linkDelay(l *Link, d time.Duration) bool {
	select {
	case <-l.ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
func (e *Engine) acceptOnLink(l *Link) {
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}
		c, err := e.dial(l.client, Hello{Kind: "accept", Token: l.relay.BrokerToken, Transport: l.transport, ServerName: l.serverName})
		if err != nil {
			if !linkDelay(l, 3*time.Second) {
				return
			}
			continue
		}
		for {
			c.SetReadDeadline(time.Now().Add(45 * time.Second))
			h, err := receive(c)
			if err != nil {
				c.Close()
				break
			}
			if h.Kind == "keepalive" {
				continue
			}
			if h.Kind != "open" && h.Kind != "probe" {
				c.Close()
				break
			}
			c.SetReadDeadline(time.Time{})
			cfg := e.config()
			var route *Route
			for _, r := range cfg.Routes {
				if r.ID == h.Route && r.Target == cfg.ID && r.Enabled && r.RelayID == l.relay.ID && r.Transport == l.transport && r.ServerName == l.serverName {
					copy := r
					route = &copy
					break
				}
			}
			if route == nil || route.TargetPort == 5092 {
				send(c, Hello{Error: "service not permitted"})
				c.Close()
				break
			}
			dest, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(route.TargetPort)), 8*time.Second)
			if err != nil {
				send(c, Hello{Error: "service unavailable"})
				c.Close()
				break
			}
			if send(c, Hello{OK: true}) != nil {
				dest.Close()
				c.Close()
				break
			}
			if h.Kind == "probe" {
				dest.Close()
				// Keep QUIC's client stream alive until the broker consumed OK.
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				receive(c)
				c.Close()
				break
			}
			e.connects.Add(1)
			e.bridge(c, dest)
			break
		}
		if !linkDelay(l, 100*time.Millisecond) {
			return
		}
	}
}
func (e *Engine) pingLink(l *Link) {
	for {
		start := time.Now()
		c, err := e.dial(l.client, Hello{Kind: "ping", Token: l.relay.BrokerToken, Transport: l.transport, ServerName: l.serverName})
		if err == nil {
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			var h Hello
			h, err = receive(c)
			c.Close()
			if err == nil && !h.OK {
				err = errors.New("relay probe rejected")
			}
		}
		l.mu.Lock()
		l.connected = err == nil
		if err == nil {
			l.latency = time.Since(start).Nanoseconds()
			l.lastError = ""
		} else {
			l.latency = 0
			l.lastError = err.Error()
		}
		l.mu.Unlock()
		if !linkDelay(l, 15*time.Second) {
			return
		}
	}
}
func (e *Engine) routeClient(id string) (*client.Client, Hello, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, r := range e.cfg.Routes {
		if r.ID == id && r.Enabled && r.Source == e.cfg.ID {
			l := e.links[routeKey(r)]
			if l == nil {
				return nil, Hello{}, errors.New("configured relay link is not available")
			}
			return l.client, Hello{Kind: "dial", Token: l.relay.BrokerToken, Route: id, Transport: r.Transport, ServerName: r.ServerName}, nil
		}
	}
	return nil, Hello{}, errors.New("route disabled or removed")
}

// The optimized endpoint uses the in-process broker and existing reverse pool.
// It never creates a second tunnel identity or a second public service process.
func (e *Engine) openRoute(id string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return e.openRouteContext(ctx, id, "dial")
}
func (e *Engine) openRouteContext(ctx context.Context, id, kind string) (net.Conn, error) {
	if kind != "dial" && kind != "probe" {
		return nil, errors.New("unsupported route operation")
	}
	cfg := e.config()
	if cfg.Role != "relay" {
		cli, hello, err := e.routeClient(id)
		if err != nil {
			return nil, err
		}
		hello.Kind = kind
		return e.dialContext(ctx, cli, hello)
	}
	var token string
	for _, n := range cfg.Nodes {
		if n.ID == cfg.ID {
			token = n.Token
		}
	}
	if len(token) < 32 {
		return nil, errors.New("local broker credential missing")
	}
	for _, r := range cfg.Routes {
		if r.ID != id || !r.Enabled || r.Source != cfg.ID || r.RelayID != cfg.ID {
			continue
		}
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", e.brokerAddress)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { c.Close() })
		err = send(c, Hello{Kind: kind, Node: cfg.ID, Token: token, Route: id, Transport: r.Transport, ServerName: r.ServerName})
		stop()
		if err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	return nil, errors.New("local route disabled or removed")
}
func (e *Engine) runMultiAgent() error {
	for {
		if err := e.syncConfig(); err != nil {
			e.err(err)
			if len(e.config().Relays) > 0 {
				e.reconcileLinks()
				e.reconcileListeners()
				break
			}
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}
	e.controlLoop()
	return nil
}
func (e *Engine) revoke() {
	e.mu.Lock()
	links := e.links
	e.links = map[string]*Link{}
	for _, ln := range e.listeners {
		ln.Close()
	}
	e.listeners = map[string]net.Listener{}
	e.cfg.Nodes = nil
	e.cfg.Routes = nil
	e.cfg.Relays = nil
	for c := range e.connections {
		c.Close()
	}
	e.lastError = "node credentials revoked"
	e.mu.Unlock()
	for _, l := range links {
		l.cancel()
		l.client.Close()
	}
}
func (e *Engine) pruneRevoked() {
	e.mu.Lock()
	defer e.mu.Unlock()
	valid := map[string]string{}
	for _, n := range e.cfg.Nodes {
		valid[n.ID] = n.Token
	}
	routes := map[string]Route{}
	for _, r := range e.cfg.Routes {
		if r.Enabled {
			routes[r.ID] = r
		}
	}
	for c, h := range e.connections {
		if !safeEqual(valid[h.Node], h.Token) {
			c.Close()
			continue
		}
		if h.Route != "" {
			r, ok := routes[h.Route]
			if !ok || r.Transport != h.Transport || r.ServerName != h.ServerName {
				c.Close()
			}
		}
	}
	for key, p := range e.pools {
		keep := false
		for _, r := range e.cfg.Routes {
			if r.Enabled && key == r.Target+"|"+r.Transport+"|"+r.ServerName {
				keep = true
				break
			}
		}
		if !keep {
			delete(e.pools, key)
			for len(p) > 0 {
				(<-p).Close()
			}
		}
	}
}
