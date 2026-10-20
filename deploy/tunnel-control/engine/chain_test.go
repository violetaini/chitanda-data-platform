package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/server"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Two independent real protocol listeners, not a mocked forwarding function.
func exerciseRealRelayChain(t *testing.T, protocol string, certificate tls.Certificate, localTarget ...bool) {
	t.Helper()
	psk := []byte(strings.Repeat("m", 32))
	name := "custom.chitanda.net"
	if protocol == "stream" {
		name = ""
	}
	a, b := testEngine(t), testEngine(t)
	a.cfg.ID = "hop-a"
	b.cfg.ID = "hop-b"
	forward := Route{ID: "chain-forward", Source: "cn", Target: "intl", RelayID: "hop-a", RelayIDs: []string{"hop-a", "hop-b"}, Transport: protocol, ServerName: name, Enabled: true}
	reverse := forward
	reverse.ID = "chain-reverse"
	reverse.Source = "intl"
	reverse.Target = "cn"
	reverse.RelayID = "hop-b"
	reverse.RelayIDs = []string{"hop-b", "hop-a"}
	a.cfg.Routes = []Route{forward, reverse}
	b.cfg.Routes = []Route{forward, reverse}
	token := strings.Repeat("a", 64)
	a.cfg.Nodes = []Node{{ID: "cn", Token: token}, {ID: "hop-b", Token: token}}
	b.cfg.Nodes = []Node{{ID: "intl", Token: token}, {ID: "hop-a", Token: token}}
	start := func(e *Engine) Relay {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
		path := "/chain-test"
		if protocol == "stream" {
			srv := server.NewStreamServer(psk, e.cfg.ID, auth.NewReplayCache(), func(ctx context.Context, network, address string) (net.Conn, error) {
				return e.brokerConnection(ctx, address)
			})
			go srv.Serve(ln)
			t.Cleanup(func() { srv.Close(); ln.Close() })
		} else {
			app := server.NewServer(path, psk, auth.NewReplayCache(), http.NotFoundHandler(), 0)
			app.SetDialTargetForTest(e.brokerConnection)
			if protocol == "h2" {
				srv := &http.Server{Handler: app, TLSConfig: cfg}
				go srv.ServeTLS(ln, "", "")
				t.Cleanup(func() { srv.Close() })
			} else {
				udp, err := net.ListenPacket("udp", ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				ln.Close()
				srv := server.NewHTTP3Server(app, cfg, 1252)
				go srv.Serve(udp)
				t.Cleanup(func() { srv.Close() })
			}
		}
		host, port, _ := net.SplitHostPort(ln.Addr().String())
		var n int
		fmt.Sscan(port, &n)
		return Relay{ID: e.cfg.ID, Host: host, Port: n, StreamPort: n, Path: path, PSK: base64.StdEncoding.EncodeToString(psk), BrokerToken: token}
	}
	ra, rb := start(a), start(b)
	a.cfg.Relays = []Relay{rb}
	b.cfg.Relays = []Relay{ra}
	origin := func(marker string) (net.Listener, int) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			fmt.Fprintf(w, "%s:%x", marker, sha256.Sum256(raw))
		})}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		return ln, ln.Addr().(*net.TCPAddr).Port
	}
	target, port := origin("intl")
	_, cnPort := origin("cn")
	forward.TargetPort = port
	reverse.TargetPort = cnPort
	local := len(localTarget) > 0 && localTarget[0]
	if local {
		forward.Target = "hop-b"
		reverse.Source = "hop-b"
		b.cfg.Role = "relay"
		b.cfg.Nodes = append(b.cfg.Nodes, Node{ID: "hop-b", Token: token})
	}

	for _, e := range []*Engine{a, b} {
		e.cfg.Routes = []Route{forward, reverse}
	}
	cn := &Engine{cfg: Config{ID: "cn", Role: "agent", Relays: []Relay{ra, rb}, Routes: []Route{forward, reverse}}, listeners: map[string]net.Listener{}, outbound: make(chan struct{}, 96)}
	intl := &Engine{cfg: Config{ID: "intl", Role: "agent", Relays: []Relay{ra, rb}, Routes: []Route{forward, reverse}}, listeners: map[string]net.Listener{}, outbound: make(chan struct{}, 96)}
	endpoint := intl
	if local {
		endpoint = b
	}
	for _, e := range []*Engine{a, b, cn, endpoint} {
		e.reconcileLinks()
		t.Cleanup(e.revoke)
	}
	open := func(e *Engine, id, kind string) (net.Conn, Hello, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := e.openRouteContext(ctx, id, kind)
		if err != nil {
			return nil, Hello{}, err
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		h, err := receive(c)
		return c, h, err
	}
	// Wait for the destination's authenticated reverse pool, then probe the full chain.
	var ready bool
	for i := 0; i < 40; i++ {
		if (local || len(b.pool("intl|"+protocol+"|"+name)) > 0) && len(a.pool("cn|"+protocol+"|"+name)) > 0 {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("reverse links not established")
	}
	for _, v := range []struct {
		e  *Engine
		id string
	}{{cn, forward.ID}, {endpoint, reverse.ID}} {
		c, h, err := open(v.e, v.id, "probe")
		if c != nil {
			c.Close()
		}
		if err != nil || !h.OK {
			t.Fatal("full chain probe", h, err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			src, id, marker := cn, forward.ID, "intl"
			if i%2 == 1 {
				src, id, marker = endpoint, reverse.ID, "cn"
			}
			c, h, err := open(src, id, "dial")
			if c != nil {
				defer c.Close()
			}
			if err != nil || !h.OK {
				errs <- fmt.Errorf("open: %v %v", h, err)
				return
			}
			raw := strings.Repeat(fmt.Sprint(i)+"data", 32768)
			req, _ := http.NewRequest("POST", "http://fixed.invalid/check", strings.NewReader(raw))
			req.Close = true
			if err = req.Write(c); err != nil {
				errs <- err
				return
			}
			reply, err := http.ReadResponse(bufio.NewReader(c), req)
			if err != nil {
				errs <- err
				return
			}
			body, _ := io.ReadAll(reply.Body)
			reply.Body.Close()
			if string(body) != fmt.Sprintf("%s:%x", marker, sha256.Sum256([]byte(raw))) {
				errs <- fmt.Errorf("integrity mismatch")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	// A closed multiplexed client must be retired instead of reused indefinitely.
	key := rb.ID + "|" + protocol + "|" + name
	a.mu.RLock()
	stale := a.links[key]
	a.mu.RUnlock()
	stale.client.Close()
	a.pingLink(stale)
	a.reconcileLinks()
	a.mu.RLock()
	fresh := a.links[key]
	a.mu.RUnlock()
	if fresh == nil || fresh == stale {
		t.Fatal("failed carrier was reused")
	}
	c2, h2, err2 := open(cn, forward.ID, "probe")
	if c2 != nil {
		c2.Close()
	}
	if err2 != nil || !h2.OK {
		t.Fatal("rebuilt carrier did not recover", h2, err2)
	}
	// Even a valid peer must not skip an upstream hop and dial a later broker.
	c := connectTest(t, b)
	send(c, Hello{Kind: "dial", Node: "intl", Token: token, Route: forward.ID, Transport: protocol, ServerName: name})
	h, _ := receive(c)
	c.Close()
	if h.OK || h.Error != "route not permitted" {
		t.Fatal("hop bypass accepted", h)
	}
	target.Close()
	c, h, err := open(cn, forward.ID, "probe")
	if c != nil {
		c.Close()
	}
	if err != nil || h.OK || h.Error != "target service unavailable" {
		t.Fatal("target failure not propagated", h, err)
	}
}

func TestFailedLinkRetirementDoesNotRemoveReplacement(t *testing.T) {
	old := &Link{relay: Relay{ID: "hop"}, transport: "h3", serverName: "scope.test"}
	fresh := &Link{relay: old.relay, transport: old.transport, serverName: old.serverName}
	other := &Link{relay: Relay{ID: "other"}, transport: "h2"}
	e := &Engine{links: map[string]*Link{"hop|h3|scope.test": fresh, "other|h2|": other}}
	e.retireFailedLink(old)
	if e.links["hop|h3|scope.test"] != fresh || e.links["other|h2|"] != other {
		t.Fatal("stale failure removed a different link")
	}
	e.retireFailedLink(fresh)
	if len(e.links) != 1 || e.links["other|h2|"] != other {
		t.Fatal("retirement affected another route")
	}
}
