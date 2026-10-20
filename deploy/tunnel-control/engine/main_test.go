package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e := &Engine{cfg: Config{Nodes: []Node{{ID: "mainland", Token: strings.Repeat("a", 64)}, {ID: "international", Token: strings.Repeat("b", 64)}}, Routes: []Route{{ID: "test-route", Source: "mainland", Target: "international", Enabled: true}}}, started: time.Now(), pools: map[string]chan net.Conn{}, listeners: map[string]net.Listener{}, slots: make(chan struct{}, 96)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.brokerAddress = ln.Addr().String()
	go e.serveBroker(ln)
	t.Cleanup(func() { ln.Close() })
	return e
}
func connectTest(t *testing.T, e *Engine) net.Conn {
	t.Helper()
	c, err := e.brokerConnection(context.Background(), "bridge.internal:1")
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}
func TestRelayIsFixedLocalEndpoint(t *testing.T) {
	e := testEngine(t)
	e.cfg.ID = "relay"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	e.cfg.Routes[0].Target = "relay"
	e.cfg.Routes[0].TargetPort = ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	c := connectTest(t, e)
	send(c, Hello{Kind: "dial", Node: "mainland", Token: strings.Repeat("a", 64), Route: "test-route"})
	h, err := receive(c)
	if err != nil || !h.OK {
		t.Fatal("local relay endpoint unavailable", h, err)
	}
	c.Write([]byte("relay-endpoint"))
	buf := make([]byte, 14)
	if _, err = io.ReadFull(c, buf); err != nil || string(buf) != "relay-endpoint" {
		t.Fatal("local endpoint data failed", err)
	}
	e.cfg.Routes[0].TargetPort = 5092
	denied := connectTest(t, e)
	send(denied, Hello{Kind: "dial", Node: "mainland", Token: strings.Repeat("a", 64), Route: "test-route"})
	h, err = receive(denied)
	if err != nil || h.Error != "service not permitted" {
		t.Fatal("management port was not denied", h, err)
	}
}
func TestRelaySourceUsesExistingReversePool(t *testing.T) {
	for _, role := range []string{"relay", "agent"} {
		t.Run(role, func(t *testing.T) {
			e := testEngine(t)
			e.cfg.ID = "mainland"
			e.cfg.Role = role
			e.cfg.Routes[0].RelayID = "mainland"
			dest := connectTest(t, e)
			send(dest, Hello{Kind: "accept", Node: "international", Token: strings.Repeat("b", 64)})
			go func() {
				h, err := receive(dest)
				if err != nil || h.Kind != "open" {
					return
				}
				send(dest, Hello{OK: true})
				buf := make([]byte, 6)
				if _, err = io.ReadFull(dest, buf); err == nil {
					dest.Write(buf)
				}
			}()
			c, err := e.openRoute("test-route")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			h, err := receive(c)
			if err != nil || !h.OK {
				t.Fatal("relay reverse route failed", h, err)
			}
			c.Write([]byte("origin"))
			buf := make([]byte, 6)
			if _, err = io.ReadFull(c, buf); err != nil || string(buf) != "origin" {
				t.Fatal("relay reverse bytes failed", err)
			}
			if c, err := e.openRoute("not-configured"); err == nil {
				c.Close()
				t.Fatal("arbitrary local route allowed")
			}
		})
	}
}
func TestBrokerAuthenticationAndTargetBoundary(t *testing.T) {
	e := testEngine(t)
	if c, err := e.brokerConnection(context.Background(), "127.0.0.1:22"); err == nil {
		c.Close()
		t.Fatal("arbitrary target accepted")
	}
	c := connectTest(t, e)
	send(c, Hello{Kind: "ping", Node: "mainland", Token: "wrong"})
	if _, err := receive(c); err == nil {
		t.Fatal("invalid token accepted")
	}
	c = connectTest(t, e)
	send(c, Hello{Kind: "dial", Node: "international", Token: strings.Repeat("b", 64), Route: "test-route"})
	h, err := receive(c)
	if err != nil || h.Error == "" {
		t.Fatal("unauthorized route source accepted", h, err)
	}
}
func TestDialDoesNotFallBackToControllerCredential(t *testing.T) {
	e := &Engine{cfg: Config{ID: "mainland", Token: strings.Repeat("c", 64)}}
	if _, err := e.dial(nil, Hello{Kind: "ping"}); err == nil {
		t.Fatal("missing broker credential accepted")
	}
}
func TestLegacyCacheCannotRestoreControllerCredentials(t *testing.T) {
	current := Config{ID: "node", Token: "private-controller-token", Controller: "https://controller.test", CA: "public-ca", Revision: 10, CredentialVersion: "broker-v1"}
	cached := current
	if !compatibleCache(current, cached) {
		t.Fatal("matching cache rejected")
	}
	cached.CredentialVersion = ""
	if compatibleCache(current, cached) {
		t.Fatal("legacy credential cache accepted")
	}
	cached = current
	cached.Revision--
	if compatibleCache(current, cached) {
		t.Fatal("older configuration cache accepted")
	}
	cached = current
	cached.Token = "revoked-token"
	if compatibleCache(current, cached) {
		t.Fatal("revoked identity cache accepted")
	}
}
func TestBrokerLargeTransferAndHalfClose(t *testing.T) {
	e := testEngine(t)
	dest := connectTest(t, e)
	send(dest, Hello{Kind: "accept", Node: "international", Token: strings.Repeat("b", 64)})
	payload := []byte(strings.Repeat("chitanda-transit-", 131072))
	hash := sha256.Sum256(payload)
	result := make(chan error, 1)
	go func() {
		h, err := receive(dest)
		if err != nil {
			result <- err
			return
		}
		if h.Route != "test-route" {
			result <- io.ErrUnexpectedEOF
			return
		}
		send(dest, Hello{OK: true})
		got, err := io.ReadAll(dest)
		if err != nil {
			result <- err
			return
		}
		sum := sha256.Sum256(got)
		_, err = dest.Write([]byte(hex.EncodeToString(sum[:])))
		halfClose(dest)
		result <- err
	}()
	source := connectTest(t, e)
	send(source, Hello{Kind: "dial", Node: "mainland", Token: strings.Repeat("a", 64), Route: "test-route"})
	h, err := receive(source)
	if err != nil || !h.OK {
		t.Fatal(h, err)
	}
	if _, err = source.Write(payload); err != nil {
		t.Fatal(err)
	}
	halfClose(source)
	reply, err := io.ReadAll(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != hex.EncodeToString(hash[:]) {
		t.Fatal("large transfer hash mismatch")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
