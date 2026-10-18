package main

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
)

func TestProbeToLocalRelayChecksPortWithoutBusinessPayload(t *testing.T) {
	e := testEngine(t)
	e.cfg.ID = "relay"
	e.cfg.Routes[0].Target = "relay"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	e.cfg.Routes[0].TargetPort = ln.Addr().(*net.TCPAddr).Port
	received := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		raw, _ := io.ReadAll(c)
		received <- len(raw)
	}()
	c := connectTest(t, e)
	send(c, Hello{Kind: "probe", Node: "mainland", Token: strings.Repeat("a", 64), Route: "test-route"})
	reply, err := receive(c)
	c.Close()
	if err != nil || !reply.OK {
		t.Fatal("local target probe failed", reply, err)
	}
	select {
	case n := <-received:
		if n != 0 {
			t.Fatal("probe wrote business payload")
		}
	case <-time.After(time.Second):
		t.Fatal("probe did not close target socket")
	}
	if e.active.Load() != 0 || e.connects.Load() != 0 {
		t.Fatal("probe was counted as a business stream")
	}
	e.cfg.Routes[0].TargetPort = 5092
	c = connectTest(t, e)
	send(c, Hello{Kind: "probe", Node: "mainland", Token: strings.Repeat("a", 64), Route: "test-route"})
	reply, _ = receive(c)
	if reply.OK {
		t.Fatal("management target was accepted")
	}
}
func TestRouteCheckRejectsStaleOrForeignCommands(t *testing.T) {
	e := testEngine(t)
	e.cfg.ID = "mainland"
	e.cfg.Revision = 7
	task := RouteCheckTask{ID: "check-example", RouteID: "test-route", Revision: 6, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
	r := e.runRouteCheck(task)
	if r.Status != "cancelled" || r.Attempts != 0 {
		t.Fatal("stale command executed")
	}
	task.Revision = 7
	e.cfg.Routes[0].Source = "international"
	r = e.runRouteCheck(task)
	if r.Status != "cancelled" || r.Attempts != 0 {
		t.Fatal("foreign source command executed")
	}
	e.cfg.Routes[0].Source = "mainland"
	missing := e.runRouteCheck(task)
	if missing.Reason != "source-unavailable" || missing.Attempts != 0 {
		t.Fatal("missing source listener was not detected", missing)
	}
	e.cfg.Routes[0].Enabled = false
	r = e.runRouteCheck(task)
	if r.Attempts != 0 {
		t.Fatal("paused route was tested")
	}
}

// Called inside the existing real-TLS test, using its private CA and carrier.
func exerciseRealRouteChecks(t *testing.T, broker *Engine, cli *client.Client, address string, psk []byte, protocol, sni string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	payloads := make(chan int, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			raw, _ := io.ReadAll(c)
			c.Close()
			payloads <- len(raw)
		}
	}()
	route := broker.config().Routes[0]
	route.RelayID = "diagnostic-relay"
	route.TargetPort = ln.Addr().(*net.TCPAddr).Port
	sourceListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sourceListener.Close()
	route.ListenPort = sourceListener.Addr().(*net.TCPAddr).Port
	targetClient, err := client.New(client.Config{Server: address, ServerID: "diagnostic-relay", ServerName: sni, Path: "/api/v1/transit-test", PSK: psk, TCPTransport: protocol, TCPPoolSize: 1, UDPPoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer targetClient.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := &Engine{cfg: Config{ID: "international", Routes: []Route{route}}}
	targetLink := &Link{relay: Relay{ID: route.RelayID, BrokerToken: strings.Repeat("b", 64)}, transport: protocol, serverName: sni, client: targetClient, ctx: ctx, cancel: cancel}
	go target.acceptOnLink(targetLink)
	sourceLink := &Link{relay: Relay{ID: route.RelayID, BrokerToken: strings.Repeat("a", 64)}, transport: protocol, serverName: sni, client: cli}
	source := &Engine{cfg: Config{ID: "mainland", Role: "agent", Revision: 9, Routes: []Route{route}}, links: map[string]*Link{routeKey(route): sourceLink}, listeners: map[string]net.Listener{route.ID: sourceListener}}
	task := RouteCheckTask{ID: "check-real-path", RouteID: route.ID, Revision: 9, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
	result := source.runRouteCheck(task)
	if result.Status != "complete" || result.Attempts != 3 || len(result.Samples) != 3 {
		t.Fatal("real full-path probe failed", result)
	}
	for i := 0; i < 3; i++ {
		select {
		case n := <-payloads:
			if n != 0 {
				t.Fatal("probe wrote to business service")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("missing target port check")
		}
	}
	if target.active.Load() != 0 || target.connects.Load() != 0 {
		t.Fatal("probe became a business stream")
	}
	ln.Close()
	task.ID = "check-closed-target"
	result = source.runRouteCheck(task)
	if result.Attempts != 1 || len(result.Samples) != 0 || result.Reason != "target-unavailable" {
		t.Fatal("closed target was not detected", result)
	}
}
