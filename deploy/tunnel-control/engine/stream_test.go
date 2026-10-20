package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/server"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNativeStreamIntegrityHalfCloseAuthenticationAndProbes(t *testing.T) {
	broker := testEngine(t)
	broker.cfg.ID = "diagnostic-relay"
	broker.cfg.Routes[0].Transport = "stream"
	broker.cfg.Routes[0].Target = "diagnostic-relay"
	psk := []byte(strings.Repeat("s", 32))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	native := server.NewStreamServer(psk, broker.cfg.ID, auth.NewReplayCache(), func(ctx context.Context, network, address string) (net.Conn, error) {
		return broker.brokerConnection(ctx, address)
	})
	go native.Serve(ln)
	defer native.Close()
	cli, err := client.New(client.Config{Server: ln.Addr().String(), ServerID: broker.cfg.ID, PSK: psk, TCPTransport: "stream"})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	destination, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	broker.cfg.Routes[0].TargetPort = destination.Addr().(*net.TCPAddr).Port
	go func() {
		c, err := destination.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		raw, _ := io.ReadAll(c)
		fmt.Fprintf(c, "%x", sha256.Sum256(raw))
	}()
	source := &Engine{cfg: Config{ID: "mainland"}}
	c, err := source.dial(cli, Hello{Kind: "dial", Route: "test-route", Transport: "stream", Token: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	ack, err := receive(c)
	if err != nil || !ack.OK {
		t.Fatal("native route rejected", ack, err)
	}
	payload := strings.Repeat("chitanda-stream-data-", 65536)
	if _, err = io.WriteString(c, payload); err != nil {
		t.Fatal(err)
	}
	halfClose(c)
	reply, err := io.ReadAll(c)
	if err != nil || string(reply) != fmt.Sprintf("%x", sha256.Sum256([]byte(payload))) {
		t.Fatal("stream integrity/half-close failed", err, len(reply))
	}
	for _, config := range []client.Config{{Server: ln.Addr().String(), ServerID: broker.cfg.ID, PSK: []byte(strings.Repeat("x", 32)), TCPTransport: "stream"}, {Server: ln.Addr().String(), ServerID: "different-relay", PSK: psk, TCPTransport: "stream"}} {
		bad, err := client.New(config)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := bad.DialContext(ctx, "tcp", "bridge.internal:1")
		cancel()
		bad.Close()
		if err == nil {
			conn.Close()
			t.Fatal("wrong PSK/server identity accepted")
		}
	}
	broker.mu.Lock()
	broker.cfg.Routes[0].Target = "international"
	broker.mu.Unlock()
	exerciseRealRouteChecks(t, broker, cli, ln.Addr().String(), psk, "stream", "")
	exerciseRealRelayChain(t, "stream", tls.Certificate{})
	exerciseRealRelayChain(t, "stream", tls.Certificate{}, true)
}
