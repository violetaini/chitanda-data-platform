package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDirectEndpointCarrierLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("target Linux listener lifecycle")
	}
	freePort := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		return port
	}
	e := testEngine(t)
	e.replayCacheFile = filepath.Join(t.TempDir(), "replay.db")
	e.cfg.Role = "agent"
	e.cfg.ID = "direct-endpoint"
	e.cfg.Routes = nil
	port, streamPort := freePort(), freePort()
	profile := &Relay{ID: e.cfg.ID, Port: port, StreamPort: streamPort}
	e.cfg.SelfRelay = profile
	e.cfg.PSK = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32)))
	e.cfg.Path = "/direct-test"
	e.cfg.Listen = fmt.Sprintf("127.0.0.1:%d", port)
	e.cert.Store(telemetryCertificate(t, 89, time.Now().Add(time.Hour)))
	await := func(pred func() bool) {
		t.Helper()
		until := time.Now().Add(5 * time.Second)
		for !pred() {
			if time.Now().After(until) {
				t.Fatal("endpoint lifecycle deadline")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	listening := func(port int) bool {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if c != nil {
			c.Close()
		}
		return err == nil
	}
	stop := func() {
		e.mu.Lock()
		e.cfg.SelfRelay = nil
		e.mu.Unlock()
		e.reconcileEndpointServer()
		await(func() bool { e.endpointMu.Lock(); defer e.endpointMu.Unlock(); return e.endpointStop == nil })
		if listening(port) || listening(streamPort) {
			t.Fatal("paused direct carrier still listening")
		}
	}
	t.Cleanup(func() { stop() })
	for i := 0; i < 2; i++ {
		e.mu.Lock()
		e.cfg.SelfRelay = profile
		e.mu.Unlock()
		e.reconcileEndpointServer()
		await(func() bool { return listening(port) && listening(streamPort) })
		if e.config().Role != "agent" {
			t.Fatal("endpoint identity changed")
		}
		stop()
	}
}
