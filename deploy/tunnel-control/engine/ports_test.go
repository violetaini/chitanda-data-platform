package main

import (
	"net"
	"reflect"
	"runtime"
	"sync"
	"testing"
)

func TestConcurrentListenerReconciliationKeepsOneOwner(t *testing.T) {
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	e := testEngine(t)
	e.cfg.ID = "mainland"
	e.cfg.Routes[0].ListenPort = port
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); e.reconcileListeners() }()
	}
	wg.Wait()
	defer func() {
		for _, ln := range e.listeners {
			ln.Close()
		}
	}()
	if len(e.listeners) != 1 || len(e.listenerErrors) != 0 {
		t.Fatal("concurrent reconciles claimed a false conflict", e.listenerErrors)
	}
}

func TestListeningPortParserUsesOnlyTCPListeners(t *testing.T) {
	ports := map[int]bool{}
	parseListeningPorts([]byte("0: 00000000:3AE9 00000000:0000 0A\n1: 00000000000000000000000000000000:3AEA 00000000:0000 0A\n2: 00000000:3AEB 00000000:0000 01\n3: garbage\n4: 00000000:ZZZZ 00000000:0000 0A\n"), ports)
	if !reflect.DeepEqual(ports, map[int]bool{15081: true, 15082: true}) {
		t.Fatal(ports)
	}
}

func TestOccupiedListenerFailsAndRecoversWithoutChangingPort(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if runtime.GOOS == "linux" {
		inventory := collectPorts()
		found := false
		for _, p := range inventory.TCP {
			found = found || p == port
		}
		if !inventory.Complete || !found {
			t.Fatal("real occupied port missing", inventory)
		}
	}
	e := testEngine(t)
	e.cfg.ID = "mainland"
	e.cfg.Routes[0].ListenPort = port
	e.reconcileListeners()
	if len(e.listeners) != 0 || e.listenerErrors["test-route"] != "port-in-use" {
		t.Fatal("collision not surfaced", e.listenerErrors)
	}
	ln.Close()
	e.reconcileListeners()
	defer func() {
		for _, l := range e.listeners {
			l.Close()
		}
	}()
	if e.listeners["test-route"] == nil || len(e.listenerErrors) != 0 || e.cfg.Routes[0].ListenPort != port {
		t.Fatal("recovery changed configured port or retained error")
	}
}
