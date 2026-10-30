package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func failoverEngine() *Engine {
	return &Engine{cfg: Config{ID: "cn", Routes: []Route{
		{ID: "main", Source: "cn", Target: "jp", TargetPort: 16082, Enabled: true, FallbackRouteIDs: []string{"backup", "second"}},
		{ID: "backup", ParentRouteID: "main", Source: "cn", Target: "jp", TargetPort: 16082, Enabled: true},
		{ID: "second", ParentRouteID: "main", Source: "cn", Target: "jp", TargetPort: 16082, Enabled: true},
	}}}
}
func TestFailoverOrderedRetryAndRecovery(t *testing.T) {
	e := failoverEngine()
	var calls []string
	e.readyRouteDial = func(ctx context.Context, id, kind string) (net.Conn, error) {
		calls = append(calls, id)
		if id != "second" {
			return nil, errors.New("cut link")
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	c, err := e.openReadyFailover(context.Background(), "main")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if strings.Join(calls, ",") != "main,backup,second" {
		t.Fatal(calls)
	}
	calls = nil
	c, err = e.openReadyFailover(context.Background(), "main")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if strings.Join(calls, ",") != "second" {
		t.Fatal("unhealthy paths were retried", calls)
	}
	e.markFailover("main", "main", true, false)
	e.markFailover("main", "main", true, false)
	e.failoverMu.Lock()
	e.failoverStates["main"].SwitchedAt = time.Now().Add(-16 * time.Second).UnixMilli()
	e.failoverMu.Unlock()
	if e.failoverCandidates("main", e.failoverRoutes("main"))[0].ID != "main" {
		t.Fatal("primary was not preferred after recovery")
	}
	e.mu.Lock()
	e.cfg.Routes[1].Target = "unrelated"
	e.mu.Unlock()
	if len(e.failoverRoutes("main")) != 2 {
		t.Fatal("cross-target fallback accepted")
	}
}
func TestFailoverHTTPDoesNotReplayWritesAndRetriesReads(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			e := failoverEngine()
			var primary, backup atomic.Int32
			e.readyRouteDial = func(ctx context.Context, id, kind string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					req, err := http.ReadRequest(bufio.NewReader(b))
					if err != nil {
						return
					}
					io.Copy(io.Discard, req.Body)
					if id == "main" {
						primary.Add(1)
						fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nbroken")
						return
					}
					backup.Add(1)
					fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ngood")
				}()
				return a, nil
			}
			var body io.Reader
			if method == "POST" {
				body = strings.NewReader("sensitive-write")
			}
			req, _ := http.NewRequest(method, "http://route.internal/test", body)
			response, err := (&routeHTTPFailover{e, "main"}).RoundTrip(req)
			if method == "GET" {
				if err != nil {
					t.Fatal(err)
				}
				raw, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(raw) != "good" || backup.Load() != 1 {
					t.Fatal(string(raw), err, backup.Load())
				}
			}
			if method == "POST" {
				if err == nil {
					_, _ = io.ReadAll(response.Body)
					response.Body.Close()
				}
				if backup.Load() != 0 {
					t.Fatal("write replayed")
				}
			}
			if primary.Load() != 1 {
				t.Fatal("primary attempts", primary.Load())
			}
		})
	}
}
func TestFailoverHTTPWriteCanSwitchBeforeSending(t *testing.T) {
	e := failoverEngine()
	var writes atomic.Int32
	e.readyRouteDial = func(ctx context.Context, id, kind string) (net.Conn, error) {
		if id == "main" {
			return nil, errors.New("no ack")
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			r, err := http.ReadRequest(bufio.NewReader(b))
			if err != nil {
				return
			}
			v, _ := io.ReadAll(r.Body)
			if string(v) == "payload" {
				writes.Add(1)
			}
			fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}()
		return a, nil
	}
	req, _ := http.NewRequest("POST", "http://route.internal", strings.NewReader("payload"))
	r, err := (&routeHTTPFailover{e, "main"}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if writes.Load() != 1 {
		t.Fatal(writes.Load())
	}
}
func TestFailoverHTTPPreservesLargeAndUnknownBodies(t *testing.T) {
	for _, size := range []int{120, 2 << 20} {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprint(size, chunked), func(t *testing.T) {
				e := failoverEngine()
				payload := strings.Repeat("x", size)
				e.readyRouteDial = func(ctx context.Context, id, kind string) (net.Conn, error) {
					a, b := net.Pipe()
					go func() {
						defer b.Close()
						http.ReadRequest(bufio.NewReader(b))
						if chunked {
							fmt.Fprint(b, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
							fmt.Fprintf(b, "%x\r\n%s\r\n0\r\n\r\n", size, payload)
						} else {
							fmt.Fprintf(b, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", size, payload)
						}
					}()
					return a, nil
				}
				req, _ := http.NewRequest("GET", "http://route.internal", nil)
				r, err := (&routeHTTPFailover{e, "main"}).RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := io.ReadAll(r.Body)
				r.Body.Close()
				if err != nil || string(raw) != payload {
					t.Fatal("body altered", len(raw), err)
				}
			})
		}
	}
}
func TestFailoverHTTPTimeoutCancellation(t *testing.T) {
	e := failoverEngine()
	e.readyRouteDial = func(ctx context.Context, id, kind string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "GET", "http://route.internal", nil)
	start := time.Now()
	_, err := (&routeHTTPFailover{e, "main"}).RoundTrip(r)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal(err, time.Since(start))
	}
}
func TestFailoverHTTPBodyCancellationClosesStream(t *testing.T) {
	e := failoverEngine()
	done := make(chan struct{})
	e.readyRouteDial = func(ctx context.Context, id, kind string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			defer close(done)
			http.ReadRequest(bufio.NewReader(b))
			fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
			var p [1]byte
			b.Read(p[:])
		}()
		return a, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://route.internal", nil)
	_, err := (&routeHTTPFailover{e, "main"}).RoundTrip(req)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled read leaked a stream")
	}
}
