package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"
)

type routeHTTPFailover struct {
	engine *Engine
	route  string
}

// Some endpoints keep public TLS in Nginx/a small gateway. Their fixed
// loopback URL-access port must get the same request-aware failover behavior.
func (e *Engine) serveFailoverHTTPSource(ln net.Listener, id string) {
	requests := make(chan struct{}, 8)
	proxy := &httputil.ReverseProxy{Rewrite: func(p *httputil.ProxyRequest) {
		p.Out.URL.Scheme = "http"
		p.Out.URL.Host = "route.internal"
		p.Out.Host = p.In.Host
	}, Transport: &routeHTTPFailover{e, id}, FlushInterval: -1, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) { http.Error(w, "channel unavailable", 502) }}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- struct{}{}:
			defer func() { <-requests }()
		default:
			http.Error(w, "channel busy", 503)
			return
		}
		select {
		case e.outbound <- struct{}{}:
			defer func() { <-e.outbound }()
		default:
			http.Error(w, "channel busy", 503)
			return
		}
		if r.Method == http.MethodConnect || r.Method == http.MethodTrace || r.Header.Get("Upgrade") != "" {
			http.Error(w, "request not permitted", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
		proxy.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 300 * time.Second, WriteTimeout: 300 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	_ = srv.Serve(ln)
}

type watchedRouteBody struct {
	io.ReadCloser
	once   sync.Once
	failed func()
}

func (b *watchedRouteBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		b.once.Do(b.failed)
	}
	return n, err
}

type joinedRouteBody struct {
	io.Reader
	io.Closer
}

func (e *Engine) failoverHTTPTransport(id string) http.RoundTripper {
	if len(e.failoverRoutes(id)) < 2 {
		return nil
	}
	return &routeHTTPFailover{e, id}
}
func (t *routeHTTPFailover) RoundTrip(req *http.Request) (*http.Response, error) {
	e := t.engine
	routes := e.failoverRoutes(t.route)
	if len(routes) == 0 {
		return nil, errors.New("route removed")
	}
	candidates := e.failoverCandidates(t.route, routes)
	safeRead := (req.Method == http.MethodGet || req.Method == http.MethodHead) && (req.Body == nil || req.Body == http.NoBody) && len(req.TransferEncoding) == 0
	for _, route := range candidates {
		ctx, cancel := context.WithTimeout(req.Context(), 1500*time.Millisecond)
		c, err := e.openReadyPhysical(ctx, route.ID, "dial")
		cancel()
		if err != nil {
			e.markFailover(t.route, route.ID, false, false)
			if req.Context().Err() != nil {
				return nil, req.Context().Err()
			}
			continue
		}
		used := false
		headerTimeout := 240 * time.Second
		if safeRead {
			headerTimeout = 5 * time.Second
		}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: headerTimeout, MaxConnsPerHost: 1, DialContext: func(context.Context, string, string) (net.Conn, error) {
			if used {
				return nil, errors.New("one stream per attempt")
			}
			used = true
			return c, nil
		}}
		response, err := transport.RoundTrip(req.Clone(req.Context()))
		transport.CloseIdleConnections()
		if err != nil {
			c.Close()
			if req.Context().Err() == nil {
				e.markFailover(t.route, route.ID, false, false)
			}
			if safeRead && req.Context().Err() == nil {
				continue
			}
			return nil, err
		}
		failed := func() {
			if req.Context().Err() == nil {
				e.markFailover(t.route, route.ID, false, false)
			}
		}
		response.Body = &watchedRouteBody{ReadCloser: response.Body, failed: failed}
		// Delay commitment of small read responses so a broken channel can be
		// retried without exposing a partial response. Large streams remain streams.
		if safeRead && response.ContentLength <= 1<<20 {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			buffered, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
			_ = c.SetReadDeadline(time.Time{})
			if readErr != nil {
				response.Body.Close()
				c.Close()
				failed()
				if req.Context().Err() == nil {
					continue
				}
				return nil, req.Context().Err()
			}
			if len(buffered) <= 1<<20 {
				response.Body.Close()
				response.Body = io.NopCloser(bytes.NewReader(buffered))
			} else {
				response.Body = &joinedRouteBody{Reader: io.MultiReader(bytes.NewReader(buffered), response.Body), Closer: response.Body}
			}
		}
		e.markFailover(t.route, route.ID, true, true)
		return response, nil
	}
	return nil, errors.New("all configured HTTP paths are unavailable")
}
