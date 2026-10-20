package main

import (
	"errors"
	"github.com/violetaini/chitanda/pkg/client"
)

// Legacy single-relay configurations retain their exact wire behavior.
func (r Route) relayPath() []string {
	if len(r.RelayIDs) > 0 {
		return r.RelayIDs
	}
	return []string{r.RelayID}
}
func (r Route) firstRelay() string { return r.relayPath()[0] }
func (r Route) lastRelay() string  { p := r.relayPath(); return p[len(p)-1] }
func (r Route) brokerSource(id string) string {
	for i, n := range r.relayPath() {
		if n == id {
			if i == 0 {
				return r.Source
			}
			return r.relayPath()[i-1]
		}
	}
	// Tests and legacy broker fixtures without an explicit relay ID.
	if r.RelayID == "" && len(r.RelayIDs) == 0 {
		return r.Source
	}
	return ""
}
func (r Route) nextRelay(id string) string {
	p := r.relayPath()
	for i, n := range p {
		if n == id && i+1 < len(p) {
			return p[i+1]
		}
	}
	return ""
}
func (r Route) linkRelay(id string) string {
	if id == r.Source && id != r.firstRelay() {
		return r.firstRelay()
	}
	if id == r.Target && id != r.lastRelay() {
		return r.lastRelay()
	}
	return r.nextRelay(id)
}
func (e *Engine) forwardClient(r Route, next, kind string) (*client.Client, Hello, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	r.RelayID = next
	l := e.links[routeKey(r)]
	if l == nil {
		return nil, Hello{}, errors.New("configured next relay unavailable")
	}
	return l.client, Hello{Kind: kind, Token: l.relay.BrokerToken, Route: r.ID, Transport: r.Transport, ServerName: r.ServerName}, nil
}
