package main

import "log"

// Ordinary endpoints open an authenticated carrier only while an enabled direct
// route needs it. This does not change their enrollment identity or purpose.
func (e *Engine) reconcileEndpointServer() {
	cfg := e.config()
	if cfg.Role != "agent" {
		return
	}
	e.endpointMu.Lock()
	defer e.endpointMu.Unlock()
	if cfg.SelfRelay == nil {
		if e.endpointStop != nil && !e.endpointStopping {
			close(e.endpointStop)
			e.endpointStopping = true
		}
		return
	}
	if e.endpointStop != nil {
		return
	}
	stop := make(chan struct{})
	e.endpointStop = stop
	go func() {
		err := e.runRelayUntil(stop)
		if err != nil {
			e.err(err)
			log.Printf("endpoint carrier: %v", err)
		}
		e.endpointMu.Lock()
		e.endpointStop = nil
		e.endpointStopping = false
		e.endpointMu.Unlock()
	}()
}
