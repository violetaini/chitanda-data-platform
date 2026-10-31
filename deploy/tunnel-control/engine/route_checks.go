package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

type RouteCheckTask struct {
	ID        string `json:"id"`
	RouteID   string `json:"routeId"`
	Revision  int    `json:"revision"`
	ExpiresAt string `json:"expiresAt"`
}
type RouteCheckResult struct {
	ID         string    `json:"id"`
	RouteID    string    `json:"routeId"`
	Revision   int       `json:"revision"`
	Status     string    `json:"status"`
	Attempts   int       `json:"attempts"`
	Samples    []float64 `json:"samples"`
	Reason     string    `json:"reason,omitempty"`
	FinishedAt time.Time `json:"-"`
}

func (e *Engine) checkReports() []RouteCheckResult {
	e.checkMu.Lock()
	defer e.checkMu.Unlock()
	out := []RouteCheckResult{}
	for id, r := range e.checkResults {
		if time.Since(r.FinishedAt) > 5*time.Minute {
			delete(e.checkResults, id)
			continue
		}
		copy := r
		copy.Samples = append([]float64{}, r.Samples...)
		out = append(out, copy)
	}
	return out
}
func (e *Engine) startChecks(tasks []RouteCheckTask) {
	for _, task := range tasks {
		expiry, err := time.Parse(time.RFC3339, task.ExpiresAt)
		if err != nil || !expiry.After(time.Now()) || expiry.After(time.Now().Add(95*time.Second)) || len(task.ID) < 8 || len(task.ID) > 80 {
			continue
		}
		e.checkMu.Lock()
		if e.checkResults == nil {
			e.checkResults = map[string]RouteCheckResult{}
		}
		_, done := e.checkResults[task.ID]
		if e.checkBusy || done {
			e.checkMu.Unlock()
			continue
		}
		e.checkBusy = true
		e.checkMu.Unlock()
		go func(task RouteCheckTask) {
			result := e.runRouteCheck(task)
			e.checkMu.Lock()
			if len(e.checkResults) >= 32 {
				for id := range e.checkResults {
					delete(e.checkResults, id)
					break
				}
			}
			e.checkResults[task.ID] = result
			e.checkBusy = false
			e.checkMu.Unlock()
			// Serialize with the periodic heartbeat and publish the result immediately.
			if err := e.syncConfig(); err != nil {
				e.err(err)
			}
		}(task)
		break
	}
}
func (e *Engine) runRouteCheck(task RouteCheckTask) RouteCheckResult {
	result := RouteCheckResult{ID: task.ID, RouteID: task.RouteID, Revision: task.Revision, Status: "complete", Samples: []float64{}}
	for i := 0; i < 3; i++ {
		cfg := e.config()
		permitted := false
		var route Route
		for _, r := range cfg.Routes {
			if r.ID == task.RouteID && r.Enabled && r.Source == cfg.ID && r.TargetPort != 5092 {
				permitted = true
				route = r
				break
			}
		}
		expiry, err := time.Parse(time.RFC3339, task.ExpiresAt)
		if !permitted || cfg.Revision != task.Revision || err != nil || !expiry.After(time.Now()) {
			result.Status = "cancelled"
			result.Reason = "config-changed"
			break
		}
		e.mu.RLock()
		ln := e.listeners[task.RouteID]
		listening := ln != nil && ln.Addr().String() == net.JoinHostPort("127.0.0.1", fmt.Sprint(route.ListenPort))
		e.mu.RUnlock()
		if !listening {
			result.Reason = "source-unavailable"
			break
		}
		deadline := time.Now().Add(8 * time.Second)
		if expiry.Before(deadline) {
			deadline = expiry
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		start := time.Now()
		result.Attempts++
		reason := e.probeRoute(ctx, task.RouteID)
		elapsed := float64(time.Since(start).Microseconds()) / 1000
		cancel()
		if reason != "" {
			result.Reason = reason
			break
		}
		result.Samples = append(result.Samples, elapsed)
		if i < 2 {
			time.Sleep(150 * time.Millisecond)
		}
	}
	result.FinishedAt = time.Now()
	return result
}
func (e *Engine) probeRoute(ctx context.Context, id string) string {
	if len(e.failoverRoutes(id)) > 1 {
		for _, r := range e.failoverCandidates(id, e.failoverRoutes(id)) {
			attempt, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			c, err := e.openReadyPhysical(attempt, r.ID, "probe")
			cancel()
			e.markFailover(id, r.ID, err == nil, false)
			if c != nil {
				c.Close()
			}
			if err == nil {
				return ""
			}
			if ctx.Err() != nil {
				return "timeout"
			}
		}
		return "channel-unavailable"
	}
	c, err := e.openRouteContext(ctx, id, "probe")
	if err != nil {
		var n net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &n) && n.Timeout()) {
			return "timeout"
		}
		return "channel-unavailable"
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok {
		c.SetReadDeadline(deadline)
	}
	reply, err := receive(c)
	if err != nil {
		var n net.Error
		if errors.As(err, &n) && n.Timeout() {
			return "timeout"
		}
		return "channel-unavailable"
	}
	if reply.OK {
		return ""
	}
	switch reply.Error {
	case "target service unavailable", "service unavailable":
		return "target-unavailable"
	case "target node is offline or busy":
		return "target-offline"
	case "route not permitted", "service not permitted":
		return "not-permitted"
	}
	return "channel-unavailable"
}
