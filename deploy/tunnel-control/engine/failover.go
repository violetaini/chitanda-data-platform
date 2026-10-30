package main

import (
	"context"
	"errors"
	"net"
	"time"
)

// Alternate wire routes keep independent hop authorization and reverse pools.
// Only the logical route owns a local listener and public access grant.
type failoverPathHealth struct {
	Healthy   bool  `json:"healthy"`
	CheckedAt int64 `json:"checkedAt"`
	Successes int   `json:"successes"`
	Failures  int   `json:"failures"`
	RetryAt   int64 `json:"retryAt"`
	busy      bool
}
type routeFailoverState struct {
	Active     string                         `json:"activePathId"`
	Switches   int64                          `json:"switches"`
	SwitchedAt int64                          `json:"switchedAt"`
	Paths      map[string]*failoverPathHealth `json:"paths"`
}

func (e *Engine) failoverRoutes(id string) []Route {
	cfg := e.config()
	var root *Route
	for _, r := range cfg.Routes {
		if r.ID == id && r.Enabled && r.Source == cfg.ID && r.ParentRouteID == "" {
			v := r
			root = &v
			break
		}
	}
	if root == nil {
		return nil
	}
	out := []Route{*root}
	seen := map[string]bool{id: true}
	for _, key := range root.FallbackRouteIDs {
		if len(out) >= 9 {
			break
		}
		if seen[key] {
			continue
		}
		for _, r := range cfg.Routes {
			if r.ID == key && r.ParentRouteID == id && r.Source == root.Source && r.Target == root.Target && r.TargetPort == root.TargetPort && r.Enabled {
				out = append(out, r)
				seen[key] = true
				break
			}
		}
	}
	return out
}
func (e *Engine) failoverStateLocked(id string) *routeFailoverState {
	if e.failoverStates == nil {
		e.failoverStates = map[string]*routeFailoverState{}
	}
	s := e.failoverStates[id]
	if s == nil {
		s = &routeFailoverState{Active: id, Paths: map[string]*failoverPathHealth{}}
		e.failoverStates[id] = s
	}
	return s
}
func (e *Engine) pathHealthLocked(s *routeFailoverState, id string) *failoverPathHealth {
	p := s.Paths[id]
	if p == nil {
		p = &failoverPathHealth{}
		s.Paths[id] = p
	}
	return p
}
func (e *Engine) markFailover(id, path string, healthy, selected bool) {
	e.failoverMu.Lock()
	defer e.failoverMu.Unlock()
	s := e.failoverStateLocked(id)
	p := e.pathHealthLocked(s, path)
	p.Healthy = healthy
	p.CheckedAt = time.Now().UnixMilli()
	p.busy = false
	if healthy {
		p.Successes++
		p.Failures = 0
		p.RetryAt = 0
		if selected && s.Active != path {
			s.Active = path
			s.Switches++
			s.SwitchedAt = p.CheckedAt
		}
	} else {
		p.Successes = 0
		p.Failures++
		p.RetryAt = p.CheckedAt + 5000
	}
}
func (e *Engine) failoverCandidates(id string, routes []Route) []Route {
	if len(routes) < 2 {
		return routes
	}
	e.failoverMu.Lock()
	defer e.failoverMu.Unlock()
	s := e.failoverStateLocked(id)
	now := time.Now().UnixMilli()
	preferred := s.Active
	if p := s.Paths[id]; p != nil && p.Healthy && p.Successes >= 2 && now-s.SwitchedAt >= 15000 {
		preferred = id
	}
	out := []Route{}
	for _, r := range routes {
		if r.ID == preferred {
			p := s.Paths[r.ID]
			if p == nil || p.RetryAt <= now {
				out = append(out, r)
			}
		}
	}
	for _, r := range routes {
		if r.ID == preferred {
			continue
		}
		p := s.Paths[r.ID]
		if p == nil || p.RetryAt <= now {
			out = append(out, r)
		}
	}
	return out
}
func (e *Engine) openReadyPhysical(ctx context.Context, id, kind string) (net.Conn, error) {
	if e.readyRouteDial != nil {
		return e.readyRouteDial(ctx, id, kind)
	}
	c, err := e.openRouteContext(ctx, id, kind)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetReadDeadline(deadline)
	}
	reply, err := receive(c)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil || !reply.OK {
		c.Close()
		return nil, errors.New("configured path did not acknowledge its target")
	}
	if ctx.Err() != nil {
		c.Close()
		return nil, ctx.Err()
	}
	return c, nil
}
func (e *Engine) openReadyFailover(ctx context.Context, id string) (net.Conn, error) {
	routes := e.failoverRoutes(id)
	if len(routes) == 0 {
		return nil, errors.New("logical route disabled or removed")
	}
	candidates := e.failoverCandidates(id, routes)
	for _, r := range candidates {
		attempt := ctx
		cancel := func() {}
		if len(routes) > 1 {
			attempt, cancel = context.WithTimeout(ctx, 1500*time.Millisecond)
		}
		c, err := e.openReadyPhysical(attempt, r.ID, "dial")
		cancel()
		if err == nil {
			if len(routes) > 1 {
				e.markFailover(id, r.ID, true, true)
			}
			return c, nil
		}
		if len(routes) > 1 {
			e.markFailover(id, r.ID, false, false)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("all configured paths are unavailable")
}
func (e *Engine) penalizeActivePath(id string) {
	if len(e.failoverRoutes(id)) < 2 {
		return
	}
	e.failoverMu.Lock()
	s := e.failoverStateLocked(id)
	active := s.Active
	e.failoverMu.Unlock()
	e.markFailover(id, active, false, false)
}
func (e *Engine) failoverSnapshot() map[string]routeFailoverState {
	e.failoverMu.Lock()
	defer e.failoverMu.Unlock()
	out := map[string]routeFailoverState{}
	for id, s := range e.failoverStates {
		v := *s
		v.Paths = map[string]*failoverPathHealth{}
		for key, p := range s.Paths {
			copy := *p
			v.Paths[key] = &copy
		}
		out[id] = v
	}
	return out
}
func (e *Engine) syncFailoverProbes() {
	cfg := e.config()
	active := map[string]map[string]bool{}
	for _, r := range cfg.Routes {
		if r.Enabled && r.Source == cfg.ID && r.ParentRouteID == "" && len(r.FallbackRouteIDs) > 0 {
			ids := map[string]bool{r.ID: true}
			for _, key := range r.FallbackRouteIDs {
				ids[key] = true
			}
			active[r.ID] = ids
		}
	}
	e.failoverMu.Lock()
	defer e.failoverMu.Unlock()
	for id, s := range e.failoverStates {
		ids, ok := active[id]
		if !ok {
			delete(e.failoverStates, id)
			continue
		}
		for key := range s.Paths {
			if !ids[key] {
				delete(s.Paths, key)
			}
		}
		if !ids[s.Active] {
			s.Active = id
		}
	}
	if len(active) == 0 {
		if e.failoverStop != nil {
			close(e.failoverStop)
			e.failoverStop = nil
		}
		return
	}
	if e.failoverStop != nil {
		return
	}
	stop := make(chan struct{})
	e.failoverStop = stop
	if e.failoverProbeSlots == nil {
		e.failoverProbeSlots = make(chan struct{}, 4)
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				e.probeFailoverPaths()
			}
		}
	}()
}
func (e *Engine) probeFailoverPaths() {
	cfg := e.config()
	type task struct{ root, path string }
	all := []task{}
	for _, r := range cfg.Routes {
		if r.Source == cfg.ID && r.Enabled && r.ParentRouteID == "" && len(r.FallbackRouteIDs) > 0 {
			for _, p := range e.failoverRoutes(r.ID) {
				all = append(all, task{r.ID, p.ID})
			}
		}
	}
	if len(all) == 0 {
		return
	}
	for checked := 0; checked < len(all); checked++ {
		e.failoverMu.Lock()
		i := e.failoverProbeCursor % len(all)
		e.failoverProbeCursor++
		t := all[i]
		s := e.failoverStateLocked(t.root)
		p := e.pathHealthLocked(s, t.path)
		due := !p.busy && time.Now().UnixMilli()-p.CheckedAt >= 3000
		if due {
			select {
			case e.failoverProbeSlots <- struct{}{}:
				p.busy = true
			default:
				due = false
			}
		}
		e.failoverMu.Unlock()
		if !due {
			continue
		}
		go func(t task) {
			defer func() { <-e.failoverProbeSlots }()
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			c, err := e.openReadyPhysical(ctx, t.path, "probe")
			if c != nil {
				c.Close()
			}
			e.markFailover(t.root, t.path, err == nil, false)
		}(t)
	}
}
