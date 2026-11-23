package mcra

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const defaultTTL = 30 * time.Second

// loader loads one hub snapshot. It does not take a token, a user, or an impersonation config.
type loader interface {
	Load(ctx context.Context) (grantIndex, error)
}

// snapshot is the only writer of the process grantIndex for one hub and TTL.
// Callers hold grantIndex by value. Its maps are never written after grantIndexFrom.
// mu guards entry and flight. Do not copy a snapshot by value.
type snapshot struct {
	ttl    time.Duration
	now    func() time.Time
	load   loader
	mu     sync.Mutex
	entry  *cacheEntry
	flight *flight
}

type cacheEntry struct {
	index   grantIndex
	expires time.Time
}

type flight struct {
	done  chan struct{}
	index grantIndex
	err   error
}

func newSnapshot(ttl time.Duration, now func() time.Time, load loader) *snapshot {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if now == nil {
		now = time.Now
	}
	return &snapshot{ttl: ttl, now: now, load: load}
}

// grants returns the current allow-list.
// One Load serves every subject and every waiter. Errors are not cached.
// The load uses a fresh context, so a caller cancel does not cancel it and the
// loader cannot see the request's bearer token. listTimeout bounds that load.
func (s *snapshot) grants(ctx context.Context) (idx grantIndex, err error) {
	s.mu.Lock()
	if s.entry != nil && s.now().Before(s.entry.expires) {
		idx = s.entry.index
		s.mu.Unlock()
		return idx, nil
	}
	s.entry = nil
	if s.flight != nil {
		f := s.flight
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return grantIndex{}, ctx.Err()
		case <-f.done:
			return f.index, f.err
		}
	}
	f := &flight{done: make(chan struct{})}
	s.flight = f
	s.mu.Unlock()

	// If Load panics, still clear the flight and close done so waiters unblock.
	defer func() {
		if rec := recover(); rec != nil {
			idx = grantIndex{}
			err = fmt.Errorf("mcra: list panicked: %v", rec)
			f.index = grantIndex{}
			f.err = err
		}
		s.mu.Lock()
		if s.flight == f {
			s.flight = nil
		}
		s.mu.Unlock()
		close(f.done)
	}()

	loadCtx, cancel := context.WithTimeout(context.Background(), listTimeout)
	defer cancel()

	idx, err = s.load.Load(loadCtx)
	if err != nil {
		f.err = err
		idx = grantIndex{}
		return idx, err
	}
	f.index = idx
	s.mu.Lock()
	s.entry = &cacheEntry{index: idx, expires: s.now().Add(s.ttl)}
	s.mu.Unlock()
	return idx, nil
}

// snapshotKey shares snapshots across NewMiddleware calls.
// Mode and MaxTenants are not part of the key. The cached value is the full grantIndex.
type snapshotKey struct {
	kubeconfig string
	ttl        time.Duration
}

var (
	snapshotsMu sync.Mutex
	snapshots   map[snapshotKey]*snapshot
)

// acquireSnapshot returns the shared snapshot, or a private one when a test seam is set.
// A non-nil loader or a non-nil now does not call loadHubConfig.
// Do not call grants while holding snapshotsMu.
func acquireSnapshot(opts Options) *snapshot {
	if opts.loader != nil || opts.now != nil {
		return newSnapshot(opts.TTL, opts.now, opts.loader)
	}
	snapshotsMu.Lock()
	defer snapshotsMu.Unlock()
	if snapshots == nil {
		snapshots = make(map[snapshotKey]*snapshot)
	}
	key := snapshotKey{kubeconfig: opts.Kubeconfig, ttl: opts.TTL}
	if snap, ok := snapshots[key]; ok {
		return snap
	}
	cfg, err := loadHubConfig(opts.Kubeconfig)
	if err != nil {
		panic(fmt.Errorf("mcra: load hub config: %w", err))
	}
	hub, err := newHubLoader(cfg)
	if err != nil {
		panic(fmt.Errorf("mcra: load hub config: %w", err))
	}
	snap := newSnapshot(opts.TTL, nil, hub)
	snapshots[key] = snap
	return snap
}
