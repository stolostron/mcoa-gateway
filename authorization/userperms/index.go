package userperms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// credential is the principal a hub list runs as.
// token is set only for a bearer credential. user and groups are set only for impersonation.
type credential struct {
	kind   credentialKind
	token  string
	user   string
	groups []string
}

type credentialKind uint8

const (
	credBearer credentialKind = iota + 1
	credImpersonate
)

func (k credentialKind) String() string {
	switch k {
	case credBearer:
		return "bearer"
	case credImpersonate:
		return "impersonate"
	default:
		return "unknown"
	}
}

// normalizeGroups returns a sorted, unique copy and drops empty strings.
// An empty result is nil.
func normalizeGroups(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, g := range in {
		if g != "" {
			out = append(out, g)
		}
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// fingerprint is the hex SHA-256 of a domain-separated encoding.
//
//	bearer:      "bearer\x00" + token
//	impersonate: "impersonate\x00" + user + ("\x00" + group)...
//
// A zero credential panics. Groups are normalized before they are hashed,
// so input order does not change the fingerprint.
type fingerprint string

func (c credential) fingerprint() fingerprint {
	if c.kind == 0 {
		panic("userperms: zero credential")
	}

	h := sha256.New()
	switch c.kind {
	case credBearer:
		_, _ = h.Write([]byte("bearer\x00"))
		_, _ = h.Write([]byte(c.token))
	case credImpersonate:
		_, _ = h.Write([]byte("impersonate\x00"))
		_, _ = h.Write([]byte(c.user))
		for _, g := range normalizeGroups(c.groups) {
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(g))
		}
	default:
		panic("userperms: unknown credential kind")
	}
	sum := h.Sum(nil)
	return fingerprint(hex.EncodeToString(sum))
}

// clusterSet is an immutable set of ManagedCluster names.
// The zero value admits nothing. names is never appended to after newClusterSet returns.
type clusterSet struct {
	names []string
}

func newClusterSet(names []string) clusterSet {
	if len(names) == 0 {
		return clusterSet{}
	}
	cp := make([]string, 0, len(names))
	for _, name := range names {
		if name != "" {
			cp = append(cp, name)
		}
	}
	if len(cp) == 0 {
		return clusterSet{}
	}
	slices.Sort(cp)
	cp = slices.Compact(cp)
	return clusterSet{names: cp}
}

func (s clusterSet) has(name string) bool {
	_, ok := slices.BinarySearch(s.names, name)
	return ok
}

func (s clusterSet) len() int { return len(s.names) }

// joined is the derive tenant. names is already sorted and de-duplicated.
func (s clusterSet) joined() string {
	return strings.Join(s.names, "|")
}

const (
	// defaultTTL is how long one credential's clusterSet may be reused.
	defaultTTL = 30 * time.Second

	// maxEntries bounds the fingerprint map. Past this, drop expired entries
	// first, then the entry with the earliest expiry.
	maxEntries = 4096
)

// lister loads the full set for one credential.
// The index never sees a rest.Config or a UserPermission.
type lister interface {
	List(ctx context.Context, cred credential) (clusterSet, error)
}

// accessIndex is the only writer of fingerprint to clusterSet.
// Callers hold clusterSet by value. The backing array is never written after newClusterSet.
// mu guards items and flights. Do not copy an accessIndex by value.
type accessIndex struct {
	ttl     time.Duration
	now     func() time.Time
	load    lister
	mu      sync.Mutex
	items   map[fingerprint]cacheEntry
	flights map[fingerprint]*flight
}

type cacheEntry struct {
	set     clusterSet
	expires time.Time
}

type flight struct {
	done chan struct{}
	set  clusterSet
	err  error
}

func newAccessIndex(ttl time.Duration, now func() time.Time, load lister) *accessIndex {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if now == nil {
		now = time.Now
	}
	return &accessIndex{
		ttl:     ttl,
		now:     now,
		load:    load,
		items:   make(map[fingerprint]cacheEntry),
		flights: make(map[fingerprint]*flight),
	}
}

// clusterSet returns the subject's clusters.
// The lock is held from the freshness check through flight creation so two misses cannot both lead.
func (x *accessIndex) clusterSet(ctx context.Context, cred credential) (set clusterSet, err error) {
	fp := cred.fingerprint()
	x.mu.Lock()
	if entry, ok := x.items[fp]; ok {
		if x.now().Before(entry.expires) {
			set = entry.set
			x.mu.Unlock()
			return set, nil
		}
		delete(x.items, fp)
	}
	if f, ok := x.flights[fp]; ok {
		x.mu.Unlock()
		select {
		case <-ctx.Done():
			return clusterSet{}, ctx.Err()
		case <-f.done:
			return f.set, f.err
		}
	}
	f := &flight{done: make(chan struct{})}
	x.flights[fp] = f
	x.mu.Unlock()

	// If List panics, still delete the flight and close done so waiters unblock.
	defer func() {
		if rec := recover(); rec != nil {
			set = clusterSet{}
			err = fmt.Errorf("userpermissions list panicked: %v", rec)
			f.set = clusterSet{}
			f.err = err
		}
		x.mu.Lock()
		delete(x.flights, fp)
		x.mu.Unlock()
		close(f.done)
	}()

	set, err = x.load.List(ctx, cred)
	if err != nil {
		f.err = err
		return clusterSet{}, err
	}
	f.set = set
	x.mu.Lock()
	x.items[fp] = cacheEntry{set: set, expires: x.now().Add(x.ttl)}
	x.evictLocked()
	x.mu.Unlock()
	return set, nil
}

func (x *accessIndex) evictLocked() {
	for len(x.items) > maxEntries {
		now := x.now()
		expired := make([]fingerprint, 0)
		var oldest fingerprint
		var oldestExp time.Time
		haveOldest := false
		for fp, entry := range x.items {
			if !now.Before(entry.expires) {
				expired = append(expired, fp)
				continue
			}
			if !haveOldest || entry.expires.Before(oldestExp) {
				haveOldest = true
				oldest = fp
				oldestExp = entry.expires
			}
		}
		if len(expired) > 0 {
			for _, fp := range expired {
				delete(x.items, fp)
			}
			continue
		}
		if !haveOldest {
			return
		}
		delete(x.items, oldest)
	}
}

// indexKey shares indexes across NewMiddleware calls.
// The header name is not part of the key. The set depends on the hub and the credential.
// Mode and MaxTenants are not part of the key. The cached value is the full clusterSet.
// The cap is applied when derive reads the set.
type indexKey struct {
	kubeconfig string
	ttl        time.Duration
}

var (
	indexesMu sync.Mutex
	indexes   map[indexKey]*accessIndex
)

// acquireIndex returns the shared index, or a private one when a test seam is set.
// Do not call clusterSet while holding indexesMu.
func acquireIndex(opts Options) *accessIndex {
	if opts.loader != nil || opts.now != nil {
		return newAccessIndex(opts.TTL, opts.now, opts.loader)
	}
	indexesMu.Lock()
	defer indexesMu.Unlock()
	if indexes == nil {
		indexes = make(map[indexKey]*accessIndex)
	}
	key := indexKey{kubeconfig: opts.Kubeconfig, ttl: opts.TTL}
	if idx, ok := indexes[key]; ok {
		return idx
	}
	cfg, err := loadHubConfig(opts.Kubeconfig)
	if err != nil {
		panic(fmt.Errorf("userperms: load hub config: %w", err))
	}
	idx := newAccessIndex(opts.TTL, nil, kubeLister{base: cfg})
	indexes[key] = idx
	return idx
}
