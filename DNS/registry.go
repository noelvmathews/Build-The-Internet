// Package registry is the thread-safe, in-memory domain -> IP table.
package registry

import (
	"context"
	"sync"
	"time"
)

// Entry is one registered domain.
type Entry struct {
	Domain       string
	IP           string
	RegisteredAt time.Time
	LastSeen     time.Time
}

// Registry maps domain names to source IPs. Lookups are O(1) under a read lock.
// With ttl > 0, an entry not re-registered within ttl is treated as absent
// (checked lazily on lookup and physically removed by Sweep).
type Registry struct {
	mu      sync.RWMutex
	entries map[string]Entry
	ttl     time.Duration
	now     func() time.Time
}

// New creates a registry. ttl == 0 disables expiry.
func New(ttl time.Duration) *Registry {
	return &Registry{
		entries: make(map[string]Entry),
		ttl:     ttl,
		now:     time.Now,
	}
}

// TTL returns the configured expiry (0 = never).
func (r *Registry) TTL() time.Duration { return r.ttl }

func (r *Registry) expired(e Entry, now time.Time) bool {
	return r.ttl > 0 && now.Sub(e.LastSeen) > r.ttl
}

// Register stores (or overwrites) domain -> ip and refreshes its lease.
// existed reports whether a live entry was already present; prevIP is its old IP.
func (r *Registry) Register(domain, ip string) (prevIP string, existed bool) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.entries[domain]
	if ok && r.expired(e, now) {
		ok = false
	}
	if ok {
		prevIP = e.IP
		e.IP = ip
		e.LastSeen = now
	} else {
		e = Entry{Domain: domain, IP: ip, RegisteredAt: now, LastSeen: now}
	}
	r.entries[domain] = e
	return prevIP, ok
}

// Lookup returns the live entry for domain. It does not refresh the lease.
func (r *Registry) Lookup(domain string) (Entry, bool) {
	now := r.now()
	r.mu.RLock()
	e, ok := r.entries[domain]
	r.mu.RUnlock()
	if !ok || r.expired(e, now) {
		return Entry{}, false
	}
	return e, true
}

// Len returns the number of live entries.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.ttl == 0 {
		return len(r.entries)
	}
	now := r.now()
	n := 0
	for _, e := range r.entries {
		if !r.expired(e, now) {
			n++
		}
	}
	return n
}

// Sweep deletes expired entries and returns them.
func (r *Registry) Sweep() []Entry {
	if r.ttl <= 0 {
		return nil
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	var removed []Entry
	for d, e := range r.entries {
		if r.expired(e, now) {
			delete(r.entries, d)
			removed = append(removed, e)
		}
	}
	return removed
}

// RunSweeper periodically calls Sweep until ctx is cancelled.
// onExpire (optional) is invoked for every removed entry.
func (r *Registry) RunSweeper(ctx context.Context, interval time.Duration, onExpire func(Entry)) {
	if r.ttl <= 0 || interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, e := range r.Sweep() {
				if onExpire != nil {
					onExpire(e)
				}
			}
		}
	}
}
