// Package events keeps a small in-memory ring buffer of recent DNS events so
// the acm-app frontend can visualize registrations and lookups.
package events

import (
	"sync"
	"time"
)

// Event type names (also used as structured-log message names).
const (
	DomainRegistered = "DOMAIN_REGISTERED"
	DomainUpdated    = "DOMAIN_UPDATED"
	DomainExpired    = "DOMAIN_EXPIRED"
	RegisterFailed   = "REGISTER_FAILED"
	LookupFound      = "LOOKUP_FOUND"
	LookupNotFound   = "LOOKUP_NOT_FOUND"
	LookupFailed     = "LOOKUP_FAILED"
)

type Event struct {
	Seq    uint64    `json:"seq"`
	Time   time.Time `json:"time"`
	Type   string    `json:"type"`
	Domain string    `json:"domain,omitempty"`
	IP     string    `json:"ip,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Log is a fixed-size, concurrency-safe ring buffer of events.
type Log struct {
	mu  sync.Mutex
	max int
	seq uint64
	buf []Event
}

// NewLog creates a log holding at most max events (default 500).
func NewLog(max int) *Log {
	if max <= 0 {
		max = 500
	}
	return &Log{max: max, buf: make([]Event, 0, max)}
}

// Add appends an event, dropping the oldest when full.
func (l *Log) Add(typ, domain, ip, detail string) Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e := Event{Seq: l.seq, Time: time.Now().UTC(), Type: typ, Domain: domain, IP: ip, Detail: detail}
	if len(l.buf) == l.max {
		copy(l.buf, l.buf[1:])
		l.buf[len(l.buf)-1] = e
	} else {
		l.buf = append(l.buf, e)
	}
	return e
}

// Since returns events with Seq > after, oldest first. Never returns nil.
func (l *Log) Since(after uint64) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, 0, len(l.buf))
	for _, e := range l.buf {
		if e.Seq > after {
			out = append(out, e)
		}
	}
	return out
}
