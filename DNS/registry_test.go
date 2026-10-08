package registry

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestRegisterAndLookup(t *testing.T) {
	r := New(0)
	if _, ok := r.Lookup("acm-db"); ok {
		t.Fatal("empty registry must not resolve anything")
	}
	prev, existed := r.Register("acm-db", "10.0.0.1")
	if existed || prev != "" {
		t.Fatalf("first register: prev=%q existed=%v", prev, existed)
	}
	e, ok := r.Lookup("acm-db")
	if !ok || e.IP != "10.0.0.1" || e.Domain != "acm-db" {
		t.Fatalf("lookup = %+v, %v", e, ok)
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d", r.Len())
	}
}

func TestOverwriteKeepsRegisteredAt(t *testing.T) {
	r := New(0)
	clock := time.Unix(1000, 0)
	r.now = func() time.Time { return clock }
	r.Register("acm-db", "10.0.0.1")

	clock = clock.Add(time.Minute)
	prev, existed := r.Register("acm-db", "10.0.0.2")
	if !existed || prev != "10.0.0.1" {
		t.Fatalf("prev=%q existed=%v", prev, existed)
	}
	e, _ := r.Lookup("acm-db")
	if e.IP != "10.0.0.2" || !e.RegisteredAt.Equal(time.Unix(1000, 0)) || !e.LastSeen.Equal(clock) {
		t.Fatalf("unexpected entry %+v", e)
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1", r.Len())
	}
}

func TestMultipleServices(t *testing.T) {
	r := New(0)
	r.Register("acm-db", "10.0.0.1")
	r.Register("acm-server", "10.0.0.2")
	r.Register("acm-app", "10.0.0.3")
	for d, ip := range map[string]string{"acm-db": "10.0.0.1", "acm-server": "10.0.0.2", "acm-app": "10.0.0.3"} {
		if e, ok := r.Lookup(d); !ok || e.IP != ip {
			t.Errorf("%s -> %+v, %v", d, e, ok)
		}
	}
}

func TestTTLExpiryAndRefresh(t *testing.T) {
	r := New(10 * time.Second)
	clock := time.Unix(1000, 0)
	r.now = func() time.Time { return clock }

	r.Register("acm-db", "10.0.0.1")
	clock = clock.Add(5 * time.Second)
	if _, ok := r.Lookup("acm-db"); !ok {
		t.Fatal("entry should still be live at 5s")
	}

	clock = clock.Add(6 * time.Second) // 11s since registration
	if _, ok := r.Lookup("acm-db"); ok {
		t.Fatal("entry should be expired at 11s")
	}
	if r.Len() != 0 {
		t.Fatalf("Len = %d, want 0 for expired entry", r.Len())
	}

	// Re-registering an expired entry is a fresh registration.
	if _, existed := r.Register("acm-db", "10.0.0.9"); existed {
		t.Fatal("expired entry should count as new registration")
	}
	clock = clock.Add(8 * time.Second)
	r.Register("acm-db", "10.0.0.9") // refresh
	clock = clock.Add(8 * time.Second)
	if _, ok := r.Lookup("acm-db"); !ok {
		t.Fatal("refresh should extend the lease")
	}
}

func TestSweep(t *testing.T) {
	r := New(10 * time.Second)
	clock := time.Unix(1000, 0)
	r.now = func() time.Time { return clock }
	r.Register("old", "10.0.0.1")
	clock = clock.Add(8 * time.Second)
	r.Register("fresh", "10.0.0.2")
	clock = clock.Add(5 * time.Second)

	removed := r.Sweep()
	if len(removed) != 1 || removed[0].Domain != "old" {
		t.Fatalf("removed = %+v", removed)
	}
	if _, ok := r.Lookup("fresh"); !ok {
		t.Fatal("fresh entry must survive sweep")
	}
	if New(0).Sweep() != nil {
		t.Fatal("sweep with ttl=0 must be a no-op")
	}
}

func TestRunSweeperStopsOnCancel(t *testing.T) {
	r := New(time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	expired := make(chan string, 1)
	go func() {
		r.RunSweeper(ctx, 5*time.Millisecond, func(e Entry) {
			select {
			case expired <- e.Domain:
			default:
			}
		})
		close(done)
	}()
	r.Register("short-lived", "10.0.0.1")
	select {
	case d := <-expired:
		if d != "short-lived" {
			t.Fatalf("expired %q", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sweeper never expired the entry")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sweeper did not stop after cancel")
	}
}

func TestConcurrentRegisterAndLookup(t *testing.T) {
	r := New(0)
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				d := fmt.Sprintf("svc-%d", i%20)
				r.Register(d, "10.0.0."+strconv.Itoa(g))
				r.Lookup(d)
				r.Len()
			}
		}(g)
	}
	wg.Wait()
	if r.Len() != 20 {
		t.Fatalf("Len = %d, want 20", r.Len())
	}
}

func BenchmarkLookup(b *testing.B) {
	r := New(0)
	names := make([]string, 1000)
	for i := range names {
		names[i] = fmt.Sprintf("service-%d", i)
		r.Register(names[i], "10.0.0.1")
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			r.Lookup(names[i%len(names)])
			i++
		}
	})
}

func BenchmarkRegister(b *testing.B) {
	r := New(0)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.Register("acm-db", "10.0.0.1")
		}
	})
}
