package events

import (
	"sync"
	"testing"
)

func TestAddAndSince(t *testing.T) {
	l := NewLog(3)
	if got := l.Since(0); got == nil || len(got) != 0 {
		t.Fatalf("empty log must return empty non-nil slice, got %#v", got)
	}
	for i := 0; i < 5; i++ {
		l.Add(LookupFound, "acm-db", "10.0.0.1", "")
	}
	all := l.Since(0)
	if len(all) != 3 || all[0].Seq != 3 || all[2].Seq != 5 {
		t.Fatalf("ring buffer wrong: %+v", all)
	}
	if got := l.Since(4); len(got) != 1 || got[0].Seq != 5 {
		t.Fatalf("Since(4) = %+v", got)
	}
}

func TestConcurrentAdd(t *testing.T) {
	l := NewLog(100)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				l.Add(DomainRegistered, "x", "", "")
				l.Since(0)
			}
		}()
	}
	wg.Wait()
	if got := l.Since(0); len(got) != 100 || got[99].Seq != 3200 {
		t.Fatalf("len=%d lastSeq=%d", len(got), got[len(got)-1].Seq)
	}
}
