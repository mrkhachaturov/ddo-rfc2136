package state

import (
	"sync"
	"testing"

	"github.com/mrkhachaturov/ddo-rfc2136/internal/dnsop"
)

func TestAXFRCache_PutGetDrop(t *testing.T) {
	c := NewAXFRCache()
	if _, ok := c.Get("z"); ok {
		t.Fatalf("empty cache should miss")
	}
	c.Put("z", []dnsop.Record{{Name: "a", Type: "A", Value: "1.1.1.1"}})
	got, ok := c.Get("z")
	if !ok || len(got) != 1 {
		t.Fatalf("missing: %+v", got)
	}
	c.Drop("z")
	if _, ok := c.Get("z"); ok {
		t.Fatalf("after drop should miss")
	}
}

func TestZonePins_SetGet(t *testing.T) {
	p := NewZonePins()
	if _, ok := p.Get("z"); ok {
		t.Fatalf("empty pins should miss")
	}
	p.Set("z", "dc01")
	dc, ok := p.Get("z")
	if !ok || dc != "dc01" {
		t.Fatalf("pin: %q ok=%v", dc, ok)
	}
}

func TestZoneLocks_SameZoneSerialisesGoroutines(t *testing.T) {
	zl := NewZoneLocks()
	var inFlight, max int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := zl.For("z")
			m.Lock()
			defer m.Unlock()
			mu.Lock()
			inFlight++
			if inFlight > max {
				max = inFlight
			}
			mu.Unlock()
			// no sleep — relying on the lock to guarantee mutual exclusion.
			mu.Lock()
			inFlight--
			mu.Unlock()
		}()
	}
	wg.Wait()
	if max != 1 {
		t.Fatalf("expected at most 1 goroutine inside the per-zone lock, saw %d", max)
	}
}
