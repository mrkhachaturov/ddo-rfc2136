package state

import (
	"testing"
	"time"
)

func TestDCBreaker_OpensAfterThreshold(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewDCBreaker(3)
	b.SetClock(func() time.Time { return now })

	if !b.IsAvailable("dc01") {
		t.Fatalf("fresh breaker must be available")
	}
	if d := b.RecordFailure("dc01"); d != 0 {
		t.Fatalf("first failure should not open: %v", d)
	}
	if d := b.RecordFailure("dc01"); d != 0 {
		t.Fatalf("second failure should not open: %v", d)
	}
	if d := b.RecordFailure("dc01"); d != 60*time.Second {
		t.Fatalf("third failure should open for 60s, got %v", d)
	}
	if b.IsAvailable("dc01") {
		t.Fatalf("must be unavailable while open")
	}
}

func TestDCBreaker_ReclosesAfterCooldown(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewDCBreaker(2)
	b.SetClock(func() time.Time { return now })
	b.RecordFailure("dc01")
	b.RecordFailure("dc01")
	if b.IsAvailable("dc01") {
		t.Fatalf("expected open")
	}
	now = now.Add(61 * time.Second)
	if !b.IsAvailable("dc01") {
		t.Fatalf("expected re-closed after cooldown")
	}
}

func TestDCBreaker_ExponentialBackoffCappedAt1h(t *testing.T) {
	// Re-opens after a cool-off elapse compound the exponent. Each iteration
	// fails enough times to cross the threshold again; the cooldown should
	// grow 60s, 120s, 240s, ... capped at 1h.
	now := time.Unix(0, 0)
	b := NewDCBreaker(1)
	b.SetClock(func() time.Time { return now })

	wants := []time.Duration{60, 120, 240, 480, 960, 1920, 3600, 3600}
	for i, w := range wants {
		// Trigger one failure -> threshold=1 means immediate open.
		got := b.RecordFailure("dc01")
		if got != w*time.Second {
			t.Fatalf("step %d: got %v want %v", i, got, w*time.Second)
		}
		// Walk the clock past the cooldown so the next IsAvailable lazily
		// reopens for trial. RecordFailure right after must re-open with the
		// next-larger cooldown — note the fail counter is NOT reset on
		// re-availability when we want exponential backoff to keep growing.
		now = now.Add(got + time.Second)
		if !b.IsAvailable("dc01") {
			t.Fatalf("step %d: should be available after cooldown", i)
		}
	}
}

func TestDCBreaker_SuccessClearsStreak(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewDCBreaker(2)
	b.SetClock(func() time.Time { return now })
	b.RecordFailure("dc01")
	b.RecordSuccess("dc01")
	if d := b.RecordFailure("dc01"); d != 0 {
		t.Fatalf("after success, single failure should not open: %v", d)
	}
}
