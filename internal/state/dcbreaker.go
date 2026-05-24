package state

import (
	"sync"
	"time"
)

// DCBreaker tracks per-DC failure streaks and "open" windows.
//
// Behaviour, per the v1 spec brief:
//
//   - Each consecutive failed AXFR cycle increments a per-DC fail counter.
//   - When the counter reaches Threshold the circuit opens for
//     min(60s * 2^opens, 1h), where `opens` is how many times this DC has
//     already been opened. The opens counter survives a successful trial
//     so a chronically flapping DC keeps backing off exponentially.
//   - RecordSuccess clears the consecutive-failure counter AND resets the
//     opens counter — a clean cycle is enough to start the backoff over.
//   - Past the cooldown, IsAvailable lazily re-closes the circuit and
//     gives the DC one trial cycle (failure counter reset to 0 so a single
//     failure does not immediately re-open).
type DCBreaker struct {
	mu        sync.Mutex
	Threshold int
	now       func() time.Time
	fails     map[string]int
	opens     map[string]int
	openUntil map[string]time.Time
}

// NewDCBreaker constructs a breaker with the given consecutive-failure
// threshold. The clock is overridable for tests.
func NewDCBreaker(threshold int) *DCBreaker {
	if threshold < 1 {
		threshold = 1
	}
	return &DCBreaker{
		Threshold: threshold,
		now:       time.Now,
		fails:     map[string]int{},
		opens:     map[string]int{},
		openUntil: map[string]time.Time{},
	}
}

// SetClock swaps the clock used for cooldown bookkeeping (test seam).
func (b *DCBreaker) SetClock(f func() time.Time) { b.now = f }

// IsAvailable returns true if the DC's circuit is closed (or has just
// elapsed its cooldown). Past the cooldown it resets the consecutive
// failure counter so a single trial failure doesn't immediately re-open.
// The opens counter is preserved so the next open uses the next larger
// cooldown.
func (b *DCBreaker) IsAvailable(dc string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	openUntil, openIsSet := b.openUntil[dc]
	if !openIsSet {
		return true
	}
	if b.now().Before(openUntil) {
		return false
	}
	delete(b.openUntil, dc)
	b.fails[dc] = 0
	return true
}

// RecordSuccess clears any pending failure streak for a DC and resets
// the opens counter — a clean cycle wipes the backoff history.
func (b *DCBreaker) RecordSuccess(dc string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.openUntil, dc)
	b.fails[dc] = 0
	b.opens[dc] = 0
}

// RecordFailure bumps a DC's failure counter and, if the threshold is
// crossed and the circuit isn't already open, opens it for the next
// cooldown step. Returns the cooldown duration when the circuit transitions
// open this call (otherwise 0).
func (b *DCBreaker) RecordFailure(dc string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fails[dc] = b.fails[dc] + 1
	if b.fails[dc] < b.Threshold {
		return 0
	}
	if _, alreadyOpen := b.openUntil[dc]; alreadyOpen {
		return 0
	}
	opens := b.opens[dc]
	cooldown := 60 * time.Second
	for i := 0; i < opens; i++ {
		cooldown *= 2
		if cooldown >= time.Hour {
			cooldown = time.Hour
			break
		}
	}
	b.openUntil[dc] = b.now().Add(cooldown)
	b.opens[dc] = opens + 1
	return cooldown
}
