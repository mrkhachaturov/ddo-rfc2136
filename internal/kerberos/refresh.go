package kerberos

import (
	"context"
	"log"
	"time"

	"github.com/mrkhachaturov/ddo-rfc2136/internal/state"
)

// DefaultRefreshInterval is the CEILING on the background TGT refresh cadence,
// not a fixed period. The actual cadence is derived per-ticket from the
// lifetime the KDC actually grants: next refresh = now + 0.5*(endtime-now),
// capped at this ceiling (see refreshOnce).
//
// 8h is deliberately below the common Active Directory MaxTicketAge default
// of 10h: if for any reason the issued lifetime can't be read, this ceiling
// alone still refreshes before a 10h ticket expires. (The old 12h value
// assumed a 24h MIT/client-requested lifetime; AD caps the *issued* lifetime
// at its own MaxTicketAge regardless of what the client asks for, so a 12h
// ceiling left a 2h expiry window every cycle against a 10h ticket.)
const DefaultRefreshInterval = 8 * time.Hour

// retryBackoffMin/Max bound the reschedule delay after a FAILED refresh. A
// single transient KDC error at the tick must not make us wait a full
// interval — that alone can open an expiry window. Bias low: an extra kinit
// is cheap, a late kinit is an outage.
const (
	retryBackoffMin = 1 * time.Minute
	retryBackoffMax = 5 * time.Minute
)

// LifetimeSource reads the endtime of the TGT currently in the ccache. It is
// injectable so tests don't need a real KDC; production uses CCacheLifetime.
type LifetimeSource interface {
	// TGTEndTime returns the absolute expiry of the cached TGT.
	TGTEndTime() (time.Time, error)
}

// Refresher periodically re-runs kinit so the cached TGT never expires.
// On failure it flips the shared state to "expired" but does NOT exit — a
// later refresh may recover (KDC transient, time skew correction, keytab
// hot-swap, etc.). The sidecar's /healthz surfaces the current state so an
// operator (or orchestrator probe) can decide what to do.
type Refresher struct {
	Kinit     *Kinit
	Krb5Conf  string
	Keytab    string // empty when Password is set
	Password  string // empty when Keytab is set
	Principal string
	Interval  time.Duration
	State     *state.Kerberos

	// Lifetime reads the issued TGT's endtime after each successful kinit so
	// the next refresh can be scheduled from the real ticket lifetime rather
	// than a static guess. nil falls back to the configured/default ceiling.
	Lifetime LifetimeSource

	// now is injectable so tests can pin the timestamp written into state and
	// drive the lifetime math without sleeping. nil falls back to time.Now.
	now func() time.Time
}

// ceiling returns the configured upper bound on the refresh interval, or the
// default when unset.
func (r *Refresher) ceiling() time.Duration {
	if r.Interval > 0 {
		return r.Interval
	}
	return DefaultRefreshInterval
}

// Run executes the refresh loop until ctx is cancelled. It returns nil on
// graceful shutdown. The first kinit is performed by main.go before this
// loop starts (so a startup misconfiguration fails fast); Run only handles
// subsequent refreshes.
//
// Unlike a fixed ticker, the delay between refreshes is recomputed after each
// kinit from the lifetime of the ticket just issued, so a short-lived ticket
// is refreshed proportionally sooner and a failed refresh retries on a short
// backoff rather than waiting a full interval.
func (r *Refresher) Run(ctx context.Context) error {
	now := r.now
	if now == nil {
		now = time.Now
	}

	// First sleep is the ceiling: we have no fresh ticket-lifetime reading
	// until the first in-loop refresh runs.
	next := r.ceiling()
	t := time.NewTimer(next)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			next = r.refreshOnce(now)
			t.Reset(next)
		}
	}
}

// refreshOnce performs one kinit, updates shared state, and returns the delay
// until the NEXT refresh should run:
//
//   - success: min(configuredOrDefaultCeiling, 0.5*(endtime-now)). If the
//     lifetime can't be read, falls back to the ceiling (the ticket is valid,
//     we just can't see its endtime).
//   - failure: a short backoff in [retryBackoffMin, retryBackoffMax].
//
// It is split out so tests can drive it directly without spinning a timer.
func (r *Refresher) refreshOnce(now func() time.Time) time.Duration {
	var err error
	if r.Password != "" {
		err = r.Kinit.RunWithPassword(r.Krb5Conf, r.Principal, r.Password)
	} else {
		err = r.Kinit.Run(r.Krb5Conf, r.Keytab, r.Principal)
	}
	if err != nil {
		backoff := retryBackoffMin
		log.Printf("rfc2136-webhook: kinit refresh failed: %v (state=expired, retrying in %v)", err, backoff)
		if r.State != nil {
			r.State.MarkExpired(err.Error())
		}
		return backoff
	}

	next := r.ceiling()
	if r.Lifetime != nil {
		if endtime, lerr := r.Lifetime.TGTEndTime(); lerr != nil {
			log.Printf("rfc2136-webhook: kinit refresh ok but could not read TGT endtime: %v (falling back to ceiling %v)", lerr, next)
		} else {
			remaining := endtime.Sub(now())
			half := remaining / 2
			if half > 0 && half < next {
				next = half
			}
		}
	}

	log.Printf("rfc2136-webhook: kinit refresh ok (next refresh in %v)", next)
	if r.State != nil {
		r.State.MarkReady(now())
	}
	return next
}
