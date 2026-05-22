package kerberos

import (
	"context"
	"log"
	"time"

	"github.com/mrkhachaturov/docker-external-dns/transport-rfc2136/internal/state"
)

// DefaultRefreshInterval is half of the AD default ticket lifetime (24h), giving
// us one full ticket-lifetime of headroom before any UPDATE call would see an
// expired TGT.
const DefaultRefreshInterval = 12 * time.Hour

// Refresher periodically re-runs kinit so the cached TGT never expires.
// On failure it flips the shared state to "expired" but does NOT exit — a
// later refresh may recover (KDC transient, time skew correction, keytab
// hot-swap, etc.). The sidecar's /healthz surfaces the current state so an
// operator (or orchestrator probe) can decide what to do.
type Refresher struct {
	Kinit     *Kinit
	Krb5Conf  string
	Keytab    string
	Principal string
	Interval  time.Duration
	State     *state.Kerberos

	// now is injectable so tests can pin the timestamp written into state
	// without sleeping. nil falls back to time.Now.
	now func() time.Time
}

// Run executes the refresh loop until ctx is cancelled. It returns nil on
// graceful shutdown. The first kinit is performed by main.go before this
// loop starts (so a startup misconfiguration fails fast); Run only handles
// subsequent refreshes.
func (r *Refresher) Run(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	now := r.now
	if now == nil {
		now = time.Now
	}

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.refreshOnce(now)
		}
	}
}

// refreshOnce is split out so tests can drive it directly without spinning a
// real ticker.
func (r *Refresher) refreshOnce(now func() time.Time) {
	if err := r.Kinit.Run(r.Krb5Conf, r.Keytab, r.Principal); err != nil {
		log.Printf("rfc2136-transport: kinit refresh failed: %v (state=expired, will retry on next interval)", err)
		if r.State != nil {
			r.State.MarkExpired(err.Error())
		}
		return
	}
	log.Printf("rfc2136-transport: kinit refresh ok")
	if r.State != nil {
		r.State.MarkReady(now())
	}
}
