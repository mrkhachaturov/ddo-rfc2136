package kerberos

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrkhachaturov/ddo-rfc2136/internal/state"
)

// countingExec records the kinit invocations and lets each call return a
// different error (or nil) based on its index. Used so tests can simulate
// "first refresh ok, second fails" patterns deterministically.
type countingExec struct {
	calls      int32
	stdinCalls int32
	results    []error
	lastArgs   []string
	lastStdin  string
}

func (c *countingExec) Run(name string, args ...string) error {
	c.lastArgs = args
	i := int(atomic.AddInt32(&c.calls, 1)) - 1
	if i < len(c.results) {
		return c.results[i]
	}
	return nil
}

func (c *countingExec) RunWithStdin(name string, stdin string, args ...string) error {
	c.lastArgs = args
	c.lastStdin = stdin
	atomic.AddInt32(&c.stdinCalls, 1)
	i := int(atomic.AddInt32(&c.calls, 1)) - 1
	if i < len(c.results) {
		return c.results[i]
	}
	return nil
}

func newRefresher(t *testing.T, exec Executor, st *state.Kerberos, interval time.Duration) *Refresher {
	t.Helper()
	return &Refresher{
		Kinit:     &Kinit{Exec: exec},
		Krb5Conf:  "/etc/krb5.conf",
		Keytab:    "/run/secrets/keytab",
		Principal: "svc-dns@CORP.EXAMPLE.COM",
		Interval:  interval,
		State:     st,
		now:       func() time.Time { return time.Unix(1700000000, 0) },
	}
}

func TestRefresher_SuccessfulRefreshMarksReady(t *testing.T) {
	st := state.NewKerberos()
	exec := &countingExec{results: []error{nil}}
	r := newRefresher(t, exec, st, time.Hour)

	r.refreshOnce(r.now)

	status, detail, last := st.Snapshot()
	if status != state.StatusReady {
		t.Fatalf("status: got %q want %q", status, state.StatusReady)
	}
	if detail != "" {
		t.Fatalf("detail: got %q want empty", detail)
	}
	if last.IsZero() {
		t.Fatalf("lastRefresh: expected non-zero")
	}
}

func TestRefresher_FailureMarksExpiredButDoesNotPanic(t *testing.T) {
	st := state.NewKerberos()
	st.MarkReady(time.Unix(1, 0))
	exec := &countingExec{results: []error{errors.New("KDC unreachable")}}
	r := newRefresher(t, exec, st, time.Hour)

	r.refreshOnce(r.now)

	status, detail, last := st.Snapshot()
	if status != state.StatusExpired {
		t.Fatalf("status: got %q want %q", status, state.StatusExpired)
	}
	if detail == "" {
		t.Fatalf("detail: expected non-empty error message")
	}
	if !last.Equal(time.Unix(1, 0)) {
		t.Fatalf("lastRefresh: must preserve last successful refresh, got %v", last)
	}
}

func TestRefresher_RunHonoursContextCancellation(t *testing.T) {
	st := state.NewKerberos()
	exec := &countingExec{results: []error{nil, nil, nil, nil}}
	// 5ms interval so we get at least one tick well before the deadline.
	r := newRefresher(t, exec, st, 5*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned err: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Run did not exit after context cancellation")
	}

	if atomic.LoadInt32(&exec.calls) == 0 {
		t.Fatalf("expected at least one refresh tick before cancellation")
	}
	status, _, _ := st.Snapshot()
	if status != state.StatusReady {
		t.Fatalf("expected StatusReady after successful ticks, got %q", status)
	}
}

func TestRefresher_DefaultIntervalIs8Hours(t *testing.T) {
	if DefaultRefreshInterval != 8*time.Hour {
		t.Fatalf("DefaultRefreshInterval: got %v want %v", DefaultRefreshInterval, 8*time.Hour)
	}
}

// fakeLifetime is an injectable TGT-lifetime source so tests need no KDC.
type fakeLifetime struct {
	endtime time.Time
	err     error
}

func (f fakeLifetime) TGTEndTime() (time.Time, error) { return f.endtime, f.err }

// When the issued ticket is short (4h), the next refresh must land at
// 0.5*lifetime (2h) — well below the configured 8h ceiling.
func TestRefresher_IntervalShorterThanConfiguredForShortTicket(t *testing.T) {
	st := state.NewKerberos()
	now := time.Unix(1700000000, 0)
	exec := &countingExec{results: []error{nil}}
	r := newRefresher(t, exec, st, 8*time.Hour)
	r.now = func() time.Time { return now }
	r.Lifetime = fakeLifetime{endtime: now.Add(4 * time.Hour)}

	next := r.refreshOnce(r.now)

	if want := 2 * time.Hour; next != want {
		t.Fatalf("next interval: got %v want %v (0.5 * 4h ticket)", next, want)
	}
}

// When the issued ticket is long (24h → 0.5*lifetime = 12h), the configured
// ceiling (8h) wins: interval = min(configured, 0.5*lifetime).
func TestRefresher_CeilingHonoredForLongTicket(t *testing.T) {
	st := state.NewKerberos()
	now := time.Unix(1700000000, 0)
	exec := &countingExec{results: []error{nil}}
	r := newRefresher(t, exec, st, 8*time.Hour)
	r.now = func() time.Time { return now }
	r.Lifetime = fakeLifetime{endtime: now.Add(24 * time.Hour)}

	next := r.refreshOnce(r.now)

	if want := 8 * time.Hour; next != want {
		t.Fatalf("next interval: got %v want %v (configured ceiling)", next, want)
	}
}

// With no configured interval, the default (8h) is the ceiling.
func TestRefresher_DefaultCeilingWhenUnconfigured(t *testing.T) {
	st := state.NewKerberos()
	now := time.Unix(1700000000, 0)
	exec := &countingExec{results: []error{nil}}
	r := newRefresher(t, exec, st, 0)
	r.now = func() time.Time { return now }
	r.Lifetime = fakeLifetime{endtime: now.Add(100 * time.Hour)}

	next := r.refreshOnce(r.now)

	if want := DefaultRefreshInterval; next != want {
		t.Fatalf("next interval: got %v want %v (default ceiling)", next, want)
	}
}

// A failed refresh must reschedule on a short backoff (1-5 min), NOT the
// full interval — one transient miss must not open an expiry window.
func TestRefresher_FailureRetriesOnShortBackoff(t *testing.T) {
	st := state.NewKerberos()
	st.MarkReady(time.Unix(1, 0))
	exec := &countingExec{results: []error{errors.New("KDC unreachable")}}
	r := newRefresher(t, exec, st, 8*time.Hour)
	// lifetime source should not even be consulted on failure.
	r.Lifetime = fakeLifetime{err: errors.New("no ccache")}

	next := r.refreshOnce(r.now)

	if next < retryBackoffMin || next > retryBackoffMax {
		t.Fatalf("retry backoff: got %v want within [%v,%v]", next, retryBackoffMin, retryBackoffMax)
	}
	status, _, _ := st.Snapshot()
	if status != state.StatusExpired {
		t.Fatalf("status after failure: got %q want %q", status, state.StatusExpired)
	}
}

// If kinit succeeds but the ccache can't be read, fall back to the
// configured ceiling rather than crashing — the ticket is valid, we just
// can't see its endtime.
func TestRefresher_LifetimeReadErrorFallsBackToCeiling(t *testing.T) {
	st := state.NewKerberos()
	now := time.Unix(1700000000, 0)
	exec := &countingExec{results: []error{nil}}
	r := newRefresher(t, exec, st, 6*time.Hour)
	r.now = func() time.Time { return now }
	r.Lifetime = fakeLifetime{err: errors.New("ccache parse error")}

	next := r.refreshOnce(r.now)

	if want := 6 * time.Hour; next != want {
		t.Fatalf("fallback interval: got %v want %v (configured ceiling)", next, want)
	}
	status, _, _ := st.Snapshot()
	if status != state.StatusReady {
		t.Fatalf("status: got %q want %q (kinit succeeded)", status, state.StatusReady)
	}
}

func TestRefresher_PasswordModeDispatchesStdinKinit(t *testing.T) {
	st := state.NewKerberos()
	exec := &countingExec{results: []error{nil}}
	r := &Refresher{
		Kinit:     &Kinit{Exec: exec},
		Krb5Conf:  "/etc/krb5.conf",
		Password:  "hunter2",
		Principal: "svc-dns@CORP.EXAMPLE.COM",
		Interval:  time.Hour,
		State:     st,
		now:       func() time.Time { return time.Unix(1700000000, 0) },
	}

	r.refreshOnce(r.now)

	if atomic.LoadInt32(&exec.stdinCalls) != 1 {
		t.Fatalf("expected password kinit to use stdin path, stdinCalls=%d", exec.stdinCalls)
	}
	if exec.lastStdin != "hunter2\n" {
		t.Fatalf("password not piped to refresher kinit: %q", exec.lastStdin)
	}
	status, _, _ := st.Snapshot()
	if status != state.StatusReady {
		t.Fatalf("expected StatusReady after successful password refresh, got %q", status)
	}
}
