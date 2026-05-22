package kerberos

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrkhachaturov/docker-external-dns/transport-rfc2136/internal/state"
)

// countingExec records the kinit invocations and lets each call return a
// different error (or nil) based on its index. Used so tests can simulate
// "first refresh ok, second fails" patterns deterministically.
type countingExec struct {
	calls   int32
	results []error
}

func (c *countingExec) Run(name string, args ...string) error {
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

func TestRefresher_DefaultIntervalIs12Hours(t *testing.T) {
	if DefaultRefreshInterval != 12*time.Hour {
		t.Fatalf("DefaultRefreshInterval: got %v want %v", DefaultRefreshInterval, 12*time.Hour)
	}
}
