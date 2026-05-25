// Package state holds process-global runtime state shared between the
// background kinit-refresh goroutine and the /healthz HTTP handler.
package state

import (
	"sync"
	"time"
)

// KerberosStatus is the string emitted from /healthz.
//
//   - "ready"      most recent kinit succeeded; the cached TGT should be valid.
//   - "expired"    the most recent kinit attempt failed; ticket has likely
//     expired or the KDC/keytab/principal config is broken.
//     The sidecar keeps running because the next refresh cycle
//     might recover (transient KDC blip, time skew correction,
//     etc.).
//   - "unknown"    initial state before the first kinit has completed.
type KerberosStatus string

const (
	StatusUnknown KerberosStatus = "unknown"
	StatusReady   KerberosStatus = "ready"
	StatusExpired KerberosStatus = "expired"
)

// Kerberos is the small, read-mostly state container shared between the
// refresh goroutine (writer) and HTTP handlers (readers). The zero value is
// safe to use and reports StatusUnknown with no last-refresh timestamp.
type Kerberos struct {
	mu          sync.RWMutex
	status      KerberosStatus
	detail      string
	lastRefresh time.Time
}

// NewKerberos returns a fresh state container in StatusUnknown.
func NewKerberos() *Kerberos {
	return &Kerberos{status: StatusUnknown}
}

// MarkReady records a successful kinit refresh at time `at`.
func (k *Kerberos) MarkReady(at time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.status = StatusReady
	k.detail = ""
	k.lastRefresh = at
}

// MarkExpired records a failed kinit refresh and the error string. The
// last-refresh timestamp is left untouched so observers can see how long ago
// the last *successful* kinit was.
func (k *Kerberos) MarkExpired(detail string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.status = StatusExpired
	k.detail = detail
}

// Snapshot returns a read-only copy of the current state for callers (e.g.
// /healthz) that need a consistent view without holding the lock.
func (k *Kerberos) Snapshot() (status KerberosStatus, detail string, lastRefresh time.Time) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.status, k.detail, k.lastRefresh
}
