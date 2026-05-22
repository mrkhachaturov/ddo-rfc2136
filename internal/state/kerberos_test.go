package state

import (
	"testing"
	"time"
)

func TestKerberos_DefaultStateIsUnknown(t *testing.T) {
	k := NewKerberos()
	status, detail, last := k.Snapshot()
	if status != StatusUnknown {
		t.Fatalf("default status: got %q want %q", status, StatusUnknown)
	}
	if detail != "" {
		t.Fatalf("default detail: got %q want empty", detail)
	}
	if !last.IsZero() {
		t.Fatalf("default lastRefresh: got %v want zero", last)
	}
}

func TestKerberos_MarkReadyClearsDetail(t *testing.T) {
	k := NewKerberos()
	k.MarkExpired("kinit failed")
	at := time.Unix(1700000000, 0)
	k.MarkReady(at)

	status, detail, last := k.Snapshot()
	if status != StatusReady {
		t.Fatalf("status: got %q want %q", status, StatusReady)
	}
	if detail != "" {
		t.Fatalf("detail: got %q want empty (MarkReady must clear it)", detail)
	}
	if !last.Equal(at) {
		t.Fatalf("lastRefresh: got %v want %v", last, at)
	}
}

func TestKerberos_MarkExpiredPreservesLastSuccess(t *testing.T) {
	k := NewKerberos()
	good := time.Unix(1700000000, 0)
	k.MarkReady(good)
	k.MarkExpired("kdc unreachable")

	status, detail, last := k.Snapshot()
	if status != StatusExpired {
		t.Fatalf("status: got %q want %q", status, StatusExpired)
	}
	if detail != "kdc unreachable" {
		t.Fatalf("detail: got %q", detail)
	}
	if !last.Equal(good) {
		t.Fatalf("lastRefresh: got %v want %v (MarkExpired must not clobber last success)", last, good)
	}
}
