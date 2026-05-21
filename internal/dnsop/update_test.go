package dnsop

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestBuildUpdateMsg_AddAndDelete(t *testing.T) {
	prereqs := []Prereq{
		{Kind: "NXRRSET", Name: "app.example.com", Type: "A"},
		{Kind: "YXRRSET", Name: "dnsync-a.app.example.com", Type: "TXT", Value: "\"owned-by=test:1\""},
	}
	changes := []Change{
		{Op: "add", Record: Record{Name: "app.example.com", Type: "A", TTL: 300, Value: "10.1.2.3"}},
		{Op: "delete", Record: Record{Name: "app.example.com", Type: "A", TTL: 300, Value: "10.0.0.1"}},
	}
	msg, err := BuildUpdateMsg("example.com", prereqs, changes)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if msg.Opcode != dns.OpcodeUpdate {
		t.Fatalf("expected UPDATE opcode")
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("expected 2 prereq records, got %d", len(msg.Answer))
	}
	if len(msg.Ns) != 2 {
		t.Fatalf("expected 2 update records, got %d", len(msg.Ns))
	}
}

func TestBuildUpdateMsg_RejectsUnknownPrereqKind(t *testing.T) {
	_, err := BuildUpdateMsg("example.com",
		[]Prereq{{Kind: "BOGUS", Name: "x", Type: "A"}},
		nil)
	if err == nil || !strings.Contains(err.Error(), "BOGUS") {
		t.Fatalf("expected error on bad prereq kind, got %v", err)
	}
}

func TestClassifyRcode(t *testing.T) {
	cases := []struct {
		rcode     int
		wantOk    bool
		wantRcode string
		wantRetry bool
	}{
		{dns.RcodeSuccess, true, "NOERROR", false},
		{dns.RcodeServerFailure, false, "SERVFAIL", true},
		{dns.RcodeYXRrset, false, "YXRRSET", false},
		{dns.RcodeNXRrset, false, "NXRRSET", false},
		{dns.RcodeNotAuth, false, "NOTAUTH", false},
		{dns.RcodeRefused, false, "REFUSED", false},
	}
	for _, c := range cases {
		got := ClassifyRcode(c.rcode)
		if got.OK != c.wantOk || got.Rcode != c.wantRcode || got.Retryable != c.wantRetry {
			t.Errorf("rcode=%d got=%+v", c.rcode, got)
		}
	}
}
